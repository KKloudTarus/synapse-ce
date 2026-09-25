import importlib.util
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = pathlib.Path(__file__).with_name("dispatch_sca_trusted_ssm.py")
SPEC = importlib.util.spec_from_file_location("trusted_ssm_dispatch", SCRIPT)
DISPATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISPATCH)


class EnvelopeTests(unittest.TestCase):
    def provenance(self, root):
        for name in ("approval.json", "authorization.json", "handoff.json"):
            (root / name).write_text('{"name":"%s"}' % name, encoding="utf-8")

    def args(self, root):
        return type("Args", (), {
            "provenance_dir": str(root), "source_sha": "a" * 40,
            "run_id": "123", "run_attempt": "2", "output": str(root / "envelope.json"),
        })()

    def test_envelope_binds_exact_artifact_bytes_and_run_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.provenance(root)
            DISPATCH.build_envelope(self.args(root))
            output = json.loads((root / "envelope.json").read_text(encoding="utf-8"))
            self.assertRegex(output["sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(output["base64"])

    def test_envelope_rejects_extra_artifact_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.provenance(root)
            (root / "unexpected.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly"):
                DISPATCH.build_envelope(self.args(root))

    def test_summary_rejects_unaccepted_result(self):
        args = type("Args", (), {
            "source_sha": "a" * 40, "run_id": "123", "run_attempt": "2",
            "provenance_sha256": "sha256:" + "b" * 64,
        })()
        output = json.dumps({
            "schema_version": DISPATCH.SUMMARY_SCHEMA,
            "source_sha": "a" * 40, "workflow_run_id": "123", "workflow_run_attempt": "2",
            "provenance_sha256": "sha256:" + "b" * 64,
            "accepted": False, "observations": 24,
            "report_s3_uri": "s3://bucket/key", "report_version_id": "version",
        })
        with self.assertRaisesRegex(ValueError, "accepted"):
            DISPATCH.parse_summary(output, args, "command")

    def test_dispatch_retries_unpublished_ssm_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = type("Args", (), {
                "source_sha": "a" * 40, "run_id": "123", "run_attempt": "2",
                "provenance_sha256": "sha256:" + "b" * 64,
                "provenance_base64": "e30=", "mode": "run", "document": "fixed-document",
                "instance_id": "i-fixed", "region": "us-east-1",
                "timeout_seconds": 10, "poll_seconds": 1,
                "summary_path": str(root / "summary.json"),
            })()
            summary = {
                "schema_version": DISPATCH.SUMMARY_SCHEMA,
                "accepted": True, "source_sha": args.source_sha,
                "workflow_run_id": args.run_id, "workflow_run_attempt": args.run_attempt,
                "provenance_sha256": args.provenance_sha256, "observations": 24,
                "report_s3_uri": "s3://fixed-bucket/report.json",
                "report_version_id": "report-version",
            }
            calls = []

            def fake_aws(command):
                calls.append(command)
                if command[1] == "send-command":
                    return "command-id"
                invocation_count = len([item for item in calls if item[1] == "get-command-invocation"])
                if invocation_count == 1:
                    raise ValueError("AWS CLI failed: An error occurred (InvocationDoesNotExist) when calling the GetCommandInvocation operation")
                if invocation_count == 2:
                    return json.dumps({"Status": "Pending"})
                return json.dumps({"Status": "Success", "StandardOutputContent": json.dumps(summary)})

            with patch.object(DISPATCH, "aws", side_effect=fake_aws), patch.object(DISPATCH.time, "sleep"):
                DISPATCH.dispatch(args)
            saved = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["report_version_id"], "report-version")
            self.assertIn("--document-version", calls[0])
            self.assertEqual([call[1] for call in calls].count("get-command-invocation"), 3)

    def test_report_requires_exact_versioned_artifacts_and_passing_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source_sha = "a" * 40
            provenance_sha = "sha256:" + "b" * 64
            bucket = "trusted-bucket"
            prefix = "trusted/20260925/ci-results/123/2"
            report_uri = "s3://%s/%s/acceptance-report.json" % (bucket, prefix)
            archive_uri = "s3://%s/%s/publication.tar.gz" % (bucket, prefix)
            run = {
                "implementation_commit": source_sha, "run_key": "123/2",
                "observations": [[{} for _ in range(12)] for _ in range(2)],
                "result": {"gate": {"passed": True}},
            }
            run_bytes = json.dumps(run, separators=(",", ":")).encode()
            run_path = root / "run.json"
            run_path.write_bytes(run_bytes)
            archive_path = root / "source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(run_path, arcname="publication/run.json")
            report = {
                "schema_version": "synapse-sca-trusted-acceptance-report-v1",
                "accepted": True, "source_sha": source_sha,
                "workflow_run_id": "123", "workflow_run_attempt": "2",
                "provenance_sha256": provenance_sha, "observations": 24,
                "publication_s3_uri": archive_uri, "publication_version_id": "archive-version",
                "publication_sha256": DISPATCH.digest(archive_path.read_bytes()),
                "run_sha256": DISPATCH.digest(run_bytes),
            }
            report_bytes = json.dumps(report, separators=(",", ":")).encode()
            summary = {
                "report_s3_uri": report_uri, "report_version_id": "report-version",
                "report_sha256": DISPATCH.digest(report_bytes),
            }
            summary_path = root / "summary.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            args = type("Args", (), {
                "source_sha": source_sha, "run_id": "123", "run_attempt": "2",
                "provenance_sha256": provenance_sha, "summary_path": str(summary_path),
                "output_dir": str(root / "output"), "bucket": bucket, "region": "us-east-1",
            })()

            def fake_aws(command):
                destination = pathlib.Path(command[-1])
                if any("acceptance-report.json" in part for part in command):
                    destination.write_bytes(report_bytes)
                else:
                    destination.write_bytes(archive_path.read_bytes())

            with patch.object(DISPATCH, "aws", side_effect=fake_aws):
                DISPATCH.verify_report(args)
            self.assertTrue((root / "output/acceptance-report.json").exists())
            summary["report_s3_uri"] = "s3://trusted-bucket/other/report.json"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            with patch.object(DISPATCH, "aws") as aws:
                with self.assertRaisesRegex(ValueError, "fixed report object"):
                    DISPATCH.verify_report(args)
                aws.assert_not_called()


if __name__ == "__main__":
    unittest.main()

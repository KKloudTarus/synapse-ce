import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("sca_trusted_dispatch", Path(__file__).with_name("sca-trusted-dispatch.py"))
dispatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatch)

SHA = "a" * 40
RUN = "123456"
ATTEMPT = "2"


def encoded(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def provenance(overrides=None):
    approval = encoded({"implementation_commit": SHA})
    authorization = encoded({"implementation_commit": SHA})
    handoff = {
        "schema_version": "synapse-sca-maintainer-authorization-handoff-v1",
        "repository": "KKloudTarus/synapse-ce",
        "pull_number": 1320,
        "source_sha": SHA,
        "workflow_run_id": RUN,
        "workflow_run_attempt": ATTEMPT,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "approval_sha256": dispatch.digest(approval),
        "authorization_sha256": dispatch.digest(authorization),
    }
    if overrides:
        handoff.update(overrides)
    envelope = encoded({
        "schema_version": dispatch.SCHEMA,
        "source_sha": SHA,
        "workflow_run_id": RUN,
        "workflow_run_attempt": ATTEMPT,
        "approval": base64.b64encode(approval).decode(),
        "authorization": base64.b64encode(authorization).decode(),
        "handoff": base64.b64encode(encoded(handoff)).decode(),
    })
    return {"SSM_provenanceBase64": base64.b64encode(envelope).decode(), "SSM_provenanceSha256": dispatch.digest(envelope)}


class TrustedDispatchTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Linux file locking is required")
    def test_second_run_cannot_enter_locked_host(self):
        import fcntl

        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "trusted.lock"
            with lock_path.open("a+") as first:
                fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
                values = {"sourceSha": SHA, "runId": RUN, "runAttempt": ATTEMPT, "mode": "run"}
                with patch.object(dispatch, "LOCK_FILE", lock_path), \
                     patch.object(dispatch, "env", side_effect=lambda name, _pattern: values[name]), \
                     patch.object(dispatch, "load_provenance", return_value=("sha256:" + "b" * 64, {})), \
                     patch.object(dispatch, "execute") as execute:
                    with self.assertRaisesRegex(ValueError, "already active"):
                        dispatch.main()
                    execute.assert_not_called()

    def test_accepts_exact_fresh_handoff(self):
        supplied = provenance()
        with patch.dict(os.environ, supplied, clear=False):
            digest, records = dispatch.load_provenance(SHA, RUN, ATTEMPT)
        self.assertEqual(digest, dispatch.digest(base64.b64decode(supplied["SSM_provenanceBase64"])))
        self.assertEqual(records["approval"][1]["implementation_commit"], SHA)

    def test_rejects_wrong_pull_and_expired_handoff(self):
        for changed in (
            {"pull_number": 1321},
            {"generated_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=16)).isoformat()},
            {"approval_sha256": "sha256:" + "0" * 64},
        ):
            with self.subTest(changed=changed), patch.dict(os.environ, provenance(changed), clear=False):
                with self.assertRaises(ValueError):
                    dispatch.load_provenance(SHA, RUN, ATTEMPT)

    def test_rejects_replaced_envelope_even_with_claimed_digest(self):
        supplied = provenance()
        supplied["SSM_provenanceSha256"] = "sha256:" + "0" * 64
        with patch.dict(os.environ, supplied, clear=False):
            with self.assertRaises(ValueError):
                dispatch.load_provenance(SHA, RUN, ATTEMPT)

    def test_publication_requires_accepted_gate_and_all_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            publication = {
                "implementation_commit": SHA,
                "run_key": f"{RUN}/{ATTEMPT}",
                "repetitions": 2,
                "observations": [[{} for _ in range(12)] for _ in range(2)],
                "result": {"gate": {"passed": True}},
                "cleanup": {"raw_run_removed": True, "docker_cleaned": True},
            }
            path = output / "run.json"
            path.write_bytes(encoded(publication))
            self.assertEqual(dispatch.inspect_publication(output, SHA, RUN, ATTEMPT), publication)
            publication["result"]["gate"]["passed"] = False
            path.write_bytes(encoded(publication))
            with self.assertRaises(ValueError):
                dispatch.inspect_publication(output, SHA, RUN, ATTEMPT)
            publication["result"]["gate"]["passed"] = True
            publication["observations"][0].pop()
            path.write_bytes(encoded(publication))
            with self.assertRaises(ValueError):
                dispatch.inspect_publication(output, SHA, RUN, ATTEMPT)

    def test_run_snapshot_is_removed_after_cycle_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_file = root / "source-sha"
            approval_file = root / "approval-sha256"
            source_file.write_text(SHA)
            approval_file.write_text(dispatch.digest(b"approval"))
            inputs = root / "inputs"
            raw = root / "raw"
            staging = root / "staging"
            for path in (inputs, raw, staging):
                path.mkdir()
            with patch.object(dispatch, "SOURCE_SHA_FILE", source_file), \
                 patch.object(dispatch, "APPROVAL_DIGEST_FILE", approval_file), \
                 patch.object(dispatch, "TRUSTED_INPUTS", inputs), \
                 patch.object(dispatch, "RAW_RETENTION", raw), \
                 patch.object(dispatch, "STAGING", staging), \
                 patch.object(dispatch, "execute_cycle", side_effect=ValueError("cycle failed")):
                with self.assertRaisesRegex(ValueError, "cycle failed"):
                    dispatch.execute(SHA, RUN, ATTEMPT, "sha256:" + "b" * 64,
                                     {"approval": (b"approval", {})}, "run")
            self.assertEqual(list(staging.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

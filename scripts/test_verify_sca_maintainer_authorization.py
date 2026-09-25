import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("verify_sca_maintainer_authorization.py")
SPEC = importlib.util.spec_from_file_location("authorization_verifier", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


REPOSITORY = "KKloudTarus/synapse-ce"
SHA = "a" * 40
TIME = "2026-09-25T02:30:00Z"


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


class HandoffVerificationTests(unittest.TestCase):
    def write_handoff(self, root, source_sha=SHA, run_id="123", attempt="2", generated_at=TIME):
        digests = {name: "sha256:" + char * 64 for name, char in (("catalog", "1"), ("oracle", "2"), ("ratchet", "3"), ("policy", "4"))}
        approval = {
            "schema_version": VERIFIER.SCHEMA,
            "id": "17",
            "url": "https://github.com/%s/pull/1320#issuecomment-17" % REPOSITORY,
            "head_url": "https://github.com/%s/commit/%s" % (REPOSITORY, source_sha),
            "login": "pho-veteran",
            "created_at": generated_at,
            "updated_at": generated_at,
            "decision": "approved",
            "implementation_commit": source_sha,
            "body": VERIFIER.canonical_body(source_sha, digests),
        }
        approval_bytes = VERIFIER.canonical_json(approval)
        authorization = {
            "schema_version": VERIFIER.AUTHORIZATION_SCHEMA,
            "approval_id": "17",
            "approval_digest": digest(approval_bytes),
            "maintainer_login": "pho-veteran",
            "implementation_commit": source_sha,
            "catalog_digest": digests["catalog"],
            "oracle_digest": digests["oracle"],
            "ratchet_digest": digests["ratchet"],
            "policy_digest": digests["policy"],
            "decision": "approved",
            "transcribed_by": "github-actions-hosted-provenance",
            "transcribed_at": generated_at,
            "body": "captured",
        }
        authorization_bytes = VERIFIER.canonical_json(authorization)
        handoff = {
            "schema_version": VERIFIER.HANDOFF_SCHEMA,
            "repository": REPOSITORY,
            "pull_number": 1320,
            "source_sha": source_sha,
            "workflow_run_id": run_id,
            "workflow_run_attempt": attempt,
            "generated_at": generated_at,
            "approval_sha256": digest(approval_bytes),
            "authorization_sha256": digest(authorization_bytes),
        }
        (root / "approval.json").write_bytes(approval_bytes)
        (root / "authorization.json").write_bytes(authorization_bytes)
        (root / "handoff.json").write_bytes(VERIFIER.canonical_json(handoff))

    def args(self, root):
        return type("Args", (), {
            "repository": REPOSITORY, "pull_number": 1320, "source_sha": SHA,
            "workflow_run_id": "123", "workflow_run_attempt": "2", "handoff_dir": str(root),
            "max_age_seconds": 900, "now": "2026-09-25T02:35:00Z",
        })()

    def test_accepts_exact_same_run_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.write_handoff(root)
            VERIFIER.verify_handoff(self.args(root))

    def test_rejects_tampered_approval_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.write_handoff(root)
            (root / "approval.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "content hash"):
                VERIFIER.verify_handoff(self.args(root))

    def test_rejects_other_workflow_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.write_handoff(root, attempt="1")
            with self.assertRaisesRegex(ValueError, "run or attempt"):
                VERIFIER.verify_handoff(self.args(root))

    def test_rejects_stale_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.write_handoff(root, generated_at="2026-09-25T01:00:00Z")
            with self.assertRaisesRegex(ValueError, "freshness"):
                VERIFIER.verify_handoff(self.args(root))


class CaptureTests(unittest.TestCase):
    def test_comment_lookup_reads_later_pages(self):
        paths = []

        def fake_get(_base, _token, path):
            paths.append(path)
            return [{}] * 100 if path.endswith("&page=1") else [{"id": 101}]

        original = VERIFIER.api_get
        VERIFIER.api_get = fake_get
        try:
            comments = VERIFIER.issue_comments("https://api.github.test", "token", REPOSITORY, 1320)
        finally:
            VERIFIER.api_get = original
        self.assertEqual(len(comments), 101)
        self.assertEqual(len(paths), 2)

    def args(self, temporary):
        digests = {name: "sha256:" + char * 64 for name, char in (("catalog", "1"), ("oracle", "2"), ("ratchet", "3"), ("policy", "4"))}
        digest_path = pathlib.Path(temporary) / "digests.json"
        digest_path.write_text(json.dumps(digests), encoding="utf-8")
        return type("Args", (), {
            "api_base": "https://api.github.test", "token": "test-token", "repository": REPOSITORY,
            "pull_number": 1320, "source_sha": SHA, "digests": str(digest_path),
            "workflow_run_id": "123", "workflow_run_attempt": "2", "out_dir": str(pathlib.Path(temporary) / "out"),
        })(), digests

    def test_capture_rejects_author_without_maintain_permission(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, digests = self.args(temporary)
            body = VERIFIER.canonical_body(SHA, digests)
            responses = [
                {"number": 1320, "head": {"sha": SHA}},
                [{"id": 17, "body": body, "user": {"login": "pho-veteran"},
                  "html_url": "https://github.com/%s/pull/1320#issuecomment-17" % REPOSITORY,
                  "issue_url": "https://api.github.test/repos/%s/issues/1320" % REPOSITORY,
                  "created_at": TIME, "updated_at": TIME}],
                {"permission": "write"},
            ]
            original = VERIFIER.api_get
            VERIFIER.api_get = lambda *_: responses.pop(0)
            try:
                with self.assertRaisesRegex(ValueError, "admin or maintain"):
                    VERIFIER.capture(args)
            finally:
                VERIFIER.api_get = original

    def test_capture_emits_authorization_bound_to_live_comment(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, digests = self.args(temporary)
            body = VERIFIER.canonical_body(SHA, digests)
            responses = [
                {"number": 1320, "head": {"sha": SHA}},
                [{"id": 17, "body": body, "user": {"login": "pho-veteran"},
                  "html_url": "https://github.com/%s/pull/1320#issuecomment-17" % REPOSITORY,
                  "issue_url": "https://api.github.test/repos/%s/issues/1320" % REPOSITORY,
                  "created_at": TIME, "updated_at": TIME}],
                {"permission": "admin"},
            ]
            original = VERIFIER.api_get
            VERIFIER.api_get = lambda *_: responses.pop(0)
            try:
                VERIFIER.capture(args)
            finally:
                VERIFIER.api_get = original
            approval = json.loads((pathlib.Path(args.out_dir) / "approval.json").read_text(encoding="utf-8"))
            authorization = json.loads((pathlib.Path(args.out_dir) / "authorization.json").read_text(encoding="utf-8"))
            self.assertEqual(approval["body"], body)
            self.assertEqual(authorization["approval_id"], "17")
            self.assertEqual(authorization["implementation_commit"], SHA)

    def test_capture_preserves_unedited_windows_line_endings(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, digests = self.args(temporary)
            body = VERIFIER.canonical_body(SHA, digests).replace("\n", "\r\n")
            responses = [
                {"number": 1320, "head": {"sha": SHA}},
                [{"id": 17, "body": body, "user": {"login": "pho-veteran"},
                  "html_url": "https://github.com/%s/pull/1320#issuecomment-17" % REPOSITORY,
                  "issue_url": "https://api.github.test/repos/%s/issues/1320" % REPOSITORY,
                  "created_at": TIME, "updated_at": TIME}],
                {"permission": "admin"},
            ]
            original = VERIFIER.api_get
            VERIFIER.api_get = lambda *_: responses.pop(0)
            try:
                VERIFIER.capture(args)
            finally:
                VERIFIER.api_get = original
            approval = json.loads((pathlib.Path(args.out_dir) / "approval.json").read_bytes())
            self.assertEqual(approval["body"], body)

    def test_capture_accepts_maintain_role_name_with_write_base_permission(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, digests = self.args(temporary)
            responses = [
                {"number": 1320, "head": {"sha": SHA}},
                [{"id": 17, "body": VERIFIER.canonical_body(SHA, digests),
                  "user": {"login": "pho-veteran"},
                  "html_url": "https://github.com/%s/pull/1320#issuecomment-17" % REPOSITORY,
                  "issue_url": "https://api.github.test/repos/%s/issues/1320" % REPOSITORY,
                  "created_at": TIME, "updated_at": TIME}],
                {"permission": "write", "role_name": "maintain"},
            ]
            original = VERIFIER.api_get
            VERIFIER.api_get = lambda *_: responses.pop(0)
            try:
                VERIFIER.capture(args)
            finally:
                VERIFIER.api_get = original
            self.assertTrue((pathlib.Path(args.out_dir) / "approval.json").exists())


if __name__ == "__main__":
    unittest.main()

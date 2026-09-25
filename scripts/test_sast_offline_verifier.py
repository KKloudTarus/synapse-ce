import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("sast_offline_verifier.py")
SPEC = importlib.util.spec_from_file_location("sast_offline_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


def mocked_runtime():
    stack = ExitStack()
    stack.enter_context(patch.object(verifier.runtime_attestation, "require_live_container", return_value={"observed": "test runtime"}))
    stack.enter_context(patch.object(verifier.runtime_attestation, "validate_record", return_value=None))
    return stack


class OfflineVerifierTests(unittest.TestCase):
    def test_packet_digest_matches_go_proposal_digest_algorithm(self):
        finding = {"file": "source-opaque.java", "line": 12, "cwe": "CWE-79"}
        proposal_id = hashlib.sha256(b"source-opaque.java\x0012\x00CWE-79").hexdigest()
        packet = {
            "schema": verifier.PROPOSAL_SCHEMA,
            "corpus_digest": "corpus",
            "proposer": "scanner",
            "proposals": [{"id": proposal_id, "finding": finding, "source_context": "void f() {}"}],
        }
        path = Path(self._testMethodName + ".json")
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_bytes(verifier.canonical_json(packet))
        _, digest = verifier.load_packet(path)
        expected = hashlib.sha256((proposal_id + "\x00source-opaque.java\x0012\x00CWE-79\x00void f() {}\n").encode()).hexdigest()
        self.assertEqual(expected, digest)

    def test_decision_parser_accepts_one_fenced_json_object(self):
        self.assertEqual(("confirmed", "flow is credible"), verifier.parse_model_decision('```json\n{"decision":"confirmed","reason":"flow is credible"}\n```'))

    def test_decision_parser_rejects_extraneous_text_and_unknown_fields(self):
        with self.assertRaises(verifier.VerificationError):
            verifier.parse_model_decision('result: {"decision":"confirmed","reason":"x"}')
        with self.assertRaises(verifier.VerificationError):
            verifier.parse_model_decision('{"decision":"confirmed","reason":"x","extra":true}')

    def test_runner_retains_raw_exchange_and_emits_replay_artifacts(self):
        finding = {"file": "source-opaque.java", "line": 12, "cwe": "CWE-79"}
        proposal_id = hashlib.sha256(b"source-opaque.java\x0012\x00CWE-79").hexdigest()
        packet = {"schema": verifier.PROPOSAL_SCHEMA, "corpus_digest": "corpus", "proposer": "scanner", "proposals": [{"id": proposal_id, "finding": finding, "source_context": "void f() {}"}]}
        received: list[bytes] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                response = json.dumps({"model": "/models/test-model", "choices": [{"finish_reason": "stop", "message": {"content": '```json\n{"decision":"confirmed","reason":"context is incomplete"}\n```'}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            initial = root / "initial"
            initial.mkdir()
            input_path = initial / "packet.json"
            input_path.write_bytes(verifier.canonical_json(packet))
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
            arguments = ["--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json", "--endpoint", endpoint, "--model", "test-model", "--gguf-sha256", "a" * 64, "--runtime-image", "sha256:" + "b" * 64, "--gguf-path", "test-model", "--container", "test-container", "--attestation", "evidence/attestation.json"]
            previous = Path.cwd()
            os.chdir(initial)
            try:
                with mocked_runtime(), patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9"}), patch.object(urllib.request, "proxy_bypass", return_value=False):
                    self.assertEqual(0, verifier.main(arguments))
                    self.assertEqual(0, verifier.main(["--mode", "verify", "--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json"]))
            finally:
                os.chdir(previous)
            artifact = json.loads((initial / "evidence" / "verdict.json").read_text())
            verdict_path = initial / "evidence" / "verdict.json"
            original_verdict = verdict_path.read_bytes()
            altered = dict(artifact)
            altered["role"] = "self-reported reviewer"
            verdict_path.write_text(json.dumps(altered))
            os.chdir(initial)
            try:
                with mocked_runtime(), self.assertRaises(verifier.VerificationError):
                    verifier.main(["--mode", "verify", "--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json"])
            finally:
                verdict_path.write_bytes(original_verdict)
                os.chdir(previous)
            normalized = (initial / "evidence" / "response.json").read_bytes()
            transcript = json.loads((initial / "evidence" / "transcript.json").read_text())
            request = verifier.decode_base64(transcript["records"][0]["request_base64"], "test request")
            self.assertEqual(request, received[0])
            self.assertEqual(hashlib.sha256(normalized).hexdigest(), artifact["response_digest"])
            self.assertEqual([{"proposal_id": proposal_id, "decision": "confirmed"}], artifact["verdicts"])
            self.assertEqual("evidence/response.json", artifact["response_ref"])
            relocated = root / "relocated"
            relocated.mkdir()
            shutil.copy2(initial / "packet.json", relocated / "packet.json")
            shutil.copytree(initial / "evidence", relocated / "evidence")
            os.chdir(relocated)
            try:
                with mocked_runtime():
                    self.assertEqual(0, verifier.main(["--mode", "verify", "--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json"]))
                    (relocated / "evidence" / "attestation.json").write_text("{}")
                    with self.assertRaises(verifier.VerificationError):
                        verifier.main(["--mode", "verify", "--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json"])
            finally:
                os.chdir(previous)

    def test_provider_response_rejects_truncation(self):
        raw = b'{"model":"test-model","choices":[{"finish_reason":"length","message":{"content":"{\\"decision\\":\\"confirmed\\",\\"reason\\":\\"x\\"}"}}]}'
        with self.assertRaises(verifier.VerificationError):
            verifier.extract_content(raw, "test-model")

    def test_provider_request_rejects_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(307)
                self.send_header("Location", "http://127.0.0.1:9/v1/chat/completions")
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        with self.assertRaises(verifier.VerificationError):
            verifier.post_json(f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions", b"{}", 2)

    def test_runner_resumes_verified_checkpoint_and_rejects_tampering(self):
        def proposal(file_name, line, cwe):
            finding = {"file": file_name, "line": line, "cwe": cwe}
            return {"id": verifier.proposal_id(finding), "finding": finding, "source_context": "void f() {}"}

        packet = {"schema": verifier.PROPOSAL_SCHEMA, "corpus_digest": "corpus", "proposer": "scanner", "proposals": [proposal("source-one.java", 1, "CWE-79"), proposal("source-two.java", 2, "CWE-78")]}

        class Handler(BaseHTTPRequestHandler):
            calls: list[bytes] = []
            fail_second = True

            def do_POST(self):
                Handler.calls.append(self.rfile.read(int(self.headers["Content-Length"])))
                finish_reason = "length" if Handler.fail_second and len(Handler.calls) == 2 else "stop"
                response = json.dumps({"model": "/models/test-model", "choices": [{"finish_reason": finish_reason, "message": {"content": '{"decision":"confirmed","reason":"context is incomplete"}'}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "packet.json").write_bytes(verifier.canonical_json(packet))
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
            arguments = ["--packet", "packet.json", "--response", "evidence/response.json", "--verdict", "evidence/verdict.json", "--raw-transcript", "evidence/transcript.json", "--endpoint", endpoint, "--model", "test-model", "--gguf-sha256", "a" * 64, "--runtime-image", "sha256:" + "b" * 64, "--gguf-path", "test-model", "--container", "test-container", "--attestation", "evidence/attestation.json"]
            previous = Path.cwd()
            os.chdir(root)
            try:
                with mocked_runtime():
                    with self.assertRaises(verifier.VerificationError):
                        verifier.main(arguments)
                    checkpoint = json.loads((root / "evidence" / "transcript.json").read_text())
                    self.assertEqual(1, len(checkpoint["records"]))
                    Handler.fail_second = False
                    self.assertEqual(0, verifier.main(arguments))
                    self.assertEqual(3, len(Handler.calls))
                    checkpoint["records"][0]["request_digest"] = "0" * 64
                    (root / "evidence" / "transcript.json").write_text(json.dumps(checkpoint))
                    with self.assertRaises(verifier.VerificationError):
                        verifier.main(arguments)
                    self.assertEqual(3, len(Handler.calls))
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()

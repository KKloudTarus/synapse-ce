"""Offline calibration for model evidence and syntax-gated final decisions."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import sast_composite_verifier as composite
import sast_offline_verifier as model_runner


def proposal(name: str, line: int, source: str) -> dict:
    finding = {"file": name, "line": line, "cwe": "CWE-79"}
    return {
        "id": model_runner.proposal_id(finding),
        "finding": finding,
        "source_context": source,
    }


class CompositeVerifierTests(unittest.TestCase):
    def test_retains_unsupported_model_rejection_and_verifies_raw_evidence(self) -> None:
        unreachable = proposal(
            "source-one.java", 3,
            "// synapse-sast-proof-context: start_line=1\n"
            "void sample() {\nif (false) {\nout.print(input);\n}\n}",
        )
        reachable = proposal(
            "source-two.java", 2,
            "// synapse-sast-proof-context: start_line=1\n"
            "void sample() {\nout.print(input);\n}",
        )
        packet = {
            "schema": model_runner.PROPOSAL_SCHEMA,
            "corpus_digest": "synthetic-calibration",
            "proposer": "scanner",
            "proposals": [unreachable, reachable],
        }

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers["Content-Length"]))
                response = json.dumps({
                    "model": "/models/test-model",
                    "choices": [{
                        "finish_reason": "stop",
                        "message": {"content": '{"decision":"rejected","reason":"claimed impossible"}'},
                    }],
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "packet.json").write_bytes(model_runner.canonical_json(packet))
            model_args = [
                "--packet", "packet.json",
                "--response", "evidence/model-response.json",
                "--verdict", "evidence/model-verdict.json",
                "--raw-transcript", "evidence/model-transcript.json",
                "--endpoint", f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions",
                "--model", "test-model", "--gguf-sha256", "a" * 64,
                "--runtime-image", "sha256:" + "b" * 64,
                "--gguf-path", "test-model", "--container", "test-container",
                "--attestation", "evidence/attestation.json",
            ]
            composite_args = [
                "--packet", "packet.json",
                "--model-response", "evidence/model-response.json",
                "--model-verdict", "evidence/model-verdict.json",
                "--model-transcript", "evidence/model-transcript.json",
                "--response", "evidence/response.json",
                "--verdict", "evidence/verdict.json",
                "--audit", "evidence/audit.json",
            ]
            previous = Path.cwd()
            os.chdir(root)
            try:
                with patch.object(model_runner.runtime_attestation, "require_live_container", return_value={"observed": "test runtime"}), patch.object(model_runner.runtime_attestation, "validate_record", return_value=None):
                    self.assertEqual(0, model_runner.main(model_args))
                    overlapping = composite_args.copy()
                    overlapping[overlapping.index("evidence/response.json")] = "evidence/model-response.json"
                    with self.assertRaises(model_runner.VerificationError):
                        composite.main(overlapping)
                    overlapping_attestation = composite_args.copy()
                    overlapping_attestation[overlapping_attestation.index("evidence/response.json")] = "evidence/attestation.json"
                    with self.assertRaises(model_runner.VerificationError):
                        composite.main(overlapping_attestation)
                    self.assertEqual(0, composite.main(composite_args))
                    self.assertEqual(0, composite.main(["--mode", "verify", *composite_args]))
                response = json.loads((root / "evidence/response.json").read_text())
                self.assertEqual(
                    {unreachable["id"]: "rejected", reachable["id"]: "confirmed"},
                    {item["proposal_id"]: item["decision"] for item in response["verdicts"]},
                )
                audit = json.loads((root / "evidence/audit.json").read_text())
                self.assertEqual({"rejected"}, {item["model_decision"] for item in audit["records"]})
                self.assertEqual(1, sum(item["proof_valid"] for item in audit["records"]))
                audit["records"][0]["final_decision"] = "confirmed"
                (root / "evidence/audit.json").write_text(json.dumps(audit))
                with patch.object(model_runner.runtime_attestation, "validate_record", return_value=None):
                    with self.assertRaises(model_runner.VerificationError):
                        composite.main(["--mode", "verify", *composite_args])
                    self.assertEqual(0, composite.main(composite_args))
                    transcript = json.loads((root / "evidence/model-transcript.json").read_text())
                    transcript["records"][0]["response_digest"] = "0" * 64
                    (root / "evidence/model-transcript.json").write_text(json.dumps(transcript))
                    with self.assertRaises(model_runner.VerificationError):
                        composite.main(["--mode", "verify", *composite_args])
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()

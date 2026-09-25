#!/usr/bin/env python3
"""Check fresh proof decisions and packet-bound verifier output."""

import json
from pathlib import Path
import tempfile
import unittest

import sast_offline_verifier
import sast_proof_verifier


class ProofVerifierTest(unittest.TestCase):
    def test_rejects_only_proven_unreachable_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet_path = root / "packet.json"
            response_path = root / "response.json"
            verdict_path = root / "verdict.json"
            finding = {"file": "opaque.java", "line": 3, "cwe": "CWE-79"}
            proposal = {
                "id": sast_offline_verifier.proposal_id(finding),
                "finding": finding,
                "source_context": "// synapse-sast-proof-context: start_line=1\nvoid sample() {\nif (false) {\nout.print(input);\n}\n}",
            }
            packet = {"schema": "synapse-sast-proposals-v1", "corpus_digest": "pinned", "proposer": "synapse-owned", "proposals": [proposal]}
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            self.assertEqual(sast_proof_verifier.evaluate(packet_path, response_path, verdict_path), (1, 1))
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            response = json.loads(response_path.read_text(encoding="utf-8"))
            self.assertEqual(verdict["verdicts"], response["verdicts"])
            self.assertEqual(verdict["response_digest"], sast_proof_verifier.sha256(response_path.read_bytes()))
            self.assertEqual(verdict["response_ref"], str(response_path))

            proposal["source_context"] = "// synapse-sast-proof-context: start_line=1\nvoid sample() {\nout.print(input);\n}"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            self.assertEqual(sast_proof_verifier.evaluate(packet_path, response_path, verdict_path), (1, 0))
            changed = json.loads(verdict_path.read_text(encoding="utf-8"))
            self.assertEqual(changed["verdicts"][0]["decision"], "confirmed")
            self.assertNotEqual(changed["proposal_digest"], verdict["proposal_digest"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Apply the bounded syntactic proof to every fresh blinded SAST proposal."""

import argparse
import hashlib
import json
from pathlib import Path

import sast_offline_verifier
import sast_proof_gate


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def evaluate(packet_path, response_path, verdict_path):
    packet, packet_digest = sast_offline_verifier.load_packet(packet_path)
    if not packet["proposals"]:
        raise ValueError("post-triage packet has no proposals")
    verdicts = []
    for proposal in packet["proposals"]:
        proved, _ = sast_proof_gate.prove_rejection(proposal)
        verdicts.append({
            "proposal_id": proposal["id"],
            "decision": "rejected" if proved else "confirmed",
        })
    response = {
        "schema": "synapse-sast-verdict-response-v1",
        "proposal_digest": packet_digest,
        "verdicts": verdicts,
    }
    response_bytes = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
    response_path.write_bytes(response_bytes)
    artifact = {
        "schema": "synapse-sast-verdicts-v1",
        "corpus_digest": packet["corpus_digest"],
        "proposal_digest": packet_digest,
        "verifier": "syntactic-proof-v1",
        "model": "bounded-java-syntax-v1",
        "role": "deterministic syntax verifier",
        "config_digest": sha256(Path(__file__).read_bytes()),
        "prompt_digest": sha256(Path(sast_proof_gate.__file__).read_bytes()),
        "packet_digest": packet_digest,
        "response_digest": sha256(response_bytes),
        "response_ref": str(response_path),
        "verdicts": verdicts,
    }
    verdict_path.write_text(json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return len(verdicts), sum(row["decision"] == "rejected" for row in verdicts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--verdict", required=True, type=Path)
    args = parser.parse_args()
    total, rejected = evaluate(args.packet, args.response, args.verdict)
    print(f"proof triage: proposals={total} proven_rejections={rejected}")


if __name__ == "__main__":
    main()

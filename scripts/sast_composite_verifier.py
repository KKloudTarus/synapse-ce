#!/usr/bin/env python3
"""Seal a blinded model review with a separately checked rejection proof.

The model exchange remains intact. A model rejection without a syntactic proof is
recorded as unsupported in the audit and retained in the final finding set.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import sast_offline_verifier as model_runner
import sast_proof_gate as proof_gate


SCHEMA = "synapse-sast-composite-verifier-config-v1"
AUDIT_SCHEMA = "synapse-sast-composite-verifier-audit-v1"
POLICY_VERSION = "model-rejection-requires-syntactic-proof-v1"
VERIFIER = "offline-local-llama-cpp+syntactic-proof-v1"
ROLE = "blinded model review with independently checked rejection proof"


def source_digest(path: Path) -> str:
    return model_runner.sha256_hex(path.read_bytes().replace(b"\r\n", b"\n"))


def encoded(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def expected_outputs(
    packet_path: Path,
    model_response_path: Path,
    model_verdict_path: Path,
    model_transcript_path: Path,
    model_response_ref: str,
    response_ref: str,
) -> tuple[bytes, bytes, bytes, bytes]:
    root = Path.cwd().resolve()
    model_runner.verify_evidence(
        root, packet_path, model_response_path, model_verdict_path,
        model_transcript_path, model_response_ref,
    )
    packet, packet_digest = model_runner.load_packet(packet_path)
    model_artifact = model_runner.strict_json(model_verdict_path.read_bytes(), "model verdict")
    model_response = model_runner.strict_json(model_response_path.read_bytes(), "model response")
    raw_decisions = {
        item["proposal_id"]: item["decision"] for item in model_response["verdicts"]
    }
    if len(raw_decisions) != len(packet["proposals"]):
        raise model_runner.VerificationError("model response does not cover proposal packet")

    config = {
        "schema": SCHEMA,
        "policy_version": POLICY_VERSION,
        "model_config_digest": model_artifact["config_digest"],
        "model_prompt_digest": model_artifact["prompt_digest"],
        "model_verifier": model_artifact["verifier"],
        "model_runner_sha256": source_digest(Path(model_runner.__file__)),
        "proof_checker_sha256": source_digest(Path(proof_gate.__file__)),
        "composite_runner_sha256": source_digest(Path(__file__)),
        "rule": "reject only when model rejects and a syntactic proof validates",
    }
    config_bytes = model_runner.canonical_json(config)
    config_digest = model_runner.sha256_hex(config_bytes)

    audit_records = []
    verdicts = []
    for proposal in packet["proposals"]:
        proposal_id = proposal["id"]
        model_decision = raw_decisions[proposal_id]
        if model_decision == "rejected":
            proof_valid, proof_reason = proof_gate.prove_rejection(proposal)
            if not isinstance(proof_valid, bool) or not isinstance(proof_reason, str) or not proof_reason:
                raise model_runner.VerificationError("proof checker returned invalid result")
        else:
            proof_valid, proof_reason = False, "model confirmed; no rejection proof requested"
        final_decision = "rejected" if model_decision == "rejected" and proof_valid else "confirmed"
        verdicts.append({"proposal_id": proposal_id, "decision": final_decision})
        audit_records.append({
            "proposal_id": proposal_id,
            "model_decision": model_decision,
            "proof_valid": proof_valid,
            "proof_reason": proof_reason,
            "final_decision": final_decision,
        })

    audit = {
        "schema": AUDIT_SCHEMA,
        "proposal_digest": packet_digest,
        "config_digest": config_digest,
        "model_response_digest": model_artifact["response_digest"],
        "records": audit_records,
    }
    normalized = {
        "schema": model_runner.RECORDED_RESPONSE_SCHEMA,
        "proposal_digest": packet_digest,
        "verdicts": verdicts,
    }
    response_bytes = encoded(normalized)
    artifact = {
        "schema": model_runner.VERDICT_SCHEMA,
        "corpus_digest": packet["corpus_digest"],
        "proposal_digest": packet_digest,
        "verifier": VERIFIER,
        "model": model_artifact["model"],
        "role": ROLE,
        "config_digest": config_digest,
        "prompt_digest": model_artifact["prompt_digest"],
        "packet_digest": packet_digest,
        "response_digest": model_runner.sha256_hex(response_bytes),
        "response_ref": response_ref,
        "verdicts": verdicts,
    }
    return config_bytes + b"\n", encoded(audit), response_bytes, encoded(artifact)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("run", "verify"), default="run")
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--model-response", required=True, type=Path)
    parser.add_argument("--model-verdict", required=True, type=Path)
    parser.add_argument("--model-transcript", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--verdict", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    args = parser.parse_args(argv)
    root = Path.cwd().resolve()
    model_response_path, model_response_ref = model_runner.portable_output_path(
        root, args.model_response, "model-response"
    )
    model_verdict_path, _ = model_runner.portable_output_path(root, args.model_verdict, "model-verdict")
    model_transcript_path, _ = model_runner.portable_output_path(root, args.model_transcript, "model-transcript")
    response_path, response_ref = model_runner.portable_output_path(root, args.response, "response")
    verdict_path, _ = model_runner.portable_output_path(root, args.verdict, "verdict")
    audit_path, _ = model_runner.portable_output_path(root, args.audit, "audit")
    config_path = model_runner.config_path_for(verdict_path)
    model_config_path = model_runner.config_path_for(model_verdict_path)
    model_config = model_runner.strict_json(model_config_path.read_bytes(), "model config")
    attestation_path, _ = model_runner.portable_output_path(
        root, Path(model_runner.require_string(model_config["attestation_ref"], "attestation reference")),
        "attestation",
    )
    inputs = {
        args.packet.resolve(), model_response_path, model_verdict_path,
        model_transcript_path, model_config_path, attestation_path,
    }
    outputs_paths = (config_path, audit_path, response_path, verdict_path)
    if len(set(outputs_paths)) != len(outputs_paths) or any(path in inputs for path in outputs_paths):
        raise model_runner.VerificationError("composite outputs must be distinct from each other and model inputs")
    outputs = expected_outputs(
        args.packet, model_response_path, model_verdict_path,
        model_transcript_path, model_response_ref, response_ref,
    )
    for path, data in zip(
        outputs_paths, outputs, strict=True
    ):
        if args.mode == "verify":
            if path.read_bytes() != data:
                raise model_runner.VerificationError(f"composite evidence mismatch: {path}")
        else:
            model_runner.atomic_write(path, data)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, model_runner.VerificationError) as err:
        print(f"sast composite verifier: {err}", file=sys.stderr)
        raise SystemExit(1)

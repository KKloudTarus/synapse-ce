#!/usr/bin/env python3
"""Run a frozen offline verifier over a blinded SAST proposal packet.

This runner deliberately has no corpus, answer-key, or scorer inputs.  It retains the
provider exchange separately from the normalized response consumed by SAST replay.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import sast_runtime_attestation as runtime_attestation


PROPOSAL_SCHEMA = "synapse-sast-proposals-v1"
VERDICT_SCHEMA = "synapse-sast-verdicts-v1"
RECORDED_RESPONSE_SCHEMA = "synapse-sast-verdict-response-v1"
POLICY_VERSION = "offline-blind-sast-verifier-v1"
DEFAULT_ENDPOINT = "http://127.0.0.1:18080/v1/chat/completions"
DEFAULT_VERIFIER = "offline-local-llama-cpp"
VERIFIER_ROLE = "independent blinded offline verifier"
CONFIG_SCHEMA = "synapse-sast-offline-verifier-config-v2"

# This policy is intentionally source-controlled.  Do not make it a command-line
# argument: baseline and candidate runs must use the same policy text.
FROZEN_SYSTEM_PROMPT = """You are an independent security finding verifier. Evaluate one proposed Java finding using only the provided opaque filename, CWE, line number, and comment-stripped method context. Do not infer benchmark labels or look for external information. CWE-79 concerns untrusted data reaching HTML or script output. CWE-89 concerns untrusted data used to construct an SQL query. CWE-78 concerns untrusted data used to execute an operating-system command. Confirm when the claimed CWE has a credible source-to-sink or dangerous-operation path, or when the context is incomplete or uncertain. Reject only when the shown code proves the claimed path is impossible, such as a literal unreachable branch or a demonstrated correct sanitizer for the specific CWE. Give a short evidence-grounded reason. Output no Markdown. Return exactly one JSON object with only these fields: {"decision":"confirmed"|"rejected","reason":"brief evidence-grounded explanation"}."""


class VerificationError(RuntimeError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json(data: bytes | str, label: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, VerificationError) as err:
        raise VerificationError(f"parse {label}: {err}") from err


def require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerificationError(f"{label} must contain exactly {sorted(keys)}")
    return value


def require_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise VerificationError(f"{label} must be a non-empty string")
    return value


def require_sha256(value: str, label: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise VerificationError(f"{label} must be a lower-case SHA-256 hex digest")
    return value


def proposal_id(finding: dict[str, Any]) -> str:
    return sha256_hex((finding["file"] + "\x00" + str(finding["line"]) + "\x00" + finding["cwe"]).encode("utf-8"))


def load_packet(path: Path) -> tuple[dict[str, Any], str]:
    packet = require_object(strict_json(path.read_bytes(), "proposal packet"), "proposal packet", {"schema", "corpus_digest", "proposer", "proposals"})
    if packet["schema"] != PROPOSAL_SCHEMA:
        raise VerificationError(f"proposal packet schema must be {PROPOSAL_SCHEMA!r}")
    require_string(packet["corpus_digest"], "proposal packet corpus_digest")
    require_string(packet["proposer"], "proposal packet proposer")
    if not isinstance(packet["proposals"], list):
        raise VerificationError("proposal packet proposals must be an array")
    rows: list[str] = []
    seen: set[str] = set()
    for index, proposal in enumerate(packet["proposals"]):
        proposal = require_object(proposal, f"proposal {index}", {"id", "finding", "source_context"})
        finding = require_object(proposal["finding"], f"proposal {index} finding", {"file", "line", "cwe"})
        require_string(finding["file"], f"proposal {index} finding file")
        require_string(finding["cwe"], f"proposal {index} finding cwe")
        if isinstance(finding["line"], bool) or not isinstance(finding["line"], int) or finding["line"] < 0:
            raise VerificationError(f"proposal {index} finding line must be a non-negative integer")
        if proposal["id"] != proposal_id(finding):
            raise VerificationError(f"proposal {index} ID does not match blinded finding")
        if proposal["id"] in seen:
            raise VerificationError(f"duplicate proposal ID {proposal['id']}")
        seen.add(proposal["id"])
        require_string(proposal["source_context"], f"proposal {index} source_context", nonempty=False)
        rows.append("\x00".join((proposal["id"], finding["file"], str(finding["line"]), finding["cwe"], proposal["source_context"])))
    digest = sha256_hex("".join(row + "\n" for row in sorted(rows)).encode("utf-8"))
    return packet, digest


def parse_model_decision(content: str) -> tuple[str, str]:
    fenced = re.fullmatch(r"\s*```(?:json)?[ \t]*\r?\n(.*?)\r?\n?```\s*", content, flags=re.DOTALL)
    candidate = fenced.group(1) if fenced else content
    parsed = require_object(strict_json(candidate, "model decision"), "model decision", {"decision", "reason"})
    decision = require_string(parsed["decision"], "model decision decision")
    reason = require_string(parsed["reason"], "model decision reason")
    if decision not in {"confirmed", "rejected"}:
        raise VerificationError("model decision must be confirmed or rejected")
    return decision, reason


def extract_content(raw_response: bytes, request_model: str) -> str:
    parsed = strict_json(raw_response, "provider response")
    if not isinstance(parsed, dict) or not isinstance(parsed.get("choices"), list) or len(parsed["choices"]) != 1:
        raise VerificationError("provider response must contain exactly one choice")
    if "model" in parsed:
        response_model = require_string(parsed["model"], "provider response model")
        if Path(response_model).name != Path(request_model).name:
            raise VerificationError("provider response model does not match request model")
    choice = parsed["choices"][0]
    if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
        raise VerificationError("provider response choice must contain a message")
    if choice.get("finish_reason") != "stop":
        raise VerificationError("provider response is incomplete or truncated")
    return require_string(choice["message"].get("content"), "provider response message content")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def post_json(endpoint: str, body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    class RejectRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
            return None

    # The inspected container is published on loopback. Environment proxy settings
    # and HTTP redirects must not send its requests to a different server.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise VerificationError(f"verifier endpoint returned HTTP {response.status}")
            return response.read()
    except urllib.error.HTTPError as err:
        err.close()
        raise VerificationError(f"call verifier endpoint: HTTP {err.code}") from err
    except urllib.error.URLError as err:
        raise VerificationError(f"call verifier endpoint: {err}") from err


def validate_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.path != "/v1/chat/completions":
        raise VerificationError("endpoint must be a loopback http(s) /v1/chat/completions URL")
    return endpoint


def config_path_for(verdict_path: Path) -> Path:
    return verdict_path.with_name(verdict_path.stem + ".config.json")


def portable_output_path(root: Path, value: Path, label: str) -> tuple[Path, str]:
    if value.is_absolute() or any(part == ".." for part in value.parts):
        raise VerificationError(f"{label} must be a relative path inside the artifact root")
    resolved = (root / value).resolve()
    try:
        portable = resolved.relative_to(root).as_posix()
    except ValueError as err:
        raise VerificationError(f"{label} must stay inside the artifact root") from err
    return resolved, portable


def decode_base64(value: Any, label: str) -> bytes:
    encoded = require_string(value, label)
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as err:
        raise VerificationError(f"{label} is not valid base64") from err


def request_body_for(proposal: dict[str, Any], model_name: str) -> dict[str, Any]:
    return {
        "model": model_name, "temperature": 0, "seed": 42, "max_tokens": 256,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": FROZEN_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({"proposal_id": proposal["id"], "finding": proposal["finding"], "source_context": proposal["source_context"]}, ensure_ascii=False, separators=(",", ":"))},
        ],
    }


def valid_verdicts(value: Any, proposals: list[dict[str, Any]], label: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(proposals):
        raise VerificationError(f"{label} must contain one verdict for every proposal")
    expected = {proposal["id"] for proposal in proposals}
    seen: set[str] = set()
    verdicts: list[dict[str, str]] = []
    for index, verdict in enumerate(value):
        verdict = require_object(verdict, f"{label} {index}", {"proposal_id", "decision"})
        proposal_id_value = require_string(verdict["proposal_id"], f"{label} {index} proposal_id")
        decision = require_string(verdict["decision"], f"{label} {index} decision")
        if proposal_id_value not in expected or proposal_id_value in seen or decision not in {"confirmed", "rejected"}:
            raise VerificationError(f"{label} {index} is not a unique decision for this proposal packet")
        seen.add(proposal_id_value)
        verdicts.append({"proposal_id": proposal_id_value, "decision": decision})
    return verdicts


def transcript_payload(packet_digest: str, config_digest: str, records: list[dict[str, str]]) -> dict[str, Any]:
    return {"schema": "synapse-sast-raw-verifier-exchange-v1", "proposal_digest": packet_digest, "config_digest": config_digest, "records": records}


def validate_raw_records(transcript: Any, packet_digest: str, config_digest: str, proposals: list[dict[str, Any]], request_model: str, *, complete: bool) -> tuple[list[dict[str, str]], dict[str, str]]:
    transcript = require_object(transcript, "raw transcript", {"schema", "proposal_digest", "config_digest", "records"})
    if transcript["schema"] != "synapse-sast-raw-verifier-exchange-v1" or transcript["proposal_digest"] != packet_digest or transcript["config_digest"] != config_digest or not isinstance(transcript["records"], list):
        raise VerificationError("raw transcript does not bind this verifier run")
    if complete and len(transcript["records"]) != len(proposals):
        raise VerificationError("raw transcript does not cover every proposal")
    if len(transcript["records"]) > len(proposals):
        raise VerificationError("raw transcript has more records than proposals")
    by_id = {proposal["id"]: proposal for proposal in proposals}
    seen: set[str] = set()
    records: list[dict[str, str]] = []
    decisions: dict[str, str] = {}
    for index, record in enumerate(transcript["records"]):
        record = require_object(record, f"raw transcript record {index}", {"proposal_id", "request_base64", "request_digest", "response_base64", "response_digest"})
        proposal_id_value = require_string(record["proposal_id"], f"raw transcript record {index} proposal_id")
        if proposal_id_value not in by_id or proposal_id_value in seen:
            raise VerificationError("raw transcript has duplicate or foreign proposal")
        seen.add(proposal_id_value)
        request_bytes = decode_base64(record["request_base64"], f"raw transcript record {index} request_base64")
        provider_response = decode_base64(record["response_base64"], f"raw transcript record {index} response_base64")
        if record["request_digest"] != sha256_hex(request_bytes) or record["response_digest"] != sha256_hex(provider_response):
            raise VerificationError("raw transcript digest does not match retained exchange")
        if request_bytes != canonical_json(request_body_for(by_id[proposal_id_value], request_model)):
            raise VerificationError("retained request does not match this blinded proposal and frozen config")
        decision, _reason = parse_model_decision(extract_content(provider_response, request_model))
        decisions[proposal_id_value] = decision
        records.append({"proposal_id": proposal_id_value, "request_base64": record["request_base64"], "request_digest": record["request_digest"], "response_base64": record["response_base64"], "response_digest": record["response_digest"]})
    return records, decisions


def verify_evidence(root: Path, packet_path: Path, response_path: Path, verdict_path: Path, transcript_path: Path, response_ref: str) -> None:
    packet, packet_digest = load_packet(packet_path)
    artifact = require_object(strict_json(verdict_path.read_bytes(), "verdict artifact"), "verdict artifact", {"schema", "corpus_digest", "proposal_digest", "verifier", "model", "role", "config_digest", "prompt_digest", "packet_digest", "response_digest", "response_ref", "verdicts"})
    config_bytes = config_path_for(verdict_path).read_bytes()
    config = require_object(strict_json(config_bytes, "verifier config"), "verifier config", {"schema", "policy_version", "endpoint", "request_model", "model", "gguf_sha256", "runtime_image", "temperature", "seed", "max_tokens", "response_format", "timeout_seconds", "system_prompt", "attestation_ref", "attestation_digest"})
    if canonical_json(config) != config_bytes.rstrip(b"\n"):
        raise VerificationError("verifier config is not canonical JSON")
    require_sha256(artifact["config_digest"], "artifact config_digest")
    if artifact["config_digest"] != sha256_hex(config_bytes.rstrip(b"\n")):
        raise VerificationError("verdict artifact config digest does not match retained config")
    if config["schema"] != CONFIG_SCHEMA or config["policy_version"] != POLICY_VERSION or config["system_prompt"] != FROZEN_SYSTEM_PROMPT:
        raise VerificationError("retained verifier config does not use the frozen policy")
    validate_endpoint(require_string(config["endpoint"], "config endpoint"))
    request_model = require_string(config["request_model"], "config request_model")
    gguf_sha = require_sha256(require_string(config["gguf_sha256"], "config gguf_sha256"), "config gguf_sha256")
    runtime_image = require_sha256(require_string(config["runtime_image"], "config runtime_image").removeprefix("sha256:"), "config runtime_image")
    attestation_path, attestation_ref = portable_output_path(root, Path(require_string(config["attestation_ref"], "config attestation_ref")), "attestation")
    if attestation_ref != config["attestation_ref"]:
        raise VerificationError("attestation reference is not canonical")
    attestation_bytes = attestation_path.read_bytes()
    if sha256_hex(attestation_bytes) != require_sha256(config["attestation_digest"], "config attestation_digest"):
        raise VerificationError("attestation digest does not match retained record")
    runtime_attestation.validate_record(strict_json(attestation_bytes, "runtime attestation"), request_model, gguf_sha, runtime_image, config["endpoint"])
    if config["model"] != f"{request_model}@gguf-sha256:{gguf_sha};runtime=sha256:{runtime_image}" or config["temperature"] != 0 or config["seed"] != 42 or config["max_tokens"] != 256 or config["response_format"] != "json_object" or not isinstance(config["timeout_seconds"], (int, float)) or config["timeout_seconds"] <= 0:
        raise VerificationError("retained verifier config has unpinned generation settings")
    if artifact["prompt_digest"] != sha256_hex(FROZEN_SYSTEM_PROMPT.encode("utf-8")):
        raise VerificationError("verdict artifact prompt digest does not match the frozen policy")
    if artifact["schema"] != VERDICT_SCHEMA or artifact["corpus_digest"] != packet["corpus_digest"] or artifact["proposal_digest"] != packet_digest or artifact["packet_digest"] != packet_digest:
        raise VerificationError("verdict artifact does not bind this proposal packet")
    if artifact["verifier"] != DEFAULT_VERIFIER or artifact["role"] != VERIFIER_ROLE or artifact["verifier"] == packet["proposer"]:
        raise VerificationError("verdict artifact verifier identity or role does not match frozen policy")
    if artifact["model"] != config["model"]:
        raise VerificationError("verdict artifact model does not match retained config")
    if artifact["response_ref"] != response_ref:
        raise VerificationError("verdict artifact response reference does not match retained response path")
    response_bytes = response_path.read_bytes()
    response = require_object(strict_json(response_bytes, "recorded verdict response"), "recorded verdict response", {"schema", "proposal_digest", "verdicts"})
    normalized_verdicts = valid_verdicts(response["verdicts"], packet["proposals"], "recorded verdict response verdict")
    artifact_verdicts = valid_verdicts(artifact["verdicts"], packet["proposals"], "verdict artifact verdict")
    if response["schema"] != RECORDED_RESPONSE_SCHEMA or response["proposal_digest"] != packet_digest or normalized_verdicts != artifact_verdicts:
        raise VerificationError("recorded verdict response does not match verdict artifact")
    if artifact["response_digest"] != sha256_hex(response_bytes):
        raise VerificationError("verdict artifact response digest does not match recorded response")
    records, raw_decisions = validate_raw_records(strict_json(transcript_path.read_bytes(), "raw transcript"), packet_digest, artifact["config_digest"], packet["proposals"], request_model, complete=True)
    if len(records) != len(packet["proposals"]):
        raise VerificationError("raw transcript does not cover every proposal")
    for verdict in normalized_verdicts:
        if raw_decisions[verdict["proposal_id"]] != verdict["decision"]:
            raise VerificationError("normalized verdict does not match retained provider response")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("run", "verify"), default="run")
    parser.add_argument("--packet", required=True, type=Path, help="blinded ProposalBatch JSON")
    parser.add_argument("--response", required=True, type=Path, help="normalized RecordedVerdictResponse output")
    parser.add_argument("--verdict", required=True, type=Path, help="VerdictArtifact output")
    parser.add_argument("--raw-transcript", required=True, type=Path, help="raw-exchange manifest output")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--model")
    parser.add_argument("--gguf-sha256")
    parser.add_argument("--runtime-image")
    parser.add_argument("--gguf-path", type=Path)
    parser.add_argument("--container")
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)
    artifact_root = Path.cwd().resolve()
    response_path, response_ref = portable_output_path(artifact_root, args.response, "response")
    verdict_path, _verdict_ref = portable_output_path(artifact_root, args.verdict, "verdict")
    transcript_path, _transcript_ref = portable_output_path(artifact_root, args.raw_transcript, "raw-transcript")
    if args.mode == "verify":
        verify_evidence(artifact_root, args.packet, response_path, verdict_path, transcript_path, response_ref)
        return 0
    if args.timeout_seconds <= 0:
        raise VerificationError("timeout-seconds must be positive")
    endpoint = validate_endpoint(args.endpoint)
    gguf_sha = require_sha256(require_string(args.gguf_sha256, "gguf-sha256"), "gguf-sha256")
    runtime = require_string(args.runtime_image, "runtime-image").removeprefix("sha256:")
    require_sha256(runtime, "runtime-image")
    model_name = require_string(args.model, "model")
    model_path = args.gguf_path
    container_name = require_string(args.container, "container")
    if model_path is None or args.attestation is None:
        raise VerificationError("run mode requires --gguf-path and --attestation")
    attestation_path, attestation_ref = portable_output_path(artifact_root, args.attestation, "attestation")
    observed = runtime_attestation.require_live_container(model_path, model_name, gguf_sha, runtime, container_name, endpoint)
    attestation_bytes = canonical_json(observed) + b"\n"
    if attestation_path.exists():
        if attestation_path.read_bytes() != attestation_bytes:
            raise VerificationError("existing attestation does not match the live pinned runtime")
    else:
        atomic_write(attestation_path, attestation_bytes)

    packet, packet_digest = load_packet(args.packet)
    if DEFAULT_VERIFIER == packet["proposer"]:
        raise VerificationError("verifier must differ from proposal proposer")
    prompt_digest = sha256_hex(FROZEN_SYSTEM_PROMPT.encode("utf-8"))
    model_identity = f"{model_name}@gguf-sha256:{gguf_sha};runtime=sha256:{runtime}"
    config = {
        "schema": CONFIG_SCHEMA, "policy_version": POLICY_VERSION,
        "endpoint": endpoint, "request_model": model_name, "model": model_identity, "gguf_sha256": gguf_sha, "runtime_image": "sha256:" + runtime, "temperature": 0, "seed": 42,
        "max_tokens": 256, "response_format": "json_object", "timeout_seconds": args.timeout_seconds, "system_prompt": FROZEN_SYSTEM_PROMPT,
        "attestation_ref": attestation_ref, "attestation_digest": sha256_hex(attestation_bytes),
    }
    config_bytes = canonical_json(config)
    config_digest = sha256_hex(config_bytes)
    config_path = config_path_for(verdict_path)
    expected_config = config_bytes + b"\n"
    if config_path.exists():
        if config_path.read_bytes() != expected_config:
            raise VerificationError("existing verifier config does not match frozen run settings")
    else:
        atomic_write(config_path, expected_config)

    if transcript_path.exists():
        raw_records, decisions = validate_raw_records(strict_json(transcript_path.read_bytes(), "raw transcript"), packet_digest, config_digest, packet["proposals"], model_name, complete=False)
    else:
        raw_records, decisions = [], {}
    records_by_id = {record["proposal_id"]: record for record in raw_records}
    for proposal in packet["proposals"]:
        if proposal["id"] in decisions:
            continue
        request_body = request_body_for(proposal, model_name)
        request_bytes = canonical_json(request_body)
        raw_response = post_json(endpoint, request_bytes, args.timeout_seconds)
        decision, _reason = parse_model_decision(extract_content(raw_response, model_name))
        decisions[proposal["id"]] = decision
        records_by_id[proposal["id"]] = {"proposal_id": proposal["id"], "request_base64": base64.b64encode(request_bytes).decode("ascii"), "request_digest": sha256_hex(request_bytes), "response_base64": base64.b64encode(raw_response).decode("ascii"), "response_digest": sha256_hex(raw_response)}
        raw_records = [records_by_id[current["id"]] for current in packet["proposals"] if current["id"] in records_by_id]
        atomic_write(transcript_path, json.dumps(transcript_payload(packet_digest, config_digest, raw_records), ensure_ascii=False, indent=2).encode("utf-8") + b"\n")

    if len(raw_records) != len(packet["proposals"]):
        raise VerificationError("verifier run ended without decisions for every proposal")
    verdicts = [{"proposal_id": proposal["id"], "decision": decisions[proposal["id"]]} for proposal in packet["proposals"]]

    normalized = {"schema": RECORDED_RESPONSE_SCHEMA, "proposal_digest": packet_digest, "verdicts": verdicts}
    normalized_bytes = json.dumps(normalized, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    atomic_write(response_path, normalized_bytes)
    artifact = {
        "schema": VERDICT_SCHEMA, "corpus_digest": packet["corpus_digest"], "proposal_digest": packet_digest,
        "verifier": DEFAULT_VERIFIER, "model": model_identity, "role": VERIFIER_ROLE,
        "config_digest": config_digest, "prompt_digest": prompt_digest, "packet_digest": packet_digest,
        "response_digest": sha256_hex(normalized_bytes), "response_ref": response_ref, "verdicts": verdicts,
    }
    atomic_write(verdict_path, json.dumps(artifact, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    atomic_write(transcript_path, json.dumps(transcript_payload(packet_digest, config_digest, raw_records), ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError, runtime_attestation.AttestationError) as err:
        print(f"sast offline verifier: {err}", file=sys.stderr)
        raise SystemExit(1)

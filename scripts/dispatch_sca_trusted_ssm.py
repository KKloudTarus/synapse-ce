#!/usr/bin/env python3
"""Create and dispatch the bounded SCA provenance envelope over AWS SSM."""

import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import time


SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
ENVELOPE_SCHEMA = "synapse-sca-trusted-provenance-envelope-v1"
SUMMARY_SCHEMA = "synapse-sca-trusted-dispatch-summary-v1"


def fail(message):
    raise ValueError(message)


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def checked_identity(source_sha, run_id, run_attempt):
    if not SHA.fullmatch(source_sha):
        fail("source SHA must be a lower-case 40-character SHA")
    if not run_id.isdecimal() or not run_attempt.isdecimal() or int(run_attempt) < 1:
        fail("run identity must contain a numeric run ID and positive attempt")


def read_exact_provenance(root):
    expected = {"approval.json", "authorization.json", "handoff.json"}
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if actual != expected:
        fail("provenance handoff must contain exactly approval, authorization, and handoff")
    return {name: (root / name).read_bytes() for name in sorted(expected)}


def build_envelope(args):
    checked_identity(args.source_sha, args.run_id, args.run_attempt)
    documents = read_exact_provenance(pathlib.Path(args.provenance_dir))
    envelope = {
        "schema_version": ENVELOPE_SCHEMA,
        "source_sha": args.source_sha,
        "workflow_run_id": args.run_id,
        "workflow_run_attempt": args.run_attempt,
        "approval": base64.b64encode(documents["approval.json"]).decode("ascii"),
        "authorization": base64.b64encode(documents["authorization.json"]).decode("ascii"),
        "handoff": base64.b64encode(documents["handoff.json"]).decode("ascii"),
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    output = {"base64": base64.b64encode(encoded).decode("ascii"), "sha256": digest(encoded)}
    if args.output:
        pathlib.Path(args.output).write_text(json.dumps(output, separators=(",", ":")), encoding="utf-8")
    else:
        print(json.dumps(output, separators=(",", ":")))


def aws(arguments):
    completed = subprocess.run(["aws", *arguments], check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        fail("AWS CLI failed: " + completed.stderr.strip())
    return completed.stdout.strip()


def dispatch(args):
    checked_identity(args.source_sha, args.run_id, args.run_attempt)
    if not SHA256.fullmatch(args.provenance_sha256):
        fail("provenance SHA-256 is invalid")
    if args.mode != "run":
        fail("only run mode is authorized")
    parameters = {
        "sourceSha": [args.source_sha],
        "runId": [args.run_id],
        "runAttempt": [args.run_attempt],
        "provenanceBase64": [args.provenance_base64],
        "provenanceSha256": [args.provenance_sha256],
        "mode": [args.mode],
    }
    command_id = aws([
        "ssm", "send-command", "--region", args.region, "--document-name", args.document,
        "--document-version", "1",
        "--instance-ids", args.instance_id, "--parameters", json.dumps(parameters, separators=(",", ":")),
        "--query", "Command.CommandId", "--output", "text",
    ])
    if not command_id or command_id == "None":
        fail("SSM did not return a command ID")
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        try:
            result = aws([
                "ssm", "get-command-invocation", "--region", args.region, "--command-id", command_id,
                "--instance-id", args.instance_id, "--output", "json",
            ])
        except ValueError as error:
            if "(InvocationDoesNotExist) when calling the GetCommandInvocation operation" not in str(error):
                raise
            time.sleep(args.poll_seconds)
            continue
        try:
            invocation = json.loads(result)
        except json.JSONDecodeError as error:
            fail("SSM invocation response is invalid JSON: " + str(error))
        status = invocation.get("Status")
        if status == "Success":
            summary = parse_summary(invocation.get("StandardOutputContent", ""), args, command_id)
            pathlib.Path(args.summary_path).write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            return
        if status in {"Pending", "InProgress", "Delayed"}:
            time.sleep(args.poll_seconds)
            continue
        fail("SSM command %s ended with %r: %s" % (command_id, status, invocation.get("StandardErrorContent", "").strip()))
    fail("SSM command %s exceeded its timeout" % command_id)


def parse_summary(output, args, command_id):
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        fail("SSM command must emit exactly one summary JSON line")
    try:
        summary = json.loads(lines[0])
    except json.JSONDecodeError as error:
        fail("SSM summary is invalid JSON: " + str(error))
    required = {
        "schema_version": SUMMARY_SCHEMA,
        "source_sha": args.source_sha,
        "workflow_run_id": args.run_id,
        "workflow_run_attempt": args.run_attempt,
        "provenance_sha256": args.provenance_sha256,
        "accepted": True,
        "observations": 24,
    }
    for field, expected in required.items():
        if summary.get(field) != expected:
            fail("SSM summary has invalid %s" % field)
    if not isinstance(summary.get("report_s3_uri"), str) or not summary["report_s3_uri"].startswith("s3://"):
        fail("SSM summary lacks a versioned S3 report location")
    if not isinstance(summary.get("report_version_id"), str) or not summary["report_version_id"]:
        fail("SSM summary lacks an immutable report version ID")
    return summary


def verify_report(args):
    checked_identity(args.source_sha, args.run_id, args.run_attempt)
    summary = json.loads(pathlib.Path(args.summary_path).read_text(encoding="utf-8"))
    prefix = "trusted/20260925/ci-results/%s/%s" % (args.run_id, args.run_attempt)
    report_key = prefix + "/acceptance-report.json"
    archive_key = prefix + "/publication.tar.gz"
    report_uri = "s3://%s/%s" % (args.bucket, report_key)
    archive_uri = "s3://%s/%s" % (args.bucket, archive_key)
    if summary.get("report_s3_uri") != report_uri or not isinstance(summary.get("report_version_id"), str) or not summary["report_version_id"]:
        fail("trusted summary does not bind the fixed report object and version")
    if not SHA256.fullmatch(summary.get("report_sha256", "")):
        fail("trusted summary has no report digest")
    output = pathlib.Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "acceptance-report.json"
    aws(["s3api", "get-object", "--region", args.region, "--bucket", args.bucket,
         "--key", report_key, "--version-id", summary["report_version_id"], str(report_path)])
    report_bytes = report_path.read_bytes()
    if digest(report_bytes) != summary["report_sha256"]:
        fail("versioned acceptance report digest does not match")
    report = json.loads(report_bytes)
    required = {"schema_version": "synapse-sca-trusted-acceptance-report-v1", "accepted": True,
                "source_sha": args.source_sha, "workflow_run_id": args.run_id,
                "workflow_run_attempt": args.run_attempt, "provenance_sha256": args.provenance_sha256,
                "observations": 24, "publication_s3_uri": archive_uri}
    if any(report.get(name) != value for name, value in required.items()):
        fail("versioned acceptance report is not bound to the trusted run")
    if not isinstance(report.get("publication_version_id"), str) or not report["publication_version_id"] or not SHA256.fullmatch(report.get("publication_sha256", "")) or not SHA256.fullmatch(report.get("run_sha256", "")):
        fail("acceptance report lacks versioned publication hashes")
    archive_path = output / "publication.tar.gz"
    aws(["s3api", "get-object", "--region", args.region, "--bucket", args.bucket,
         "--key", archive_key, "--version-id", report["publication_version_id"], str(archive_path)])
    if digest(archive_path.read_bytes()) != report["publication_sha256"]:
        fail("versioned publication archive digest does not match")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        paths = {item.name for item in members}
        if any(item.issym() or item.islnk() or item.isdev() or item.name.startswith("/") or ".." in pathlib.PurePosixPath(item.name).parts for item in members):
            fail("publication archive contains unsafe members")
        if "publication/run.json" not in paths:
            fail("publication archive has no run.json")
        run_bytes = archive.extractfile("publication/run.json").read()
    archive_path.unlink()
    if digest(run_bytes) != report["run_sha256"]:
        fail("published run.json digest does not match")
    run_record = json.loads(run_bytes)
    observations = run_record.get("observations")
    if run_record.get("implementation_commit") != args.source_sha or run_record.get("run_key") != "%s/%s" % (args.run_id, args.run_attempt) or run_record.get("result", {}).get("gate", {}).get("passed") is not True or not isinstance(observations, list) or len(observations) != 2 or any(not isinstance(group, list) or len(group) != 12 for group in observations):
        fail("published run.json does not prove 24 passing observations")


def parser():
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    envelope = commands.add_parser("envelope")
    envelope.add_argument("--provenance-dir", required=True)
    envelope.add_argument("--source-sha", required=True)
    envelope.add_argument("--run-id", required=True)
    envelope.add_argument("--run-attempt", required=True)
    envelope.add_argument("--output")
    envelope.set_defaults(handler=build_envelope)
    dispatch_parser = commands.add_parser("dispatch")
    dispatch_parser.add_argument("--document", required=True)
    dispatch_parser.add_argument("--instance-id", required=True)
    dispatch_parser.add_argument("--region", required=True)
    dispatch_parser.add_argument("--source-sha", required=True)
    dispatch_parser.add_argument("--run-id", required=True)
    dispatch_parser.add_argument("--run-attempt", required=True)
    dispatch_parser.add_argument("--provenance-base64", required=True)
    dispatch_parser.add_argument("--provenance-sha256", required=True)
    dispatch_parser.add_argument("--mode", required=True)
    dispatch_parser.add_argument("--summary-path", required=True)
    dispatch_parser.add_argument("--timeout-seconds", type=int, default=2400)
    dispatch_parser.add_argument("--poll-seconds", type=int, default=5)
    dispatch_parser.set_defaults(handler=dispatch)
    verify_parser = commands.add_parser("verify-report")
    verify_parser.add_argument("--summary-path", required=True)
    verify_parser.add_argument("--output-dir", required=True)
    verify_parser.add_argument("--bucket", required=True)
    verify_parser.add_argument("--region", required=True)
    verify_parser.add_argument("--source-sha", required=True)
    verify_parser.add_argument("--run-id", required=True)
    verify_parser.add_argument("--run-attempt", required=True)
    verify_parser.add_argument("--provenance-sha256", required=True)
    verify_parser.set_defaults(handler=verify_report)
    return result


def main():
    args = parser().parse_args()
    if hasattr(args, "timeout_seconds") and (args.timeout_seconds <= 0 or args.poll_seconds <= 0):
        fail("SSM timeout and poll interval must be positive")
    args.handler(args)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("trusted SSM dispatch failed: " + str(error), file=sys.stderr)
        sys.exit(1)

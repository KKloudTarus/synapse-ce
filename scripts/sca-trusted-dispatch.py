#!/usr/bin/env python3
"""Run one source-bound SCA acceptance cycle on the protected Linux host."""

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


SOURCE_SHA_FILE = Path("/etc/synapse-sca/trusted-source-sha")
APPROVAL_DIGEST_FILE = Path("/etc/synapse-sca/trusted-approval-sha256")
VERIFIER = Path("/opt/synapse-sca/verify-publication")
RUNUSER = "/usr/sbin/runuser"
LOCK_FILE = Path("/run/lock/synapse-sca-trusted.lock")
SOURCE_REPO = Path("/protected/sca-staging/repo")
STAGING = Path("/protected/sca-staging/ci-results")
TRUSTED_INPUTS = Path("/protected/sca-inputs")
RAW_RETENTION = Path("/protected/sca-raw")
BUCKET = "synapse-sca-benchmark-evidence-116378167742-20260923-e1b6fb88"
REGION = "us-east-1"
SCHEMA = "synapse-sca-trusted-provenance-envelope-v1"
SUMMARY_SCHEMA = "synapse-sca-trusted-dispatch-summary-v1"
EXPECTED_REPO = "KKloudTarus/synapse-ce"
EXPECTED_PULL = 1320
MAX_PROVENANCE_BYTES = 32_768
MAX_PROVENANCE_AGE = dt.timedelta(minutes=15)


def fail(message):
    raise ValueError(message)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(data):
    record = json.loads(data, object_pairs_hook=unique_pairs)
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if encoded != data:
        fail("provenance JSON is not canonical")
    return record


def require_keys(record, expected):
    if not isinstance(record, dict) or set(record) != set(expected):
        fail("provenance JSON has unexpected fields")


def env(name, pattern):
    value = os.environ.get("SSM_" + name, "")
    if not re.fullmatch(pattern, value, re.ASCII):
        fail(f"invalid {name}")
    return value


def load_provenance(source_sha, run_id, attempt):
    encoded = env("provenanceBase64", r"[A-Za-z0-9+/=]{1,50000}")
    expected_digest = env("provenanceSha256", r"sha256:[0-9a-f]{64}")
    data = base64.b64decode(encoded, validate=True)
    if len(data) > MAX_PROVENANCE_BYTES or digest(data) != expected_digest:
        fail("provenance envelope digest or size does not match")
    envelope = canonical_json(data)
    require_keys(envelope, ("schema_version", "source_sha", "workflow_run_id", "workflow_run_attempt", "approval", "authorization", "handoff"))
    if envelope["schema_version"] != SCHEMA or envelope["source_sha"] != source_sha:
        fail("provenance envelope source mismatch")
    if str(envelope["workflow_run_id"]) != run_id or str(envelope["workflow_run_attempt"]) != attempt:
        fail("provenance envelope run mismatch")
    records = {}
    for name in ("approval", "authorization", "handoff"):
        value = envelope[name]
        if not isinstance(value, str):
            fail(f"{name} is not base64 text")
        payload = base64.b64decode(value, validate=True)
        records[name] = (payload, canonical_json(payload))
    approval, authorization, handoff = (records[name][1] for name in ("approval", "authorization", "handoff"))
    require_keys(handoff, ("schema_version", "repository", "pull_number", "source_sha", "workflow_run_id", "workflow_run_attempt", "generated_at", "approval_sha256", "authorization_sha256"))
    if handoff["schema_version"] != "synapse-sca-maintainer-authorization-handoff-v1" or handoff["repository"] != EXPECTED_REPO or handoff["pull_number"] != EXPECTED_PULL or handoff["source_sha"] != source_sha:
        fail("handoff repository, pull request, or source mismatch")
    if str(handoff["workflow_run_id"]) != run_id or str(handoff["workflow_run_attempt"]) != attempt:
        fail("handoff run mismatch")
    if handoff["approval_sha256"] != digest(records["approval"][0]) or handoff["authorization_sha256"] != digest(records["authorization"][0]):
        fail("handoff payload digest mismatch")
    timestamp = dt.datetime.fromisoformat(handoff["generated_at"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        fail("handoff timestamp has no timezone")
    age = dt.datetime.now(dt.timezone.utc) - timestamp
    if age < -dt.timedelta(minutes=2) or age > MAX_PROVENANCE_AGE:
        fail("handoff verification has expired")
    if approval.get("implementation_commit") != source_sha or authorization.get("implementation_commit") != source_sha:
        fail("approval source mismatch")
    if approval.get("schema_version") != "github-maintainer-issue-comment-capture-v1" or approval.get("decision") != "approved":
        fail("approval record is not an approved maintainer capture")
    if authorization.get("schema_version") != "maintainer-authorization-v2" or authorization.get("decision") != "approved" or \
            authorization.get("approval_id") != approval.get("id") or \
            authorization.get("approval_digest") != digest(records["approval"][0]) or \
            authorization.get("maintainer_login") != approval.get("login"):
        fail("authorization is not bound to the pinned approval")
    input_digests = {}
    for name in ("catalog", "oracle", "ratchet", "policy"):
        value = authorization.get(name + "_digest")
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            fail("authorization has an invalid input digest")
        input_digests[name] = value
    expected_body = "\n".join(("decision: approved", "implementation_commit: " + source_sha,
                               *(name + "_digest: " + input_digests[name] for name in ("catalog", "oracle", "ratchet", "policy"))))
    accepted_bodies = {expected_body, expected_body + "\n", expected_body.replace("\n", "\r\n"),
                       expected_body.replace("\n", "\r\n") + "\r\n"}
    if approval.get("body") not in accepted_bodies:
        fail("pinned maintainer approval does not authorize these input digests")
    return expected_digest, records


def run(*args, capture=False, **kwargs):
    result = subprocess.run(args, check=True, text=True, capture_output=capture, **kwargs)
    return result.stdout.strip() if capture else None


def as_user(*args, capture=False, **kwargs):
    return run(RUNUSER, "-u", "ec2-user", "--", *args, capture=capture, **kwargs)


def prepare_source(source_sha):
    current = as_user("git", "-C", str(SOURCE_REPO), "status", "--porcelain", "--untracked-files=all", capture=True)
    if current:
        fail("VM source checkout is dirty")
    as_user("git", "-C", str(SOURCE_REPO), "fetch", "--no-tags", "origin", source_sha)
    fetched = as_user("git", "-C", str(SOURCE_REPO), "rev-parse", "FETCH_HEAD", capture=True)
    if fetched != source_sha:
        fail("fetched source differs from authorized SHA")
    as_user("git", "-C", str(SOURCE_REPO), "checkout", "--detach", source_sha)
    current = as_user("git", "-C", str(SOURCE_REPO), "rev-parse", "HEAD", capture=True)
    if current != source_sha:
        fail("source checkout differs from authorized SHA")
    if as_user("git", "-C", str(SOURCE_REPO), "status", "--porcelain", "--untracked-files=all", capture=True):
        fail("authorized source checkout became dirty")


def prepare_inputs(run_root, records):
    snapshot = run_root / "inputs"
    run("cp", "-a", str(TRUSTED_INPUTS), str(snapshot))
    for parent in (snapshot / "repository/reviews/github", snapshot / "repository/reviews/dispositions/github"):
        if parent.exists() and any(parent.iterdir()):
            fail("protected input snapshot already contains review evidence")
        parent.mkdir(parents=True, exist_ok=True)
    (snapshot / "repository/reviews/github/approval.json").write_bytes(records["approval"][0])
    (snapshot / "repository/reviews/dispositions/github/authorization.json").write_bytes(records["authorization"][0])
    run("chown", "-R", "root:root", str(snapshot))
    run("chmod", "-R", "u=rwX,go=rX", str(snapshot))
    return snapshot


def inspect_publication(output_root, source_sha, run_id, attempt):
    data = json.loads((output_root / "run.json").read_bytes(), object_pairs_hook=unique_pairs)
    observations = data.get("observations")
    if data.get("implementation_commit") != source_sha or data.get("run_key") != f"{run_id}/{attempt}":
        fail("trusted publication identity mismatch")
    if data.get("repetitions") != 2 or not isinstance(observations, list) or len(observations) != 2 or any(not isinstance(group, list) or len(group) != 12 for group in observations):
        fail("trusted publication does not contain 24 observations")
    if data.get("result", {}).get("gate", {}).get("passed") is not True:
        fail("trusted benchmark ratchet did not pass")
    if data.get("cleanup") != {"raw_run_removed": True, "docker_cleaned": True}:
        fail("trusted benchmark cleanup did not pass")
    return data


def put_object(path, key):
    result = json.loads(run("aws", "s3api", "put-object", "--region", REGION, "--bucket", BUCKET, "--key", key, "--body", str(path), "--server-side-encryption", "AES256", capture=True))
    version = result.get("VersionId")
    if not isinstance(version, str) or not version:
        fail("S3 did not return a versioned result")
    return version


def execute(source_sha, run_id, attempt, provenance_digest, records, mode):
    authorized_sha = SOURCE_SHA_FILE.read_text().strip()
    if authorized_sha != source_sha:
        fail("source SHA is not authorized by protected host configuration")
    if not TRUSTED_INPUTS.is_dir() or not RAW_RETENTION.is_dir():
        fail("protected benchmark inputs are absent")
    if mode == "validate":
        return {"schema_version": SUMMARY_SCHEMA, "mode": "validate", "source_sha": source_sha, "workflow_run_id": run_id, "workflow_run_attempt": attempt, "provenance_sha256": provenance_digest, "validated": True}
    if APPROVAL_DIGEST_FILE.read_text().strip() != digest(records["approval"][0]):
        fail("approval capture is not authorized by protected host configuration")

    run_root = STAGING / f"{run_id}-{attempt}"
    run_root.mkdir(parents=True, exist_ok=False)
    run_root.chmod(0o755)
    try:
        return execute_cycle(run_root, source_sha, run_id, attempt, provenance_digest, records)
    finally:
        shutil.rmtree(run_root)


def execute_cycle(run_root, source_sha, run_id, attempt, provenance_digest, records):
    snapshot = prepare_inputs(run_root, records)
    prepare_source(source_sha)
    output_parent = run_root / "output"
    output_parent.mkdir(mode=0o700)
    run("chown", "ec2-user:ec2-user", str(output_parent))
    output_root = output_parent / "publication"
    log_path = run_root / "benchmark.log"
    environment = {"PATH": "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/ec2-user", "XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "RUNNER_TEMP": "/protected/sca-staging"}
    command = [RUNUSER, "-u", "ec2-user", "--", "bash", "scripts/run-sca-cycle-delegated.sh", "run", "--corpus-root", str(SOURCE_REPO / "internal/usecase/scabench/corpus"), "--trusted-input-root", str(snapshot), "--output-root", str(output_root), "--raw-retention-root", str(RAW_RETENTION), "--implementation-commit", source_sha, "--run-key", f"{run_id}/{attempt}"]
    with log_path.open("wb") as log:
        completed = subprocess.run(command, cwd=SOURCE_REPO, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=2500, check=False)
    if completed.returncode:
        tail = log_path.read_text(errors="replace")[-3000:]
        fail(f"trusted cycle failed with exit {completed.returncode}: {tail}")
    sealed_parent = run_root / "sealed"
    sealed_parent.mkdir(mode=0o700)
    sealed_output = sealed_parent / "publication"
    shutil.copytree(output_root, sealed_output, symlinks=True)
    run(str(VERIFIER), "--publication", str(sealed_output), "--source-sha", source_sha,
        "--run-key", f"{run_id}/{attempt}")
    publication = inspect_publication(sealed_output, source_sha, run_id, attempt)
    if (sealed_output / "reviews/review.json").read_bytes() != records["approval"][0] or (sealed_output / "reviews/disposition.json").read_bytes() != records["authorization"][0]:
        fail("published review evidence differs from the live GitHub handoff")
    authorization = records["authorization"][1]
    input_digests = publication.get("input_digests")
    if not isinstance(input_digests, dict) or any(input_digests.get(name) != authorization.get(name + "_digest") for name in ("catalog", "oracle", "ratchet", "policy")):
        fail("published benchmark inputs differ from maintainer authorization")
    archive_path = run_root / "publication.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(sealed_output, arcname="publication", recursive=True)
    prefix = f"trusted/20260925/ci-results/{run_id}/{attempt}"
    archive_key = f"{prefix}/publication.tar.gz"
    archive_version = put_object(archive_path, archive_key)
    report = {"schema_version": "synapse-sca-trusted-acceptance-report-v1", "accepted": True, "source_sha": source_sha, "workflow_run_id": run_id, "workflow_run_attempt": attempt, "provenance_sha256": provenance_digest, "observations": sum(len(group) for group in publication["observations"]), "input_digests": publication["input_digests"], "run_sha256": digest((sealed_output / "run.json").read_bytes()), "publication_s3_uri": f"s3://{BUCKET}/{archive_key}", "publication_version_id": archive_version, "publication_sha256": digest(archive_path.read_bytes())}
    report_path = run_root / "acceptance-report.json"
    report_path.write_bytes(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    report_key = f"{prefix}/acceptance-report.json"
    report_version = put_object(report_path, report_key)
    return {"schema_version": SUMMARY_SCHEMA, "source_sha": source_sha, "workflow_run_id": run_id, "workflow_run_attempt": attempt, "provenance_sha256": provenance_digest, "accepted": True, "observations": 24, "report_s3_uri": f"s3://{BUCKET}/{report_key}", "report_version_id": report_version, "report_sha256": digest(report_path.read_bytes())}


def main():
    import fcntl

    source_sha = env("sourceSha", r"[0-9a-f]{40}")
    run_id = env("runId", r"[1-9][0-9]{0,19}")
    attempt = env("runAttempt", r"[1-9][0-9]{0,5}")
    mode = env("mode", r"validate|run")
    provenance_digest, records = load_provenance(source_sha, run_id, attempt)
    with LOCK_FILE.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another trusted SCA cycle is already active")
        summary = execute(source_sha, run_id, attempt, provenance_digest, records, mode)
    print(json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"trusted SCA dispatch: {error}", file=sys.stderr)
        sys.exit(1)

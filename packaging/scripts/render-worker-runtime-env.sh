#!/usr/bin/env bash
set -euo pipefail

: "${SYNAPSE_WORKER_SECRET_ID:?set SYNAPSE_WORKER_SECRET_ID}"
: "${AWS_REGION:?set AWS_REGION}"

umask 0077
payload_file=$(mktemp /etc/synapse-worker/secret.json.XXXXXX)
worker_tmp=$(mktemp /etc/synapse-worker/runtime.env.XXXXXX)
broker_tmp=$(mktemp /etc/synapse-worker/egress-broker.env.XXXXXX)
trap 'rm -f "$payload_file" "$worker_tmp" "$broker_tmp"' EXIT

aws secretsmanager get-secret-value \
    --region "$AWS_REGION" \
    --secret-id "$SYNAPSE_WORKER_SECRET_ID" \
    --query SecretString \
    --output text >"$payload_file"

python3 - "$payload_file" "$worker_tmp" "$broker_tmp" <<'PY'
import json
import os
import pathlib
import sys

required = {
    "SYNAPSE_API_TOKEN",
    "SYNAPSE_BLOB_BUCKET",
    "SYNAPSE_BLOB_ENDPOINT",
    "SYNAPSE_DB_DSN",
    "SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN",
    "SYNAPSE_EGRESS_GRANT_AUTHORITY_URL",
    "SYNAPSE_EGRESS_GRANT_PUBLIC_KEY",
    "SYNAPSE_EVIDENCE_SIGNING_SEED",
    "SYNAPSE_MEASURE_CURSOR_SECRET",
    "SYNAPSE_TOOL_HASHES",
    "SYNAPSE_VAULT_MASTER_KEY",
}
optional = {"SYNAPSE_BLOB_ACCESS_KEY", "SYNAPSE_BLOB_SECRET_KEY"}
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(value, dict):
    raise SystemExit("worker secret must be a JSON object")
missing = sorted(required - set(value))
extra = sorted(set(value) - required - optional)
static_keys = optional & set(value)
if missing or extra or (static_keys and static_keys != optional):
    raise SystemExit(f"worker secret keys mismatch: missing={missing} extra={extra} static_pair={sorted(static_keys)}")


def quote(raw):
    raw = str(raw)
    if "\n" in raw or "\r" in raw or "\x00" in raw:
        raise SystemExit("worker secret values must be single-line")
    return "'" + raw.replace("'", "'\\''") + "'"


public_key = value.pop("SYNAPSE_EGRESS_GRANT_PUBLIC_KEY")
worker_path = pathlib.Path(sys.argv[2])
with worker_path.open("w", encoding="utf-8", newline="\n") as output:
    for key in sorted(value):
        output.write(f"{key}={quote(value[key])}\n")
os.chmod(worker_path, 0o640)

broker_path = pathlib.Path(sys.argv[3])
with broker_path.open("w", encoding="utf-8", newline="\n") as output:
    output.write(f"SYNAPSE_EGRESS_GRANT_PUBLIC_KEY={quote(public_key)}\n")
os.chmod(broker_path, 0o600)
PY

rm -f "$payload_file"
chown root:synapse-worker "$worker_tmp"
chown root:root "$broker_tmp"
mv -f "$worker_tmp" /etc/synapse-worker/runtime.env
mv -f "$broker_tmp" /etc/synapse-worker/egress-broker.env
trap - EXIT

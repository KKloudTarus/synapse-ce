#!/usr/bin/env sh
set -eu
chart_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
values="$chart_dir/tests/production-values.yaml"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# A production deployment must declare one governed Kubernetes region for the
# control-plane data-processing tier. The migration job must inherit that region.
helm template synapse "$chart_dir" -f "$values" --kube-version 1.29.0 >"$out"
grep -q 'topology.kubernetes.io/region: "us-east-1"' "$out"
awk '
  /^---$/ { kind=""; migrate=0; region=0; next }
  /^kind: Job$/ { kind="Job" }
  /app\.kubernetes\.io\/component: migrate/ { migrate=1 }
  /topology\.kubernetes\.io\/region: "us-east-1"/ { region=1 }
  { if (kind == "Job" && migrate && region) ok=1 }
  END { exit ok ? 0 : 1 }
' "$out" || {
  printf '%s\n' 'expected the migration Job to inherit the governed data region' >&2
  exit 1
}

# A regional cell is intentionally single-tenant. This makes tenant assignment a
# deployment boundary rather than allowing one process to route data across regions.
awk '/name: SYNAPSE_SINGLE_TENANT/{getline; if ($0 ~ /value: "true"/) ok=1} END{exit ok?0:1}' "$out"

if helm template synapse "$chart_dir" -f "$values" --kube-version 1.29.0 \
  --set 'api.nodeSelector.topology\.kubernetes\.io/region=' >/dev/null 2>&1; then
  printf '%s\n' 'expected production render without a governed data region to fail' >&2
  exit 1
fi

# In-cluster execution handles tenant data too, so its broker/worker region must
# match the control-plane region exactly.
if helm template synapse "$chart_dir" -f "$values" --kube-version 1.29.0 \
  --set execution.mode=inClusterBroker \
  --set egressBroker.enabled=true \
  --set egressBroker.grantAuthorityURL=https://grant.internal.example \
  --set egressBroker.grantPublicKey=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzJieXRlcw== \
  --set 'egressBroker.nodeSelector.topology\.kubernetes\.io/region=eu-west-1' >/dev/null 2>&1; then
  printf '%s\n' 'expected cross-region in-cluster execution placement to fail' >&2
  exit 1
fi

printf '%s\n' 'data governance chart checks passed'

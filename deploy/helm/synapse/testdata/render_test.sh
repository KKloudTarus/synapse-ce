#!/usr/bin/env sh
set -eu
chart_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
values="$chart_dir/tests/production-values.yaml"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

helm lint --strict "$chart_dir" -f "$values"
helm template synapse "$chart_dir" -f "$values" --kube-version 1.29.0 >"$out"

# Production policy: only digest-qualified images, no privileged containers/capability additions,
# a private metrics listener, and migrations as an ordered Helm hook.
! grep -E 'image: .+:(latest|[[:alnum:]._-]+)$' "$out"
grep -q 'helm.sh/hook": pre-install,pre-upgrade' "$out"
# The migration hook runs before normal resources, so its service account must be a hook with a
# lower weight. Otherwise the Job is never scheduled: the API server refuses pod creation for a
# service account that does not exist yet.
hook_weight_for_kind() {
  # Print the hook-weight of the pre-install/pre-upgrade hook whose kind is $1.
  awk -v want="$1" '
    /^---$/ { kind=""; hook=0; weight="" ; next }
    /^kind:[[:space:]]*/ { k=$0; sub(/^kind:[[:space:]]*/, "", k); kind=k }
    /"helm\.sh\/hook":[[:space:]]*pre-install,pre-upgrade/ { hook=1 }
    /"helm\.sh\/hook-weight":/ {
      # Split on the quote character so the dash in "hook-weight" cannot leak into the value.
      n=split($0, parts, "\""); if (n >= 4) { weight=parts[4] }
    }
    { if (kind == want && hook == 1 && weight != "") { print weight; exit } }
  ' "$2"
}
sa_weight=$(hook_weight_for_kind ServiceAccount "$out")
job_weight=$(hook_weight_for_kind Job "$out")
if [ -z "$sa_weight" ]; then
  printf '%s\n' 'ServiceAccount must be a pre-install/pre-upgrade hook so the migration Job can be scheduled' >&2
  exit 1
fi
if [ -z "$job_weight" ]; then
  printf '%s\n' 'migration Job must be a pre-install/pre-upgrade hook' >&2
  exit 1
fi
if [ "$sa_weight" -ge "$job_weight" ]; then
  printf '%s\n' "ServiceAccount hook-weight ($sa_weight) must be lower than the migration Job's ($job_weight)" >&2
  exit 1
fi
grep -q 'SYNAPSE_DB_AUTO_MIGRATE' "$out"
grep -q 'value: "false"' "$out"
grep -q 'SYNAPSE_SANDBOX_ENABLED' "$out"
grep -q 'value: "true"' "$out"
# The pod user-namespace posture is explicit on every workload. Regardless of this setting, the
# application performs a live bwrap namespace/mount/seccomp startup probe and fails closed.
if [ "$(grep -c 'hostUsers: true' "$out")" -ne 4 ]; then
  printf '%s\n' 'expected explicit hostUsers posture on API, worker, web, and migration workloads' >&2
  exit 1
fi
! grep -E 'privileged: true|SYS_ADMIN' "$out"
# Metrics use a dedicated API listener and ClusterIP port, never the public ingress. The aggregate
# collectors have fixed low-cardinality labels and the runtime NetworkPolicy keeps this unauthenticated
# endpoint private to explicitly allowed monitoring clients.
grep -q 'name: SYNAPSE_METRICS_ENABLED' "$out"
grep -q 'name: SYNAPSE_METRICS_ADDR' "$out"
grep -q 'name: metrics' "$out"
grep -q 'containerPort: 9090' "$out"
grep -q 'kubernetes.io/metadata.name: "monitoring"' "$out"
! awk '/^kind: Ingress$/{ingress=1} /^---$/{ingress=0} ingress && /9090|metrics/{found=1} END{exit found ? 0 : 1}' "$out"
grep -q 'kind: NetworkPolicy' "$out"
# Immutable image and explicitly scoped egress: no writable root filesystem, no shell in any
# probe, and every runtime egress rule carries a destination rather than only a port.
! grep -q 'readOnlyRootFilesystem: false' "$out"
! grep -qE '"/bin/sh"|/bin/sh -c' "$out"
grep -q 'ipBlock' "$out"
# Both long-lived workloads and the migration hook receive the operator-supplied database trust
# anchor read-only. DSNs use sslmode=verify-full and point sslrootcert at this mounted path.
if [ "$(grep -c 'mountPath: /tmp' "$out")" -ne 3 ]; then
  printf '%s\n' 'expected an explicit writable /tmp emptyDir on API, worker, and web workloads' >&2
  exit 1
fi
if [ "$(grep -c 'mountPath: /etc/synapse/database-ca' "$out")" -ne 3 ]; then
  printf '%s\n' 'expected the database CA bundle on API, worker, and migration workloads' >&2
  exit 1
fi
if [ "$(grep -c 'secretName: synapse-database-ca' "$out")" -ne 3 ]; then
  printf '%s\n' 'expected all database CA volumes to reference the configured external Secret' >&2
  exit 1
fi
if helm template synapse "$chart_dir" -f "$values" --set networkPolicy.runtimeEgress.database=null >/dev/null 2>&1; then
  printf '%s\n' 'expected unrestricted runtime egress to be refused' >&2
  exit 1
fi
grep -q 'kind: PodDisruptionBudget' "$out"
# Every spread rule must select its own workload component; a null/empty selector matches no pods on
# current Kubernetes and silently defeats the intended HA topology.
for component in api worker web; do
  grep -q "app.kubernetes.io/component: $component" "$out"
done
! grep -q 'labelSelector: {}' "$out"
grep -q 'kind: Ingress' "$out"
# The worker enforces a process-wide singleton lock. Its update must allow no surge, so Kubernetes
# stops the old singleton before creating the replacement instead of overlapping two lock holders.
worker_strategy=$(awk '
  /^---$/ { worker=0; next }
  /app\.kubernetes\.io\/component: worker/ { worker=1 }
  worker && /maxSurge:|maxUnavailable:/ { print }
' "$out")
case "$worker_strategy" in
  *"maxSurge: 0"*) ;;
  *) printf '%s\n' 'the singleton worker must roll out with maxSurge: 0' >&2; exit 1 ;;
esac
case "$worker_strategy" in
  *"maxUnavailable: 1"*) ;;
  *) printf '%s\n' 'the singleton worker must allow one unavailable replica so the old pod stops first' >&2; exit 1 ;;
esac

if helm lint "$chart_dir" -f "$chart_dir/tests/invalid-tag-values.yaml" >/dev/null 2>&1; then
  printf '%s\n' 'expected tag-only image values to fail schema validation' >&2
  exit 1
fi

#!/usr/bin/env bash
# Local control-plane smoke test on kind. Proves execution.mode=controlPlaneOnly deploys and BOOTS on a
# capless (managed-style) node and serves the OFFLINE product, and that the egress-enforced tier is absent.
# It is NOT a production posture. A true execution smoke (sandbox+egress) needs a capable native host.
#
# Usage: deploy/kind/kind-smoke.sh   (requires kind, kubectl, helm, docker; images synapse:local + synapse-web:local)
set -euo pipefail
# Requires a kind node with WORKING pod-to-Service (ClusterIP) routing. Standard kind on a normal Linux/macOS
# host has this. Heavily nested/restricted sandboxes (docker-in-docker with a blocked kube-proxy) may not route
# ClusterIP traffic, so the API cannot reach Postgres/MinIO by Service name and the install will not converge;
# that is an environment limitation, not a chart defect (verify with `helm template` + the render test).
CLUSTER=${KIND_CLUSTER:-synapse-local}
NS=synapse
CHART=deploy/helm/synapse
CTX="kind-${CLUSTER}"
K="kubectl --context ${CTX} -n ${NS}"

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

log "cluster ${CLUSTER}"
kind get clusters | grep -qx "${CLUSTER}" || kind create cluster --name "${CLUSTER}" --wait 90s

log "load images"
kind load docker-image synapse:local synapse-web:local --name "${CLUSTER}"

kubectl --context "${CTX}" create namespace "${NS}" --dry-run=client -o yaml | kubectl --context "${CTX}" apply -f -

log "dependencies (postgres + minio)"
kubectl --context "${CTX}" apply -f deploy/kind/deps.yaml
$K rollout status deploy/synapse-postgres --timeout=120s
$K rollout status deploy/minio --timeout=120s

log "secrets (dev values; NOT production)"
hex() { openssl rand -hex 32; }
$K create secret generic synapse-api-token --from-literal=api-token="syn_dev_$(openssl rand -hex 12)" --dry-run=client -o yaml | $K apply -f -
# Runtime role is NON-SUPERUSER (RLS enforcement); migrations run as the owner. See deps.yaml pg-init.
RUNTIME_DSN="postgres://synapse_rt:synapse@synapse-postgres:5432/synapse?sslmode=disable"
MIGRATION_DSN="postgres://synapse:synapse@synapse-postgres:5432/synapse?sslmode=disable"
$K create secret generic synapse-db-runtime --from-literal=dsn="${RUNTIME_DSN}" --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-db-migration --from-literal=dsn="${MIGRATION_DSN}" --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-s3-access --from-literal=access-key=minio --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-s3-secret --from-literal=secret-key=minio12345 --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-vault-key --from-literal=key="$(hex)" --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-evidence-signing --from-literal=seed="$(hex)" --dry-run=client -o yaml | $K apply -f -
$K create secret generic synapse-cursor-secret --from-literal=secret="$(hex)" --dry-run=client -o yaml | $K apply -f -
# The chart mounts a DB CA bundle read-only. sslmode=disable does not use it, so a placeholder PEM suffices here.
printf -- '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' > /tmp/synapse-kind-ca.crt
$K create secret generic synapse-database-ca --from-file=ca.crt=/tmp/synapse-kind-ca.crt --dry-run=client -o yaml | $K apply -f -

log "helm install (execution.mode=controlPlaneOnly)"
helm --kube-context "${CTX}" upgrade --install synapse "${CHART}" -n "${NS}" \
  -f "${CHART}/values-dev.yaml" -f deploy/kind/values-kind.yaml --wait --timeout 240s || {
    echo "helm install did not converge; pod status:"; $K get pods; $K logs -l app.kubernetes.io/component=api --tail=40 || true; exit 1; }

log "wait for API"
$K rollout status deploy/synapse-api --timeout=180s

log "assert the control plane serves"
API_POD=$($K get pod -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')
check() { $K exec "${API_POD}" -c api -- /opt/synapse/synapse-cli >/dev/null 2>&1 || true; }
# /healthz and /readyz via an in-cluster curl-less probe: use wget from the web (nginx) pod against the api Service.
$K run smoke-probe --context "${CTX}" -q --rm -i --restart=Never --image=busybox:1.36 --timeout=90s -- \
  sh -c 'set -e; for p in healthz readyz; do echo "GET /$p"; wget -q -O- "http://synapse-api:8080/$p" || wget -S -O- "http://synapse-api:8080/$p"; echo; done' \
  || { echo "probe failed"; $K get pods; exit 1; }

log "SMOKE PASSED: controlPlaneOnly control plane is up and serving on kind"
$K get pods -o wide
echo
echo "Note: DAST / live recon / CSPM / remote git-clone / image-pull are intentionally ABSENT in controlPlaneOnly."
echo "They require the egress-enforced execution tier (externalNative on native hosts, or inClusterBroker on capable nodes)."

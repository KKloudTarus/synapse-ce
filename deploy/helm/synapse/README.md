# Synapse Helm chart

This chart deploys the production control plane: at least two API replicas, one lease-locked worker, a static web dashboard, and a pre-install/pre-upgrade migration Job. It expects external PostgreSQL and S3-compatible object storage.

## Prerequisites

- Kubernetes 1.29 or later, Helm 4, and an ingress controller.
- A Linux amd64 node runtime that permits unprivileged user namespaces. Bubblewrap is installed in the production image and Synapse supplies its own default-deny seccomp BPF filter. The chart does not request privileged mode, `SYS_ADMIN`, host networking, or host mounts.
- Pre-created, split Secrets named by `existingSecrets` and a pre-created TLS Secret named by `ingress.tls.secretName`. The chart never renders Secret data.
- Digest-qualified production images. Tags are rejected by `values.schema.json`.

## Install

Copy the production test values as a starting point, replace only references and non-secret endpoints, and use your secret-management controller for the referenced Secrets:

```bash
helm upgrade --install synapse deploy/helm/synapse \
  --namespace synapse --create-namespace \
  --values deploy/helm/synapse/tests/production-values.yaml
```

The migration hook uses the separate owner DSN Secret. API and worker set `SYNAPSE_DB_AUTO_MIGRATE=false`; the application verifies migration readiness before serving work. The API exposes aggregate Prometheus metrics on a dedicated ClusterIP port. That listener is unauthenticated by design, never appears on the public ingress, and its NetworkPolicy accepts traffic only from `api.metrics.monitoringNamespace`.

## Validation

```bash
helm lint --strict deploy/helm/synapse -f deploy/helm/synapse/tests/production-values.yaml
helm template synapse deploy/helm/synapse -f deploy/helm/synapse/tests/production-values.yaml --kube-version 1.29.0
(cd deploy/helm/synapse && sh testdata/render_test.sh)
```

NetworkPolicy starts with namespace-wide default deny, allows ingress only from the configured ingress-controller namespace, permits DNS plus TLS/PostgreSQL egress, and grants HTTP/S recon egress only to the worker. Configure an FQDN-aware CNI or egress gateway with managed PostgreSQL/S3 and authorized-target allowlists before production use.

The disposable EKS rehearsal proved the chart's HA, migration, TLS, private-service, and fail-closed startup paths. Its standard managed-node runtime denied the nested unprivileged namespaces required by bubblewrap, so positive sandbox execution remains a deployment prerequisite: validate the target AMI/runtime and run a sandboxed worker job before relying on the chart for production workloads.

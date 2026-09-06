# Synapse Helm chart

This chart deploys Synapse. `execution.mode` selects the tool-execution placement: `controlPlaneOnly` (the default — API + web + migration, offline product, boots on any node including managed EKS and kind), `externalNative` (production control plane here, execution tier on native EC2 hosts — the recommended posture), or `inClusterBroker` (execution in-cluster via a privileged egress-broker DaemonSet on capable nodes). It expects external PostgreSQL and S3-compatible object storage. The runtime DB role must be `NOSUPERUSER NOBYPASSRLS`. See `docs/guide/deployment.md` for the full matrix.

## Prerequisites

- Kubernetes 1.29 or later, Helm 4, and an ingress controller.
- A Linux amd64 node runtime that permits unprivileged user namespaces. Bubblewrap is installed in the production image and Synapse supplies its own default-deny seccomp BPF filter. The chart does not request privileged mode, `SYS_ADMIN`, host networking, or host mounts.
- Pre-created, split Secrets named by `existingSecrets` and a pre-created TLS Secret named by `ingress.tls.secretName`. The chart never renders Secret data.
- Digest-qualified production images. Tags are rejected by `values.schema.json`.
- For production execution modes, nodes in the control-plane data region must carry the standard `topology.kubernetes.io/region` label and `api.nodeSelector.topology.kubernetes.io/region` must select that governed region.

## First install

The chart is fail-closed. A bare `helm lint deploy/helm/synapse` or `helm template deploy/helm/synapse` fails on purpose, because rendering with the shipped defaults would produce a deployment whose runtime egress is unrestricted:

```
[ERROR] values.yaml: - at '/api/grantAuthority/networkPolicySourceCIDRs': minItems: got 0, want 1
Error: networkPolicy.runtimeEgress.database must list the PostgreSQL CIDR(s)
```

Three CIDR lists have no safe default and must be supplied:

| Value | What it must contain |
| --- | --- |
| `networkPolicy.runtimeEgress.database` | The address range PostgreSQL resolves to, for example the RDS subnet CIDRs. |
| `networkPolicy.runtimeEgress.objectStore` | The address range of the S3-compatible endpoint, for example the S3 prefix-list ranges. |
| `api.grantAuthority.networkPolicySourceCIDRs` | The dedicated private NLB subnet CIDRs. The schema requires a non-empty list even while `api.grantAuthority.enabled` is `false`. |

Eight Secrets must already exist in the release namespace. The chart references them and never renders Secret data, so supply them with external-secrets, the Secrets Store CSI driver, or an equivalent controller:

| `existingSecrets` path | Default Secret name | Key | Contents |
| --- | --- | --- | --- |
| `apiToken` | `synapse-api-token` | `api-token` | Bootstrap-admin bearer token. |
| `database.runtime` | `synapse-db-runtime` | `dsn` | Runtime DSN for the non-superuser application role, `sslmode=verify-full`. |
| `database.migration` | `synapse-db-migration` | `dsn` | Owner DSN used only by the migration Job. |
| `objectStore.accessKey` | `synapse-s3-access` | `access-key` | Object-store access key. |
| `objectStore.secretKey` | `synapse-s3-secret` | `secret-key` | Object-store secret key. |
| `cryptography.vaultMasterKey` | `synapse-vault-key` | `key` | 32-byte vault master key. |
| `cryptography.evidenceSigningSeed` | `synapse-evidence-signing` | `seed` | Evidence signing seed. |
| `cryptography.measureCursorSecret` | `synapse-cursor-secret` | `secret` | HMAC key for Measures pagination cursors. |

Two more Secrets are referenced outside `existingSecrets`: `externalDatabase.caBundle.secretName` (`synapse-database-ca`, key `ca.crt`) supplies the database trust anchor, and `ingress.tls.secretName` (`synapse-tls`) supplies the ingress certificate. Enabling `oidc.enabled` or `api.grantAuthority.enabled` adds `existingSecrets.oidc.clientSecret` and the two `existingSecrets.egressGrant` entries.

`values-dev.yaml` supplies the three CIDR lists and a local ingress host so the chart renders and installs on a development cluster without touching the production defaults:

```bash
helm lint --strict deploy/helm/synapse -f deploy/helm/synapse/values-dev.yaml
helm template synapse deploy/helm/synapse -f deploy/helm/synapse/values-dev.yaml --kube-version 1.29.0
```

Its image digests are the all-zero placeholders from `values.yaml`: they satisfy the schema and will not pull. Pass real digests on install. Replica counts stay at the schema floor of two API and two web replicas even in development, because a single replica cannot prove the rollout path the chart is built around.

## Regional data-governance contract

A production Helm release is a **single-tenant regional cell**. The API explicitly sets `SYNAPSE_SINGLE_TENANT=true`; serve a tenant from exactly one governed cell, and use a separate release, datastore, Terraform state/backend, and region when a different residency boundary is required. The chart does not route tenant data between regions inside one cell.

Production modes (`externalNative` and `inClusterBroker`) must set `api.nodeSelector.topology.kubernetes.io/region` to the governed region containing the durable data plane. The migration Job automatically inherits that selector because schema changes operate on tenant-owned durable state. In `inClusterBroker`, the execution broker/worker selector must declare the **same** region; a mismatched or missing region fails Helm rendering.

Helm cannot query the physical region or encryption configuration of an external PostgreSQL or S3-compatible endpoint. Operators must therefore place those services in the same governed region and verify their at-rest encryption outside the chart. `deploy/aws/staging` is the reference implementation: it provisions the database, evidence bucket, control plane and native worker tier from one AWS provider region and binds RDS, S3, ECR and worker EBS storage to one rotating customer-managed KMS key. Its static tests fail when that contract is weakened.

The chart enforces the transport half of the boundary independently: production object-store traffic requires TLS, database DSNs use `sslmode=verify-full` with an operator-supplied CA, ingress uses a TLS Secret, and the native-worker grant authority is an internal TLS-terminating NLB.

Example production placement:

```yaml
api:
  nodeSelector:
    synapse.example/runtime: control-plane
    topology.kubernetes.io/region: us-east-1

egressBroker:
  nodeSelector:
    synapse.dev/execution-node: "true"
    topology.kubernetes.io/region: us-east-1
```

The second selector matters only for `inClusterBroker`. `externalNative` workers live outside Kubernetes; the supported AWS Terraform deployment keeps them in the same provider region instead.

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
(cd deploy/helm/synapse && sh testdata/data_governance_test.sh)
```

NetworkPolicy starts with namespace-wide default deny, allows ingress only from the configured ingress-controller namespace, permits DNS plus TLS/PostgreSQL egress, and grants HTTP/S recon egress only to the worker. Configure an FQDN-aware CNI or egress gateway with managed PostgreSQL/S3 and authorized-target allowlists before production use.

The disposable EKS rehearsal proved the chart's HA, migration, TLS, private-service, and fail-closed startup paths. Its standard managed-node runtime denied the nested unprivileged namespaces required by bubblewrap, so positive sandbox execution remains a deployment prerequisite: validate the target AMI/runtime and run a sandboxed worker job before relying on the chart for production workloads.

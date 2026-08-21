# ADR 0005 — Production Helm and EKS topology

**Status:** Accepted · **Date:** 2026-08-20 · **Deciders:** Issue #590

## Context

The Compose stack is explicitly a local-development profile. Production needs independently scalable
control-plane services, private durable data, TLS at the public edge, and an upgrade order that never
lets a workload use an unprepared database. The production sandbox is a Linux fail-closed boundary, not
a best-effort container setting. See [Deployment](../guide/deployment.md) and [ADR 0004](0004-cspm-helper-authorization.md).

## Decision

The production reference deployment is a Helm release on Amazon EKS:

- Run `synapse-api` as a Deployment with at least two replicas behind a TLS-terminating Ingress/load
  balancer. Use readiness probes to remove a replica from service; do not use a single API replica as
  the availability plan.
- Run `synapse-worker` as its own scalable Deployment. It shares the API's durable database and object
  store but is not co-located with the API tier.
- Use externally operated PostgreSQL and S3-compatible object storage. They are private dependencies,
  not Helm-managed StatefulSets; workload identities receive the minimum database and bucket access
  required.
- Set `SYNAPSE_DB_AUTO_MIGRATE=false`. A one-at-a-time Helm pre-install/pre-upgrade migration Job uses
  the owner migration identity. The release waits for that Job, and API and worker rollout is gated on
  its successful completion. A failed Job blocks the release rather than starting workloads on an
  unknown schema.
- Terminate and enforce TLS before public API traffic reaches the API Pods. Keep database, object-store,
  metrics, and worker endpoints off the public ingress.
- Schedule execution-capable Pods only onto approved Linux nodes that provide bubblewrap and the kernel
  features required by the configured sandbox. Enable `SYNAPSE_SANDBOX_ENABLED=true`, pin helper hashes,
  and preserve Synapse's startup refusal when those prerequisites are absent. A Pod that cannot provide
  the sandbox must not fall back to unsandboxed execution.

## Consequences

- Helm values and the platform runbook must model API and worker capacity separately, including a
  minimum of two ready APIs.
- Database migration credentials are isolated from runtime credentials, and migration failure is an
  explicit deployment failure.
- EKS node images, admission policy, and sandbox prerequisite checks become release dependencies.
- Backup, restore, and rollback follow [ADR 0007](0007-paired-backup-and-forward-only-upgrades.md), not
  a Helm database downgrade.

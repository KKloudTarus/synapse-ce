# External CI/CD integrations

[Documentation home](README.md) · [Configuration](configuration.md) · [Security model](security.md)

Synapse provides a tenant-scoped, provider-neutral framework for observing external CI/CD systems. The first adapter is Jenkins. The MVP is read-only, polling-based, and requires no Jenkins plugin.

## Jenkins workflow

1. Open **Settings → Integrations** and choose the Jenkins provider descriptor.
2. Enter a display name and an HTTPS Jenkins endpoint. Private-network access is off unless an administrator explicitly approves it.
3. Save a Jenkins username and API token. Credentials are write-only: the browser clears them after save and the API returns only `credential_configured`.
4. Run **Test connection**. Synapse refuses to enable an integration until a test operation succeeds.
5. Run **Discover**, select a classic job, Pipeline, folder job, or multibranch job, and bind it to a Synapse Project.
6. Enable the integration, then use **Poll now** or the optional worker scheduler.
7. Review operation history and normalized external runs. Exact commit matches link to one Project analysis; missing or ambiguous matches remain visibly unlinked.

Use Jenkins API tokens rather than passwords. Synapse performs authenticated GET requests only and never triggers builds or mutates Jenkins.

## Architecture

```text
HTTP API / Settings UI / leader-gated scheduler
                    |
           integrations.Service
                    |
       code-owned provider registry
          /          |          \
       test       discover      read runs
                    |
          Jenkins read-only adapter
                    |
     bounded SSRF-resistant HTTP client
```

The core model stores provider-neutral integrations, write-only credential references, Project bindings, durable operations, and normalized external runs. Provider slugs are validated opaque identifiers; adding another reviewed adapter does not change domain rules, persistence tables, or public API flow.

Operations and durable queue jobs are inserted atomically in PostgreSQL. At-least-once redelivery is safe because an operation has one durable identity, active operations are unique per integration, and external runs are upserted by tenant, integration, and provider key. Poll checkpoints advance only after successful materialization.

## Jenkins discovery and correlation

- Discovery recursively handles folders, organization folders, multibranch projects, Pipeline jobs, and classic jobs.
- Job paths are canonical relative Jenkins paths; returned cross-origin URLs are rejected.
- Polling reads the Jenkins queue and recent builds, normalizing queued, running, completed, success, failure, unstable, aborted, not-built, and unknown states.
- Revision extraction prefers `lastBuiltRevision`; a change-set fallback is accepted only when exactly one commit is present.
- Correlation requires the binding's Project and an exact commit. Zero matches produce `missing`; more than one produces `ambiguous`; Synapse never guesses.

## Operations

Manual test, discovery, and poll actions use the same durable worker path as scheduled polling. An operation may be `queued`, `running`, `succeeded`, `partial`, `failed`, or `cancelled`. Provider failures preserve the previous pipeline and run projections; the UI reports stale or error health from operation history.

Scheduled polling is off by default. To enable it, configure PostgreSQL workers with:

```bash
SYNAPSE_LEADER_ENABLED=true
SYNAPSE_INTEGRATION_SCHEDULER_ENABLED=true
SYNAPSE_INTEGRATION_SCHEDULER_POLL=1m
SYNAPSE_INTEGRATION_SCHEDULER_DISPATCH_LIMIT=10
SYNAPSE_INTEGRATION_SCHEDULER_MAX_QUEUE_DEPTH=100
```

The worker refuses to start when the integration scheduler is enabled without leader election. Dispatch also stops at the configured aggregate queue depth.

When metrics are enabled on the worker, `synapse_integration_operations_total` exposes only `provider`, `operation`, and `outcome` labels. Tenant IDs, endpoints, pipeline names, job names, revisions, and credentials are never metric labels.

## Security boundaries

- Integration reads require view permission; configuration, credentials, operations, lifecycle changes, and bindings require administer permission.
- Every integration table carries `tenant_id`, uses forced PostgreSQL row-level security, and is accessed through tenant-bound contexts or transactions.
- Credential bundles use AES-256-GCM with additional authenticated data bound to tenant, integration, and credential identity.
- Secrets never enter durable job payloads, provider errors, audit metadata, logs, metrics, API responses, or stored browser state after save.
- Endpoints require HTTPS and reject userinfo, queries, fragments, redirects, cross-origin provider URLs, and invalid TLS.
- The connector resolves and validates addresses on every dial. Loopback, link-local, metadata, multicast, unspecified, and private destinations are blocked unless private-network access is explicitly enabled; dangerous special-use ranges remain blocked.
- Responses, discovery depth, discovered pipeline count, builds per pipeline, operation errors, and persisted JSON are bounded.

Custom CA bundles and insecure TLS are intentionally unsupported in this MVP. Add verified custom trust bundles only when deployment evidence requires them; never add a certificate-verification bypass.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Enable is unavailable | A successful connection test must exist for the current integration. |
| Authentication failed | Replace the username/API token; Jenkins API-token requests do not need a crumb for these GET-only calls. |
| Endpoint rejected | Use HTTPS without userinfo, query, or fragment; explicitly approve private-network access only for an internal Jenkins origin. |
| No pipelines | Confirm the credential can read the relevant folders/jobs, then run discovery again. |
| Runs stay unlinked | Confirm Jenkins reports the exact source commit and the bound Project has exactly one matching analysis. |
| Scheduler does not start | Enable `SYNAPSE_LEADER_ENABLED` and verify PostgreSQL migrations/RLS readiness. |
| Health is stale | Inspect the latest poll operation, worker queue depth, and provider availability; last-known-good runs remain available. |

## Optional Jenkins LTS harness

`deploy/jenkins-integration` starts PostgreSQL, the migrator, `synapse-api`, `synapse-worker`, and an authenticated HTTPS Jenkins `2.568.2-lts-jdk21` container without installing plugins. The smoke creates a Project and integration through the public API, stores the write-only API token, executes durable test/discover/poll jobs through the worker, binds the core freestyle job, and proves exact-commit correlation against a PostgreSQL Project analysis:

```bash
./deploy/jenkins-integration/smoke.sh
```

Set `KEEP_JENKINS=1` to leave the fixture running on `http://localhost:18080` for manual Synapse API/UI testing. The fixture password and generated token are test-only and must never be reused outside this local harness.

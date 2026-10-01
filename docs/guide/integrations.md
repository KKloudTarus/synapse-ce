# External CI/CD integrations

[Documentation home](README.md) · [Configuration](configuration.md) · [Security model](security.md)

Synapse provides a tenant-scoped, provider-neutral framework for observing external CI/CD systems. Jenkins and Azure Pipelines are read-only polling adapters sharing the same tenant-scoped integration and credential framework. Neither needs an agent plugin.

## Jenkins workflow

1. Open **Settings → Integrations**, select **Manage CI/CD** in the CI/CD group (`/settings/integrations/ci`), and choose the Jenkins provider descriptor.
2. Enter a display name and an HTTPS Jenkins endpoint. Private-network access is off unless both a tenant administrator requests it and an operator enables `SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK=true`. The operator can also limit which hosts integrations may use with `SYNAPSE_INTEGRATION_HOST_ALLOWLIST`, and which private ranges with `SYNAPSE_INTEGRATION_PRIVATE_CIDRS`; an endpoint outside them is refused when it is saved and again before every connection.
3. Save a Jenkins username and API token. Credentials are write-only: the browser clears them after save and the API returns only `credential_configured`.
4. Run **Test connection**. Synapse refuses to enable an integration until a test operation succeeds.
5. Run **Discover**, select a classic job, Pipeline, folder job, or multibranch job, and bind it to a Synapse Project.
6. Enable the integration, then use **Poll now** or the optional worker scheduler.
7. Review operation history and normalized external runs. Exact commit matches link to one Project analysis; missing or ambiguous matches remain visibly unlinked.

Use Jenkins API tokens rather than passwords. Synapse performs authenticated GET requests only and never triggers builds or mutates Jenkins.

## Azure Pipelines workflow

Choose **Azure Pipelines** in Settings → Integrations. The HTTPS endpoint must name exactly one cloud organization and project, for example https://dev.azure.com/example/My%20Project. Configure a PAT with the **Build: Read** scope only. After a successful connection test, discover build definitions and bind a numeric definition ID to an existing Synapse Project. Enable the integration and poll manually or with the leader-only scheduler.

The adapter uses authenticated GET requests to Azure DevOps Build REST API v7.1, bounded pagination, the shared SSRF-safe client and the operation request/response budget. It synthesizes console links from the trusted endpoint and numeric IDs, not from returned URL fields. Build IDs remain stable across queued, running and completed transitions; `partiallySucceeded` maps to unstable and `canceled` to aborted. Each poll materializes at most the newest 200 runs for a bound definition; deeper history is deliberately left unread instead of turning a long-lived pipeline into a permanent polling failure. Recent rows are re-read so queued and running builds can advance to completed. This adapter never starts, cancels or modifies builds.

## GitHub inbound webhook workflow

GitHub is an inbound-only provider in this workstream. Create a `github` integration, then bind it to exactly one existing Git-backed Project. The single-binding rule is deliberate: webhook payload repository URLs are never trusted for routing, so the authenticated integration must resolve to one server-owned Project unambiguously.

With `SYNAPSE_INBOUND_WEBHOOKS_ENABLED=true`, an administrator calls `POST /api/v1/integrations/{id}/inbound-webhook` with the webhook `secret` in the JSON request body. Use that same secret in GitHub. Synapse seals it immediately and never returns plaintext credential material; the response contains only the opaque relative hook path plus version/rotation metadata. Calling the route again with a new secret rotates the sealed credential while keeping the path. Provisioning is allowed while the integration is disabled, so configure GitHub first, then enable the integration when the hook is ready to receive deliveries. Configure GitHub to send `push` and `pull_request` events to the public Synapse origin plus that path.

Synapse verifies `X-Hub-Signature-256` over the exact raw body and durably deduplicates `X-GitHub-Delivery`. Pushes scan the delivered commit. Pull requests scan on `opened`, `reopened`, `synchronize`, and `ready_for_review`; other actions are acknowledged without scheduling work. The repository URL always comes from the bound Project's persisted source binding, never from the GitHub payload, and acquisition pins the exact webhook commit SHA.

Fork pull requests are treated as untrusted source. Synapse does not resolve or present a source-control connector credential for their clone/fetch path and disables Maven, Gradle, npm, manifest-resolver, and Go dependency-graph command execution. Static source analysis and SBOM inspection continue without executing repository-controlled build/dependency commands.

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
          Jenkins / Azure read-only adapters
                    |
     bounded SSRF-resistant HTTP client
```

The core model stores provider-neutral integrations, write-only credential references, Project bindings, durable operations, and normalized external runs. Provider slugs are validated opaque identifiers; adding another reviewed adapter does not change domain rules, persistence tables, or public API flow.

Operations and durable queue jobs are inserted atomically in PostgreSQL. At-least-once redelivery is safe because an operation has one durable identity, active operations are unique per integration, and external runs are upserted by tenant, integration, and provider key. Poll checkpoints advance only after successful materialization.

## Jenkins discovery and correlation

- Discovery recursively handles folders, organization folders, multibranch projects, Pipeline jobs, and classic jobs.
- Job paths are canonical relative Jenkins paths; returned cross-origin URLs are rejected.
- Jenkins must report its externally reachable URL with the same HTTPS origin and base path configured in Synapse. Explicit default port `:443` is treated as the same origin; reverse proxies that rewrite the origin or base path must set Jenkins' public URL accordingly.
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

The worker refuses to start when the integration scheduler is enabled without leader election. Dispatch also stops at the configured aggregate queue depth. The scheduler considers only registered providers advertising `read_runs` before sorting and limiting due integrations; write-only providers cannot consume dispatch slots or starve Jenkins polls. Other provider capabilities, including manual tests and discovery, remain independently gated by their descriptors.

When metrics are enabled on the worker, `synapse_integration_operations_total` exposes only `provider`, `operation`, and `outcome` labels. Tenant IDs, endpoints, pipeline names, job names, revisions, and credentials are never metric labels.

## Security boundaries

- Integration reads require view permission. Enabling, disabling and archiving an integration, starting and cancelling operations, and editing bindings require `manage_integrations`, held by `admin` and `integration_admin`. Creating an integration, changing its endpoint or private-network setting, and replacing or deleting its credential require `administer`, which only `admin` holds. Machine roles hold neither.
- Every integration audit entry records the actor and the endpoint masked to `scheme://host`; an update also records `destination_changed` and, on a host change, the previous masked endpoint. The endpoint path is never written to the audit log.
- Every integration table carries `tenant_id`, uses forced PostgreSQL row-level security, and is accessed through tenant-bound contexts or transactions.
- Credential bundles use AES-256-GCM with additional authenticated data bound to tenant, integration, and credential identity.
- Secrets never enter durable job payloads, provider errors, audit metadata, logs, metrics, API responses, or stored browser state after save.
- Endpoints require HTTPS and reject userinfo, queries, fragments, redirects, cross-origin provider URLs, and invalid TLS.
- The connector resolves and validates addresses on every dial. Loopback, link-local, metadata, multicast, unspecified, carrier-grade NAT, IPv6 6to4 (`2002::/16`), and the well-known NAT64 prefix (`64:ff9b::/96`) are always blocked. Private destinations additionally require both the operator gate and the per-integration exception.
- Responses, discovery depth, discovered pipeline count, builds per pipeline, operation errors, and persisted JSON are bounded.

Private-network access is a deployment-level SSRF exception. Keep the operator gate off unless the deployment has an approved internal Jenkins origin and outbound network controls. Create/update audit entries record the normalized endpoint and whether this exception was requested; credential material is never audited.

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


### Bitbucket Cloud push and pull-request webhooks

The Bitbucket Cloud provider receives repository pushes and open pull-request creation/update events for **one existing Git Project per integration**. It does not discover pipelines or poll Bitbucket, so no polling token is needed. Bind your Git Project directly in the CI/CD integration settings, have an administrator save the webhook secret, configure the returned path and the same secret in Bitbucket Cloud, and enable the integration. Non-administrators can inspect bindings but cannot configure or rotate the secret.

Webhook scans pin the source SHA and use the Project's stored repository URL. Fork PR scans suppress Git credentials, build execution and forge writes. Fork commits that cannot be fetched anonymously from the stored origin fail closed. See [Bitbucket Cloud webhook configuration](configuration.md#bitbucket-cloud-inbound-webhooks) for headers, events, rotation, replay behavior and deployment requirements.

Local console screenshots and validation limits are recorded in [the Bitbucket webhook review evidence](bitbucket-webhook-evidence.md).

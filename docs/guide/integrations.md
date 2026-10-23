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

## Document publishing connections

The Documentation group in **Settings → Integrations** lists only providers that
advertise the `documents` capability. It uses the same tenant-scoped integration
records, sealed write-only credentials, endpoint validation, permissions, audit
trail, and PostgreSQL row-level security as the other integration groups. See
[Governed document publishing](document-publishing.md) for release and
unpublish APIs.

- `google-drive` accepts only `https://www.googleapis.com` and a dedicated
  service-owned My Drive parent folder. The configured group permission and owner
  are proved before sensitive writes; shared drives are refused.
- `sharepoint` and `onedrive` use the configured HTTPS SharePoint site origin as
  the authority for a restricted Business folder. They require separate sealed
  Microsoft Graph and SharePoint REST tokens, an exact reader group, and a service
  custodian principal with the required SharePoint role proof.
- `s3-compatible` uses the HTTPS S3 API origin of an AWS or self-hosted bucket. It
  requires versioning and a bucket policy that grants read to exactly the
  configured principal for the publication prefix; a public grant is a lost
  restriction and an unreadable policy refuses the release.
- `confluence-cloud` and `confluence-dc` retain their existing restricted-space
  profiles.

Document releases are durable, idempotent commands. The worker rechecks current
tenant authority, destination configuration, release policy, legal hold, sharing
proof, and credential/destination revisions before each outward write. Provider
opaque revision tokens are compared exactly for Drive, SharePoint/OneDrive, and
S3-compatible buckets, which fence on the object version; reconciliation does not
infer a changed body from a numeric version or a 404.
Command leases and intent/progress revisions fence stale workers and concurrent
republish or unpublish operations.
Contract tests cover the profile boundaries. Selected personal Drive lifecycle cases
have native evidence; Microsoft and broader failure acceptance remain open in the
[acceptance ledger](../evidence/remaining-providers/live/README.md).

## Ticket provider connections

The Ticketing group in **Settings → Integrations** opens **Manage tickets** at
`/settings/integrations/tickets`. It lists only connections with the `tickets`
capability and provides loading, empty, provider-error, and permission-denied states.
Tenant administrators and integration administrators can inspect ticket connections;
tenant administrators create or change destination mappings. The mapping form discovers
metadata through `GET /api/v1/integrations/{integrationID}/ticket-metadata` and only
offers the provider's returned destinations, issue type, and visibility policy.

Add the outbound providers from **Manage connections and credentials**:

- `github-issues` requires an HTTPS forge host and an `owner/repository` value. It
  reuses the tenant's SCM connector for that exact forge host; do not enter a second
  token. Only private repositories with Issues enabled and sufficient repository access
  can receive a finding ticket.
- `gitlab-issues` requires an HTTPS forge host and a project path, including nested
  namespaces. It also reuses the host's tenant SCM connector and creates confidential
  issues only.
- `azure-boards` requires a `https://dev.azure.com/{organization}/{project}` endpoint,
  a work-item type, and a sealed PAT.
- `servicenow` requires a SaaS instance endpoint, an `incident` or
  `sn_vul_vulnerable_item` table, and a sealed API token.
- `linear` requires `https://api.linear.app/graphql`, a team ID, and a sealed API token.

Azure Boards renders the canonical message subset as safe HTML while building the
preview's native JSON Patch. Paragraphs, line breaks, lists, emphasis and code are
preserved; body-supplied HTML and links remain literal, with explicit URL forms
defanged. Only separately supplied, validated HTTPS links become anchors. The
rendered wire is frozen with the preview and is not rendered again during dispatch.
This uses the existing email fragment renderer; email's layout and severity stay
unchanged. Native Azure rendering acceptance still requires an authorized sandbox.

ServiceNow identifies its authenticated principal through the standard Table API:
`GET /api/now/table/sys_user` with the fixed query
`sys_id=javascript:gs.getUserID()`, fields `sys_id`, and limit `2`. Exactly one
32-character user ID is required. An empty, ambiguous, or malformed result fails
closed; a username or display name is never substituted.

Provision ServiceNow credentials for GET collection/record and POST collection on
the selected ticket table, plus GET collection on `sys_user` for the authenticated
user's own identity. The query is not an authorization boundary: enforce own-row
read access independently with a Deny-Unless ACL for the dedicated machine user,
preserving other callers' existing access. Do not grant user-directory writes.

For OAuth, enable **Enforce Token Restrictions**, use a client-specific
authentication profile and table- and method-specific API access policies, and
preserve the endpoint's existing authentication profiles. A policy profile alone
does not deny unlinked endpoints. On instances with Machine Identity Access
Control, link the web-service-only machine user to exactly those policies and
tables; leave child tables and SOAP disabled. Verify explicit authorization denials
for other tables, resources and write methods with the actual token. An empty
200 response is not proof of endpoint isolation. Do not change shared scope mappings
or other clients to make this connection work. The tested personal instance uses
client-specific Broadly scoped OAuth together with this machine boundary; never
use Broadly scoped alone as proof of restricted access. Client Credentials also
requires ServiceNow's documented instance property, not a Synapse environment variable.

Field ACLs must permit every approved payload field during insert. ServiceNow can
silently omit fields that lack write permission. The personal incident sandbox
needed a parallel `incident.description` write Allow-If ACL with
`UserIsAuthenticated` and a script requiring the exact machine user ID and
`current.isNewRecord()`. It has no required roles and preserves the existing
same-target ACL's Admin overrides value; existing native ACLs remain unchanged.
Verify full description, summary and correlation readback after creating a
synthetic record. Descriptions render the message subset as plain text: punctuation
and literal hostile markup are preserved without Markdown backslashes, while
server-built links remain separate. Keep existing-record update/delete methods denied; do not grant
`itil`, `sn_incident_write` or admin merely to satisfy field access. This sandbox
configuration proves the incident profile only; a vulnerability table needs its
own policy, field-permission and native acceptance checks.

GitHub's inbound `github` provider remains separate: it receives webhooks for source
scanning and is not an outbound Issues connection. GitLab's inbound identity is also
not reused as an outbound ticket provider. SCM credentials are tenant/host scoped and
remain the only credential source for GitHub Issues and GitLab Issues. Azure Boards,
ServiceNow, and Linear keep their supplied credential sealed and write-only.

Every ticket is built from a required preview. For native providers, the exact vendor
wire request is frozen with the preview digest, then Submit adds the durable correlation
marker. An uncertain create is reconciled before a retry. Native mappings intentionally
do not expose grouping, transitions, labels, priority maps, components, or custom Jira
fields because those controls are unsupported by these serializers. Their native privacy
policy has no waiver path.

Ticket status polling and recovery create reviewable proposals only; they do not mutate
finding triage or status automatically.

Inbound ticket polling claims due targets atomically by tenant and reserves their
next poll before provider I/O. A successful target has a one-minute minimum
interval; unavailable targets wait five minutes. A 429 waits at least five minutes
and never shortens a longer provider `Retry-After`, including a refusal during
integration-identity lookup. Other targets on the same integration are skipped
for that pass after a throttle. Deadlines survive restarts and stale completions
cannot shorten a newer claim or delay. This is per-target scheduling, not an
integration-wide quota limiter: previously unclaimed targets can still issue a
request on a later pass. Size the target set against the provider's quota, allowing
for privacy/access preflights, identity reads, discovery and outward writes.
A GitHub target normally requires both a repository preflight and the issue read.

Apply the provider retry-scheduling migration before upgrading APIs and workers,
and upgrade every worker before relying on the interval or throttle guarantees.
Older binaries do not observe the new due columns. Disable affected integrations
and drain workers before rollback; the migration refuses to remove future poll
claims or provider-directed deferrals. Prefer a forward repair when a delay is
still active.

Connection credentials, URLs with query data,
and provider response bodies are not retained in ticket audit records. Selected
personal ticket sandbox cases have [native evidence](../evidence/remaining-providers/live/README.md);
remaining acceptance is listed separately and is not represented as passed.

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

# Jira ticketing

Jira uses the shared integration registry and credential vault. Cloud connections
use an email and API token; Data Center connections use a personal access token.
Data Center destinations require an explicit operator host allowlist. Outbound
connections enforce the address policy at dial time and refuse redirects.

When Data Center requires a Reporter without a default, discovery resolves the
authenticated Jira user. That reporter is visible in preview and sealed in the
submitted payload; mappings cannot assign a different reporter. An unavailable
identity or any other unsupported required field blocks preview and creation.

Manual HTTPS ticket links do not require a provider and are never fetched. Ticket
mappings belong to one tenant and one project or engagement. A mapping selects
discovered Jira project, issue type, fields, priority and issue security level.
Ticket actions operate on canonical Findings. Project mapping CRUD does not add
Jira actions to Code Quality Issues; that consumer requires a separate identity
and adoption contract. An assessment's visible Project association cannot authorize
a Project mapping.
Creating a vulnerability ticket without a security level requires an administrator's
audited waiver. Changing the destination invalidates credentials and disables the
integration; submitted commands cannot silently move to a different Jira site.

Preview filters the finding using the effective data class, redacts sensitive text,
and renders built-in English or Vietnamese templates or mapping-specific templates.
It requires `SYNAPSE_PUBLIC_BASE_URL` to identify the trusted HTTPS console for
finding deep links. Manual ticket links do not require this setting.
Submission checks the preview digest and persists the final provider payload before
any outbound create. The correlation label is generated from the durable intent ID.
The worker uses that snapshot, not a later version of the finding or mapping.

The durable intent is the work source. A compare-and-swap lease permits one local
claim. The outbound request deadline is shorter than the lease. A valid provider
acknowledgment creates the link and completes the intent atomically. A timeout,
ambiguous response, crash or expired lease becomes `uncertain`; it never authorizes
another automatic POST. Breakers and rate-limit eligibility survive process restart.
Definite 400/401/403/404 failures open the destination tuple until an audited
administrator recovery. A 429 cooldown cannot be reset before `Retry-After` expires.

To identify the blocked destination, use the failed intent's immutable snapshot.
The current mapping may already point somewhere else. An authorized operator can
run this read-only query with the normal tenant-scoped database role, substituting
the authorized tenant and the intent ID returned by
`GET /api/v1/engagements/{id}/findings/{fid}/tickets` (`intents[].id`):

```sql
BEGIN READ ONLY;
SELECT set_config('app.current_tenant', 'authorized-tenant-id', true);
SELECT i.id, i.integration_id,
       i.payload_snapshot #>> '{fields,project,key}' AS project_key,
       i.payload_snapshot #>> '{fields,issuetype,id}' AS issue_type,
       b.breaker_code, b.gate_until
FROM ticket_intents AS i
LEFT JOIN ticket_dispatch_breakers AS b
  ON b.tenant_id = i.tenant_id AND b.integration_id = i.integration_id
 AND b.project_key = i.payload_snapshot #>> '{fields,project,key}'
 AND b.issue_type = i.payload_snapshot #>> '{fields,issuetype,id}'
WHERE i.tenant_id = current_setting('app.current_tenant')
  AND i.id = 'intent-id';
ROLLBACK;
```

`issue_type` is the Jira issue type ID, such as `10001`, not its display name
such as `Bug`. If the snapshot target is missing, stop and investigate the retained
intent; do not substitute the current mapping. The query returns only destination
and gate fields, without exposing the stored payload or credentials.

After repairing the credential or other 400/401/403/404 cause, a human administrator can send
`POST /api/v1/integrations/{integrationID}/jira-breaker/reset` with
`{"project_key":"SEC","issue_type":"10001"}` using the original destination
tuple. This audited operation clears its gate without retrying a failed command,
changing an approved snapshot or releasing an active lease. It also works when a
replacement is already pending or the failed command's finding no longer exists.
The next worker poll revalidates pending commands before sending them; commands
approved before a credential or mapping change still require a fresh preview and
replacement. An active 429 cooldown returns 409 and remains enforced.
Resetting an existing, already-clear tuple still records a `ticket.breaker.reset`
audit entry and returns 204; it does not retry a command. A valid tuple that has never
been recorded returns 404 without a reset audit entry. Each successful explicit
reset is audited, including repeated requests; an active dispatch lease is kept.

Bulk submission returns one result per finding. A policy or permission refusal
uses `error_code: permission_denied`, rather than `unavailable`. Other stable
per-item codes are `validation`, `not_found`, `conflict` and `unavailable`; raw
provider and policy error text is not returned. HTTP 202 means the batch was
processed, not that every item was accepted. Repair the refused condition and
prepare a fresh preview before resubmitting; route-level permission denial remains
HTTP 403.

Reconciliation searches the original destination for the exact correlation label.
One verified match completes the intent; multiple matches require human review.
Zero matches remain uncertain because Jira search is eventually consistent. An
explicit human retry must acknowledge that the original request may still complete
and create a duplicate. Search errors and incomplete pages never count as absence.
After changing a mapping, policy or credentials, prepare and approve a new preview
before submitting a replacement command. Retained commands preserve the originally
approved authority revisions and payload.

Use a maintenance window for the source-job migration and drain requests and all
database clients, including API, worker, MCP, and scanner processes, before running
`synapse-migrate`. Migration `0260` changes `scan_jobs` under an access-exclusive
lock. Migration `0251` has no deployment-time ticket-intent backfill: the runtime
uses a tenant-scoped, forced-RLS keyset cursor to catch up durable completed creates
in bounded batches, while a trigger captures later eligible writes. Start matching
API and workers only after migration completes and readiness checks pass.

Deploy migrations before API and worker. Disable Jira integrations before application
rollback and retain intent, snapshot and breaker history. Memory persistence is for
development only. PostgreSQL is required for durable production recovery.

Do not mix old and new Jira consumers when deploying separate durable status
comments. Disable the affected Jira integrations, let in-flight provider calls
finish, then stop every old Jira worker before starting the new planner or worker.
Deploy the new API and workers together, verify their versions, and re-enable only
the canary connection first. New workers retain support for legacy bundled
transition snapshots; old workers cannot execute the new transition-only snapshots
or dedicated comment intents.

Before rollback, disable the affected integrations, drain in-flight calls and stop
the new workers. Keep Jira disabled on the older binary. Retain all new snapshots,
intents and audit records for recovery with a compatible forward version; do not
rewrite them into legacy commands or replay uncertain writes. An old binary is
not a recovery executor for these records.

The deployment operator should first enable only a dedicated test connection and
test engagement. Create one English and one Vietnamese finding ticket on each
supported Jira deployment, inspect the resulting fields and correlation label,
and follow each console link back to its finding. Observe two worker polling
cycles after completion and confirm that no second ticket appears. Stop the canary
and disable the connection on any wrong destination, exposed secret, duplicate,
unexpected `uncertain` result or failed atomic link. Keep the intent and audit
history for reconciliation; restarting the worker does not authorize another POST.

Before widening the canary, the operator must choose a backlog-age threshold from
the deployment's expected volume and Jira quota and assign an alert owner. Poll
failures produce `ticket tenant polling failed` or `ticket intent polling failed`
warnings. Use the tenant-scoped intent records to distinguish waiting work from
expired claims; no records or logs is not proof that the worker is running. The
following read-only query reports counts and oldest work without exposing payloads.
Run it under the normal RLS-enabled database role with the authorized tenant ID:

```sql
BEGIN READ ONLY;
SELECT set_config('app.current_tenant', 'authorized-tenant-id', true);
SELECT state, count(*) AS intents, min(updated_at) AS oldest_update,
       count(*) FILTER (WHERE state = 'in_flight' AND lease_until <= now()) AS expired_claims
FROM ticket_intents
WHERE state IN ('pending', 'in_flight', 'uncertain', 'failed')
GROUP BY state;
ROLLBACK;
```

An expired claim that persists while the worker is healthy warrants investigation;
the next eligible poll should move it to `uncertain`. Resolve the cause of a
growing backlog or polling failure before resuming rollout. Production backup
restore, recovery targets and quota headroom must be checked for that deployment;
the local crash and lease tests do not establish those operational targets.

Contract references: [Jira Cloud issues](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/),
[Cloud search consistency](https://developer.atlassian.com/cloud/jira/platform/search-and-reconcile/),
and [Data Center REST examples](https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples/).

## Automatic creation policy

Automatic creation requires PostgreSQL and enabled notification event producers
(`SYNAPSE_NOTIFICATIONS_ENABLED=true`). It is off on new and existing mappings. A tenant administrator can
opt in and select the minimum severity in Jira settings. The policy applies only to
confirmed findings; unconfirmed observations and external imports cannot authorize
an automatic ticket. Manual preview and submit remain available under their existing
permissions. The worker rechecks current confirmation, severity, mapping policy,
destination security and privacy settings before dispatching a queued command.

Policy admission consumes stored `finding.status_changed` business events with durable
consumer progress; a worker restart must not lose or duplicate a logical command.
Changing or disabling a policy invalidates stale queued automatic work. Historical
status events preceding opt-in do not trigger a backfill. Automatic creation is once per
finding and mapping: later confirmation events retain its linked ticket or the
initial command, including an uncertain or refused command that requires explicit
operator recovery. Existing links on that integration suppress automatic creation;
use a reviewed manual preview when a different destination is intended. Initial
command discovery reads at most 200 recent intents; if a full page cannot establish
absence, admission defers rather than risking another ticket.

## Vulnerability grouping

The default remains one ticket per finding. Project mappings at `detail` class can
select one ticket per vulnerability and project. Group identity includes the tenant,
mapping, Project and authoritative vulnerability identity. Missing vulnerability
identity never merges unrelated findings. The asset table uses stored attribution;
free-text descriptions do not establish an asset relationship.

A pending or uncertain initial write reserves its group, so another request cannot
create a second remote ticket while the first outcome is unresolved. Later members
and rescans update the same remote issue. Lowering the effective destination class
blocks grouped content until the privacy configuration permits detail again.

## Project source scans and Jira

An operator can run a vulnerabilities-only scan for one relative subdirectory of a
local Project binding with `POST /api/v1/projects/{key}/source-scans`. The server
selects the Project root and internal scan context; do not send a filesystem root,
an engagement ID, or an absolute/traversal path. This scan does not replace the
Project quality-analysis status or baseline.

Use `/api/v1/projects/{key}/source-findings` to review and triage the resulting
findings. The scoped ticket preview and submit routes under each finding use the
same permissions, preview digest, destination checks, restricted-sharing checks,
and durable intent rules as engagement tickets. For a Project vulnerability mapping,
the rendered Jira link points to the Project source-finding view, so the hidden scan
context is never exposed in the ticket body or API response.

## Outbound status transitions

Administrators can configure transition IDs for `remediated`, `accepted`,
`false_positive` and `reopen`. Empty configuration disables status sync. Discover
IDs on an existing Jira issue in each relevant workflow state; a transition can be
available from one state and absent from another. The worker records a durable
command for the existing ticket, sends the transition and explanatory comment
first, then updates fields. An uncertain transition is retained for recovery.
Accepted risk comes from the effective SLA lifecycle; an expired acceptance is open.
For a grouped ticket, any active member keeps the ticket open.

## Signed inbound observations

With PostgreSQL, the vault master key and `SYNAPSE_INBOUND_WEBHOOKS_ENABLED=true`,
a tenant administrator can configure or rotate a webhook in **Settings → Jira**.
Enter the same randomly generated 32–128 byte secret in Synapse and Jira. Synapse
returns an opaque relative hook path once; append it to the public Synapse origin.
Keep the secret and path out of logs and screenshots. Rotation retains the path
and permits the previous key for two hours. Disabling the integration stops hook
admission and outbound work.

Cloud is supported. Data Center currently requires version 11.3 or newer; older
and unknown versions are refused rather than accepting unsigned delivery. This is
the supported minimum for this adapter, not the first Jira release with webhook
secrets. Configure HMAC-SHA256 on the exact body through `X-Hub-Signature`, and
preserve `X-Atlassian-Webhook-Identifier` on retries. Subscribe to issue updates
and comment creation/updates. Delivery identifiers and signed body digests are
deduplicated for two hours, together with all local effects in one transaction.
Cloud requires its delivery identifier. For Data Center deliveries without that
header, the authenticated body digest is the receipt identity; malformed supplied
headers are rejected.

The WS10 hook route requires a query-free request. Native Jira Cloud deliveries
can append the informational `triggeredByUser` query parameter. When using an
ingress proxy, match only the configured opaque hook path and forward that path
without its query; preserve the body, signature and delivery identifier unchanged.
Do not forward other application routes through a webhook-only ingress.

The finding's ticket panel shows external status, retest proposals and external
comments. A transition into `fields.status.statusCategory.key == "done"` can
request a retest at most once per finding in a rolling hour. Resolution is context,
never the trigger. The authenticated integration principal suppresses its own
status writes. A later human comment does not become evidence that the human
closed the issue. Comments are redacted literal text, capped at 16 KiB, and never
passed through the mention or triage parser. A reviewer records the retest through
the existing finding workflow; Jira never changes finding security state.

Polling reads current linked issues through the same reducer. It requests recent
status history with the issue and attributes a status author only when the history
proves that transition. Missing or truncated history leaves a retest decision
pending until trustworthy attribution is available; a missed webhook plus missing
history can therefore delay a proposal. The current external status remains
visible. A Jira 404 means deleted **or unreadable**, not remediated. Once a
provider timestamp is known, equal or older readable replays cannot clear that
flag; a strictly newer timestamp is required. If no provider timestamp was ever
known, the first timestamped readable observation establishes that baseline.

Contract references: [Cloud signed webhooks](https://developer.atlassian.com/cloud/jira/software/webhooks/),
[Data Center webhook administration](https://confluence.atlassian.com/adminjiraserver/managing-webhooks-938846912.html),
and [Cloud issue history](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/).

Project source findings use bounded ID-keyset pages (50 by default, at most 100).
The console resolves a finding deep link through its scoped single-finding route,
so selection does not depend on which page is visible. Source-job diagnostics and
errors retain the internal execution context on the server.

For observed asset rows, enable the existing `SYNAPSE_FLEET_ASSETS_ENABLED` flag
on both the API and SCA worker. Both use the same canonical asset store and
producer attribution recorder; each source target replaces only its own observed
bindings. A source scan does not create a full quality analysis or replace its
latest-analysis status. Deploy migration 0260 with the migration credential
before deploying the matching API and worker.

Project source scans use the existing `sca` queue kind. Stop and drain old SCA
consumers before enabling source-scan admission; do not run mixed versions against
this queue. Older binaries ignore the server-owned selection and purpose fields,
so they cannot preserve the confined snapshot or current-binding checks. Apply
migration 0260 first, then deploy the matching API and workers, and only then admit
source scans.

For rollback, stop source-scan admission first. Drain source jobs with compatible
workers or retain them until compatible workers are restored. Keep migration 0260
and the immutable purpose values while any source records or queued jobs remain;
do not down-migrate, relabel, or hand those jobs to older workers.

Jira Data Center 11.3 administrative webhook registration uses
`/rest/jira-webhook/1.0/webhooks` with the signing secret in
`configuration.SECRET`. A top-level `secret` field is not this native contract.
Keep the secret in private administration state and verify a real signed delivery
before considering registration complete. Data Center callbacks can use the root
`event` field; Cloud uses `webhookEvent`. Conflicting event fields are refused.

## Refused status updates and historical catch-up

A definite refusal of a transition, comment or field refresh remains attached to
that durable intent. A per-ticket HTTP 400/404 does not pause unrelated creates or
status work. Credential HTTP 401/403 still fence the shared destination, and a
rejected Create 400/404 still diagnoses the mapping. The planner adopts retained
status commands before preview discovery, so a refused field update remains quiet.
After fixing the provider edit screen or destination configuration, an administrator
can use the existing version-fenced intent retry with an acknowledgement and reason.
It retries the failed update; it does not repeat its completed transition or comment.

Migration 0251 defers discovery of historical intents to the tenant worker. The
keyset cursor advances across eligible and ineligible rows and resumes after a
restart; the trigger captures newly eligible writes immediately. The current
worker admits ten raw historical rows per successful tick. At one tick every five
seconds, one million retained rows require at least about 5.8 days to discover;
two million require about 11.6 days. Tenant rotation and slow providers lengthen
that interval. This is a derived lower bound, not a benchmark or a recovery SLO.
The first batch can be polled immediately; the whole history is not blocked until
catch-up finishes. Check the tenant cursor's progress during rollout and rehearse
with representative retained-history volume before relying on a recovery window.

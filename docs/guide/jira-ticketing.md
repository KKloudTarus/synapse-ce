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

Reconciliation searches the original destination for the exact correlation label.
One verified match completes the intent; multiple matches require human review.
Zero matches remain uncertain because Jira search is eventually consistent. An
explicit human retry must acknowledge that the original request may still complete
and create a duplicate. Search errors and incomplete pages never count as absence.
After changing a mapping, policy or credentials, prepare and approve a new preview
before submitting a replacement command. Retained commands preserve the originally
approved authority revisions and payload.

Deploy migrations before API and worker. Disable Jira integrations before application
rollback and retain intent, snapshot and breaker history. Memory persistence is for
development only. PostgreSQL is required for durable production recovery.

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

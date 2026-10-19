# Historical acceptance snapshot — 17 October 2026

This retained snapshot predates the requested review corrections. Its Ready/Closes
and current-check claims are superseded by [the current ledger](README.md). Provider
captures describe only the observed run; they do not establish current reruns.

# Jira sync and report publishing acceptance

This is the current acceptance ledger for PR #1586. It is owned by
`pho-veteran`; it is not merged and must not be merged by this work. The refreshed
`origin/main` at `caa6b1ea` is integrated into the PR work. The implementation
reuses the shipped B04 and #1434 foundations and the
#1442 document foundation from PR #1577 (`8a6c785b`), rather than recreating them.

The original ledger was established before implementation against `8a6c785b`.
Its early captures remain useful only for the limited paths they actually recorded:
for example, a Cloud restriction refusal, Free-plan behavior, and earlier mail
delivery. They are superseded by the continuation results below wherever they
conflict. In particular, they do not prove current restricted publication, current
strict sharing, or the final visual review requirement.

## Current acceptance ledger

| Order | Issue | Verified continuation evidence | PR disposition |
| --- | --- | --- | --- |
| 1 | #1431 | Cloud Jira company-managed project `B7R` uses an issue-security level whose only member is a personal one-member group, plus a sole administrator role. `B7R-1` demonstrates Vietnamese auto-push and `B7R-2` English auto-push of confirmed high findings. Open/high and confirmed/low fixtures create zero tickets. The same ticket exercised false-positive → Done (`statusCategory.key == "done"`) → To Do (`new`) with three independent durable-comment intent markers and stable quiescence without a duplicate. | Closes; acceptance supported by the recorded evidence. |
| 2 | #1432 | A real bounded source run evolved private rooted source `a → b → a`, preserving the canonical advisory ID and existing-asset attribution. Cloud `B7R-3` and DC `SYNACC-6` each grouped two observed assets under security level 10000, then updated the same issue from English to Vietnamese. Removing the Log4j dependency from service `a` and submitting the normal review preview updated the same issues with only service `b`; no duplicate group was created. | Closes; acceptance supported by the recorded evidence. |
| 3 | #1433 | Cloud and DC exercised same-ticket lifecycle paths. Cloud `B7R-1` covered false-positive and reopen. DC covered `SYNACC-3` remediated → reopen, `SYNACC-4` false-positive → reopen, and genuine SCA accepted-risk on `SYNACC-5` to Done/Highest. Locale, priority, security, and deep links were inspected against live providers. | Closes; acceptance supported by the recorded evidence. |
| 4 | #1435 | Real signed Cloud callbacks created a proposal only. The fresh isolated Jira DC 11.3.12 rerun received seven valid native HMAC forwards at 18:39:28–18:40:36 UTC, before the official test license expired at 20:54:31. An independent reviewer marked restricted `SYNACC-1` Done; Synapse kept the finding confirmed with one pending proposal. Native comment create/edit produced exactly two distinct snapshots for one remote comment, and repeated To Do → Done kept one proposal. All native registrations/proxies/routes were closed. | Closes; fresh licensed provider proof and inspected screenshots support acceptance. |
| 5 | #1436 | Cloud polling and reconciliation contracts remain covered, including deleted/unreadable detection, watermark retention, fair request budgeting, drift repair, and tenant isolation. | Closes; acceptance supported by the recorded evidence. |
| 6 | #1443 | Fresh normal Create completed in one attempt on Cloud page `131374` and DC page `327686`, without manual ACL repair or resume. Exact group-only restrictions were verified before uploads. Republish produced version 3, then real weekly occurrences produced version 4 on each page. Unchanged content skipped. All distinct downloaded PDFs were rendered and inspected; the DC native viewer opened its attachment. Purge removed both fresh pages, history and every PDF, with authenticated 404 readback. | Closes; automatic Cloud and DC acceptance is complete. |
| 7 | #1444 | Admission and recovery recheck human `PermReview`, source/detail/legal-hold conditions, tenant fences, destination revisions, and receipt history. The Cloud publish was resumed from a neutral prepared page with the original actor and version-fenced audit record. Real Cloud and DC release/purge paths completed and were verified absent. A real legal hold was placed and read back, blocked valid publish and unpublish with 403, and was released; runtime flags were restored. Loading, empty, error, and read-only UI states were inspected. | Closes; acceptance supported by the recorded evidence. |
| 8 | #1445 | The Cloud weekly schedule ran at 21:15 Asia/Ho_Chi_Minh (14:15 UTC), reached Done with no failed or uncertain delivery, and was disabled by a versioned request. An unchanged-hash run skipped publication. A fresh 23:33 Asia/Ho_Chi_Minh weekly run delivered the final PDF to both verified personal recipients (Done, delivered 2, failed 0, uncertain 0), then was disabled. Gmail opened both PDF pages; Outlook received the attachment and its complete staged bytes match the source hash, although Outlook’s native preview service failed. | Closes; email receipt and PDF visual evidence are recorded, with the client preview limitation explicit. |

One theme is sufficient for acceptance. Provider mocks and UI fixtures do not
substitute for the live results above. The final visual gallery and manifest cover
73 inspected images, four unique PDFs, and all five rendered PDF pages; they are ready for
the PR's inline review material.

The new Documentation group reflects the actual durable PostgreSQL service wiring.
Confluence Cloud/DC cards, the shared External integrations editor, and configured,
empty, loading, error, and read-only states were inspected in Edge. The role guard
prevents non-administrators from seeing creation or credential fields even while
identity is loading. See [Documentation proof](documentation-discovery-proof.json).

## Environment and credential boundaries

- The real stack is the isolated `synapse-b07-runtime` Docker Compose project:
  API, worker, web, PostgreSQL, MinIO, Mailpit, and trusted local TLS. Provider
  acceptance uses real API/worker/web paths, not mocks.
- The local Data Center lab runs pinned Jira 11.3.12 and Confluence 10.2.17 with
  official three-hour, ten-user Atlassian test licenses. Fresh lab administrator
  credentials and personal access tokens remain private and are retained through
  the PR as directed.
- Personal no-card Confluence Standard, Atlassian Guard Standard, and Jira Standard
  trials are retained through acceptance under the user's instruction. Jira Standard
  was activated unexpectedly by a read-style “Try now” navigation; no card, billing,
  or school-organization resource was added or changed.
- The Gmail OAuth client and grant remain private until this PR merges, even after
  the earlier credential exposure. Do not revoke or delete them before merge. The
  organization policy read key is private/vault-only and has only policy-read scope
  through 2026-10-18.
- The temporary Cloud webhook tunnel exposed only the signed webhook route during
  the test. It is closed; no URL, path, HMAC material, or credential is recorded in
  this directory.

## Provider results and limits

### Jira Cloud and Data Center

Cloud restricted-sharing acceptance uses the dedicated `B7R` project rather than
the earlier unrestricted personal-lab fixtures. The effective current-user
permissions include browse, create, set issue security, add comments, transition,
and project administration; the level is actually selectable by the integration
actor. English and Vietnamese tickets were inspected after provider writes.

Data Center acceptance uses restricted `SYNACC` issues: `SYNACC-2` is an English
confirmed-high auto-push under security level 10000, and the negative fixtures
remain at zero. `SYNACC-3`, `SYNACC-4`, and `SYNACC-5` cover the Vietnamese lifecycle
paths listed in the ledger. Reviewer browser login succeeded without a reset; the
earlier 403 came from Jira's native Basic-auth filtering. These were performed
against the official local lab, not by direct database changes.

The new Project path uses canonical observed assets, not fabricated SQL rows. A
private bounded source changed from `a` to `b` and back to `a`; the resulting
Cloud `B7R-3` and DC `SYNACC-6` each represented the same two-asset group, retained
its canonical advisory identity, and were updated in place across English and
Vietnamese. A later normal review/preview/submit after removing the Log4j dependency
from service `a` reduced the group to service `b` without creating another ticket.
The public [continuation provider proof](continuation-provider-proof.json) records
only the whitelisted provider states and observed-asset rows used for this run.

The Cloud-origin test is complete and safely closed. The fresh isolated Jira DC
11.3.12 rerun created restricted `SYNACC-1` through the normal Synapse API and worker,
then used an independent reviewer to mark it Done, create/edit one comment and
repeat To Do → Done. Seven native HMAC forwards returned 202 between
18:39:28 and 18:40:36 UTC, before the official test license expired at 20:54:31.
Independent final readback found one pending proposal, the finding still confirmed,
and exactly two distinct comment bodies for one remote comment. The vendor license
was still active and valid at the final readback. After the screenshots, the fresh
integration was disabled with a version fence and the Jira application/TLS stopped;
its PostgreSQL data and private credentials remain preserved. See the
[fresh native proof](fresh-jira-native-provider-proof.json) and inspected screenshots.

The [earlier DC callback record](dc-webhook-provider-proof.json) occurred after the
old lab license expired and is retained as historical behavior only. It does not
establish licensed DC acceptance. Its pre-fix duplicate rows remain append-only.

### Confluence Cloud

The automatic continuation run supersedes the earlier Cloud fresh-create gap.
The adapter now uses the documented V2 permissions and restriction-state APIs,
with the provider's default self-lockout protection. A normal Create completed in
one attempt on page `131374`, with only the configured one-member group and no
manual ACL preparation or resume. Republish produced version 3 and the real weekly
23:59 Asia/Ho_Chi_Minh occurrence produced version 4. The unchanged-hash request
skipped; the versioned schedule was disabled. A normal purge completed in one
attempt, after which current page, trash, history and all three attachments returned
404. All distinct PDF bytes were downloaded, rendered and inspected before purge.
See the [automatic Cloud proof](automatic-cloud-provider-proof.json) and
[restriction design](restricted-publication-design.md).

The following earlier runs are retained for recovery and historical context under
their then-configured group; they do not establish the current integration revision.

The Cloud policy parser now accepts the actual heterogeneous policy list and
resource representation while failing closed for invalid resource types. Before
every upload, the adapter verifies both sharing operations: read and update must
contain no explicit users and only the configured group. It also requires the
published workspace public-link block that applies to the target site; the broader
organization default being allow does not satisfy the check.

The original Cloud page required assisted neutral preparation because Confluence's
fresh group-only restriction call evicts its own actor even when that actor belongs
to the configured group. Earlier versions 2–4 carried an explicit publisher update
grant and are therefore not strict group-only proof. The page was corrected to both
group-only ACLs, then republished at version 5. A subsequent weekly occurrence
produced version 6, with no failed or uncertain result, and was disabled. The
unchanged-hash attempt skipped remote publication. The newest downloaded PDF is
two pages, and both pages were rendered and visually checked after the auto-height
layout fix. Five Cloud PDF attachments were produced by the real runs; the newest
one is the final rendered two-page artifact.

### Confluence Data Center

The fresh automatic run used official Confluence 10.2.17 and the explicit
`legacy_xmlrpc_restrictions=true` option. Normal connection testing, vault setup,
enable and Create APIs produced page `327686` in one attempt with no assisted ACL
preparation or resume. The adapter used authenticated XML-RPC only to establish
View/Edit restrictions, then verified exact group-only REST readback before any
report content upload. Everyone has no access in the native dialog; the sole
configured group can view and edit, with zero direct users.

Republish updated the same page to version 3. A real weekly occurrence at 00:34
Asia/Ho_Chi_Minh skipped unchanged content; a later occurrence at 00:37 published
version 4 with zero failed or uncertain result. Both schedules were disabled.
Three authenticated PDF downloads share the already-inspected confirmed-report
bytes; the native Confluence viewer also opened the attachment. The footer carries
the signed evidence-chain head and escaped literal source content.

Normal purge completed in one attempt. Current/trash page, versions 1–4, and all
three PDF attachments returned authenticated 404; the document link is retired.
The integration was disabled and only the fresh app/TLS containers were stopped,
preserving database and home volumes. See [automatic DC proof](automatic-dc-provider-proof.json).

The earlier assisted neutral-page run remains historical recovery evidence. It
established the DC REST PUT contract and version-fenced resume, but is superseded
by the automatic path above for fresh restriction acceptance.

## Implementation and safety evidence

- Jira status progression now separates transition, durable independent comment,
  and field update. It stores exact receipts for recovery and preserves legacy
  behavior where no comment is required. Inbound Cloud payload handling uses the
  actual author and timestamp fields; inbound events create proposals only.
- Report publication can resume a failed prepared creation only with the original
  actor, source and authority checks, frozen configuration, current sharing proof,
  and a version-fenced, stable-checkpoint audit record. It does not retry uncertain
  remote writes.
- Confluence policy and ACL validation fail closed. The DC request contract is
  provider-specific. The worker now wires the real SCA SLA assessor. PDF warning
  text uses automatic row height so long content cannot overlap the engine table.
- The rollout guidance documents the required worker ordering; mixed old and new
  workers are not a supported deployment state for the changed recovery flow.
- Legacy inbound payloads without a provider comment ID use delivery identity for
  snapshot dedupe; different deliveries without that ID cannot be correlated.
  Historical rows are not backfilled. Keep compatible consumers when deduplication
  is required, following the coordinated rollout guidance.
- Tenant/RLS, permissions, idempotency, legal holds, secret redaction, bounded
  receipts, and evidence-chain checks remain required controls. Source changes do
  not put secrets, provider credentials, webhook material, or private evidence in
  this public directory.
- The [legal-hold proof](legal-hold-provider-proof.json) records the placed hold,
  release-admission 403 denials, release, and restored runtime flags without credential data.

## Final verification and retained limits

| Item | Current state |
| --- | --- |
| Cloud and DC unpublish/purge | Complete. Fresh automatic Cloud page `131374` and DC page `327686` each completed purge in one attempt after reaching version 4; current/trash pages, historical versions and all three report PDFs read back 404, and links are retired. An earlier pre-fix Cloud purge failed before any DELETE because V1 `att` IDs were rejected; that old command remains fenced and its page is retained. The adapter now validates and normalizes Cloud attachment IDs for V2 deletion. |
| Visual preview inventory | Complete: 73 inspected images, four unique PDFs, and all five rendered PDF pages cover changed visual components and provider flows. |
| Current checks | The Go baseline passed at 18:02:48 UTC. After the final frontend permission guard, all 208 web files / 1,405 tests and the production build passed. Both complete PostgreSQL persistence runs passed on the same clean database, finishing at 17:48:51 and 18:10:55 UTC. The Confluence/docpublish race run also passed. Earlier unchanged-surface checks remain recorded in the [verification summary](verification-summary.md). |
| Current full gate | Tier 0 panel and required QA, security, performance, reliability, frontend and platform reviews passed. The current worktree-bound `.git/taurus/verification.json` is validated before each commit/push; the public [final review record](final-review-results.json) records scope and finding resolution. |
| Project multi-asset provider run | Complete. The real source, Cloud, and DC paths demonstrated canonical advisory identity, existing-asset attribution, group update-in-place, and no duplicate group. |

The licensed Jira native confirmation, complete PostgreSQL runs, final frontend
tests, browser role-state checks, automatic restricted publication and final review
are complete. The single PR is eligible for Ready after current gate validation;
merge remains outside this work. The [final secret audit](final-secret-check.json)
covers the public evidence and assembled PR body.
`Closes` is reserved for issues whose complete acceptance and visual review
material are supported by the recorded evidence.

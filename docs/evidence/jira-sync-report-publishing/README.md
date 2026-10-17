# Jira sync and report publishing acceptance

This is the current acceptance ledger for Draft PR #1586. It is owned by
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
| 4 | #1435 | Signed native Cloud and DC webhooks each received real HMAC `issue_updated` and `comment_created` deliveries (202). The Cloud Automation-for-Jira Done change created a proposal only; the finding stayed open. DC reviewer Done likewise created a proposal while the finding remained confirmed. DC native create and edit event pairs each added exactly one snapshot; repeated To Do → Done retained one proposal. Earlier duplicate historical rows remain retained. The Cloud and DC hook registrations, tunnels, and proxies are closed. | Closes; acceptance supported by the recorded evidence. |
| 5 | #1436 | Cloud polling and reconciliation contracts remain covered, including deleted/unreadable detection, watermark retention, fair request budgeting, drift repair, and tenant isolation. | Closes; acceptance supported by the recorded evidence. |
| 6 | #1443 | Cloud and DC adapters used real providers. Cloud current strict sharing is exact read and update ACLs: zero explicit users and only the configured group. A published workspace public-link block overrides the organization default. Cloud page `131244` was republished at version 5, and a real weekly IANA occurrence created version 6. The latest PDF attachment downloaded successfully and its two rendered pages were inspected with no warning/table overlap. DC provider behavior was verified through a real page and PDF after the documented PUT restriction contract fix. | Refs; unassisted fresh Cloud/DC restriction creation still fails due the provider self-eviction behavior. |
| 7 | #1444 | Admission and recovery recheck human `PermReview`, source/detail/legal-hold conditions, tenant fences, destination revisions, and receipt history. The Cloud publish was resumed from a neutral prepared page with the original actor and version-fenced audit record. Real Cloud and DC release/purge paths completed and were verified absent. A real legal hold was placed and read back, blocked valid publish and unpublish with 403, and was released; runtime flags were restored. Loading, empty, error, and read-only UI states were inspected. | Closes; acceptance supported by the recorded evidence. |
| 8 | #1445 | The Cloud weekly schedule ran at 21:15 Asia/Ho_Chi_Minh (14:15 UTC), reached Done with no failed or uncertain delivery, and was disabled by a versioned request. An unchanged-hash run skipped publication. Earlier real Gmail PDF delivery and preview remain in scope; Outlook only proves a prior Junk-folder attachment listing, not a final attachment preview. | Refs; a final Outlook PDF opened-preview is still missing. |

One theme is sufficient for acceptance. Provider mocks and UI fixtures do not
substitute for the live results above. The final visual gallery and manifest cover
49 inspected images, two PDFs, and all three rendered PDF pages; they are ready for
the Draft PR's inline review material.

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

The Cloud-origin test is complete and safely closed. The native DC test also
admitted valid signed `issue_updated` and `comment_created` events (202). A real
reviewer Done transition created a proposal while the linked finding stayed
confirmed. Native create and edit event pairs each added one snapshot, preserving
the original and edited rows; a repeated To Do → Done transition retained one
proposal. The fix scopes stable hashes, normalizes revisions, and uses PostgreSQL
primary-key dedupe. Two pre-fix duplicate historical rows are retained rather than
rewritten. The [DC webhook proof](dc-webhook-provider-proof.json) records these
facts and the closed hook/tunnel cleanup.

### Confluence Cloud

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

Live testing established that the DC restriction endpoint requires PUT, not POST.
The adapter sends the read operation with the configured group and explicit empty
user list while preserving the update operation. A fresh group-only request still
returns the provider's self-eviction failure, so the successful DC run also used a
neutral page prepared with the current actor, followed by UI removal of that actor.
The final API read showed zero read users, one configured read group, and an empty
explicit update ACL. Resume of the failed intent completed at version 2; a real
republish completed at version 3; unchanged content then skipped. The final one-page
PDF was downloaded successfully.

These assisted Cloud/DC paths prove fail-closed behavior and the resume/recovery
contract. They do not prove unassisted fresh group-only restriction creation. That
remaining vendor limitation is tracked as Refs #1443.

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
| Cloud and DC unpublish/purge | Complete. DC completed in one attempt: page, two historical versions, and both PDFs read back 404. A fresh Cloud publication completed purge in one attempt: current/trash page, history, and attachment listing read back 404, and the link is retired. An earlier pre-fix Cloud purge failed before any DELETE because V1 `att` IDs were rejected; that old command remains fenced and its page is retained. The adapter now validates and normalizes Cloud attachment IDs for V2 deletion. |
| Visual preview inventory | Complete: 49 inspected images, two PDFs, and all three rendered PDF pages cover changed visual components and provider flows. |
| Current checks | Nine recorded checks passed, including the final full baseline at 16:08:33 UTC, web 208 files / 1,400 tests and production build, final changed-package/HTTP race coverage, and concurrent PostgreSQL snapshot coverage. The final Source Findings icon-focused check passed 12 tests, TypeScript and the production build at 16:15:05 UTC. See [verification summary](verification-summary.md). |
| Current full gate | All final reviewers, including security's edit fix, performance and reliability's narrow delta, the late DC metadata delta, and implementation QA passed. The worktree-bound report is `.git/taurus/verification.json`; it is validated against the final staged tree before committing and refreshed for the committed tree before pushing. |
| Project multi-asset provider run | Complete. The real source, Cloud, and DC paths demonstrated canonical advisory identity, existing-asset attribution, group update-in-place, and no duplicate group. |

The PR remains Draft with Refs #1443 and Refs #1445 for the two limits stated
above. `Closes` is reserved for the six issues whose acceptance and visual review
material are supported by the recorded evidence.

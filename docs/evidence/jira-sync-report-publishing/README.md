# Jira sync and report publishing acceptance

Acceptance ledger established before implementation on 2026-10-17 against
`origin/main` at `8a6c785b`. Delivery is one Draft PR under `pho-veteran`, with no
merge. The implementation reuses B04 (#1423–#1430, PR #1582), the inbound plane
(#1434, PR #1500), WS3 email (#1368), finding status events (#1393), and the
shipped document foundation (#1442, PR #1577). Historical captures prove only
those original scopes.

## Acceptance ledger

| Order | Issue | Implementation | Current acceptance and PR disposition |
| --- | --- | --- | --- |
| 1 | #1431 | Administrator opt-in; current confirmed/native/severity eligibility; durable event receipts and dispatch rechecks | Cloud en/vi auto-created tickets, no open/high or confirmed/low submission; DC and restricted issue security not demonstrated. Refs. |
| 2 | #1432 | Finding or vulnerability/Project grouping; canonical observed assets, immutable group facts, membership/revision fencing and update-in-place | Real PostgreSQL and Cloud/DC formatting contracts pass. No genuine multi-asset Project fixture through the current API. Refs. |
| 3 | #1433 | Remediated, accepted-risk, false-positive and reopen transitions; transition before field update; independent episodes | Cloud same-ticket close → reopen → close observed. Accepted-risk, false-positive and DC live captures remain missing. Refs. |
| 4 | #1435 | WS10 signed hook admission, atomic two-hour dedupe, hourly proposal limit, status-author attribution, own-write suppression, literal external comments | Real Cloud polling created one pending proposal from Automation for Jira while finding stayed open; own-principal closure created none. Cloud-origin webhook/comment delivery and DC remain unproven. Refs. |
| 5 | #1436 | Default-on fair polling; at most 250 actual provider requests per pass; status drift repair and unreadable/deleted detection | Real Cloud deletion detected, watermark retained; drift/budget/deletion/tenant contracts pass. Closes: full reconciliation acceptance is supported by the current tests and real deletion evidence. |
| 6 | #1443 | Cloud/DC adapter, escaped allowlisted storage, PDF/images, neutral shell, exact read-group/public-sharing checks before content, update/hash skip/footer | Real connection and neutral-shell path pass; Free restriction API refuses with HTTP 403 before any attachment/body. Successful restricted publish, republish/history/hash skip/footer and DC remain missing. Refs. |
| 7 | #1444 | Current human PermReview, detail/source/legal-hold checks at admission and every write; audited release/purge, retired targets | Permission/legal-hold/RLS/purge contracts pass. No successful live restricted release or purge because the available destination cannot establish restricted sharing. Refs. |
| 8 | #1445 | Weekly/monthly IANA schedules; frozen durable occurrences, current authority/recipient checks, WS3 PDF MIME/size limits, uncertain SMTP recovery and safe history | Final occurrence delivered to Gmail with a Vietnamese-complete PDF preview; a prior occurrence reached Outlook Junk with its attachment listed but blocked from opening. Both used the independently checked owner addresses. Scheduled Confluence version remains unavailable. Refs. |

One theme per client is sufficient under the user's instruction. Captures are
inspected before inclusion. A local contract test never substitutes for a live
provider result. Native browser captures are JPEG. Console captures currently cover
the engagement panel, safe refusal, proposal and run history; new settings/Project
screens and all loading/permission-denied states are not fully captured. The final PR uses `Closes` only for an issue whose entire
acceptance is supported by current evidence.

## Safety and recovery

- Every command, group, observation, occurrence and recipient delivery is tenant
  bound; forced RLS and same-tenant parent checks remain enforced.
- Inbound input creates proposals/comments only. Done means
  `statusCategory.key == "done"`; a resolution name does not confer authority.
  Status-change author attribution is independent of a later comment author.
- Current human release permission, source privacy/state, detail classification,
  legal hold and destination revisions are rechecked before sensitive writes.
- Content comes from stored report facts and verified evidence chains. A neutral
  page contains only a preparation message and correlation marker. No report
  title, body, PDF or image is uploaded before exact restricted sharing is proven.
  Cloud additionally requires current public-link blocking policy proof; an
  operator assertion cannot substitute for it.
- Ambiguous remote writes retain their target fence. Lost SMTP acknowledgement
  stays uncertain and is not automatically resent. Frozen occurrence artifacts
  cannot be changed by lease recovery. Purge guards every attachment/page DELETE.
- The `integrations` worker uses fail-closed dispatch-only tool adapters for stored
  report generation. It claims only integration and enabled notification work;
  `all` retains its mandatory sandbox. Profiles have independent maintenance
  leases. The operator email kill switch also gates scheduled PDF delivery.

## Real environment and Cloud runs

A fresh isolated Docker Compose project, `synapse-b07-runtime`, runs current API,
worker, web, PostgreSQL, MinIO, Mailpit and trusted local TLS at
`https://localhost:8444`. Current Go binaries are built with `CGO_ENABLED=0` and
mounted into the existing production images; the frontend serves the current
production build. Worker runs non-privileged with Docker's default seccomp policy.
The `all` worker correctly refused startup when the container could not provide
bubblewrap namespaces; no capability or seccomp exception was added. The supported
`integrations` composition then started real artifact and scheduled delivery.
The older full stack and its revoked B06 OAuth credentials were not used for these
runs. Dedicated PostgreSQL containers isolate integration suites from acceptance.

The personal Atlassian site is `synapse-personal-lab.atlassian.net`, project `KAN`,
Confluence space `SIL`. Initial Free signup unexpectedly selected a Standard trial;
only this newly created sandbox was corrected to Free without a payment method.
No school organization resources were selected or changed. The user approved a
one-day account token and the displayed Developer Terms; expiry is 2026-10-18.
Credentials remain private/vault-only, with calls constrained to this lab origin.
This is an operational boundary, not a claim that an account token is site-scoped.

### Jira Cloud

The real API connection test succeeded. A detail mapping with a recorded
administrator waiver was necessary because Free exposes no issue security levels.
Only synthetic personal lab data was used. This waiver is not restricted-security
acceptance.

- Human confirmation created `KAN-4` once, in Vietnamese, through durable automatic
  processing. Intent reached `done` with one create attempt. Literal `<script>` and
  markup delimiters remained text. The finding link opened the correct console
  finding at `SYNAPSE_PUBLIC_BASE_URL`.
- The same ticket transitioned To Do → Done → To Do → Done through stored finding
  state changes, with field refresh after each transition. No replacement issue
  was created. English confirmed/critical fixture created `KAN-5`; confirmed/low
  and unconfirmed/high fixtures had no intent.
- A manual Jira flow was limited by `key = KAN-4`. Its real actor, Automation for
  Jira, differed from the integration principal. Its Done transition produced one
  pending retest proposal while the Synapse finding remained `open`. Repeated
  polling retained the same proposal. Prior own-principal changes produced none.
- The synthetic `KAN-5` was deleted through Jira's API (HTTP 204). Subsequent polling
  returned `deleted_or_unreadable: true` and retained the provider update watermark.
- A literal Vietnamese comment was posted to the sandbox issue. Polling does not
  import comments; the Cloud-origin webhook cannot reach local-only TLS. No claim
  of live inbound comment delivery is made.

Inspected captures: [Vietnamese ticket](jira-cloud-auto-push-vi-dark.jpg),
[English ticket before deletion](jira-cloud-auto-push-en-dark.jpg),
[pending proposal in console](console-jira-proposal-en-light.jpg).

### Confluence Cloud

The real connection test succeeded. Live testing found and corrected the
restriction request shape: Atlassian requires an array (or paged results object),
not a single restriction object. A Cloud/DC request-contract regression now checks
that shape and the provider-specific group identity.

On the corrected build, publication intent `c3823c49c00f02a0669569e472a2c59a`
created neutral page `131218`, version 1. Exact read restriction returned HTTP 403.
The worker retained the restrictions checkpoint and stopped with `provider_refused`;
independent API reads confirmed the preparation message/marker only and **zero
attachments**. No report title/body, PDF or image reached the page. The sharing
UI explicitly states that Free cannot restrict content to specific people.

Inspected captures: [provider restriction limitation](confluence-cloud-publication-blocked-en-light.jpg),
[console refusal](console-publication-refused-en-light.jpg). These prove safe
refusal, not successful publication. Successful Cloud restricted sharing/public-link
proof, version+1, unchanged-hash skip, PDF/footer and purge require a suitable
sandbox. The former Data Center host remains offline; no paid evaluation or trial
was started to replace it.

### Scheduled PDF

A fresh temporary Desktop OAuth client and Gmail SMTP grant were created in the
personal Google project `ezquiz` with the user's explicit approval. The grant uses
`https://mail.google.com/`; its material is private and the relay is sealed in the
vault. Revoked B06 credentials were never retried. The user subsequently instructed that the temporary grant and client remain until
after this Draft PR merges. They are retained privately; acceptance schedules are
disabled after their first occurrence. No merge is performed by this task.

The bootstrap operator is deliberately excluded from identity memberships. A
verified bootstrap contact alone therefore cannot receive governed channel mail.
The acceptance setup uses an ordinary local administrator provisioned through the
API and official identity backfill, then actual Mailpit contact verification for
the user's Gmail and Outlook mailboxes. No recipient-policy SQL or fabricated
membership/domain proof is used. The actual report endpoint returned a real PDF
with a recorded digest. The first weekly occurrence completed with two SMTP
acceptances, no failed or uncertain deliveries, and was disabled. Gmail web showed
the PDF attachment and intact Vietnamese text; its link opened the correct
engagement after ordinary sign-in. SMTP acceptance alone did not prove Outlook
receipt: the autogenerated account alias did not show that message. The final run
used the owner address independently read from an existing received message.
Outlook web then showed that occurrence in Junk with the PDF listed (19 KB),
but blocked attachment opening. The protection was left intact. A further real
occurrence after the font fix ran at 11:10 UTC, reached `done` with two SMTP
acceptances and no failures/uncertainty, and was disabled. Gmail received
`synapse-report-a524134800446a1f.pdf`; its actual PDF preview now shows the complete
Vietnamese title and finding text. The Outlook capture is the preceding 10:51 UTC
occurrence, not a claim that the final attachment was opened there.

## Checks and reviews

Passing evidence includes:

- Full web suite: 206 files, 1,366 tests (two workers); production build and TypeScript.
- Current Go build/vet/typecheck, golangci-lint 2.13.2 with zero issues, and hostile
  tenant HTTP harness.
- Real PostgreSQL document/group/inbound contracts, non-superuser migration
  rollback, schedule null/freeze/concurrent admission/recovery, and runtime RLS
  with `NOSUPERUSER NOBYPASSRLS` (owned/foreign/unbound access and forged INSERT
  specifically returning SQLSTATE 42501).
- Actual local SMTP sender contracts for accepted and lost-ACK PDF delivery,
  current-authority denial and provider-disabled scheduling before SMTP.
- Combined implementation QA passed after scheduler, closure projection,
  maintenance lease and provider-disable fixes. It does not replace final Taurus
  review or real provider acceptance.

The full PostgreSQL package passed in the broad run before the final queue fixes;
current focused PostgreSQL schedule/inbound contracts then passed with migrations
through 0259. The broad all-package command itself failed an import-graph race
while a test import changed; a subsequent complete `make test` passed, as did
current document/composition regressions. The unconstrained web run was stopped after timing failures under machine load;
the same suite passed with two workers and unchanged assertions. A dirty-database rollback guard failure
was separately resolved by resetting only an ephemeral test database and rerunning
its focused contracts. Neither failed command is presented as a pass.

Final QA, security, architecture, performance, reliability, algorithm and font
provenance review have passed.
Confirmed findings fixed include fair schedule admission, Jira stage deadlines and
timeout checkpoints, report paragraph bounds, audit failure admission, schedule
configuration fencing, visible worker failure signals and civil-date arithmetic
through Santiago’s midnight DST gap. Actual Gmail PDF inspection found missing
Vietnamese glyphs in the existing core font; both PDF renderers now embed
Liberation Sans, with full glyph-range, deterministic rendering and extraction
checks. Distribution manifests carry its exact license notice. Ordered indexes support
the new queues; recovery may still inspect an ineligible nonterminal prefix, so
no constant-time scan or production load claim is made. Frontend review passed after visually inspecting all 17 retained captures.
The tier 0 verification report is maintained locally at
`.git/taurus/verification.json`; it must validate against the exact tree before
commit and push. Remaining live-provider acceptance is listed above and does not
become complete because the implementation gate passes.

Inspected delivery captures: [Gmail message](gmail-scheduled-report-en-light.jpg),
[Gmail attachment](gmail-scheduled-pdf-attachment-en-light.jpg),
[actual Unicode PDF preview](gmail-scheduled-pdf-preview-en-light.jpg),
[Outlook prior occurrence in Junk](outlook-scheduled-report-en-light.jpg), and
[console opened from the report link](console-scheduled-report-deep-link-en-light.jpg),
and [disabled schedule with immutable run history](console-scheduled-history-en-light.jpg).
The [provider results](provider-results.json), [command records](verification-checks.json),
[reconciliation output](reconciliation-tests.txt), and [font provenance](font-provenance.json)
retain the corresponding classifications and limits.

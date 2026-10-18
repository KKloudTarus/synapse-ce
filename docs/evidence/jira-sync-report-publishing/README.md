# Jira sync and report publishing acceptance

This is the current acceptance ledger for Draft PR #1586 on 18 October 2026. The
17 October snapshot and older review records remain historical. B04/#1434 and
#1442/PR #1577 are reused foundations. Live acceptance below comes from the
isolated Docker stack and personal Cloud sites; provider failures are retained as
diagnostics, not counted as passes.

## Issue disposition

The final issue references must follow this ledger. Do not use `Closes` until the
row's remaining evidence is present in this tree and attached to the PR. The
current gaps are specific; an Outlook preview failure is recorded separately
because #1445 requires receipt of the attachment, not a successful Outlook PDF
viewer.

| Order | Issue | Current evidence | Remaining acceptance | Disposition now |
| --- | --- | --- | --- | --- |
| 1 | #1431 | Real Cloud and licensed Jira DC policy/lifecycle runs, positive/negative policy cases, one link per finding, restricted security level, and status-category readbacks. Current Cloud/DC issue EN/VI screenshots and authenticated linked-ticket console proof are present. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | `Closes` recommended |
| 2 | #1432 | Real source scans against controlled Maven test manifests yielded the actual Log4j finding. Scans observed assets `a`/`b`, rescanned `a`, removed `b`'s vulnerable dependency, then updated the same Cloud `B7R-8` and DC `SYNACC-2` group. Current Cloud/DC asset frames show only `a` after removal; separate console frames show the Confirmed finding, both linked keys and observed ticket states. | No provider acceptance gap remains; attach current proof and screenshots to the PR body. | `Closes` recommended |
| 3 | #1433 | Cloud `B7R-9`/`B7R-10` and DC `SYNACC-3`/`SYNACC-4` real transitions cover remediated, accepted risk, false positive, reopen, ordered comment/update actions, and quiet repeat. The DC SLA-backed accepted-risk case is `SYNACC-5`; current DC issue EN/VI screenshots and authenticated linked-ticket console proof are present. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | `Closes` recommended |
| 4 | #1435 | Real signed native callbacks from Cloud and licensed DC; proposals stay pending and findings stay unchanged. Proof records replay, altered-signature refusal, external comment snapshots, own-write suppression, and exact `statusCategory.key == "done"` behavior. Current Jira DC console capture shows `SYNACC-3` as new, a pending retest proposal, and both original and edited external comments. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | `Closes` recommended |
| 5 | #1436 | Cloud poll-only `Done` then deletion produced the unreadable marker while retaining the proposal; DC `SYNACC-6` read/delete/read returned 200/204/404. Four focused reconciliation tests pass and the exact output is in the PR draft. | No remaining provider/test evidence gap; attach the current proof with the PR. | `Closes` recommended |
| 6 | #1443 | Real Cloud and DC restricted publishing, republish, unchanged-hash skip, exact read restrictions, signed footer, scheduled page revision, native page/PDF/history captures, and all four downloaded PDF pages rendered. | No provider acceptance gap remains. Attach the current proof and preview links to the PR body. | `Closes` recommended |
| 7 | #1444 | Real readonly permission refusals; a summary-class connection test failed and the integration remained disabled (enable returned 409; publish/unpublish returned 403); detail-class hold blocked publish/unpublish (403), then release returned 204. The detail page audit, page ID/space, scheduled history, and purge were checked. | No provider acceptance gap remains. State the summary-class result precisely; runtime class isolation is also covered by service contracts. | `Closes` recommended |
| 8 | #1445 | Real weekly email delivered the same PDF attachment to Gmail and Outlook; Gmail opened/rendered it. A real Confluence schedule produced page version 4 and was disabled. The aligned-build republish reached v5 and the next unchanged request skipped without producing v6. | No provider acceptance gap remains. Attach the exact-leaf Confluence preview and scheduled history to the PR body. Outlook's provider preview/download failure remains disclosed; receipt is evidenced. | `Closes` recommended |

## Current Jira evidence

[Cloud lifecycle and native callback proof](current-jira-cloud-proof.json) records
the 18 October Cloud run, including EN/VI auto-push, negative controls, ordered
status work, native callbacks, replay, polling and cleanup. The real native
callback gateway checked HMAC against the unchanged body and forwarded only the
configured webhook route. Initial 401 deliveries are explicitly failures; later
202 deliveries are the accepted receipts.

[Licensed Jira Data Center proof](current-jira-dc-policy-lifecycle-proof.json)
records Jira 11.3.12 while its official test license was active, including
`SYNACC-3` and `SYNACC-4`, the SLA-backed `SYNACC-5` lifecycle, native reviewer
callbacks, replay, own-write suppression and the `SYNACC-6` deletion check. The
current EN/VI issue screenshots and authenticated linked-ticket console frame
are hash-listed in [the current DC evidence manifest](current-jira-dc-evidence-manifest.json).
The console shows `SYNACC-3` as new with a pending retest proposal, Jira
resolution context, and original/edited external comments. The older
[`dc-webhook-provider-proof.json`](dc-webhook-provider-proof.json) describes an
expired-license run and is not used as current licensed acceptance.

[Project grouping proof](current-project-provider-proof.json) and its native
readbacks record the real source observations and one updated grouped issue per
provider. The actual scanner ran against controlled local Maven manifests and
produced the Log4j finding; Confluence's manually entered synthetic report rows
are separate and are not represented as scan results. Current Cloud/DC EN/VI
issue frames and the linked console view are in
[`current-project-image-manifest.json`](current-project-image-manifest.json).

## Current Confluence and schedule evidence

The Cloud publish/restriction proof and gallery retain their provider-specific
scope. The current DC visual fixture is page `1409035`; its captured page,
restriction dialog, signed footer, history, native PDF viewer, and PDF page
previews are shown in [the visual gallery](visual-previews.md). The final
[current DC proof](current-dc-confluence-visual-proof.json) records v2 creation,
v3 republish, scheduled v4, one legitimate build-provenance update to v5, then a
successful unchanged-hash skip without v6. It records the actual read/update
group, six retained audit rows, readonly refusals, summary-class fail-closed
connection and enable results, enabled detail-class legal hold and release,
disabled schedule, and governed purge. The proof embeds SHA-256 and byte counts
for its 24 visual/PDF artifacts. Provider reads for the page, trashed
page, history, and all four attachment content endpoints returned 404. The
separate direct download URLs redirected to local login (302) without returning
a PDF; they are not reported as 404. The UI shows the unpublished/page-not-found
state.

[Current email proof](current-email-proof.json) records the 18 October weekly
occurrence, two delivered messages, and disabled schedule. Gmail's actual PDF
viewer opened the attachment. Outlook received a visible PDF attachment, but its
preview creation, normal download, and EML export failed at the provider; no
Outlook byte-hash or rendered-preview claim is made. This limitation does not add
a requirement beyond #1445's receipt evidence.

## Required reconciliation test output

Issue #1436 explicitly asks for the relevant test output in the PR description.
This is copied from [`reconciliation-tests.txt`](reconciliation-tests.txt):

```text
=== RUN   TestInboundReconcileChargesIdentityWithinReadBudget
--- PASS: TestInboundReconcileChargesIdentityWithinReadBudget (0.01s)
=== RUN   TestInboundReconcileTimeoutCheckpointsAttemptedTargetForNextFairTick
--- PASS: TestInboundReconcileTimeoutCheckpointsAttemptedTargetForNextFairTick (0.06s)
=== RUN   TestWorkflowTickReconcilesProviderStateAndMarksUnreadable
--- PASS: TestWorkflowTickReconcilesProviderStateAndMarksUnreadable (0.00s)
=== RUN   TestWorkflowTickRunsOutboundBeforeBoundedInboundRead
--- PASS: TestWorkflowTickRunsOutboundBeforeBoundedInboundRead (0.10s)
PASS
ok  	github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing	0.179s
```

## Verification, safety and limits

[Current command evidence](current-verification-checks.json) records the current
baseline, focused race checks, hostile harness, and reconciliation tests. Earlier
full PostgreSQL and frontend runs are retained in
[`verification-summary.md`](verification-summary.md) with their exact source
scope; those unchanged surfaces are not represented as freshly rerun here. The
current source delta includes automatic ticket admission/idempotency and POSIX
Git askpass handling.

The acceptance stack is isolated and uses real Docker services and provider
requests. Project grouping uses real scanner output from controlled Maven test
manifests. Manually entered synthetic findings are used only in the Confluence
report fixture. Tenant/RLS isolation, permission checks, idempotency, legal hold,
secret redaction, proposal-only inbound handling, and restriction verification
before upload remain required. Acceptance schedules are disabled after their
one-off runs. OAuth cleanup remains paused until the user reports the PR merged.
No billing or school resources were changed. PR #1586 remains a Draft and is not
merged.

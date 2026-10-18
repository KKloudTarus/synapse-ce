# Remaining acceptance execution ledger

Updated 18 October 2026 for PR #1586. This is an execution ledger, not a claim of
completion. A row changes to `Closes` only after every remaining item below is
evidenced in the public PR artifacts. Current source and provider proof are
separate: source checks do not replace live provider runs, and old screenshots
remain scoped to their original fixture.

| Order | Issue | Proven now | Remaining before `Closes` | State |
| --- | --- | --- | --- | --- |
| 1 | #1431 | Real Cloud and licensed DC positive/negative policy and lifecycle runs; current Cloud/DC issue EN/VI captures and authenticated linked-ticket console proof. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | Ready for `Closes` |
| 2 | #1432 | Real `a → b → a` scans against controlled Maven test manifests, actual canonical Log4j finding, vulnerable dependency removal, and one updated Cloud/DC grouped issue with only `a` remaining. Current Cloud/DC EN/VI issue captures and linked-console view are listed in `current-project-image-manifest.json`. | No remaining provider criterion; attach the proof and image manifest to the PR. | Ready for `Closes` |
| 3 | #1433 | Real Cloud and licensed DC lifecycle/provider readbacks, including SLA-backed accepted risk, reopen, ordered status/comment/update work, and quiet repeats; current DC issue EN/VI captures and authenticated linked-ticket console proof. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | Ready for `Closes` |
| 4 | #1435 | Real signed Cloud and licensed DC callback receipts; HMAC/replay, proposal-only, external comment snapshots, own-write suppression, and `statusCategory.key == "done"` handling. Current issue EN/VI captures exist; the DC console shows the pending retest proposal and original/edited external comments. | No remaining acceptance criterion; attach current proof and screenshots to the PR. | Ready for `Closes` |
| 5 | #1436 | Actual Cloud poll/delete/unreadable flow with proposal retained; DC `SYNACC-6` 200/204/404. Focused reconciliation tests pass and their exact output is included in the PR draft. | No remaining provider/test evidence criterion; attach the proof with the PR. | Ready for `Closes` |
| 6 | #1443 | Real Cloud restricted publication and DC page `1409035`: restrictions before content, v3 republish, scheduled v4, build-provenance v5 update, unchanged-hash skip without v6, native body/restrictions/footer/history/PDF captures, four downloaded/rendered PDF previews, and governed purge. | No remaining provider criterion; attach the current proof/gallery to the PR body. | Ready for `Closes` |
| 7 | #1444 | Real readonly 403s; real summary-class connection failure followed by enable 409 and publish/unpublish 403 while disabled; detail-class enabled legal-hold publish/unpublish 403 and release 204; six audit rows retained; purge marked done and provider content/history/attachment GETs returned 404. | No remaining provider criterion; attach proof and state that direct download URLs redirected to login (302), not 404. | Ready for `Closes` |
| 8 | #1445 | Actual weekly email reached Gmail and Outlook with the same visible PDF attachment; Gmail opened it. The Confluence schedule produced page version 4, was disabled, and its scheduled PDF has a rendered page preview. | No remaining provider criterion; attach the current scheduled Confluence proof/gallery and email receipts. | Ready for `Closes` |

## Evidence constraints

- One theme is sufficient under the user's instruction. Preserve real Cloud and DC
  captures with their fixture identities; do not label an old fixture as the
  current run. Project grouping scans used real scanner output from controlled
  Maven test manifests; the manually entered Confluence report findings are not
  scanner output.
- Outlook's PDF preview, direct attachment download and EML export failed at the
  provider. The Outlook receipt visibly contains the PDF attachment. No Outlook
  attachment byte or PDF rendering is claimed, and successful Outlook preview is
  not an acceptance criterion in #1445.
- The current Jira Data Center callback evidence supersedes the older expired
  license run for acceptance. Keep the older record as historical diagnostic
  evidence.
- Paste the focused output in [`reconciliation-tests.txt`](reconciliation-tests.txt)
  into the PR body for #1436.
- The evidence README and gallery link the final current Confluence proof,
  current Project/Jira DC EN/VI issue captures, and current Jira DC linked-ticket
  console frame. The console proof is hash-listed in
  [`current-jira-dc-evidence-manifest.json`](current-jira-dc-evidence-manifest.json).

The automatic-ticket admission regression was found during the live Cloud
reconfirmation: distinct events for the same finding could create duplicate
tickets. The current change retains existing mapping commands/links and uses a
stable finding/mapping identity; bounded full-history results defer conservatively.
The failed initial episode remains diagnostic and is not counted as a passing
provider run.

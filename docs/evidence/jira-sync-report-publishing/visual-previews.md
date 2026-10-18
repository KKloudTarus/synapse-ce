# Visual previews

The gallery retains both historical screenshots and current continuation
captures. Historical sections below retain their original fixture identities and
do not stand in for the 18 October provider runs. The current continuation
captures are grouped at the end and named `current-*`; the matching proof JSON
records their provider and run scope. A single theme is sufficient under the
user's acceptance instruction.

## Review-remediation previews — 18 October 2026

These images are current observations of the restored Docker stack and downloaded
Cloud PDFs from the review-remediation run. All pages were rendered with Poppler
and visually inspected. The current continuation captures below separately show
the subsequent licensed DC, native callback and email runs. Hashes and capture scope are in
[the current manifest](review-report-previews.json).

![Sharing unavailable](review-sharing-unverifiable.png)
![Configured sharing group mismatch](review-sharing-lost.png)

| PDF | Current rendered pages |
| --- | --- |
| [Governed stored report](review-governed-report.pdf) | ![Page 1](review-governed-report-1.png) |
| [Stored vulnerability report](review-vulnerability-report.pdf) | ![Page 1](review-vulnerability-report-1.png) ![Page 2](review-vulnerability-report-2.png) |
| [Fresh Cloud publication](review-cloud-initial-report.pdf) | ![Page 1](review-cloud-initial-report-1.png) |
| [Cloud update](review-cloud-updated-report.pdf) | ![Page 1](review-cloud-updated-report-1.png) |
| [Real scheduled Cloud report](review-cloud-scheduled-report.pdf) | ![Page 1](review-cloud-scheduled-report-1.png) |

## Historical visual previews

These captures/PDF pages belong to the 17 October acceptance run. They are retained
for design/history and do not establish current provider acceptance after review
corrections. The current warning preview is linked from [README.md](README.md).


This gallery provides inline review previews for every continuation JPG/PNG and
every rendered page of the downloaded report PDFs. The files and integrity
metadata are listed in [continuation-image-manifest.json](continuation-image-manifest.json).
All captures are from the live acceptance paths, not mocks. Loading captures use
real API responses that were temporarily rate-limited for the screenshot and then
restored; empty and error captures use real API responses. One theme is sufficient
for acceptance, so the gallery keeps the light and dark provider themes actually
observed during the runs.

## Project-source and console states

Linked project finding and ticket state:

![Linked Project source finding](console-project-source-linked-en-light.jpg)

![Project ticket state](console-project-ticket-state-en-light.jpg)

Jira DC link surfaced from the console:

![Jira DC linked finding](console-jira-dc-linked-finding-en-light.jpg)

Real loading, empty, and error states:

![Project source loading](console-project-source-loading-en-light.jpg)

![Project source empty](console-project-source-empty-en-light.jpg)

![Project source error](console-project-source-error-en-light.jpg)

## Publishing, scheduling, and permissions

Project-level empty publication and schedule controls:

![Project publication empty](console-project-publication-empty-en-light.jpg)

![Project schedule controls](console-project-schedule-controls-en-light.jpg)

Publishing loading, schedule, and timezone controls:

![Publication loading](console-publication-loading-en-light.jpg)

![Publishing schedule](console-publishing-schedule-en-light.jpg)

![Publication schedule timezone](console-publication-schedule-timezone-en-light.jpg)

Recovery, read-only, and unpublish controls:

![Publication resume refused](console-publication-resume-refused-en-light.jpg)

![Publishing read-only](console-publishing-readonly-en-light.jpg)

![Unpublish confirmation](console-unpublish-confirm-en-light.jpg)

Jira mapping, inbound settings, and literal inbound comment view:

![Jira mapping](console-jira-mapping-en-light.jpg)

![Jira inbound settings](console-jira-inbound-settings-en-light.jpg)

![Jira webhook comment](console-jira-webhook-comment-vi-light.jpg)

## Historical Jira Cloud captures

English grouped issue and observed assets:

![Cloud grouped English issue](jira-cloud-grouped-en-dark.jpg)

![Cloud grouped English assets](jira-cloud-grouped-assets-en-dark.jpg)

Vietnamese grouped issue and observed assets:

![Cloud grouped Vietnamese issue](jira-cloud-grouped-body-vi-dark.jpg)

![Cloud grouped Vietnamese assets](jira-cloud-grouped-assets-vi-dark.jpg)

After rescan, the Vietnamese group contains only the remaining observed asset:

![Cloud grouped after rescan](jira-cloud-grouped-after-rescan-vi-dark.jpg)

Restricted lifecycle, security, and durable comment evidence:

![Cloud restricted remediated](jira-cloud-restricted-remediated-en-dark.jpg)

![Cloud restricted lifecycle comments](jira-cloud-restricted-lifecycle-comments-en-dark.jpg)

![Cloud restricted reopen](jira-cloud-restricted-reopen-vi-dark.jpg)

![Cloud restricted security](jira-cloud-restricted-security-vi-dark.jpg)

## Historical Jira Data Center captures

English auto-push and grouped observed assets:

![DC auto-push English](jira-dc-auto-push-en-light.jpg)

![DC grouped English issue](jira-dc-grouped-body-en-light.jpg)

![DC grouped English assets](jira-dc-grouped-assets-en-light.jpg)

Vietnamese grouped issue and observed assets:

![DC grouped Vietnamese issue](jira-dc-grouped-body-vi-light.jpg)

![DC grouped Vietnamese assets](jira-dc-grouped-assets-vi-light.jpg)

After rescan, the Vietnamese group contains only the remaining observed asset:

![DC grouped after rescan](jira-dc-grouped-after-rescan-vi-light.jpg)

Lifecycle and accepted-risk comment evidence:

![DC false-positive reopen](jira-dc-false-positive-reopen-vi-light.jpg)

![DC accepted-risk comment](jira-dc-accepted-risk-comment-vi-light.jpg)

## Historical Confluence Cloud captures

Strict group-only restriction and public-link policy views:

![Cloud group-only read and edit restriction](confluence-cloud-group-only-read-edit-en-light.jpg)

![Cloud restrictions dialog](confluence-cloud-restrictions-dialog-en-light.jpg)

Final page footer and scheduled history:

![Cloud final footer](confluence-cloud-final-footer-en-light.jpg)

![Cloud scheduled history](confluence-cloud-scheduled-history-en-light.jpg)

Rendered pages of the downloaded final Cloud PDF:

![Cloud final PDF page 1](confluence-cloud-final-pdf-page-1.png)

![Cloud final PDF page 2](confluence-cloud-final-pdf-page-2.png)

## Historical Confluence Data Center captures

Published content, group-only restriction, footer, history, and attachment view:

![DC published body](confluence-dc-published-body-en-dark.jpg)

![DC group-only restriction](confluence-dc-group-only-en-dark.jpg)

![DC final footer](confluence-dc-footer-en-dark.jpg)

![DC republished history](confluence-dc-republished-history-en-dark.jpg)

![DC PDF attachments](confluence-dc-pdf-attachments-en-dark.jpg)

Rendered page of the downloaded final DC PDF:

![DC final PDF page 1](confluence-dc-final-pdf-page-1.png)

The fresh Cloud purge report was deliberately verified by provider readback after
deletion, before its attachment was downloaded. It therefore has no individual PDF
preview; this gallery does not imply one exists.

## Historical native DC inbound and earlier Cloud page

The real reviewer changed Jira to Done while the finding stayed Confirmed. The original and edited literal comment are separate append-only snapshots; each native callback pair adds one snapshot. Two earlier pre-fix duplicate rows are retained outside this viewport and documented in the provider proof.

![Finding remains Confirmed after native DC Done](console-jira-dc-finding-confirmed-en-light.jpg)

The earlier native callback images below were captured after the old lab license expired. They retain their observed behavior only; the fresh licensed rerun is recorded separately.

![One pending proposal and literal original/edit snapshots](console-jira-dc-webhook-proposal-en-light.jpg)

![Earlier real Confluence Cloud report body](confluence-cloud-final-body-en-light.jpg)

## Historical scheduled PDF email

A real weekly occurrence at 23:33 Asia/Ho_Chi_Minh delivered to both verified personal recipients. Gmail opened the final two-page PDF. Outlook received the same attachment; its native preview service returned a document-preview creation error. Both browser-staged downloads contain complete PDF bytes matching the source SHA-256, but Edge did not finalize the downloads. The [mail proof](scheduled-email-provider-proof.json) distinguishes these states.

![Gmail opened scheduled PDF](gmail-scheduled-pdf-open-en-dark.jpg)

![Outlook received final scheduled PDF](outlook-scheduled-pdf-received-en-light.jpg)

## Historical automatic fresh Cloud publication

The normal Create command completed in one attempt with no manual ACL repair or resume. The configured one-member group is the only direct principal. Republish produced version 3, and a real weekly occurrence produced version 4 on the same page. The three PDF attachments have two unique byte hashes; both distinct PDFs are previewed below.

![confluence cloud automatic body en light](confluence-cloud-automatic-body-en-light.jpg)

![confluence cloud automatic restrictions en light](confluence-cloud-automatic-restrictions-en-light.jpg)

![confluence cloud automatic footer en light](confluence-cloud-automatic-footer-en-light.jpg)

![confluence cloud automatic history en light](confluence-cloud-automatic-history-en-light.jpg)

![confluence cloud automatic confirmed pdf page 1](confluence-cloud-automatic-confirmed-pdf-page-1.png)

![confluence cloud automatic open pdf page 1](confluence-cloud-automatic-open-pdf-page-1.png)

## Historical automatic fresh Data Center publication

The explicit Confluence 10.2 compatibility option created exact group-only View/Edit restrictions automatically before the report upload. The live restriction dialog confirms that Everyone has no access and only the configured group can view and edit. The downloaded DC PDFs match the already-previewed Cloud confirmed report byte for byte; their individual attachment IDs and hashes are retained in provider proof.

![Confluence DC explicit compatibility configuration](console-confluence-dc-compatibility-en-light.jpg)

![Automatic Confluence DC report body](confluence-dc-automatic-body-en-dark.jpg)

![Automatic Confluence DC sole-group restrictions](confluence-dc-automatic-restrictions-en-dark.jpg)

![Automatic Confluence DC evidence chain and PDF footer](confluence-dc-automatic-footer-en-dark.jpg)

A weekly worker occurrence at 00:37 Asia/Ho_Chi_Minh produced version 4 on the same page. A separate unchanged-content occurrence skipped. Both schedules were disabled after one run. The native DC attachment viewer opened the resulting PDF.

![Confluence DC scheduled publication version 4](confluence-dc-automatic-history-en-dark.jpg)

![Confluence DC three actual PDF attachments](confluence-dc-automatic-attachments-en-dark.jpg)

![Confluence DC native PDF preview](confluence-dc-automatic-pdf-native-en-dark.jpg)

## Documentation discovery

The running PostgreSQL-backed stack exposes Confluence Cloud and Data Center under Documentation. The empty state below comes from a separate real PostgreSQL database with zero integrations.

![Documentation configured](console-documentation-configured-en-light.jpg)

![Documentation empty](console-documentation-empty-en-light.jpg)

Loading forwards the real integration-list response after a temporary 20-second delay. Error captures a real 502 while only the isolated API is stopped. The API was restored before the readonly journey.

![Documentation loading](console-documentation-loading-en-light.jpg)

![Documentation upstream error](console-documentation-error-en-light.jpg)

![Documentation readonly empty editor](console-documentation-readonly-empty-en-light.jpg)

## Fresh licensed Jira DC native callbacks

The fresh isolated Jira 11.3.12 instance received seven signed native forwards at 18:39:28–18:40:36 UTC, before its official test license expired at 20:54:31 UTC. The independent reviewer marked `SYNACC-1` Done, created and edited a comment, then repeated To Do → Done. Synapse retained one pending proposal, the finding stayed Confirmed, and one remote comment has exactly two distinct snapshots. The temporary native registration, loopback proxy and cross-stack route were closed. See [fresh native proof](fresh-jira-native-provider-proof.json).

![Fresh Jira DC Done and restricted issue security](jira-dc-fresh-native-done-en-light.jpg)

![Fresh Jira DC independent reviewer comment](jira-dc-fresh-native-reviewer-comment-en-light.jpg)

![Finding remains Confirmed after native Done](console-jira-dc-fresh-finding-confirmed-en-light.jpg)

![One pending proposal and two distinct native snapshots](console-jira-dc-fresh-proposal-snapshots-en-light.jpg)

## Current continuation screenshots — 18 October 2026

The images in this section are the actual Cloud/DC browser frames from the
continuation proof files. Current Jira lifecycle counts and provider readbacks
are in [Cloud proof](current-jira-cloud-proof.json), [licensed DC
proof](current-jira-dc-policy-lifecycle-proof.json), and [Project grouping
proof](current-project-provider-proof.json). The Cloud/DC EN/VI Project issue
captures and Jira DC policy EN/VI captures are hash-listed in
[`current-project-image-manifest.json`](current-project-image-manifest.json).
The linked-ticket screenshots are hash-listed in
[`current-jira-dc-evidence-manifest.json`](current-jira-dc-evidence-manifest.json).

### Current Jira Cloud lifecycle, native callbacks and polling

![Current Jira Cloud policy, English](current-jira-cloud-policy-en.jpg)

![Current Jira Cloud security level, English](current-jira-cloud-policy-en-security.jpg)

![Current Jira Cloud policy, Vietnamese](current-jira-cloud-policy-vi.jpg)

![Current Jira Cloud security level, Vietnamese](current-jira-cloud-policy-vi-security.jpg)

![Current linked Cloud finding, Vietnamese](current-jira-cloud-console-vi-linked.jpg)

![Current Cloud finding console](current-jira-cloud-console-vi.jpg)

![Current Cloud native callback provider](current-cloud-native-provider.jpg)

![Current Cloud native callback finding](current-cloud-native-finding.jpg)

![Current Cloud native callback console](current-cloud-native-console.jpg)

![Current Cloud polling provider](current-cloud-poll-provider.jpg)

![Current Cloud deleted-ticket console](current-cloud-poll-console.jpg)

![Cloud Automation rule disabled after acceptance](current-cloud-automation-disabled.jpg)

Current licensed Jira DC issue views:

![Current Jira DC policy issue, English, SYNACC-3](current-jira-dc-policy-en.jpg)

![Current Jira DC policy issue, Vietnamese, SYNACC-4](current-jira-dc-policy-vi.jpg)

![Current DC policy finding detail before following the Jira backlink](current-jira-dc-policy-console-context.jpg)

![Current DC linked-ticket observation after following the Jira backlink](current-jira-dc-policy-console.jpg)

The authenticated linked-ticket panel shows `SYNACC-3` as new, its retest
proposal pending, Jira's Done resolution context, and both the original and
edited external comments. [`current-jira-dc-policy-linked-ticket.jpg`](current-jira-dc-policy-linked-ticket.jpg)
is a manifest-listed copy of the same rendered frame (same SHA-256), so it is
linked here without duplicating its visual preview. Existing historical `jira-dc-*`
images above retain their original fixture identities.

### Current Project source grouping

The real scanner run used controlled Maven manifests and produced the
Log4j finding. Its findings and the native provider readbacks are in
[`current-project-cloud-provider-readback.json`](current-project-cloud-provider-readback.json),
[`current-project-cloud-provider-readback-after-removal.json`](current-project-cloud-provider-readback-after-removal.json),
and [`current-project-dc-provider-readback.json`](current-project-dc-provider-readback.json).

![Current Cloud grouped issue, English, B7R-8](current-project-cloud-en.jpg)

![Current Cloud grouped issue after removal, Vietnamese, B7R-8](current-project-cloud-vi-after-removal.jpg)

![Current Data Center grouped issue, English, SYNACC-2](current-project-dc-en.jpg)

![Current Data Center grouped issue after removal, Vietnamese, SYNACC-2](current-project-dc-vi.jpg)

![Current source finding title, status and source provenance](current-project-source-finding.jpg)

The top DC frames show title, body, priority, labels and security; the separate asset frames below show the sole remaining `source/a` row. The console captures show the same Confirmed CVE finding, both linked keys, and their observed Jira states. See [console provenance and hashes](current-project-console-proof.json).

![Current Data Center English remaining asset table](current-project-dc-assets-en.jpg)

![Current Data Center Vietnamese remaining asset table](current-project-dc-assets-vi.jpg)

![Confirmed Project finding and both linked ticket keys](current-project-console-linked-tickets.jpg)

![Project Jira observations for both linked tickets](current-project-console-ticket-states.jpg)

### Current Confluence Data Center fixture 1409035

The real local Confluence DC page `1409035` is distinct from page `1409030` in the
earlier REST-only fixture and from the historical automatic-publication fixture.
This current visual sequence shows its restricted body, restriction dialog,
signed evidence-chain footer, native PDF viewer, version history, and scheduled
revision history. The [final current DC proof](current-dc-confluence-visual-proof.json)
records create v2, republish v3, scheduled v4, a build-provenance update to v5,
then an unchanged-hash skip without v6. It also records the enabled detail-class
legal hold and release, the failed summary-class connection test and fail-closed
enable/publish/unpublish results, disabled schedule, and governed purge.

![Current DC Confluence page body](current-dc-confluence-visual-body.jpg)

![Current DC Confluence read restrictions](current-dc-confluence-visual-restrictions.jpg)

![Current DC Confluence evidence-chain footer](current-dc-confluence-visual-footer.jpg)

![Current DC Confluence native PDF viewer](current-dc-confluence-visual-pdf.jpg)

![Current DC Confluence version history](current-dc-confluence-visual-history.jpg)

![Current DC Confluence schedule history](current-dc-confluence-visual-scheduled-history.jpg)

![Current DC Confluence final footer after scheduled report](current-dc-confluence-visual-final-footer.jpg)

![Current DC Confluence final native PDF viewer](current-dc-confluence-visual-final-pdf.jpg)

![Current readonly publication console and permission state](current-dc-confluence-console-readonly.jpg)

![Current legal-hold console state](current-dc-confluence-console-legal-hold.jpg)

![Current unpublished console state](current-dc-confluence-console-unpublished.jpg)

![Current provider page-not-found after purge](current-dc-confluence-visual-purged.jpg)

Rendered previews of every downloaded current DC Confluence PDF page. The
scheduled PDF was produced at version 4; all four attachment PDFs from the
1409035 visual fixture have a rendered page below:

| DC Confluence PDF | Rendered page |
| --- | --- |
| Report before scheduled revision | ![Before schedule, page 1](current-dc-confluence-report-before-page-1.png) |
| Scheduled report revision | ![After schedule, page 1](current-dc-confluence-report-after-scheduled-page-1.png) |
| Visual fixture attachment [`0b4ae50d153ef30a`](current-dc-confluence-visual-report-0b4ae50d153ef30a.pdf) | ![Attachment 0b4ae50d153ef30a, page 1](current-dc-confluence-visual-report-0b4ae50d153ef30a-page-1.png) |
| Visual fixture attachment [`0f713e1d73df3454`](current-dc-confluence-visual-report-0f713e1d73df3454.pdf) | ![Attachment 0f713e1d73df3454, page 1](current-dc-confluence-visual-report-0f713e1d73df3454-page-1.png) |
| Scheduled attachment [`3d19c2731147e60d`](current-dc-confluence-visual-report-3d19c2731147e60d.pdf) | ![Scheduled attachment 3d19c2731147e60d, page 1](current-dc-confluence-visual-report-3d19c2731147e60d-page-1.png) |
| Republished attachment [`80d8449505e5d94a`](current-dc-confluence-visual-report-80d8449505e5d94a.pdf) | ![Republished attachment 80d8449505e5d94a, page 1](current-dc-confluence-visual-report-80d8449505e5d94a-page-1.png) |

The separate current REST-only Confluence fixture `1409030` has no native UI
captures. Its downloaded [before-schedule PDF](current-dc-confluence-report-before.pdf)
and [scheduled PDF](current-dc-confluence-report-after-scheduled.pdf) are kept as
provider/PDF evidence, not relabeled as page `1409035`:

![REST-only fixture 1409030, report before schedule, page 1](current-dc-confluence-report-before-page-1.png)

![REST-only fixture 1409030, scheduled report, page 1](current-dc-confluence-report-after-scheduled-page-1.png)

### Current scheduled email

![Current Gmail scheduled PDF receipt](current-email-gmail-receipt-attachment.jpg)

![Current Outlook scheduled PDF receipt](current-email-outlook-receipt-attachment.jpg)

![Current Outlook provider export error](current-email-outlook-eml-download-error.jpg)

![Current email deep link opened to the matching console engagement](current-email-console-deeplink.jpg)

![Current scheduled email PDF preview, page 1](current-email-source-report-page-1.jpg)

Outlook's visible receipt proves delivery of the PDF attachment. The provider
returned errors for native preview, direct download and EML export; no Outlook
PDF rendering or attachment byte-hash claim is made. See
[`current-email-proof.json`](current-email-proof.json).

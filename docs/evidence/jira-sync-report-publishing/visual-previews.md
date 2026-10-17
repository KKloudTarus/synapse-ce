# Continuation visual previews

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

## Jira Cloud

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

## Jira Data Center

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

## Confluence Cloud

Strict group-only restriction and public-link policy views:

![Cloud group-only read and edit restriction](confluence-cloud-group-only-read-edit-en-light.jpg)

![Cloud restrictions dialog](confluence-cloud-restrictions-dialog-en-light.jpg)

Final page footer and scheduled history:

![Cloud final footer](confluence-cloud-final-footer-en-light.jpg)

![Cloud scheduled history](confluence-cloud-scheduled-history-en-light.jpg)

Rendered pages of the downloaded final Cloud PDF:

![Cloud final PDF page 1](confluence-cloud-final-pdf-page-1.png)

![Cloud final PDF page 2](confluence-cloud-final-pdf-page-2.png)

## Confluence Data Center

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

## Final scheduled PDF email

A real weekly occurrence at 23:33 Asia/Ho_Chi_Minh delivered to both verified personal recipients. Gmail opened the final two-page PDF. Outlook received the same attachment; its native preview service returned a document-preview creation error. Both browser-staged downloads contain complete PDF bytes matching the source SHA-256, but Edge did not finalize the downloads. The [mail proof](scheduled-email-provider-proof.json) distinguishes these states.

![Gmail opened scheduled PDF](gmail-scheduled-pdf-open-en-dark.jpg)

![Outlook received final scheduled PDF](outlook-scheduled-pdf-received-en-light.jpg)

## Automatic fresh Cloud publication

The normal Create command completed in one attempt with no manual ACL repair or resume. The configured one-member group is the only direct principal. Republish produced version 3, and a real weekly occurrence produced version 4 on the same page. The three PDF attachments have two unique byte hashes; both distinct PDFs are previewed below.

![confluence cloud automatic body en light](confluence-cloud-automatic-body-en-light.jpg)

![confluence cloud automatic restrictions en light](confluence-cloud-automatic-restrictions-en-light.jpg)

![confluence cloud automatic footer en light](confluence-cloud-automatic-footer-en-light.jpg)

![confluence cloud automatic history en light](confluence-cloud-automatic-history-en-light.jpg)

![confluence cloud automatic confirmed pdf page 1](confluence-cloud-automatic-confirmed-pdf-page-1.png)

![confluence cloud automatic open pdf page 1](confluence-cloud-automatic-open-pdf-page-1.png)

## Automatic fresh Data Center publication

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

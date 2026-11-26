# Notification delivery acceptance

Use this page to find evidence for template previews, digests and personal notification
delivery. For setup and operation, see [Notifications and webhooks](notifications.md).

## Current acceptance scope

The [Integration EPIC closure][closure] records the completed implementation. The
remaining real-client evidence lives in [#1576][backlog], including the preview/test
pairs and digest captures transferred from [#1374][preview] and [#1377][digest].
The Teams personal delivery implementation and acceptance suite shipped, with the
live work-tenant journey still pending in [#1576][backlog]. See the
[provider prerequisites and evidence limits](notification-events-e2e.md#remaining-environments).

## Acceptance ledger

| Surface | Evidence and scope |
| --- | --- |
| Console preview and send test | The [paired console/client manifest](assets/notification-preview-client-evidence.json) binds previews to native receipts with the normalization limits stated per client. The [preview state manifest](assets/notification-preview-state-evidence.json) covers loading, errors and missing compatible channels. Send test queues a fixture using an immutable template snapshot. Raw-event webhooks bypass templates. |
| Hourly and daily digests | The [finding-only delivery receipt](assets/notification-live-delivery-evidence.json) covers 24 Slack, Telegram and Google Chat deliveries and a worker restart. The [mixed-event receipt](assets/notification-mixed-delivery-evidence.json) covers multiple event types. These runs exercised controlled windows with synthetic subjects. |
| Mail and Discord | The [native receipt manifest](assets/notification-mail-delivery-evidence.json) records Gmail and Outlook Message-ID matches and Discord provider IDs. Outlook received messages sent through Google OAuth SMTP. Microsoft SMTP remains pending. |
| Personal delivery and routing | The [historical state matrices][archive] cover inbox and bell behavior, routing-rule pickers, verified contacts and canonical assignees. Earlier Slack linking and DM evidence retains its original tested revision. Teams still needs live linking, delivery and console navigation in an authorized tenant. |
| Local verification | The [local evidence record](assets/notification-delivery-evidence.json) links the tested builds, stack, transport and regression checks. Local browser and transport fixtures cover their own boundaries. |

For checks that cross systems, correlate the source or fixture, event, delivery
attempt and provider receipt. Use the client view to check rendered content and
open the console link to verify its destination. Record the provider, locale,
data class and revision for each journey exercised.

The [full historical ledger][archive] retains the dated runs, operator notes,
screenshots, PostgreSQL checks, and separate evidence for inbox, pickers and contacts.

[closure]: https://github.com/KKloudTarus/synapse-ce/issues/1327#issuecomment-7122553225
[backlog]: https://github.com/KKloudTarus/synapse-ce/issues/1576
[preview]: https://github.com/KKloudTarus/synapse-ce/issues/1374
[digest]: https://github.com/KKloudTarus/synapse-ce/issues/1377
[archive]: https://github.com/KKloudTarus/synapse-ce/blob/4c851d90902a7db8925351d1f579b70064258fa3/docs/guide/notification-delivery-acceptance.md

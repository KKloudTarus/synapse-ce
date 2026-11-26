# Notification event live validation

Use this ledger to trace representative notification journeys from a source operation
through the durable worker to a provider receipt. For configuration, see
[Notifications and webhooks](notifications.md) and [Notification channels](notification-channels.md).
The [full historical ledger][archive] keeps each run's environment, dates, screenshots
and limits.

## Delivery and boundary evidence

The October 13 run exercised API-produced finding, scan, SLA and risk-acceptance
events on an isolated Compose stack. Across the main run and its severity follow-ups,
251 of 260 logical deliveries completed in one attempt. Nine expired warnings were
cancelled before a provider request. The [source and delivery receipt][source] records
projection and attempts for Slack, Google Chat, Telegram, Discord and the webhook
receiver. The [signature receipt][signature] verifies the receiver's actual raw body
and timestamp header. See the [historical client captures][client] for their
locale, data class and viewport.

The run also checked activation, restart and replay, along with foreign-tenant 404
responses and startup refusal with notifications disabled or the vault key missing
or invalid. The [activation][activation], [tenant isolation][tenant] and [startup][startup]
receipts preserve these checks.

## Functional follow-up

| Journey | Representative evidence |
| --- | --- |
| Findings, SLA and scan recovery | The [historical follow-up][follow-up] links all three retest outcomes, stale-version denial, one capped reminder with a controlled clock, and stale-scan/dead-letter recovery. |
| JSM and self-hosted chat | The [JSM receipt][jsm] records real alert operations. The [HTTP fixture receipt][self-hosted] records Mattermost and Rocket.Chat checks through an explicit local transport. |
| Tenant relay and Gmail | The [relay rollout receipt][relay] records relay configuration and fallback. The [Gmail receipt][gmail] binds four self-mail deliveries, EN/VI finding content and worker restart to the tested runtime. |
| Governed response and custody | The [response receipt][response] binds the authorized stop, independently verified restart and Slack deliveries. The [custody receipt][custody] records an isolated chain failure, report denial and one delivered alert. |
| Governed cloud assessment | The [Azure CSPM receipt][cspm] records partial inventory with explicit gaps and one Vietnamese Slack delivery. |
| Governed recon and HTTP verification | The [HTTPX receipt][recon] covers an owned local fixture. The [HTTP verifier receipt][dast] covers one approved GET with signed evidence and one Slack delivery. |

The [lifecycle manifests](notification-lifecycle-events.md#local-evidence-artifacts)
capture distinct channel and console evidence. Each receipt supports its recorded
operation, runtime and client. Check the original evidence before generalizing to
another provider, release, device or full production load.

## Remaining environments

The [Integration EPIC closure][closure] records that the implementation shipped.
[#1576][backlog] owns the remaining acceptance evidence. Four setups were unavailable
at closure.

| Setup | Evidence still needed |
| --- | --- |
| Microsoft Teams | An authorized work tenant with an installed test bot. Exercise the real 1:1 link, verified contact, delivery history and console navigation. |
| Microsoft SMTP / Outlook | An authorized Exchange mailbox and SMTP entitlement. Outlook client receipts sent through Google OAuth SMTP do not cover this transport. |
| SharePoint / OneDrive Business | A Business site or drive with authorized restricted-reader access. |
| Google Chat | A current eligible Workspace space with incoming webhooks enabled. Historical receipts retain their original scope. |

Okta, Google Workspace identity, PingOne and live PagerDuty are outside this
acceptance scope. [#962][identity] tracks the three identity certifications.

[archive]: https://github.com/KKloudTarus/synapse-ce/blob/4c851d90902a7db8925351d1f579b70064258fa3/docs/guide/notification-events-e2e.md
[client]: https://github.com/KKloudTarus/synapse-ce/blob/4c851d90902a7db8925351d1f579b70064258fa3/docs/guide/notification-events-e2e.md#client-inspection
[follow-up]: https://github.com/KKloudTarus/synapse-ce/blob/4c851d90902a7db8925351d1f579b70064258fa3/docs/guide/notification-events-e2e.md#functional-follow-up
[closure]: https://github.com/KKloudTarus/synapse-ce/issues/1327#issuecomment-7122553225
[backlog]: https://github.com/KKloudTarus/synapse-ce/issues/1576
[identity]: https://github.com/KKloudTarus/synapse-ce/issues/962
[source]: assets/ui/notification-events/live/source-delivery-receipt.json
[signature]: assets/ui/notification-events/live/webhook-signature-receipt.json
[activation]: assets/ui/notification-events/live/activation-receipt.json
[tenant]: assets/ui/notification-events/live/tenant-isolation-receipt.json
[startup]: assets/ui/notification-events/live/startup-guards-receipt.json
[jsm]: assets/ui/notification-events/live/jsm-source-delivery-receipt.json
[self-hosted]: assets/ui/notification-events/live/self-hosted-http-receipt.json
[relay]: assets/ui/notification-events/live/tenant-relay-rollout.json
[gmail]: assets/ui/notification-events/live/gmail-smtp-live.json
[response]: assets/ui/notification-events/live/governed-process-response.json
[custody]: assets/ui/notification-events/live/functional-followup.json
[cspm]: assets/ui/notification-events/live/cspm-azure-live.json
[recon]: assets/ui/notification-events/live/recon-live.json
[dast]: assets/ui/notification-events/live/dast-verifier-live.json

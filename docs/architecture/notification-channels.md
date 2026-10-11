# Notification delivery channels

The delivery pipeline already owns admission, encrypted configuration versions,
rendering, retries, health and audit records. Additional chat, mail and pager
providers extend its existing ports and registry.

Credentials remain write-only and sealed with tenant-scoped authenticated context.
Transport results contain bounded codes, never upstream errors or credential URLs.
Self-hosted chat and tenant SMTP destinations require exact operator host approval.
SMTP tenant overrides permit only ports 465 and 587 and verified TLS certificates.
An absent tenant override uses the operator relay; an invalid override fails closed.

Mail recipients must have an active verified contact in the same tenant or an
exact domain whose DNS TXT record proves that tenant's control. Admission and
delivery both check this policy. Administrators can remove domains or the tenant
relay. Test-send admission locks the channel and permits five events per hour;
multiple recipients of one event consume one slot.

Chat anchors are scoped to tenant, channel, destination version and subject.
Only successful, fenced delivery completion can publish a remote reference.
Concurrent first sends may both post at top level; follow-ups select the earliest
successful acknowledgement, ordered by delivery time and ID. No database lock spans a provider call. Missing or
deleted anchors allow a top-level post. Google Chat uses a deterministic scoped
thread key. The Slack bot adapter consumes the same anchor contract and retries once
at top level only when Slack explicitly reports a missing parent thread.

Pager identities use an HMAC-derived tenant key and the trusted subject identity.
Resolve requests require a prior successful trigger to the same destination.
Custom details are restricted to signal data regardless of channel configuration.
JSM uses the current integration events API with an integration API key.
An accepted asynchronous request is recorded separately from an acknowledged
alert reference. The worker commits its request ID with the fenced retry
transition before checking completion on a later attempt. Restarts resume the
status read; a missing or pending status never becomes a subject anchor. The
request ID stays internal and is cleared when delivery is acknowledged.
There remains an unavoidable crash window between provider acceptance and the
local commit: alias deduplication prevents another open alert, but the provider
may increment its occurrence count if the accepted response was lost.

Apply additive migrations before API and worker deployment. Disable affected
provider types to stop outbound delivery during rollback; preserve delivery
history and encrypted settings. Provider acceptance requires test-account client
captures in addition to local contract and isolation tests.

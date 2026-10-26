# Notification event schemas

Each file below documents the **stored versioned event envelope**, including its `data` object. Raw-mode webhooks serialize this envelope. Default webhooks use the [filtered webhook envelope](../notification-webhook.v1.schema.json), described in [notification content](../../notification-content.md). The source of truth is `internal/domain/notification/catalog.go` (`EventCatalog()`); the same version number is carried in `schema_version`. Fixtures are illustrative, contain no credentials and are checked against their schema by `go test ./internal/domain/notification`.

| Event | Contract and fixture | Maximum data class |
| --- | --- | --- |
| `vulnerability_action.created` — Risk action; severity and engagement | [JSON Schema](vulnerability_action.created.v1.schema.json) · [fixture](vulnerability_action.created.v1.fixture.json) | `detail` |
| `scan.completed` — Persisted scan completion; engagement | [v2 JSON Schema](scan.completed.v2.schema.json) · [v2 fixture](scan.completed.v2.fixture.json) · [v1 JSON Schema](scan.completed.v1.schema.json) · [v1 fixture](scan.completed.v1.fixture.json) | `detail` |
| `quality_gate.failed` — Failed project-analysis gate | [JSON Schema](quality_gate.failed.v1.schema.json) · [fixture](quality_gate.failed.v1.fixture.json) | `summary` |
| `sla.approaching_deadline` — Finding deadline and reminder lead time | [JSON Schema](sla.approaching_deadline.v1.schema.json) · [fixture](sla.approaching_deadline.v1.fixture.json) | `summary` |
| `fleet.agent.offline` — Stale agent heartbeat | [JSON Schema](fleet.agent.offline.v1.schema.json) · [fixture](fleet.agent.offline.v1.fixture.json) | `summary` |
| `incident.created` — Persisted correlated incident; optional engagement/severity | [JSON Schema](incident.created.v1.schema.json) · [fixture](incident.created.v1.fixture.json) | `detail` |
| `finding.ownership_changed` — Structured finding assignment decision | [JSON Schema](finding.ownership_changed.v1.schema.json) · [fixture](finding.ownership_changed.v1.fixture.json) | `detail` |
| `finding.created` — Immutable finding creation | [JSON Schema](finding.created.v1.schema.json) · [fixture](finding.created.v1.fixture.json) | `detail` |
| `finding.status_changed` — Immutable finding transition | [JSON Schema](finding.status_changed.v1.schema.json) · [fixture](finding.status_changed.v1.fixture.json) | `detail` |
| `finding.retest_completed` — Immutable retest outcome | [JSON Schema](finding.retest_completed.v1.schema.json) · [fixture](finding.retest_completed.v1.fixture.json) | `detail` |
| `scan.failed` — Terminal scan failure | [JSON Schema](scan.failed.v1.schema.json) · [fixture](scan.failed.v1.fixture.json) | `summary` |
| `dast.run_finished` — Terminal DAST run | [JSON Schema](dast.run_finished.v1.schema.json) · [fixture](dast.run_finished.v1.fixture.json) | `summary` |
| `recon.run_finished` — Terminal recon run | [JSON Schema](recon.run_finished.v1.schema.json) · [fixture](recon.run_finished.v1.fixture.json) | `summary` |
| `cspm.run_finished` — Terminal cloud posture run | [JSON Schema](cspm.run_finished.v1.schema.json) · [fixture](cspm.run_finished.v1.fixture.json) | `summary` |
| `sla.breached` — Durable remediation breach | [JSON Schema](sla.breached.v1.schema.json) · [fixture](sla.breached.v1.fixture.json) | `summary` |
| `risk_acceptance.created` — Risk acceptance recorded | [JSON Schema](risk_acceptance.created.v1.schema.json) · [fixture](risk_acceptance.created.v1.fixture.json) | `summary` |
| `risk_acceptance.expiring` — Risk acceptance expiry warning | [JSON Schema](risk_acceptance.expiring.v1.schema.json) · [fixture](risk_acceptance.expiring.v1.fixture.json) | `summary` |
| `risk_acceptance.expired` — Risk acceptance expired | [JSON Schema](risk_acceptance.expired.v1.schema.json) · [fixture](risk_acceptance.expired.v1.fixture.json) | `summary` |
| `engagement.created` — Engagement authorization created | [JSON Schema](engagement.created.v1.schema.json) · [fixture](engagement.created.v1.fixture.json) | `summary` |
| `engagement.status_changed` — Engagement lifecycle transition | [JSON Schema](engagement.status_changed.v1.schema.json) · [fixture](engagement.status_changed.v1.fixture.json) | `summary` |
| `engagement.window_starting` — Authorization window reminder before start | [JSON Schema](engagement.window_starting.v1.schema.json) · [fixture](engagement.window_starting.v1.fixture.json) | `summary` |
| `engagement.window_ending` — Authorization window reminder before end | [JSON Schema](engagement.window_ending.v1.schema.json) · [fixture](engagement.window_ending.v1.fixture.json) | `summary` |
| `finding.commented` — Finding comment with a bounded detail excerpt | [JSON Schema](finding.commented.v1.schema.json) · [fixture](finding.commented.v1.fixture.json) | `detail` |
| `finding.mentioned` — Validated user mention on a finding | [JSON Schema](finding.mentioned.v1.schema.json) · [fixture](finding.mentioned.v1.fixture.json) | `signal` |
| `approval.requested` — Governed agent or response approval requested | [JSON Schema](approval.requested.v1.schema.json) · [fixture](approval.requested.v1.fixture.json) | `summary` |
| `approval.decided` — Governed agent or response approval decided | [JSON Schema](approval.decided.v1.schema.json) · [fixture](approval.decided.v1.fixture.json) | `summary` |
| `approval.timed_out` — Governed approval expired without a decision | [JSON Schema](approval.timed_out.v1.schema.json) · [fixture](approval.timed_out.v1.fixture.json) | `summary` |
| `incident.updated` — Incident status, owner or disposition update | [JSON Schema](incident.updated.v1.schema.json) · [fixture](incident.updated.v1.fixture.json) | `summary` |
| `response.finished` — Governed response terminal outcome | [JSON Schema](response.finished.v1.schema.json) · [fixture](response.finished.v1.fixture.json) | `detail` |
| `report.generated` — Sealed report artifact; engagement and severity | [JSON Schema](report.generated.v1.schema.json) · [fixture](report.generated.v1.fixture.json) | `detail` |
| `evidence.chain_broken` — Mandatory critical evidence-chain verification alert | [JSON Schema](evidence.chain_broken.v1.schema.json) · [fixture](evidence.chain_broken.v1.fixture.json) | `summary` |
| `notification.destination_changed` (operator-only) — channel destination notice | [v2 JSON Schema](notification.destination_changed.v2.schema.json) · [v2 fixture](notification.destination_changed.v2.fixture.json) · [JSON Schema](notification.destination_changed.v1.schema.json) · [fixture](notification.destination_changed.v1.fixture.json) | `summary` |
| `notification.channel_paused` (operator-only) — automatic channel pause notice to tenant admins | [JSON Schema](notification.channel_paused.v1.schema.json) · [fixture](notification.channel_paused.v1.fixture.json) | `summary` |
| `notification.test` (operator-only) — channel test | [JSON Schema](notification.test.v1.schema.json) · [fixture](notification.test.v1.fixture.json) | `signal` |

| `notification.digest` (operator-only) — closed UTC digest window | [JSON Schema](notification.digest.v1.schema.json) · [fixture](notification.digest.v1.fixture.json) | `detail` |

## Version and compatibility

The v1 envelope contains `id`, `type`, `source_kind`, `source_id`, `schema_version`, `occurred_at` (RFC 3339) and `data`. `engagement_id` and `severity` appear only when supplied by the producer. `tenant_id` is intentionally omitted. An event's `source_kind` and `source_id` describe its idempotency origin; `type` describes the public event kind. Do not construct private/internal links by concatenating untrusted payload values.

**Additive optional fields** may be introduced without changing the schema version; unknown fields are accepted via `additionalProperties: true` so existing consumers remain compatible. **Renaming, removing or changing an existing field's type or meaning requires a new `schema_version` and a new versioned schema and fixture**. Never silently change an existing v1 contract. A new event type also needs its own schema and fixture. A test checks every `EventCatalog()` entry, validates both files and rejects stale schema/fixture pairs.

This directory covers every catalog entry, including configurable lifecycle and run events plus operator-only event types. Operator-only events cannot be selected as routing rules. These schemas describe event structure; the pipeline filters the scrubbed template context to the effective data class before external rendering. Raw event mode requires audited administrator opt-in on a detail webhook and remains subject to engagement suppression and signal caps. For `incident.created`, an incident without an asset carries `data.asset_id: ""` (an empty string, never `null`). See [Notifications and webhooks](../../notifications.md) for routing, retries, signature verification and retention.

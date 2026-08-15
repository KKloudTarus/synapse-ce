# Remediation SLA governance

Synapse can turn finding risk into a governed remediation clock. The feature builds on the pure,
deterministic SLA scorer and adds the operational pieces needed to use its output safely:

- tenant-owned, versioned policy;
- immutable, reproducible assessments and history;
- one current assessment pointer per finding;
- a separate human-owned remediation lifecycle;
- append-only transition evidence; and
- reassessment when continuous vulnerability intelligence changes.

It is off by default:

```bash
SYNAPSE_SLA_ENABLED=true
```

After enabling it, a new scan assesses every persisted finding. When continuous vulnerability
intelligence projection is also enabled, a material change to CVSS, KEV, EPSS, public exploit,
active exploitation, or fix availability creates a new SLA assessment. A new source risk-assessment
ID with the same SLA-relevant facts is provenance-only and cannot move the existing deadline.

## Safety model

SLA scoring and remediation workflow are deliberately separate.

The scorer owns machine-derived facts: score, tier, explanation, due dates, config version, input
hash, and source assessment. The remediation lifecycle owns human decisions: open, mitigating,
remediated, accepted risk, reason, compensating control, actor, and acceptance expiry.

This boundary enforces several invariants:

1. A scanner or intelligence refresh may advance the current assessment pointer but cannot change a
   lifecycle status, reason, actor, accepted-risk expiry, or optimistic version.
2. Replaying identical material input returns the original immutable assessment. Its deadlines do
   not move forward just because another scan ran.
3. A changed input or policy creates another assessment linked through `previous_assessment_id`.
4. Accepted risk is effective only before its expiry. At and after expiry every read treats the
   lifecycle as open, even if a scheduler did not run.
5. Machine principal families (`agent:`, `llm:`, `mcp:`, `system:`, `machine:`, `bot:`, and
   `service:`) cannot make a remediation decision.
6. Remediated is terminal for automatic and ordinary manual transitions. New intelligence creates
   reassessment and the existing re-exposure review action; it does not silently reopen the human
   workflow.

## Default policy

The built-in `sla-v1` policy is installed for a tenant on first use. It scores a bounded `0..100`
urgency from these factors:

| Factor | Maximum points | Notes |
| --- | ---: | --- |
| Severity | 35 | Uses CVSS base score when available, otherwise the severity label. |
| Exploitability | 25 | KEV is maximal; EPSS is mapped through stable bands. |
| Threat intelligence | 10 | Active exploitation has full weight; public PoC has half. |
| Exposure | 15 | Unknown is neutral rather than falsely safe. |
| Asset criticality | 15 | Unknown is neutral rather than falsely safe. |
| Feasibility relief | -15 | A bounded relief; it cannot make the score negative. |

Deterministic overrides then apply:

- active exploitation becomes emergency;
- KEV on an externally exposed asset escalates one tier; and
- a non-KEV vulnerability without a patch routes to the governed exception tier.

Overrides may escalate urgency or route to exception. They cannot silently de-escalate a score.

Default due windows are:

| Tier | Mitigate within | Remediate within |
| --- | ---: | ---: |
| Emergency | 1 day | 7 days |
| Critical | 3 days | 15 days |
| High | 7 days | 30 days |
| Medium | 30 days | 90 days |
| Low | 90 days | 180 days |
| Exception | 30 days | 180 days |

The scanner currently maps only facts it owns. It does not infer asset criticality or network
exposure from source reachability. Those inputs stay unknown/neutral unless a future governed asset
binding supplies them. Continuous intelligence retains additional public-exploit and active-
exploitation reason codes that are not present on a legacy finding row.

## Web workflow

Open an engagement and select **Remediation SLA**. The view shows:

- overdue, emergency, accepted-risk, and remediated counts;
- current tier and explainable score;
- mitigate-by and remediate-by timestamps;
- effective workflow state and optimistic version; and
- the policy version that produced the assessment.

A reviewer can transition a non-terminal finding. Every transition requires a reason. Accepted risk
also requires a compensating control and an explicit future expiry. If another reviewer or a risk
refresh changed the record, the request returns a conflict; reload and decide against the current
version.

## HTTP API

Read operations require `view`; transitions require `review`; policy activation requires
`administer`.

```text
GET  /api/v1/engagements/{engagement}/slas
GET  /api/v1/engagements/{engagement}/slas/{finding}
GET  /api/v1/engagements/{engagement}/slas/{finding}/assessments
GET  /api/v1/engagements/{engagement}/slas/{finding}/events
POST /api/v1/engagements/{engagement}/slas/{finding}/transition
GET  /api/v1/sla/policies
POST /api/v1/sla/policies
```

Example mitigation transition:

```json
{
  "to": "mitigating",
  "reason": "Emergency maintenance is approved",
  "version": 1
}
```

Example accepted-risk transition:

```json
{
  "to": "accepted_risk",
  "reason": "The supported vendor upgrade is scheduled",
  "compensating_control": "WAF rule and network isolation",
  "acceptance_expires_at": "2026-09-30T17:00:00Z",
  "version": 2
}
```

Policy activation takes the complete declarative `Config` object under `config`. Go durations are
encoded as integer nanoseconds in this API version. The server validates the version, weights,
strictly descending thresholds, every due range, and a SHA-256 digest before it can become active.
An existing version cannot be rewritten with different content.

## Persistence and tenant isolation

Migration `0103_sla_governance.sql` creates six tables:

- `sla_policies` and `sla_active_policies`;
- `sla_assessments` and `sla_current_assessments`; and
- `sla_lifecycles` and `sla_lifecycle_events`.

Every table carries `tenant_id`, enables and forces PostgreSQL row-level security, and is accessed
through a tenant-bound transaction. Composite foreign keys bind assessments to the exact
tenant/engagement/finding. The in-memory adapter implements the same tenant checks for development
and tests.

Assessment writes serialize on the stable tenant/engagement/finding identity. This protects the
first-write case where no row exists to lock and ensures concurrent material updates produce a
single ordered history rather than sibling assessments with the same predecessor.

## Rollout guidance

1. Apply migrations with the DDL owner and run the API with a non-superuser, non-`BYPASSRLS`
   runtime role.
2. Enable SLA governance in a test tenant and run a scan.
3. Inspect the Remediation SLA tab and confirm policy/due windows match your program.
4. Exercise accepted-risk expiry and optimistic conflicts with reviewer accounts.
5. If continuous intelligence is enabled, change an advisory signal and confirm the assessment
   advances while human lifecycle state stays unchanged.
6. Activate a tenant-specific policy only after review; existing assessments remain historical and
   adopt the new version only when explicitly reassessed.

Disabling `SYNAPSE_SLA_ENABLED` removes routes and stops new assessments. It does not delete policy,
assessment, lifecycle, or event history, so rollback is non-destructive.

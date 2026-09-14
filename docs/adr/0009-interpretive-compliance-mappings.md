# ADR 0009: Interpretive compliance framework mappings

- Status: Accepted (decision: **DEFER**)
- Date: 2026-09-13
- Issue: #1041 (EPIC #1034, maps D6.6)

## Context

Synapse maps a finding to compliance controls through a **curated, human-reviewed reference table**
(`internal/domain/compliance`). Every entry is a verbatim lookup of published guidance, never inferred at
runtime, so a compliance tag is auditable and the report path stays LLM-free. Five frameworks are mapped
today, each because it publishes a direct, per-CWE or per-control condition Synapse detection matches exactly:

- OWASP Top 10 2021 (per-category CWE lists)
- PCI DSS 4.0 requirement 6.2.4 (only the attack classes it explicitly names)
- ISO/IEC 27001:2022 A.8.28 (Secure coding)
- CIS AWS Foundations Benchmark 3.0 (per-resource controls)
- CIS Kubernetes Benchmark 1.10 (per-manifest predicates)

The open question (D6.6) is whether to add **interpretive** frameworks: NIST 800-53, HIPAA, full PCI DSS
(beyond 6.2.4), and later SOC 2. These frameworks state controls in prose whose applicability to a specific
detection rule requires qualified human semantic judgment; they do not publish a machine-consumable
rule-to-control mapping.

## Decision

**Defer** interpretive framework mappings. Keep the current exclusion: Synapse maps only the five curated
frameworks above. NIST 800-53, HIPAA, full PCI DSS, and SOC 2 remain unmapped until the reopening bar below is
met. This preserves the EPIC #1034 no-false-assurance guardrail: an unmapped control is left explicit, never
presented as satisfied.

A transitive crosswalk (`Synapse rule -> CIS control -> NIST/HIPAA/PCI`) is **rejected outright**, in this
decision and any future implementation: control-set membership is not an equivalence proof, and composing
crosswalks fabricates assurance.

## Alternatives considered

1. **Adopt now, via a direct curated table.** Rejected for now: it requires a per-entry provenance schema, a
   named owner qualified to approve semantic applicability against authoritative control text, and versioned
   OSCAL/catalog control IDs. None of that is in place, and shipping without it risks a wrong control ID,
   which is false compliance assurance, the one forbidden outcome.
2. **Adopt via automatic/bulk or transitive crosswalk mapping.** Rejected outright (see above): not an
   equivalence proof.
3. **Reject permanently.** Not chosen: interpretive mappings are a legitimate future capability if built to
   the direct-curation bar. A permanent rejection would foreclose that without cause.

## Consequences

- Reports and the API continue to enumerate only the five curated frameworks. A user needing NIST/HIPAA/SOC 2
  coverage is told, explicitly, that Synapse does not assess them, rather than shown a partial or inferred
  mapping.
- The existing honesty model is preserved: the per-framework rollup reports each control as `failed` (a
  finding mapped to it) or `not_assessed` (mapped but no finding), and **never `pass`/certified**, with an
  `assessable_controls` denominator, so "failed of assessable" is never mistaken for full-framework
  compliance, certification, or attestation.
- The exclusion is now enforced by a test (`TestInterpretiveFrameworksExcluded`), so an interpretive framework
  cannot be added to the curated table silently, without meeting the reopening bar.

## Reopening conditions

Reopen (file an implementation issue under #1034) only when ALL of the following hold, per framework:

1. A **direct, per-entry** `rule/CWE -> control` mapping, each entry **human-reviewed** against both the exact
   Synapse detection semantics and the authoritative control text. No transitive or bulk automatic mapping.
2. Control **IDs and titles taken verbatim from a versioned authoritative catalog** (e.g. NIST 800-53r5
   OSCAL), with the catalog version recorded per entry.
3. A **provenance schema** (source, reviewer, review date, expiration) and a **named approval owner**
   qualified to judge semantic applicability.
4. A **re-review trigger** when the framework catalog changes or a Synapse rule's detection semantics change.
5. API/UI/report language that keeps a partial mapping visibly distinct from certification, attestation, or
   full-framework assessment.

HIPAA and SOC 2 stay excluded until they independently meet the same bar.

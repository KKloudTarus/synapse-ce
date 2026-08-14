# Promotion Rules

Promotion rules are deterministic, pure-domain policies that propose finding-priority changes
based on cross-pillar signals. They never mutate state directly; a distinct verifier must
confirm the proposal through the judgment gate.

## Rule catalogue

### promotion.escalate.runtime_reachable_exposed

- **Inputs**: publishable reachable judgment, confident internet-exposure path, active detection on a path asset
- **Effect**: escalate (one level toward P1)
- **Confidence**: all inputs confirmed or observed
- **Reversal**: signal loss proposes de-escalation

### promotion.deescalate.deterministic_unreachable

- **Inputs**: publishable deterministic not-reachable judgment
- **Effect**: de-escalate (one level toward P5)
- **Confidence**: deterministic proof
- **Reversal**: a later reachable proof is reevaluated

### promotion.deescalate.corroborating_signal_loss

- **Inputs**: prior applied escalation plus lost or superseded corroborating input
- **Effect**: de-escalate (restores the exact prior priority from the applied escalation event)
- **Confidence**: deterministic signal loss
- **Reversal**: restores the prior escalation's before priority

### promotion.review.uncertain_corroboration

- **Inputs**: plausible runtime corroboration with inferred path or unknown reachability
- **Effect**: flag_for_review (no priority change)
- **Confidence**: uncertain
- **Reversal**: reevaluated when inputs become certain

## Priority boundaries

- Priorities are integers in the range 1..5 (P1 = highest, P5 = lowest).
- Escalation moves exactly one level toward P1. P1 cannot escalate.
- De-escalation moves toward P5. Normal de-escalation (deterministic unreachable) moves
  exactly one level. Signal-loss reversal restores the exact `BeforePriority` recorded in the
  prior escalation event, which may span multiple levels.
- P5 cannot de-escalate.
- `flag_for_review` never changes priority.

## Uncertainty

Any uncertainty token in a proposal forces the effect to `flag_for_review`. Confident
escalation or de-escalation requires all inputs to be fully confirmed or observed. Known
uncertainty tokens:

- `inferred_edge`: the attack path contains inferred (not confirmed) edges.
- `unknown_reachability`: the reachability judgment is not publishable or is `unknown`.

## Input ordering

Inputs are sorted by kind, then by ID, then by evidence ID. The sort is deterministic and
produces stable fingerprints for idempotent reevaluation.

## Fingerprint

The fingerprint is a SHA-256 digest of the complete normalized input state: finding ID, rule
key, sorted inputs, proposed effect, sorted uncertainty tokens, finding version, and
before/after priority. Two evaluations with identical state produce the same fingerprint,
enabling the service layer to skip unchanged proposals.

## Evaluation precedence

The `Evaluate` function returns at most one claim per snapshot, evaluated in this order:

1. Deterministic unreachability (highest precedence when publishable and deterministic).
2. Signal-loss reversal (when a prior escalation exists and its inputs are no longer active).
3. Runtime reachable exposed (when all corroboration signals are present and confident).
4. Uncertain corroboration (when signals are present but confidence is incomplete).
5. No claim (when no rule matches).

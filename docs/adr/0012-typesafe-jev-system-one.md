# ADR 0012: TypeSafe Jev (System One) in Synapse

- Status: Accepted (decision: **evaluate in one opt-in place, as a disagreement detector, behind a
  new port; never as a confirmer and never near numeric or temporal correctness**)
- Date: 2026-10-03
- Relates to: the judgment primitive, `ports.LLM`, `internal/usecase/fptriage`, ADR 0011 (a different
  model family, assessed separately)

## Context

Jev is TypeSafe's model and the first of what the vendor calls "System One" models. It takes a *state*
and a map of typed *questions* and returns typed answers with probability distributions and
confidence. The vendor states the problem it addresses directly:

> "When you need a model to make a judgment that your code will consume, that creates a mismatch: you
> are coercing a text-generation system into outputting structured decisions, then parsing the results
> back into something your code can depend on."

and the mechanism:

> "Jev evaluates typed *questions* against a *state* and returns structured results directly. No text
> generation, no parsing."

Three question primitives exist: **Choice** (one of up to 255 options), **Score** (ordered levels, up
to 10), and **Noul** (a yes/no probability). All questions in a request "are evaluated in parallel and
in isolation against the same *state* in one go", and the vendor claims "adding questions barely
changes the response time". The service is a hosted API: `POST https://api.typesafe.ai/v1/systemone`
with a bearer key.

ADR 0011 assessed Joint-Embedding Predictive Architectures. That record answers a different question;
the two families share nothing but an abbreviation.

## Why the shape fits this codebase

`ports.LLM` already carries the stance the vendor is selling, written before this product was
considered:

> "The model only PROPOSES tool-calls; Go validates + executes."

The same file notes that a caller "whose verdict must be reproducible" asks for temperature 0. So the
architecture already treats a model as a proposer whose output Go has to validate, and the judgment
primitive already forbids a proposer from confirming its own claim or appearing in the report path.
A model that returns a typed value with a probability instead of prose removes the parsing step
between the proposal and the validation, which is the step most likely to fail silently.

The vendor's own list of what Jev is for maps onto three existing surfaces:

| Vendor statement | Synapse surface |
| --- | --- |
| "Score something on a rubric (urgency, quality, risk) and branch on the number" | finding triage and disposition ranking |
| "Check whether a statement is true of a document, message, or record before taking an action" | the verify step of propose, verify, confirm |
| "Route a request to one of a fixed set of destinations, and know how confident that routing is" | routing a candidate finding to accept, suppress or human review |

The false-positive triage path is the one place where this is a drop-in experiment rather than new
machinery. `internal/usecase/fptriage` already runs behind a model port, and
`cmd/synapse-fptriage-eval` already replays "the production false-positive triager in shadow mode over
a versioned, human-reviewed golden dataset" and emits a deterministic report, with
`synapse-fptriage-blind`, `-compare`, `-drift` and `-release` beside it. Measuring a second model
against the incumbent is what that harness was built for.

**It does not fit `ports.LLM`.** That interface is a chat turn: a transcript, a tool catalog, an
optional response schema, a temperature. Jev takes a state and a question map. Adopting it means a new,
narrower port, which is the easier thing to reason about and keeps the orchestrator from branching on
provider.

## Five constraints, in the vendor's own words

**Prompt injection is unaddressed, and this product's inputs are attacker-controlled.** The jaggedness
page for `jev-1.13` states that given adversarial content the model "does not treat it as hostile by
default" and is "vulnerable to injected instructions and misleading framing". Every state Synapse
would send is attacker-reachable: a source file from a hostile contributor or a malicious dependency,
a webhook payload, a DAST response body, a recon banner. A comment in a dependency that reads as an
instruction to mark the finding safe is a realistic input. This alone settles that the model may never
be the thing that closes a finding.

**Calibration is a training objective, not a published measurement.** Every documented pattern
(confidence-gated routing, the "below 0.5 do not act" guidance) depends on the probabilities meaning
what they say. The primer defines calibration correctly, that "outcomes assigned a probability of
`0.2` should occur about 20% of the time", and names the training method as RLCD, with no ECE, Brier
score, reliability diagram or benchmark anywhere in the documentation. The confidence page is also
explicit that its score is a distribution-sharpness summary rather than a calibrated estimate:
confidence for a Choice is `(p_max - 1/n) / (1 - 1/n)`, and the page says TypeSafe's confidence "is one
reasonable way to summarize a distribution, not the only one". A sharp distribution and a correct one
are different properties.

**It cannot do arithmetic or time, and says so.** It "is not a calculator", "does not count reliably"
with error growing with the number of items, Score outputs lack "numerical calibration" for computing
magnitudes, and it "reads dates as text, not as ordered quantities", making ordering, duration and
window checks unreliable. Synapse computes CVSS, counts occurrences, carries byte offsets and line
numbers, enforces an authorization window server-side before any tool runs, and tracks SLA remediation
deadlines. None of those may go near this model.

**It is a hosted API with no documented self-hosted option.** State leaves the deployment. TypeSafe
commits to not training on customer data, publishes a Data Processing Agreement, and offers zero data
retention "for enterprise customers" by contacting sales. For a control plane that customers deploy
themselves and that holds their source and their findings, that makes egress an operator decision
rather than a default, and ZDR a precondition rather than an upsell.

**Two measurable biases.** The model "leans toward the option that comes first" in some Choice cases,
and "accuracy falls as the state grows" with unrelated content acting as a distractor. Both are
controllable (fix or rotate option order and measure the delta; send the minimal evidence window
rather than the whole file) and both have to be measured rather than assumed away.

## Decision

**Rejected: Jev as a confirmer anywhere.** The judgment primitive forbids it and the injection
exposure forbids it independently. It may propose; a deterministic engine or a named human confirms.

**Rejected: Jev anywhere near numeric or temporal correctness.** No CVSS computation, no counting, no
offsets or line arithmetic, no authorization-window evaluation, no SLA deadline logic. The vendor
documents the incapacity and these paths are correctness-critical.

**Rejected: any default-on dependency.** Sending customer code or findings to a third-party API cannot
be a default in a self-deployed security product. Off unless an operator turns it on, with an explicit
egress grant and ZDR in place.

**Accepted for evaluation, opt-in, in one place: the false-positive triage path, as a second
independent proposer.** The deterministic engines and the incumbent triager stay authoritative. Jev
answers the same questions independently, and the interesting output is **disagreement**: where it
differs from the incumbent, the finding is flagged for human review. That shape is what makes the
unmeasured calibration survivable, because a wrong disagreement costs a reviewer a glance while a
wrong verdict would cost correctness. It also exercises the vendor's strongest documented claim, that
many questions in one call cost little more than one, since a finding can be asked several atomic
Nouls at once rather than one compound question.

**Accepted: a new port.** `ports.LLM` is a chat contract and Jev is not a chat model. The seam is a
separate, narrower interface that takes a state and typed questions, with the adapter under
`internal/infrastructure/` like every other provider.

## What to measure before adopting

The existing harness answers all of this without any new machinery, and the bar is set before the
first call rather than after:

1. **Agreement and calibration on the golden corpus.** Run the same findings through Jev and through
   `internal/usecase/sca/testdata/fptriage-golden-v2.json` with `synapse-fptriage-eval` and
   `-compare`. Report precision and recall against the human labels, and plot observed accuracy
   against reported probability in buckets. The documentation does not publish a reliability curve, so
   Synapse measures its own.
2. **Reproducibility.** Send the identical state and questions repeatedly and record whether the
   answer and the probability are stable. The incumbent asks for temperature 0 precisely because a
   verdict in a hash-chained evidence spine has to be reproducible; Jev's documentation says nothing
   about determinism or seeding.
3. **Option-order bias.** Ask the same Choice with options in forward and reversed order and report
   the disagreement rate. The vendor names this bias, so it gets a number.
4. **Injection resistance, adversarially.** Put instruction-shaped text inside the evidence window
   (a code comment telling the model the finding is a false positive) and measure how often the verdict
   moves. The vendor states it is vulnerable; the question is the size of the effect on this corpus,
   because that bounds how much the disagreement signal can be gamed by a hostile dependency.
5. **Cost and latency at scan volume**, against the incumbent, per thousand findings.

Adopt if it beats the incumbent on the human labels while staying reproducible, or if the
disagreement signal catches labelled errors the incumbent misses. Decline if the injection effect is
large, because the input is attacker-controlled by construction.

## Consequences

- No customer data reaches the API before an operator opts in, an egress grant exists, and ZDR is
  agreed. The evaluation above runs on the committed golden corpus, which is already reviewed and
  carries no customer content.
- Synapse's detection stays its own deterministic engines. A second proposer disagreeing with the
  triager is a review signal and never a second, weaker detector beside them.
- The `ai-triage` evaluation gate and its drift command extend to cover a second provider rather than
  being replaced.

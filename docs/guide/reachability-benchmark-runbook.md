# Reachability benchmark runbook

This runbook is the EPIC #1042 / issue #1049 evidence procedure. Its guardrail is simple: a baseline
comparison is valid only when every scorecard carries the same `corpus_digest`; an absent observation is
`no_analysis`, never an uncalled function.

## Automated Go scorecard

The `Reachability Benchmark` workflow runs these checked-in controls.

| Control | Ground truth | Synapse query | OSV-Scanner | Semgrep CE |
| --- | --- | --- | --- | --- |
| `go_osv_jsonparser_delete_called` | `reachable` | SSA call graph | `GO-2026-4514` call analysis | direct `jsonparser.Delete` rule |
| `go_osv_jsonparser_delete_uncalled` | `present_unreached` | SSA call graph | `GO-2026-4514` uncalled analysis | clean result for the same rule |

The advisory is pinned by its vulnerable module version (`github.com/buger/jsonparser@v1.1.1`); its affected
public `Delete` function is recorded by `GO-2026-4514`. The corpus also has small owned-engine controls, for
which an OSS baseline honestly reports `no_analysis`.

The workflow pins OSV-Scanner and Semgrep CE, writes their raw JSON, normalizes it through
`synapse-bench`, and then runs the owned graph test. The test fails when any of these conditions holds:

- the Go recall floor in `internal/usecase/reachbench/corpus/floors.json` is missed;
- the candidate report omits a baseline language;
- candidate positive-reachability recall or precision is below either baseline;
- a baseline and candidate are scored against different corpus digests.

Do not lower a floor to make a PR green. Add a labelled regression case, fix the engine, then raise or retain
the reviewed floor. An external-tool version bump requires reviewing the uploaded raw output and normalized
scorecard before changing a pin.

## Sampled Snyk comparison

Snyk remains a sampled manual comparison because its reachable-vulnerability evidence is account and product
entitlement dependent. A reviewer performs the following for every corpus refresh:

1. Scan the two Go fixture modules with the approved Snyk organization and export the JSON evidence.
2. Record whether the affected function is reached for evidence IDs `GO-2026-4514-called` and
   `GO-2026-4514-uncalled`; retain the original JSON as the review artifact.
3. Save the reviewed labels as `{"observations":[{"evidence_id":"GO-2026-4514-called","label":"reachable"}, ...]}`.
   Convert it with `synapse-bench -mode reachability-snyk-sample` and attach the resulting report beside the
   original output.
4. Verify its `corpus_digest` matches `synapse-owned.json`, then compare precision and recall with the
   same parity rule used by the workflow. Any disagreement is recorded as a corpus review, not silently
   treated as a Synapse win.

The Snyk artifact must contain no credentials, customer source, or finding identifiers beyond the fixture.
It is review evidence rather than an automatic merge requirement; OSV-Scanner and Semgrep CE are the
reproducible CI gates.

## Adding a language

Add labelled called, uncalled, conditional, and no-analysis fixtures only when the language engine has a
deterministic adapter. Give every external baseline selector a stable tool identifier and a fixture-relative
path, add parser tests for its raw output, and add a language-specific ratchet only after a reviewed initial
scorecard exists. This is deliberately additive: a missing capability remains `no_analysis` and cannot be
mistaken for a safe negative.

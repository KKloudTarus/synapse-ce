# Code quality benchmark

Synapse measures its owned code-quality engine against SonarQube Community Edition on a curated,
version-controlled corpus, and records a per-language, per-issue-type scorecard. The benchmark answers one
question: on the same source, does Synapse find the same defects a reference tool finds?

## What it measures

Every corpus fixture is a small source tree with a hand-labelled set of true issues. Each issue carries a
location (file and line) and a SonarQube-compatible type: `bug`, `vulnerability`, `code_smell`, or
`security_hotspot`. Both engines map their detections onto that same type axis, so the comparison never
depends on either tool's rule ids.

A detection matches a labelled issue when it lands in the same file, carries the same type, and falls within
a two-line window. The window absorbs the line-attribution differences between two independent engines on the
same source (a statement versus its enclosing block); it is narrow enough that two distinct issues in a
fixture never collide. Matching is one-to-one per file and type, so two detections cannot both claim one
labelled issue.

The reducer produces, per `language/type` cell, a confusion matrix (true positives, false positives, false
negatives) and the derived precision and recall. It also records a metric-agreement section for the fixtures
that label structural metrics (max cyclomatic complexity, duplicated lines, coverage), counting how often the
engine's measure lands within tolerance of the ground truth.

## The ratchet

The owned engine's recall floors live in `internal/usecase/cqbench/corpus/floors.json`. Floors only rise: a
change that drops a gated cell below its floor fails the benchmark. A cell with no floor is reported but not
gated, so a new fixture can land before a reviewer calibrates a floor. A single loose precision tripwire
catches an all-flagging degeneracy that would otherwise buy recall by reporting everything.

The owned ratchet runs in the normal backend test suite (`TestCodeQualityHeadToHead` in
`internal/infrastructure/cqbenchrun`), so a code-quality regression is caught on every pull request without
standing up SonarQube.

## The head-to-head

The `Code Quality Benchmark` workflow (`.github/workflows/code-quality-benchmark.yml`) runs the external
baseline. It starts a pinned SonarQube CE container, scans the corpus with the pinned SonarQube scanner,
exports the issues and hotspots through the SonarQube web API, and reduces them into the same scorecard the
owned engine produces. Both reports are uploaded as CI artifacts, and the job logs the cell-by-cell
comparison.

The comparison is recorded, not gated. The gate is the owned recall ratchet; the SonarQube column is the
reference the scorecard is read against. The SonarQube image and scanner versions are pinned in the workflow,
so a run is reproducible and a version bump is reviewed as a scorecard diff.

## Extending the corpus

1. Add a fixture directory under `internal/usecase/cqbench/testdata/<fixture>/` with the source that carries
   the defect.
2. Add a case to `internal/usecase/cqbench/corpus/codequality.json` naming the fixture, its language, and the
   labelled issues (file, line, type). Label the true defects a reviewer would flag, independent of which
   engine detects them; an honest miss lowers recall and is exactly what the benchmark is for.
3. Run `go test ./internal/infrastructure/cqbenchrun/...` to see the owned engine's scorecard on the new
   case, then, once satisfied, add or raise the relevant `language/type` floor in `floors.json`.

The corpus is bound to every scorecard by a digest, so a report can only be compared head to head against
another report that measured the identical corpus.

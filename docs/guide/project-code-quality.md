# Project code quality

[Documentation home](README.md) · Next: [Governed assessments](governed-assessment-workflows.md)

A **Project** is a long-lived code-quality identity that accumulates analysis history. It is a separate
aggregate from an [Engagement](governed-assessment-workflows.md), which is a time-bounded security
assessment. Neither owns the other, and both can invoke the same analysis pipeline.

Use a Project when you want to track a codebase over time: issues, security hotspots, measures, ratings,
duplication, coverage, and a quality gate that can block a merge.

![Code Quality project portfolio showing the empty state and project creation action](assets/ui/desktop_code-quality.webp)

*The Code Quality portfolio keeps long-lived projects separate from time-bounded engagements. This sanitized local view contains no repository or customer data.*

## Analyses

An analysis is one deterministic run against a revision. Create one, then read its results:

```
POST /api/v1/projects                                   create a project
POST /api/v1/projects/{key}/analyses                     start an analysis
GET  /api/v1/projects/{key}/analysis-status               poll progress
GET  /api/v1/projects/{key}/analyses                     list history
GET  /api/v1/projects/{key}/analyses/{id}                one analysis
```

Analysis history is append-only, so a rating change is always attributable to a specific run.
`SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT` bounds how long the server waits for completion.

### Source code views

Uploaded project sources land in `SYNAPSE_PROJECT_UPLOAD_DIR`. When an analysis has retainable source,
the dashboard can render annotated code:

```
GET  /api/v1/projects/{key}/analyses/{id}/code/files      inventory
GET  /api/v1/projects/{key}/analyses/{id}/code/file       one file
GET  /api/v1/projects/{key}/analyses/{id}/code/diff       new-code diff
POST /api/v1/projects/{key}/analyses/{id}/source          publish source
```

Only files the analysis listed as retainable are accepted. `synapse-cli publish-source` uploads the
source files an existing analysis listed, so the console can annotate code; it does not upload
findings. To record a pipeline's scan result as an analysis, use
[`synapse-cli scan --server`](cli.md#push-results-to-the-console), which posts the result to
`POST /api/v1/projects/{key}/analyses/import` and marks the analysis `origin: ci`.

## Issues

An issue is a maintainability or reliability finding tracked across analyses. Its lifecycle is a closed
set of human transitions:

| Status | Meaning |
| --- | --- |
| `open` | Newly reported, not yet triaged |
| `confirmed` | A reviewer agrees it is real |
| `accepted` | Knowingly retained; no longer counted as new debt |
| `false_positive` | Not a real defect |
| `wont_fix` | Real, but deliberately not being fixed |
| `fixed` | Resolved and no longer detected |

```
GET  /api/v1/projects/{key}/issues
GET  /api/v1/projects/{key}/issues/{id}
GET  /api/v1/projects/{key}/issues/{id}/history
POST /api/v1/projects/{key}/issues/{id}/transitions
```

Every transition is recorded, so `history` explains how an issue reached its current status and who
decided.

## Security hotspots

A hotspot is security-sensitive code that requires a human judgment rather than an automatic verdict.
Its review lifecycle is deliberately separate from issues:

| Status | Meaning |
| --- | --- |
| `to_review` | Awaiting a reviewer |
| `acknowledged` | Reviewed, needs follow-up work |
| `safe` | Reviewed and judged not exploitable in this context |
| `fixed` | Changed so the sensitive pattern is gone |

```
GET  /api/v1/projects/{key}/hotspots?status=to_review&severity=high
GET  /api/v1/projects/{key}/hotspots/{id}
GET  /api/v1/projects/{key}/hotspots/{id}/history
POST /api/v1/projects/{key}/hotspots/{id}/transitions
```

Hotspots are never auto-resolved. `to_review` is the honest default, and the
`new_security_hotspots_reviewed` gate condition can require reviews on new code before a merge.

## Measures, ratings, and overview

```
GET /api/v1/projects/{key}/overview     current ratings and headline measures
GET /api/v1/projects/{key}/measures     paginated metric history
GET /api/v1/projects/{key}/analyses/{analysisID}/behavioral-hotspots
                                        ranked files from one immutable analysis
```

Measure pagination cursors are signed with `SYNAPSE_MEASURE_CURSOR_SECRET`, which is required in
production. Ratings are A–E grades for security, reliability, and maintainability, computed
deterministically from stored findings.

A metric is reported as unavailable rather than guessed when its analyzer could not run. Complexity and
structural metrics need the `synapse-ast` sidecar; without it they degrade to Go-only counts instead of
reporting a false zero. The Coupling tab derives direct first-party dependencies for Go packages and
JavaScript/TypeScript modules from source imports. It reports afferent coupling (Ca), efferent coupling
(Ce), and instability (`Ce / (Ca + Ce)`) for each module or directory boundary. An isolated module has
no defined instability, and an incomplete dependency graph is shown as unavailable instead of zero.

Complexity is rolled up from functions to files, directories, and the project root only when the AST
report proves that each eligible file was parsed successfully. The Measures complexity view exposes the
current cyclomatic and cognitive totals, signed deltas (`Δ`) against the most recent compatible analysis,
and a measured/eligible coverage count. A negative delta is a real reduction; it is never clamped to zero.
When the previous analysis is on an unknown or incompatible source, or a file was unsupported or failed
to parse, the API returns an unavailable reason and the UI shows `—` instead of inventing a value. Each
delta carries the baseline analysis ID, timestamp, and source ref used to compute it, so a historical
analysis remains reproducible even after later scans are recorded. Legacy analyses without per-file AST
coverage remain readable, but their complexity trend is explicitly unavailable.

The **Behavioral Hotspots** tab combines static complexity with recent change frequency. For each
measured source file, `score = cyclomatic complexity × number of first-parent commits that touched the
path`; files are ranked by score, changes, complexity, and then path. The default comparison depth of
256 evaluates at most 255 commits (one revision is reserved for the boundary). History is collected
without fetching, follows the first-parent chain, treats renames as delete/add paths, and is pinned to
the analysis commit. Results may be `complete`, `partial` (some inventory files lack complexity), or
`unavailable` with a reason; missing history or AST coverage is never represented as a zero score.
Behavioral hotspots are code-maintenance signals, not the separately reviewed **Security Hotspots**, and
they do not add findings or change a quality gate.

Managed server scans require both the confined tool runner and the `synapse-ast` sidecar. Local
`synapse-cli scan --server` uploads the snapshot computed from its checked-out repository. Shallow CI
checkouts must fetch at least `SYNAPSE_PROJECT_GIT_COMPARISON_DEPTH` revisions to obtain the configured
window; Synapse never deepens or otherwise mutates the checkout itself.

## Quality gates

A gate is a named set of conditions evaluated against an analysis. Gates are managed centrally and then
bound to a project:

```
GET    /api/v1/quality-gates
POST   /api/v1/quality-gates
GET    /api/v1/quality-gates/{key}
PUT    /api/v1/quality-gates/{key}
DELETE /api/v1/quality-gates/{key}
PUT    /api/v1/projects/{key}/gate          bind a gate to a project
```

Available metrics include `new_critical`, `new_high`, `new_medium`, `new_issues`, `new_vulnerability`,
`new_secret`, `new_misconfig`, `new_coverage`, `coverage`, `new_duplication`, `duplication_density`,
`maintainability_rating`, `max_efferent_coupling`, `max_instability`, and
`new_security_hotspots_reviewed`. Coupling gate metrics use the maximum complete per-module value;
collection gaps fail closed as unmeasured conditions rather than passing a threshold.

Conditions on `new_*` metrics implement Clean as You Code: a legacy codebase can adopt a strict gate for
changed lines without first repaying all existing debt.

`coverage`, `new_coverage`, and `new_duplication` are measurements rather than counters, and an analysis
may have nothing to measure: no coverage report was supplied, the analysis had no diff, or the diff touched
no line the report knows about. A condition on one of these then fails closed and is reported as
**unmeasured** (`"unmeasured": true` in the API, `no data` in the CLI) rather than being judged against a
0 nobody computed — a `new_duplication <= 3` condition does not pass on the strength of a missing
measurement. `new_coverage` is line coverage over the lines the diff added; `new_duplication` is the share
of those lines that sit inside a duplicated block. The measures snapshot's `new_code_coverage` carries the
specific reason when it is unavailable: `no_coverage_report`, `no_changed_lines`, or
`changed_lines_not_in_report`.

## Quality profiles

A profile decides which rules are active for a language and at what severity:

```
GET    /api/v1/quality-profiles
GET    /api/v1/quality-profiles/{key}
POST   /api/v1/quality-profiles/{key}/copy
POST   /api/v1/quality-profiles/{key}/activate
POST   /api/v1/quality-profiles/{key}/deactivate
POST   /api/v1/quality-profiles/{key}/severity
DELETE /api/v1/quality-profiles/{key}
PUT    /api/v1/projects/{key}/profiles/{language}
```

Built-in profiles are not edited in place. Copy one, adjust the copy, then bind it. To author new rules,
see [Code quality rule authoring](code-quality-rules.md).

## Gate the same rules in CI

The CLI runs the same analyzers without a server or database, so a pipeline can enforce the gate before
a merge:

```bash
synapse-cli gate . --new-code-only --base origin/main --coverage coverage.info
```

See the [CLI guide](cli.md#code-quality-gate-clean-as-you-code) for the gate flags, the code-health
commands, and the exit-code contract.

Next: [Governed assessments](governed-assessment-workflows.md)

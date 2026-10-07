# Scan engine coverage

Synapse records a bounded outcome for each planned scan engine. An outcome separates
whether an engine executed from whether it fully covered its required scope. A finding
is positive evidence; zero findings only supports a clean conclusion when the required
engine coverage is complete.

Each outcome contains the engine name, execution (`completed`, `failed`, `timed_out`,
`cancelled`, or `not_run`), coverage (`complete`, `partial`, `unknown`, or
`not_applicable`), a closed reason code, whether the engine was required, and bounded
numeric counts. `engine_coverage` summarizes required engines only. Dependency
resolution confidence remains a separate signal and does not prove engine coverage.

The CLI, API result, asynchronous job, report, and engagement UI expose the same
server-computed facts. A finished job means the worker reached a terminal state; it
does not mean every engine completed. Results which include retained prior findings
are labelled as such.

After scan execution, publication has one bounded ten-second window to seal and
persist a supported partial result. This allows completed work and partial coverage
to survive an exhausted scan budget. Caller cancellation or worker lease loss still
cancels publication; the window does not extend analyzer execution.

Fatal core failures return an error together with the available attempt diagnostics.
Failed asynchronous jobs retain engine outcomes and coverage. Earlier positive
observations remain available on the returned attempt, but that attempt does not
replace the latest published result or establish sealed coverage proof.

For CI, the established `--fail-on` severity gate remains the default. Add
`--require-complete` when a pipeline must also reject partial or unknown coverage. The
report is emitted before either gate determines the exit code, so the result remains
available for inspection even when a gate fails. With `--json`, the CLI also ends the run
with a summary on stderr, read from these outcomes rather than from warning text: each
required engine that did not complete, its execution and reason, the engines excluded on
purpose, and the source warnings in full.

## Compatibility and rollout

Native scan-run schema v2 stores canonical engine outcomes in the lane record that is
sealed with the run. Existing v1 hashes and the v1 canonicalization fallback remain
unchanged. Historical results without outcomes read as `unknown`; they are not
resealed or regraded.

Deploy the additive migration before enabling v2 writers. Keep readers that understand
both v1 and v2 during rollout and rollback. Older readers do not verify v2 seals, so a
rollback must retain the new readers until v2 data is no longer served. This preserves
the original evidence chain and avoids inventing historical coverage claims.

The migration refuses to drop the new columns while any scan lane or job contains
engine outcomes. For an application rollback, leave the additive columns in place;
removing recorded coverage would discard evidence.

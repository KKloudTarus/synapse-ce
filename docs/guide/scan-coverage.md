# Scan engine coverage

Synapse records a bounded outcome for each planned scan engine. An outcome separates
whether an engine executed from whether it fully covered its required scope. A finding
is positive evidence; complete required-engine coverage is necessary but not sufficient
to conclude that zero findings means clean. Source warnings can identify values that
remain unresolved within an engine's documented evaluation bounds.

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

## SBOM inventory reuse

Inventory caching does not cache advisory matching. A reused SBOM keeps its actual
producer provenance and is matched against the advisory data available to that scan.
Changing producers cannot relabel a cached inventory as another producer's output.

The owned producer bypasses inventory reuse for Maven trees, whose resolution can
change through an external local repository or fetcher without changing the target.
Syft identity includes executable contents and the effective configuration loaded
through the same runner used for generation. Unidentifiable or mutable external
inputs bypass both cache lookup and storage; generation still runs. With a sandbox
runner, use an absolute Syft path to identify its executable rather than assuming
the host and sandbox resolve a bare PATH name identically.

## Passive DAST evidence

A source-map finding requires captured source-map content from a served, nonempty
response. New public-artifact proofs use version 3. Stored versions 1 and 2
remain verifiable under their original rules. The configured-authentication check
matches only its explicit marker in the captured response.

## Infrastructure-as-code capability gaps

The `iac` engine reports partial coverage when a capability could not evaluate its input,
separately from whether the engine executed. A Helm chart that was not rendered is
reported as `unrendered_charts`; a Kustomize overlay that was not rendered is reported as
`analysis_incomplete` with the unassessed input count. Both cases carry a reason naming
what to enable, and the raw manifests behind them are still scanned, so the findings that
were available remain. Execution completing never implies that every input was assessed.

Workspace and materialized image-rootfs coverage are merged conservatively: a successful
pass cannot erase the other's gap. Indexed Kustomizations unreachable from every render
root, including cyclic components, remain unassessed and retain their raw resource findings.
Both passes retain bounded `file:line: attribute` diagnostics for unresolved Terraform
values. Persisted IaC and inventory coverage warnings appear in report scan sections, so image-rootfs
uncertainty is not silently presented as evaluated-and-clean. These diagnostics do not
change complete coverage of the documented bounded capability or the coverage gate.

[Infrastructure-as-code evaluation](iac-evaluation.md) states the full contract, including
the Terraform constructs that are evaluated and the ones that stay unresolved.

## Installed-package catalog bounds

The owned installed-package catalog walks a materialized image root filesystem under a
file cap and a component cap. Reaching either returns the packages found so far and
reports the catalog as a lower bound, naming the bound that was reached. Unreadable
directory entries and regular-file read failures—including installed metadata,
archives and binary candidates—are counted as inventory gaps. Both bounds and read
failures clear the inventory's confidence, mark the `inventory` engine's coverage
partial with `analysis_incomplete`, and add a source warning. The components that
were cataloged are kept and still match advisories.

## Semantic engine selection

Selection and availability are separate facts. The configured flags are the selection, and
whether a process could build the adapter is recorded against it, so an engine that was
asked for and could not run reports `unavailable` with required coverage rather than
`not_selected`. An entry point that does not support a capability at all reports
`not_applicable`; the CLI does this for the semantic taint engines, which run in
`synapse-api` and `synapse-worker`. [CLI](cli.md#engines-the-cli-does-not-run) lists the
contract per entry point.

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

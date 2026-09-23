# Trusted benchmark provisioning

Two benchmark workflows execute on a self-hosted Linux runner because they need a capability hosted
runners do not provide: a delegated cgroup v2 hierarchy for the strict Bubblewrap sandbox, and a
retained trusted input tree that is never published. This page records what must exist before either
can produce non-vacuous evidence, and what each setting means.

Nothing here can be applied by a pull request. Repository variables, runner registration, and the
Actions toggle are account and repository settings; a source change cannot grant itself the capability
to run. Treat this as the checklist a repository owner works through, and the reference a reviewer uses
to confirm a claimed trusted run was actually authorized.

## Current state

Measured through the GitHub API on 2026-09-22:

```text
GET /repos/KKloudTarus/synapse-ce/actions/permissions  -> {"enabled": false}
GET .../actions/variables                              -> {"total_count": 0}
GET .../actions/runners                                -> {"total_count": 0}
GET .../environments                                   -> copilot, github-pages
GET .../branches/main/protection                       -> 404 Branch not protected
```

Actions is disabled repository-wide, so no workflow runs at all today. That is a more categorical
blocker than the missing variables: provisioning every variable and runner below would still produce no
run until Actions is enabled.

## Fork exposure, and why the guards are load-bearing

This repository is public and has forks. A self-hosted runner on a public repository is a documented
code-execution risk, because a workflow triggered by a fork's pull request would otherwise run that
fork's code on the runner host.

Both trusted workflows refuse that by construction. The trust predicate hard-requires a non-pull-request
event before anything else is considered:

```bash
# .github/workflows/engine-accuracy.yml:50
if [ "$EVENT_NAME" != pull_request ] && [ "$ENABLED" = true ] && [ -n "$TRUSTED_SHA" ] \
   && [ "$REF" = "${TRUSTED_REF:-refs/heads/main}" ] && [ "$SHA" = "$TRUSTED_SHA" ]; then
```

`reachability-benchmark.yml:59` applies the same event guard. Each self-hosted job then runs only when
that predicate passed (`engine-accuracy.yml:55-59`, `reachability-benchmark.yml:65-69`), so a fork pull
request routes untrusted and the self-hosted job never dispatches.
`internal/infrastructure/reachbench/workflow_policy_test.go:146-166` pins that event truth table as a
test, so the protection cannot regress silently.

Do not weaken those predicates to make a run happen. A trusted job that dispatches on a pull request is
an arbitrary-code-execution path on the runner host, not a configuration convenience.

## Repository variables

Ten variables are referenced and none exists. Both workflows read them through `vars.*`, so an unset
variable evaluates empty and the trust predicate closes.

### SCA accuracy (`engine-accuracy.yml`)

| Variable | Meaning |
|---|---|
| `ENGINE_ACCURACY_TRUSTED_ENABLED` | Must be exactly `true` for the trusted route to open. |
| `ENGINE_ACCURACY_TRUSTED_REF` | The ref authorized to run, defaulting to `refs/heads/main`. |
| `ENGINE_ACCURACY_TRUSTED_SHA` | The exact 40-character commit authorized to run. |
| `SCA_ACCURACY_TRUSTED_INPUT_ROOT` | Absolute path to the prepared pinned input tree. |
| `SCA_ACCURACY_RAW_RETENTION_ROOT` | Absolute path where protected raw identities are retained until cleanup. |
| `SCA_ACCURACY_DELEGATED_CGROUP_ROOT` | The runner's delegated systemd service cgroup. |

`ENGINE_ACCURACY_TRUSTED_SHA` pins one commit, so it must be re-pointed for each authorized capture.
That is deliberate, because it makes an authorized run name its own subject. It also means a stale value
leaves the benchmark permanently skipped, which the aggregate treats as an untrusted route rather than a
failure.

### Reachability accuracy (`reachability-benchmark.yml`)

| Variable | Meaning |
|---|---|
| `REACHABILITY_BENCHMARK_TRUSTED_ENABLED` | Must be exactly `true`. |
| `REACHABILITY_BENCHMARK_TRUSTED_REF` | The authorized ref; this workflow has no `TRUSTED_REF` default. |
| `REACHABILITY_BENCHMARK_BASELINE_HARNESS_SHA` | Selects the protected-baseline route when it equals the source SHA. Must be a full lower-case SHA or the route job fails. |
| `REACHABILITY_BENCHMARK_CONTROLLER_ROOT` | External controller root, which must resolve outside the checkout. |

This workflow authorizes on ref alone and deliberately has **no** trusted-SHA variable:
`REACHABILITY_BENCHMARK_TRUSTED_SHA` is a forbidden string in
`internal/infrastructure/reachbench/workflow_policy_test.go:37-44`. Do not add one to mirror the engine
workflow; the difference is a recorded decision, and the two aggregates rely on it.

## Runner requirements

Two label sets, both Linux:

```text
[self-hosted, linux, sca-accuracy-trusted]           engine-accuracy.yml:59
[self-hosted, linux, reachability-accuracy-trusted]  reachability-benchmark.yml:69
```

The SCA runner needs a delegated cgroup v2 hierarchy. `cmd/synapse-sca-cycle` requires
`SCA_ACCURACY_DELEGATED_CGROUP_ROOT` to be non-empty and passes it to the sandbox runner, which rejects
any path outside `/sys/fs/cgroup` or outside its `synapse-manager` child, and requires both the `memory`
and `pids` controllers (`internal/infrastructure/sandbox/cgroup_linux.go:51-89`). This is the capability
that rules out a hosted runner and rules out running the capture on a non-Linux host at all.

The reachability runner additionally needs the Go toolchain declared by `go.mod`, .NET SDK `8.0.100`,
and OpenJDK `java`, `javac` and `jar` at `21.0.5`
(`docs/guide/reachability-benchmark-runbook.md:39-47`).

## Trusted input tree

`SCA_ACCURACY_TRUSTED_INPUT_ROOT` must be an existing absolute directory containing only prepared,
pinned data (`docs/guide/sca-accuracy-benchmark.md:23-35`):

```text
trusted-input-root/
  sboms/<target-id>.cdx.json
  tools/{grype,trivy,osv-scanner}
  databases/{owned-debian,owned-sles,owned-redhat,grype,trivy,osv}
  evidence-assets/environment/environment-attestation.json
  repository/
    capability/...
    reviews/github/<one commented review>.json
    reviews/dispositions/github/<one maintainer disposition>.json
```

The review and disposition captures are not optional and cannot be synthesized. A trusted cycle requires
exactly one review whose state is exactly `COMMENTED` and whose `commit_id` equals the implementation
commit, plus exactly one disposition whose `decision` is `approved` and whose `login` differs from the
reviewer's (`internal/infrastructure/scabench/run.go:1383-1429`). A machine identity cannot satisfy both
sides, which is the intended effect.

## Databases will not reproduce a pinned digest today

A capture verifies each prepared database against its catalog pin, and a mismatch fails the capture
(`internal/infrastructure/scabench/capture.go:660-669`). The pinned bytes for the committed corpus are
no longer retrievable: vendors republish these feeds in place, and
`docs/guide/sca-accuracy-benchmark.md:61-82` records that consequence.

Measured 2026-09-22 with `synapse-sca-archive` against the committed catalog: of 17 fetchable pins, 1
archived, 15 could not be verified against their pin, and 1 uses an `oci://` origin that needs a registry
client. So a capture on freshly provisioned infrastructure is **diagnostic measurement**, not acceptance
evidence, until the pinned bytes are archived.

The direct command remains the **raw-origin fetch archive**: it fetches vendors' currently served bytes and
reports each pin as archived, unverified, or unsupported.

```sh
go run ./cmd/synapse-sca-archive \
  --corpus-root ./internal/usecase/scabench/corpus \
  --archive-root /protected/sca-pin-archive
```

Several pins digest something derived from the download rather than the download itself. The grype pin, for
example, is the digest of the `grype` executable inside a release tarball, so an unverified result there is not
evidence the vendor republished.

After a trusted root has been prepared and its catalog pins verify, snapshot that **materialized trusted-input
archive** separately. The corpus binding specification covers every origin-bearing pin and does not change the
raw-origin archive's pin semantics:

```sh
go run ./cmd/synapse-sca-archive collect \
  --corpus-root ./internal/usecase/scabench/corpus \
  --trusted-input-root /protected/sca-inputs \
  --binding-spec ./internal/usecase/scabench/corpus/trusted-input-bindings.json \
  --archive-root /protected/sca-pin-archive \
  --manifest /protected/sca-pin-archive/trusted-input-archive.json
```

Restore that snapshot only into an existing empty directory:

```sh
go run ./cmd/synapse-sca-archive restore \
  --corpus-root ./internal/usecase/scabench/corpus \
  --binding-spec ./internal/usecase/scabench/corpus/trusted-input-bindings.json \
  --archive-root /protected/sca-pin-archive \
  --manifest /protected/sca-pin-archive/trusted-input-archive.json \
  --destination-root /protected/sca-inputs-restored
```

Neither command makes old pins retrospectively archivable. For the committed corpus, vendor bytes that have
already changed at their origins remain unavailable until a future reviewed corpus is pinned and archived while
its prepared inputs still verify.

## Order of operations

1. Enable Actions for the repository. Nothing below has any effect first.
2. Stand up the two Linux runners with the exact label sets, delegated cgroup v2, and toolchains.
3. Build the trusted input tree, including the independent review and the maintainer disposition.
4. Archive pinned vendor bytes and confirm coverage, or accept that the capture is diagnostic.
5. Set the variables. Point `ENGINE_ACCURACY_TRUSTED_SHA` at the exact commit being measured.
6. Dispatch the workflow and confirm the aggregate reports a successful benchmark with a non-empty
   artifact. An aggregate that passes with the benchmark skipped means the route was untrusted.

## Verifying a run was genuinely authorized

A green aggregate alone does not prove a trusted capture happened. Check that the trusted job ran rather
than being skipped, that it carries an uploaded artifact, and that the run's commit equals the
`TRUSTED_SHA` that was configured at the time. `engine-accuracy.yml` requires a successful benchmark and
a non-empty artifact whenever the route was trusted, and requires the benchmark to be skipped when it was
not, so the two cases are distinguishable from the aggregate's own conditions.

# Optional benchmark audit provisioning

The required `engine-accuracy.yml` and `reachability-benchmark.yml` regression gates run on GitHub-hosted Linux. They do not require this provisioning. The optional manual `engine-accuracy-audit.yml` and `reachability-audit.yml` routes use a self-hosted Linux runner for formal evidence capture. This page describes that audit setup only. A skipped or unavailable audit route does not count as a benchmark pass.

Nothing here can be applied by a pull request. Repository variables, runner registration, and the
Actions toggle are account and repository settings; a source change cannot grant itself the capability
to run. Treat this as the checklist a repository owner works through, and the reference a reviewer uses
to confirm a claimed trusted run was actually authorized.

## Historical provisioning snapshot

Measured through the GitHub API on 2026-09-23; do not treat these values as current configuration:

```text
GET /repos/KKloudTarus/synapse-ce/actions/permissions  -> {"enabled": true}
GET .../actions/variables                              -> {"total_count": 10}
GET .../actions/runners                                -> {"total_count": 0}
GET .../environments                                   -> copilot, github-pages, trusted-benchmarks
GET .../environments/trusted-benchmarks                 -> branch_policy only; no required reviewer
GET .../environments/trusted-benchmarks/deployment-branch-policies
                                                       -> feat/1034-wave1-wave2-trusted-evidence only
GET .../branches/main/protection                       -> 404 Branch not protected
```

Actions and the ten variables are present. Both `*_TRUSTED_ENABLED` variables are `false`, no runner is
registered, and the environment has no required reviewer. Its custom policy permits only the current
feature branch, which is also the value of both trusted-ref variables. Trusted jobs therefore remain
skipped; a repository owner must protect the authorized ref and environment and provision an isolated
runner before enabling either trusted route.

## Fork exposure, and why the guards are load-bearing

This repository is public and has forks. A self-hosted runner on a public repository is a documented
code-execution risk, because a workflow triggered by a fork's pull request would otherwise run that
fork's code on the runner host.

Both trusted workflows refuse that by construction. The trust predicate hard-requires a non-pull-request
event before anything else is considered:

```bash
# .github/workflows/engine-accuracy-audit.yml:50
if [ "$EVENT_NAME" != pull_request ] && [ "$ENABLED" = true ] && [ -n "$TRUSTED_SHA" ] \
   && [ "$REF" = "${TRUSTED_REF:-refs/heads/main}" ] && [ "$SHA" = "$TRUSTED_SHA" ]; then
```

`reachability-audit.yml:59` applies the same event guard. Each self-hosted job then runs only when
that predicate passed (`engine-accuracy-audit.yml:55-59`, `reachability-audit.yml:65-69`), so a fork pull
request routes untrusted and the self-hosted job never dispatches.
`internal/infrastructure/reachbench/workflow_policy_test.go:146-166` pins that event truth table as a
test, so the protection cannot regress silently.

Do not weaken those predicates to make a run happen. A trusted job that dispatches on a pull request is
an arbitrary-code-execution path on the runner host, not a configuration convenience.

## Repository variables

Ten variables are referenced. The workflows read them through `vars.*`; an unset
variable evaluates empty and the trust predicate closes. Both trusted-enabled flags currently equal `false`.

### SCA accuracy (`engine-accuracy-audit.yml`)

| Variable | Meaning |
|---|---|
| `ENGINE_ACCURACY_TRUSTED_ENABLED` | Must be exactly `true` for the trusted route to open. |
| `ENGINE_ACCURACY_TRUSTED_REF` | The ref authorized to run, defaulting to `refs/heads/main`. |
| `ENGINE_ACCURACY_TRUSTED_SHA` | The exact 40-character commit authorized to run. |
| `SCA_ACCURACY_TRUSTED_INPUT_ROOT` | Absolute path to the prepared pinned input tree. |
| `SCA_ACCURACY_RAW_RETENTION_ROOT` | Absolute path where protected raw identities are retained until cleanup. |

`ENGINE_ACCURACY_TRUSTED_SHA` pins one commit, so it must be re-pointed for each authorized capture.
That is deliberate, because it makes an authorized run name its own subject. A stale value
skips the benchmark and fails the manual audit aggregate; it cannot produce a green capture.

### Reachability accuracy (`reachability-audit.yml`)

| Variable | Meaning |
|---|---|
| `REACHABILITY_BENCHMARK_TRUSTED_ENABLED` | Must be exactly `true`. |
| `REACHABILITY_BENCHMARK_TRUSTED_REF` | The authorized ref; this workflow has no `TRUSTED_REF` default. |
| `REACHABILITY_BENCHMARK_BASELINE_HARNESS_SHA` | Selects the protected-baseline route when it equals the source SHA. Must be a full lower-case SHA or the route job fails. |
| `REACHABILITY_BENCHMARK_CONTROLLER_ROOT` | External controller root, which must resolve outside the checkout. |

This workflow authorizes on ref alone and deliberately has **no** trusted-SHA variable:
`REACHABILITY_BENCHMARK_TRUSTED_SHA` is a forbidden string in
`internal/infrastructure/reachbench/workflow_policy_test.go:37-44`. Do not add or configure one to mirror
the engine workflow; the difference is a recorded decision, and the two aggregates rely on it.

The trusted runtime also hard-codes baseline revision
`50d205260be412dc2f57736f71d1448a8f58177a`. It must exist in the trusted checkout and remain an ancestor
of the selected source revision. Regenerate the controller review and disposition evidence for the candidate
before claiming a trusted reachability acceptance run; a passing local or stale-evidence run is not acceptance
evidence.

### Owned default readiness (`owned-default-readiness.yml`)

| Variable | Meaning |
|---|---|
| `OWNED_DEFAULT_CANDIDATE_SHA` | The exact 40-character commit that changes the owned-only default. Leave it unset until such a commit exists. |

This workflow runs no trusted job and needs no runner, so it has no enabled flag and no ref variable. Its
evidence suite (comparator-relative accuracy, the committed ratchet, coverage explicitness, the owned-only
path, and graph plus advisory matching) runs on every event regardless of the variable.

The variable selects the one revision that must additionally prove its committed evidence is **current**,
meaning the corpus no longer outruns the last accepted trusted capture. The readiness job decides that by
looking for the acknowledged-debt marker in `internal/usecase/scabench/evidence_currency_test.go` and
reports `evidence_current` in its uploaded readiness report. While the marker is present the value is
`false`, and the aggregate rejects the candidate.

Currency is deliberately asserted only for the candidate revision. Requiring it on every push would leave
this check red on every commit until an accepted capture lands, which would replace a real gate with
standing noise. The same reasoning is recorded inline in `engine-accuracy-audit.yml` for its own trust predicate.

Clearing the debt is a capture step, never a code edit: run an authorized engine-accuracy capture, promote
its result to the accepted baseline, then remove the debt constant and its exemption in the currency test.
Editing the constant without a capture behind it would manufacture the very assurance the gate exists to
withhold.

## Runner requirements

Two label sets, both Linux, are attached to the `trusted-benchmarks` GitHub environment only on their
self-hosted `benchmark` jobs:

```text
[self-hosted, linux, sca-accuracy-trusted]           engine-accuracy-audit.yml
[self-hosted, linux, reachability-accuracy-trusted]  reachability-audit.yml
environment: trusted-benchmarks                       both trusted benchmark jobs
```

The SCA runner needs a delegated cgroup v2 hierarchy. Provision the dedicated runner account with a
running, lingering systemd user manager that can start transient `Delegate=yes` services. The account must
receive the `memory` and `pids` controllers and have access to the Docker daemon. The workflow builds the
cycle binary outside the checkout and starts it as the main process of its own delegated user service.
`scripts/sca-cycle-service.sh` derives `SCA_ACCURACY_DELEGATED_CGROUP_ROOT` from that process's cgroup;
the value is no longer a manually configured GitHub variable. A direct `go run` or ordinary runner-step
process leaves a parent in the service root, preventing the sandbox from enabling those controllers.
The launcher stops its service on cancellation and limits its runtime to 40 minutes. The sandbox rejects
paths outside `/sys/fs/cgroup` or outside its `synapse-manager` child
(`internal/infrastructure/sandbox/cgroup_linux.go:51-89`). These requirements rule out a hosted runner and
a non-Linux capture. The SCA cleanup barrier also invokes `docker container`, `volume`, `image`, and
`builder` prune commands; cleanup failure blocks the cycle.

The reachability runner additionally needs the Go toolchain declared by `go.mod`, .NET SDK `8.0.100`,
and OpenJDK `java`, `javac` and `jar` at `21.0.5`
(`docs/guide/reachability-benchmark-runbook.md:39-47`). Its trusted runtime also requires `unshare` and
`mount`, plus a kernel and runner policy that permit unprivileged user and mount namespaces; it runs
`unshare --user --map-root-user --mount` before creating the private read-only execution environment.

## Trusted input tree

`SCA_ACCURACY_TRUSTED_INPUT_ROOT` must be an existing absolute directory containing only prepared,
pinned data. This layout is the authoritative runtime contract: setup resolves the fixed template identities
under this root rather than retaining template host paths, while the materialized capture manifest retains
absolute runtime paths (with the owned benchmark binary rebound into its private work directory).
`docs/guide/sca-accuracy-benchmark.md:23-35` describes the pinned corpus:

```text
trusted-input-root/
  sboms/<target-id>.cdx.json
  tools/{grype,trivy,osv-scanner,syft}
  databases/{owned-debian,owned-sles,owned-redhat,grype,trivy,osv}
  evidence-assets/environment/environment-attestation.json
  repository/
    capability/...
    reviews/github/<one commented review>.json
    reviews/dispositions/github/<one maintainer disposition>.json
```

The review and disposition captures are not optional and cannot be synthesized. A trusted cycle requires
exactly one strict-v1 review whose state is `COMMENTED`, whose credential-free HTTPS `github.com` pull-request
URL has a `pullrequestreview-<id>` fragment matching its captured ID, and whose `commit_id` equals the
implementation commit. It also requires exactly one strict-v1 maintainer disposition whose `decision` is
`approved`, whose `issuecomment-<id>` pull-request URL fragment matches its captured ID, and whose `login`
differs from the reviewer's. The disposition binds both the review and implementation commits. A machine
identity cannot satisfy both sides, which is the intended effect.

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

1. Confirm Actions is enabled for the repository.
2. Protect the authorized branch and the `trusted-benchmarks` environment with independent required
   review. Align the environment branch policy with both trusted-ref variables.
3. Stand up the two Linux runners with the exact label sets, delegated cgroup v2, Docker for SCA cleanup,
   namespace support for reachability, and the required toolchains.
4. Build the trusted input tree, including the independent review and the maintainer disposition.
5. Archive pinned vendor bytes and confirm coverage, or accept that the capture is diagnostic.
6. Confirm the variables and point `ENGINE_ACCURACY_TRUSTED_SHA` at the exact commit being measured.
7. Dispatch the workflow and confirm the aggregate reports a successful benchmark with a non-empty
   artifact. An aggregate that passes with the benchmark skipped means the route was untrusted.
8. To flip the owned-only default, promote the accepted capture, clear the acknowledged evidence debt,
   then point `OWNED_DEFAULT_CANDIDATE_SHA` at the default-changing commit and confirm
   `owned-default-readiness.yml` reports `evidence_current: true` for it. The gate rejects the candidate
   while the debt marker stands, which is the intended verdict rather than a misconfiguration.

## Verifying a run was genuinely authorized

A green aggregate alone does not prove a trusted capture happened. Check that the trusted job ran rather
than being skipped and that it carries an uploaded artifact. For engine accuracy, also verify that the run's
commit equals the configured `ENGINE_ACCURACY_TRUSTED_SHA`. Reachability deliberately has no trusted-SHA
variable: verify its protected ref, selected source SHA, controller evidence, and the required historical
baseline revision instead. `engine-accuracy-audit.yml` requires a successful benchmark and a non-empty artifact
on an authorized route. An unauthorized dispatch fails the aggregate instead of claiming a pass.

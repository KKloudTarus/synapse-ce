# Command line (synapse-cli)

[Documentation home](README.md) · Previous: [Configuration](configuration.md) · Next: [Architecture](architecture.md)

`synapse-cli` runs the same SCA pipeline as the server, from the command line. It is built for
CI gating. It creates an ephemeral, scope-checked engagement covering the target path, so scope
enforcement is exercised, not bypassed. Nothing is persisted.

Build it with `make build`. The binary lands at `./bin/synapse-cli`.

## RulePack release commands

The `rulepack` command group verifies signed detection-content artifacts, replays their deterministic
fixtures, and evaluates attested release evidence. The RulePack content-signing key and gate-evidence
producer key are supplied independently as standard-base64 text containing raw 32-byte Ed25519 public
keys; neither artifact is allowed to self-authorize an embedded trust key.

```bash
synapse-cli rulepack verify \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub

synapse-cli rulepack replay \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub

synapse-cli rulepack gate \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub \
  --evidence rulepack-gate-evidence.json \
  --evidence-public-key rulepack-evidence.pub \
  --phase promotion
```

| Subcommand / flag | Description |
| --- | --- |
| `rulepack verify` | Recompute the canonical digest and verify the RulePack signature against `--public-key`. Prints the verified pack identity as JSON. |
| `rulepack replay` | Verify the artifact, then run positive fixtures before negative fixtures in deterministic order. Prints replay results as JSON and exits non-zero on any mismatch. |
| `rulepack gate` | Verify both the RulePack and the attested gate-evidence envelope, emit the deterministic gate report, and exit non-zero when the selected lifecycle phase is not eligible. |
| `--artifact <file>` | Signed RulePack JSON. Required by all three RulePack subcommands. |
| `--public-key <file>` | Externally trusted RulePack Ed25519 public key. Required by all three subcommands. |
| `--evidence <file>` | Attested `SignedGateEvidence` JSON. Required by `rulepack gate`. Raw/unattested gate input is rejected. |
| `--evidence-public-key <file>` | Externally trusted Ed25519 key for the evidence producer. Required by `rulepack gate` and intentionally separate from the RulePack content key. |
| `--phase pre-canary\|canary\|promotion` | Which lifecycle threshold to enforce. Default: `promotion`. `pre-canary` requires deployment state `candidate`; `canary` and `promotion` require state `canary`. |

Successful verification/replay/gating exits `0`; a signature, provenance, replay, lifecycle-state, or gate
failure exits non-zero and prints the reason on stderr. `rulepack gate` writes its deterministic report to
stdout after provenance verification even when the requested gate subsequently fails, so CI can retain the
failure evidence. See [RulePack release lifecycle](rulepack.md) for the signed artifact schema, retro-hunt
selector provenance, release-stage ordering, metrics, and rollback semantics.

## Doctor

```
synapse-cli doctor [path] [--json]
```

`doctor` is an offline pre-scan readiness check. It does not run a scan, install tools, or
call the network. It reports optional toolchain availability, dependency markers found in the
target tree, and whether SCA, SAST, secret, misconfig, and code-quality coverage is full,
partial, or unavailable.

```bash
# preview what Synapse can analyze before scanning the current tree
synapse-cli doctor .

# emit structured output for CI or wrapper scripts
synapse-cli doctor . --json
```

## Scan

```
synapse-cli scan <path|image-ref> [flags]
```

| Flag | Description |
| --- | --- |
| `--mode full\|vulnerabilities\|licenses` | What to scan. Default is full. |
| `--fail-on critical\|high\|medium\|low\|info` | Exit non-zero if a finding at or above this severity is present. Default is high. |
| `--image` | Treat the argument as a container image reference, pulled via crane, instead of a local path. |
| `--offline` | Skip the live advisory source and detect with the offline database only. |
| `--ignore-unfixed` | Ignore vulnerabilities that have no fix available. |
| `--detection-priority comprehensive\|precise` | `comprehensive` (default) reports every match. `precise` moves single-source, non-KEV findings into a needs-verify queue that does not trip `--fail-on`. |
| `--include-test` | Also gate on findings in test, fixture, and example paths. They are reported but gate-exempt by default. |
| `--json` | Print the full scan result as JSON to stdout, for machine consumption in CI. |
| `--sarif` | Print a SARIF 2.1.0 report to stdout, ready to upload to GitHub code scanning. Covers every finding kind; SAST, secret and misconfig findings carry a file and line so the platform annotates the exact source line. Findings exempted from the CI gate by verified AI consensus remain present and carry an external suppression with the policy version and reason. `--fail-on` still sets the exit code. |
| `--sbom` | Print the generated CycloneDX SBOM to stdout instead of a findings report. |

`--json`, `--sarif`, and `--sbom` each take over stdout completely, so they are mutually exclusive.
Passing more than one exits `2` rather than silently honoring the last flag.

### Examples

```bash
# fail a build on any high-or-critical vulnerability
synapse-cli scan . --fail-on high

# licenses only
synapse-cli scan . --mode licenses

# scan a container image, offline
synapse-cli scan alpine:3.19 --image --offline
```

The exit code is 0 when no finding meets the `--fail-on` threshold. See
[Exit codes](#exit-codes) for the full contract, which distinguishes a gate result from a usage error.

### Project analysis parity

`synapse-cli scan <local-path>` runs the same governed security scan path used by a Code Quality Project analysis and creates an ephemeral, scope-checked engagement around the target. The CLI does not attach the Project's combined code-quality report, create a Project, retain async job status, or persist the result; use `synapse-cli gate` for local code-quality gating. Git cloning and archive uploads are managed by the server-side Project flow, so clone or extract the source first for a serverless run.

## False-positive gate

A scan of a real repository surfaces findings in test files and deliberately-insecure fixtures. Synapse
handles this in two layers, and neither ever deletes a finding — both are retain-and-mark (the finding
stays in the report, it is only held back from the `--fail-on` gate).

1. **Deterministic test scope.** Findings in test/fixture/example/benchmark/docs paths — including the
   `foo_test.go`, `test_foo.py`, `foo.test.ts`, `foo_spec.rb` file conventions where the test sits beside
   its source — are classified as background scope and are exempt from the gate by default. Pass
   `--include-test` to gate on them too. This alone removes the bulk of the noise.

2. **AI critique (opt-in).** Set `SYNAPSE_FP_TRIAGE_ENABLED=true` with an LLM endpoint configured
   (`SYNAPSE_LLM_BASE_URL`, `SYNAPSE_LLM_API_KEY`, and `SYNAPSE_FP_TRIAGE_MODEL` or `SYNAPSE_LLM_MODEL`).
   After the deterministic pass, the model adjudicates the remaining production-scope first-party source
   findings (SAST/misconfig; secret findings are never sent to the LLM) and returns a typed verdict — `refuted` (suspected false positive),
   `sound`, or `uncertain` — with a confidence. The proposer only advises: single-model output can never
   change the gate. Set `SYNAPSE_VERIFIER_MODEL` to a **different model family** to enable consensus. The
   verifier may use its own `SYNAPSE_VERIFIER_BASE_URL`, `SYNAPSE_VERIFIER_API_KEY`, and explicit
   `SYNAPSE_VERIFIER_PROVIDER`; the proposer provider is `SYNAPSE_FP_TRIAGE_PROVIDER` (defaulting to
   `SYNAPSE_LLM_PROVIDER`). The verifier runs first
   with only the finding and source context; it never sees the proposer verdict.
   Provider prefixes, dated aliases, and Amazon Bedrock geographic/global inference-profile IDs are
   canonicalized fail-closed so one model family cannot verify itself under two names. Set
   `SYNAPSE_FP_TRIAGE_INDEPENDENCE=provider` to require both a different provider and a different model
   family; missing/unknown identity metadata leaves triage advisory-only. Provider/model-family/policy
   metadata is retained in the scan evidence. The rollout mode
   defaults to `SYNAPSE_FP_TRIAGE_MODE=shadow`: Synapse stores `would_gate_exempt` for measurement,
   always forces `gate_exempt=false`, and keeps the finding gating. Set the mode explicitly to `enforce`
   only after the evaluation threshold is approved. In enforced mode, a finding is gate-exempt only when
   both models independently refute it at/above the bar and the deterministic
   human-review floor permits it. High/critical findings, secrets, and dangerous injection/auth/access-
   control/SSRF/traversal/upload/deserialization CWEs always stay gating.

   Every finding remains in JSON/SARIF/compliance. The `ai_triage` JSON separates `suspected_fp`,
   `verified`, `gate_exempt`, and `review_required`, and carries model/prompt/policy metadata. These
   fields are sealed into the scan evidence hash-chain when a ledger is configured. The standalone CLI
   currently has no evidence vault, so AI triage there is advisory-only and never exempts the gate. Model,
   verifier, or evidence availability failure leaves the gate unchanged.

   Per scan, Synapse attempts at most `SYNAPSE_FP_TRIAGE_MAX_FINDINGS=100` eligible findings with
   `SYNAPSE_FP_TRIAGE_CONCURRENCY=6` simultaneous assessments by default. A distinct verifier can make
   at most two provider calls per attempted finding. If the cap is reached, selection is deterministic,
   every skipped finding remains reported and gating, and `ai_triage_budget` plus the CLI warning expose
   eligible, attempted, and skipped counts. Accepted ranges are `1..1000` findings and `1..32` concurrent
   assessments; zero, negative, malformed, and over-limit values restore the safe finite defaults.
   A second reservation guard defaults to `SYNAPSE_FP_TRIAGE_MAX_TOKENS=1000000`. Optional micro-USD
   pricing and `SYNAPSE_FP_TRIAGE_MAX_COST_MICRO_USD` add a strict cost ceiling. Reservations happen
   before either model is contacted, so a finding that does not fit receives no partial verifier call
   and remains gating. Repeated provider or invalid-output failures open a bounded circuit and keep the
   remaining findings advisory-only until its cooldown probe succeeds. API deployments expose the
   resulting request, latency, timeout, parse, token/cost, disagreement, exemption and alert views at
   `/api/v1/ai-triage/observability`. The same response carries normalized language/CWE/project
   distributions for offline drift checks:

```bash
go run ./cmd/synapse-fptriage-drift \
  --baseline ai-triage-drift-baseline.json \
  --observed ai-triage-observability.json \
  --output ai-triage-drift-report.json
```

The baseline owns its human approval, minimum sample size, and maximum total-variation distance. The
command writes deterministic evidence before returning a non-zero drift alert; it never changes runtime
gate behavior. See [AI triage evaluation](ai-triage-evaluation.md#detect-production-distribution-drift).

```bash
export SYNAPSE_LLM_BASE_URL=http://localhost:8081/v1
export SYNAPSE_LLM_API_KEY=…
SYNAPSE_FP_TRIAGE_ENABLED=true SYNAPSE_FP_TRIAGE_MODE=shadow SYNAPSE_FP_TRIAGE_MODEL=<model> \
  synapse-cli scan . --fail-on high --json
```

To evaluate a model/prompt/policy combination against the repository's versioned non-production golden
dataset, run `synapse-fptriage-eval`. It emits deterministic JSON with precision, recall, false-negative
escape rate, disagreement, coverage, language/kind/CWE/severity/framework/adversarial breakdowns, and pairwise
adversarial invariance evidence. The bundled v2 dataset pairs a clean control with a semantically
equivalent prompt-injection challenge; the v3 report records proposer, verifier, consensus, and policy
flips without copying source into the robustness summary:

```bash
SYNAPSE_FP_TRIAGE_MODEL=<proposer> SYNAPSE_VERIFIER_MODEL=<verifier> \
  go run ./cmd/synapse-fptriage-eval --output ai-triage-eval.json
```

The evaluator always invokes the server policy in shadow mode. A report containing `gate_exempt=true` is
rejected, so an evaluation run can never authorize a production quality gate.

Before reviewing a new model or prompt for promotion, compare its shadow report with the approved
baseline on the same dataset and policy:

```bash
go run ./cmd/synapse-fptriage-compare \
  --baseline ai-triage-baseline.json \
  --candidate ai-triage-candidate.json \
  --output ai-triage-comparison.json
```

The command exits non-zero on a quality regression or adversarial flip but writes the deterministic
comparison evidence first. The default policy requires complete counterfactual coverage, complete
verifier coverage whenever a pair reaches the refuted branch, and zero proposer/verifier/consensus/policy
flips. A passing result is still `review_required`; it never changes runtime AI configuration.

After that result, use `synapse-fptriage-release` to bind the baseline, candidate, comparison, unique
release version, and independent PM/Security approvals into a hash-chained ledger. Rollback appends
another approved decision targeting `initial` or a previous decision. The command writes a new ledger
file for every event and never changes live AI-triage or gate configuration. See
[AI triage evaluation](ai-triage-evaluation.md#approve-a-promotion-or-rollback).

```bash
# First print the exact digest PM and Security must approve.
go run ./cmd/synapse-fptriage-release \
  --manifest ai-triage-release.json \
  --comparison ai-triage-comparison.json \
  --baseline ai-triage-baseline.json \
  --candidate ai-triage-candidate.json \
  --print-review-digest

# After both approvals are added to the manifest, create a new ledger artifact.
go run ./cmd/synapse-fptriage-release \
  --manifest ai-triage-release-approved.json \
  --comparison ai-triage-comparison.json \
  --baseline ai-triage-baseline.json \
  --candidate ai-triage-candidate.json \
  --output ai-triage-release-ledger.json
```

The AI critique reads the target's own source into the prompt, so an **untrusted PR** can still try prompt
injection through comments or strings. Distinct consensus and the human-review floor bound the risk, and
the finding always remains in SARIF/JSON, but treat AI triage as advisory for untrusted contributor code.

## Exit codes

The exit code is a CI contract. A pipeline that branches on it can distinguish a real finding from a
misconfigured invocation:

| Code | Meaning |
| --- | --- |
| `0` | The command succeeded and no gate threshold was crossed. |
| `1` | A runtime failure, or a gate result: a finding at or above `--fail-on`, a failed quality gate, coverage below its threshold, or a rating below `--fail-below`. |
| `2` | Invalid usage: an unknown or incomplete flag, a missing required argument, or an invalid enum value such as `--fail-on none`. Nothing was analyzed. |

Treat `2` as "fix the pipeline definition" and `1` as "inspect the findings". Retrying an exit `2`
unchanged will always fail again.

## Container image (Docker)

The current release workflow does **not** publish a container image. Build one locally when a
containerized CLI is needed:

```bash
docker build -t synapse:full --target full -f deploy/Dockerfile .
docker run --rm -v "$PWD:/scan:ro" synapse:full synapse-cli scan /scan --fail-on high
```

The `full` target bundles pinned Syft and Grype and covers the pure-Go scan path: SBOM, OSV/Grype
vulnerabilities, licenses, SAST, secrets, and IaC misconfiguration. Sandboxed execution and
JVM-from-source resolution need a Linux host with bubblewrap and a JDK/Maven/Gradle, so run those on a
host install or the full Compose stack.

## Advisory sync (optional owned store)

For detection independence you can maintain an owned advisory store and ingest feeds into it.
This requires a database via `SYNAPSE_DB_DSN`.

```bash
# ingest a local OSV dump directory
synapse-cli sync-advisories <dir>

# fetch and ingest application ecosystems from the OSV bulk source
synapse-cli sync-advisories --remote

# fetch and ingest OS-package advisories (large)
synapse-cli sync-advisories --remote-distros

# ingest a local CSAF 2.0 advisory dump
synapse-cli sync-advisories --csaf <dir>

# ingest a local Ubuntu OVAL dump (com.ubuntu.*.cve.oval.xml[.bz2])
synapse-cli sync-advisories --oval <dir>
```

Enable the store at scan time with `SYNAPSE_OWNED_ADVISORY=true`, then it runs alongside the
live and offline sources.

## GitHub Action

The reusable action installs the released `synapse-cli` (plus syft and grype) and runs the gate, so a
whole scan step is three lines:

```yaml
- uses: KKloudTarus/synapse-ce@v1
  with:
    fail-on: high        # critical | high | medium | low | info (default: high)
    path: .              # what to scan (default: .)
    version: latest      # a released tag like v0.1.0, or latest (default)
```

Emit SARIF and upload it to the Security tab, while still failing the build on high findings:

```yaml
- id: synapse
  uses: KKloudTarus/synapse-ce@v1
  with:
    fail-on: high
    sarif: true
  continue-on-error: true          # let the upload run even when the gate fails
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.synapse.outputs.sarif-file }}
```

Set `offline: true` to run against the bundled offline databases only (no network egress).

### From source

Without the action you can install the tools and build the CLI yourself:

```yaml
- name: SCA scan
  run: |
    make tools
    make build
    ./bin/synapse-cli scan . --fail-on high
```

Or emit SARIF and upload it to the GitHub Security tab, while still failing the build on high findings:

```yaml
- name: Synapse scan
  run: ./bin/synapse-cli scan . --sarif --fail-on high > synapse.sarif
  continue-on-error: true            # let the upload run even when the gate fails the step
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: synapse.sarif
```

The report lands in the repository's Code scanning alerts, with each SAST, secret and misconfig
finding annotated on its exact source line.

## GitLab CI

The same gate as a GitLab job. `make tools` installs syft and grype, `make build` produces
`./bin/synapse-cli`, and a non-zero exit from the scan fails the pipeline:

```yaml
synapse-scan:
  stage: test
  image: golang:1.26
  script:
    - make tools
    - make build
    - ./bin/synapse-cli scan . --fail-on high
```

To publish to the GitLab SAST report so findings show in the merge-request widget, emit SARIF and
keep it as an artifact (GitLab reads SARIF as a `sast` report):

```yaml
synapse-scan:
  stage: test
  image: golang:1.26
  script:
    - make tools
    - make build
    - ./bin/synapse-cli scan . --sarif --fail-on high > gl-sast-report.sarif
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.sarif
```

## Jenkins

A declarative pipeline stage. The scan's exit code fails the stage on a finding at or above the
threshold:

```groovy
pipeline {
  agent { docker { image 'golang:1.26' } }
  stages {
    stage('Synapse scan') {
      steps {
        sh 'make tools'
        sh 'make build'
        sh './bin/synapse-cli scan . --fail-on high'
      }
    }
  }
}
```

To keep the SARIF report as a build artifact (for a platform or plugin that ingests SARIF), let the
scan step record its exit code, archive the report, then fail the build explicitly:

```groovy
stage('Synapse scan') {
  steps {
    sh 'make tools && make build'
    script {
      def rc = sh(returnStatus: true, script: './bin/synapse-cli scan . --sarif --fail-on high > synapse.sarif')
      archiveArtifacts artifacts: 'synapse.sarif', allowEmptyArchive: true
      if (rc != 0) { error("Synapse found a finding at or above the fail-on threshold") }
    }
  }
}
```

## Code quality gate (Clean as You Code)

Beyond security, `synapse-cli` measures code health and gates on it. The quality gate can score the
whole codebase or, with `--new-code-only`, just the lines a branch changed, so a legacy repo can adopt
the gate without fixing all pre-existing debt first.

```bash
# fail the build if new code introduces a critical/high issue, a new secret, or drops below A ratings
synapse-cli gate . --new-code-only --base origin/main

# feed a coverage report (lcov / Cobertura / JaCoCo, auto-detected); a .synapse-gate.yaml can then
# require e.g. `coverage >= 80` on new code
synapse-cli gate . --new-code-only --base origin/main --coverage coverage.info
```

| Flag | Default | Description |
| --- | --- | --- |
| `--new-code-only` | off | Score only lines changed against `--base` instead of the whole tree. |
| `--base <ref>` | `origin/main` | Git reference the new-code diff is computed against. |
| `--gate <file>` | `<path>/.synapse-gate.yaml` | Gate definition to apply. |
| `--rules <file>` | `<path>/.synapse-rules.yaml` | Rule enable/disable and severity overrides. |
| `--coverage <file>` | none | Coverage report (lcov, Cobertura, or JaCoCo, auto-detected) so gate conditions can require a coverage floor. |
| `--format text\|markdown` | `text` | Output format. `markdown` prints a ready-to-post PR summary. |

A `.synapse-gate.yaml` overrides the built-in gate, and a `.synapse-rules.yaml` enables/disables rules
or overrides severities. Use `--gate` and `--rules` to point at files outside the scanned tree:

```yaml
# .synapse-gate.yaml
conditions:
  - metric: new_critical
    op: "<="
    threshold: 0
  - metric: coverage
    op: ">="
    threshold: 80
```

Inspect coverage on its own:

```bash
synapse-cli coverage coverage.info --fail-below 80
```

### Code-health commands

These commands run the same analyzers the gate composes, but each reports one dimension on its own. None
of them needs a database or a server; all are safe in CI. Complexity and structural analysis use the
`synapse-ast` sidecar, and degrade to Go-only counts when it is unavailable rather than failing.

```
synapse-cli inventory <path>
synapse-cli metrics <path> [--fail-on-complexity N] [--top N]
synapse-cli duplication <path> [--min-tokens N] [--fail-on-duplication PCT] [--top N]
synapse-cli quality <path> [--fail-on SEV] [--min-complexity N] [--include-test-smells] [--sarif]
synapse-cli rating <path> [--json] [--fail-below GRADE]
```

| Command | Reports | Gate flag |
| --- | --- | --- |
| `inventory` | Languages, files, and lines of code | none |
| `metrics` | Per-function cyclomatic and cognitive complexity | `--fail-on-complexity N` exits `1` when any function exceeds `N` |
| `duplication` | Duplicated blocks, lines, and density | `--fail-on-duplication PCT` exits `1` when density exceeds `PCT` |
| `quality` | Maintainability and reliability findings, plus duplication and complexity bridges | `--fail-on SEV` accepts `critical\|high\|medium\|low\|info` |
| `rating` | A–E security, reliability, and maintainability grades with technical debt | `--fail-below GRADE` exits `1` when any grade falls below it |

`--top N` limits how many entries are printed. `quality --sarif` writes a SARIF report, and
`quality --include-test-smells` adds test-code smells that are otherwise suppressed.

```bash
# gate a build on complexity and duplication without a server
synapse-cli metrics . --fail-on-complexity 15
synapse-cli duplication . --fail-on-duplication 3

# publish code-quality findings to GitHub code scanning
synapse-cli quality . --sarif > quality.sarif
```

## Validate a third-party SARIF report

```
synapse-cli validate-sarif <engagement-id> <report.sarif>|- [--actor <id>] [--fail-on-refusal]
```

`validate-sarif` runs a third-party report through the same use case as the server ingest endpoint and
reports what would be accepted or refused. It **writes nothing**: the JSON output carries
`"persisted": false`, and no audit entry is recorded. To actually ingest a report, post it to
`/api/v1/engagements/{id}/sarif`, where the ingesting actor comes from the authenticated principal.

`import-sarif` remains an alias for the same command and the same non-persisting contract. Pass `-` to
read the report from stdin. `--actor` is a local label only. Exit `1` covers both a report whose results
were all refused and, with `--fail-on-refusal`, any partial refusal, so a pipeline can insist every
result be attributable.

## Publish analysis source

```
synapse-cli publish-source [dir] --server <url> --project <key> --analysis <id>
```

Uploads the source files a completed server-side analysis listed as retainable, so the dashboard can show
annotated code. It requires `SYNAPSE_API_TOKEN`, and `--server` defaults to `SYNAPSE_API_URL`. Only files
in the analysis inventory are sent; the server returns a digest-verified source manifest.

## Build an offline CVSS database

```
synapse-cli build-cvss-db <out.jsonl[.gz]> <nvd-*.json[.gz]...>
```

Converts NVD JSON feeds into a compact local database. Point `SYNAPSE_NVD_CVSS_DB` at the output to
backfill CVSS scores with no network access and no API rate limit, which suits air-gapped CI.

### PR decoration

Post the gate result as a pull-request comment. `--format markdown` prints a ready-to-post summary:

```yaml
- name: Synapse quality gate
  run: |
    make tools && make build
    ./bin/synapse-cli gate . --new-code-only --base "origin/${{ github.base_ref }}" \
      --coverage coverage.info --format markdown > gate.md || echo "GATE_FAILED=1" >> "$GITHUB_ENV"
- name: Comment the gate on the PR
  if: always()
  run: gh pr comment "${{ github.event.pull_request.number }}" --body-file gate.md
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
- name: Fail if the gate failed
  if: env.GATE_FAILED == '1'
  run: exit 1
```

Next: [Architecture](architecture.md)

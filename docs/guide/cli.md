# Command line (synapse-cli)

[Documentation home](README.md) · Previous: [Configuration](configuration.md) · Next: [Architecture](architecture.md)

`synapse-cli` runs the same SCA pipeline as the server, from the command line. It is built for
CI gating. It creates an ephemeral, scope-checked engagement covering the target path, so scope
enforcement is exercised, not bypassed. Nothing is persisted.

Build it with `make build`. The binary lands at `./bin/synapse-cli`.

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
| `--json` | Print the full scan result as JSON to stdout, for machine consumption in CI. |
| `--sarif` | Print a SARIF 2.1.0 report to stdout, ready to upload to GitHub code scanning. Covers every finding kind; SAST, secret and misconfig findings carry a file and line so the platform annotates the exact source line. `--fail-on` still sets the exit code. Cannot be combined with `--json`. |

### Examples

```bash
# fail a build on any high-or-critical vulnerability
synapse-cli scan . --fail-on high

# licenses only
synapse-cli scan . --mode licenses

# scan a container image, offline
synapse-cli scan alpine:3.19 --image --offline
```

The exit code is 0 when no finding meets the `--fail-on` threshold, and non-zero otherwise.
Wire it straight into a pipeline step.

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
   findings (SAST/secret/misconfig) and returns a typed verdict — `refuted` (suspected false positive),
   `sound`, or `uncertain` — with a confidence. The model only proposes: a `refuted` verdict at or above
   the confidence bar marks the finding a suspected false positive and holds it back from the gate; it is
   still reported (see `ai_triage` in `--json`) and sealed, never deleted, and an `uncertain` verdict
   keeps the finding gating. Best-effort: if the model can't be reached the scan proceeds unchanged.

```bash
export SYNAPSE_LLM_BASE_URL=http://localhost:8081/v1
export SYNAPSE_LLM_API_KEY=…
SYNAPSE_FP_TRIAGE_ENABLED=true SYNAPSE_FP_TRIAGE_MODEL=<model> \
  synapse-cli scan . --fail-on high --json
```

The AI critique reads the target's own source into the prompt, so treat it as a trusted-local convenience:
on a scan of an **untrusted PR**, a contributor could add a comment that tries to talk the model into
refuting their finding. The blast radius is bounded — the finding is still reported and in the SARIF/JSON
(only the `--fail-on` exit code is affected), the model only proposes (a gate exemption, never a sealed
suppression or a deletion), and the run prints how many findings were held back — but for gating untrusted
PRs, upload the SARIF to code-scanning (which shows every finding) and treat the AI verdict as advisory.

## Container image (Docker)

Every release publishes a multi-arch `synapse-cli` image to GHCR that bundles syft and grype, so you can
scan with nothing installed but Docker:

```bash
# scan the current directory (mounted read-only), fail on high-or-critical
docker run --rm -v "$PWD:/scan:ro" ghcr.io/kkloudtarus/synapse-cli scan /scan --fail-on high

# pin a version instead of latest
docker run --rm -v "$PWD:/scan:ro" ghcr.io/kkloudtarus/synapse-cli:v0.1.0 scan /scan
```

The image targets the pure-Go scan path (SBOM, OSV/Grype vulnerabilities, licenses, SAST, secrets, IaC
misconfig). Sandboxed execution and JVM-from-source resolution need a Linux host with bubblewrap and a
JDK/Maven/Gradle, so run those on a host install or the batteries-included compose image.

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
    fail-on: high        # critical | high | medium | low | info | none (default: high)
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

A `.synapse-gate.yaml` overrides the built-in gate, and a `.synapse-rules.yaml` enables/disables rules
or overrides severities:

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

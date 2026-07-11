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

## GitHub Actions

Gate a build on findings:

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

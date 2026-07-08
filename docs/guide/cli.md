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

Next: [Architecture](architecture.md)

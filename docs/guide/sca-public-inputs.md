# Public diagnostic SCA inputs

`synapse-sca-prepare` builds a local Linux diagnostic input tree when the retained trusted archive is unavailable. It never changes the catalog, Oracle, ratchet, accepted baseline, or evidence-currency state.

Run it from a Linux host with Docker available to Syft:

```sh
go run ./cmd/synapse-sca-prepare \
  --corpus-root "$PWD/internal/usecase/scabench/corpus" \
  --offline-root /var/tmp/synapse-sca-inputs \
  --raw-retention-root /var/tmp/synapse-sca-raw
```

The command fetches the catalog's public binary and capability-source origins over HTTPS, writes the original downloaded bytes under `--raw-retention-root`, extracts only the required executable or source member, and checks the extracted bytes against `trusted-input-bindings.json`. It then uses the pinned Syft binary to generate one CycloneDX SBOM for each digest-pinned OCI target. A pin mismatch, missing archive member, failed image pull, or changed SBOM stops preparation.

Both output roots must be new, distinct paths. The command rejects nested roots and symlinked output components. The raw-retention root preserves each raw and materialized digest, origin, and destination locator in `materialization-provenance.json` without making raw archives scan inputs.

Database setup is deliberately not implemented in this first command: Grype, Trivy, OSV and owned-source database origins are mutable archives or trees with scanner-specific import formats. The command exits with status 2 only after all immutable artifacts and SBOMs have verified; it prints the number of remaining database bindings. That result is still diagnostic. It cannot be promoted to accepted evidence and does not replace the protected Linux trusted-runner workflow.

# SCA accuracy benchmark

The SCA benchmark measures Synapse's owned matcher alongside Grype, Trivy, and OSV-Scanner on one frozen CycloneDX SBOM for each reviewed Debian and SLES target. Comparator scanners are benchmark-only: they are not product detection sources and are never added to `SYNAPSE_DETECTION_SOURCES`.

## Run the benchmark

A trusted Linux runner uses one command:

```sh
go run ./cmd/synapse-sca-cycle run \
  --corpus-root /workspace/synapse/internal/usecase/scabench/corpus \
  --trusted-input-root /trusted/sca-inputs \
  --output-root /runner-temp/sca-result \
  --raw-retention-root /protected/sca-raw \
  --implementation-commit <40-character-sha> \
  --run-key <run-id>/<attempt>
```

`make sca-accuracy-run` is the same command with these six inputs supplied as `SCA_BENCHMARK_*` variables. The command has no stage, retry, cell, publication, or falsifier mode.

The runner derives the fixed Debian/SLES by owned/Grype/Trivy/OSV-Scanner matrix from the frozen catalog and Oracle. It executes exactly two repetitions. Each required cell is captured once per repetition; any required-cell failure fails the entire run. SLES with OSV-Scanner is represented by its reviewed zero-dispatch unsupported capability record.

The trusted input root contains only prepared, pinned data:

```text
trusted-input-root/
  sboms/<target-id>.cdx.json
  tools/{grype,trivy,osv-scanner}
  databases/{owned-debian,owned-sles,grype,trivy,osv}
  evidence-assets/environment/environment-attestation.json
  repository/
    capability/...
    reviews/github/<one commented review>.json
    reviews/dispositions/github/<one maintainer disposition>.json
```

The runner builds the owned benchmark binary, rebinds its generated capture identity, and validates the materialized catalog and ratchet before scanning. Every engine receives the same canonical SBOM bytes. Capture keeps strict decoding, input integrity checks, authenticated bundles, bounded redacted process evidence, and replay validation.

## Result and cleanup

Before repeat comparison, both bundles pass strict `ValidateBundle` and replay. Their complete raw identities remain provenance: roots, manifests, raw process streams, artifact digests, and environment evidence are retained until cleanup. Repeat equality uses a claim-bearing projection keyed by `(target_id, engine)`. It compares pins, target/SBOM, capability, state, process outcome, parser and input-integrity status, failure code, parsed version, and canonical findings. It deliberately excludes raw streams, timestamps, duration, pointer addresses, log formatting, and raw bundle identities.

Both repetitions are independently reduced, ratcheted, rendered, and required to produce identical deterministic results. The output root receives one sanitized result directory containing the catalog, Oracle, ratchet, policy, canonical SBOMs, review/disposition captures, `run.json`, `result.json`, and `report.md`. It contains no raw scanner output, protected raw paths, scanner databases, retries, stage ledgers, publication controls, delivery receipts, or synthetic falsifier results.

The command removes its protected raw subtree and Docker containers, volumes, images, and build cache before publishing the sanitized result. Raw cleanup failure prevents publication.

## Oracle and review governance

Oracle preparation is maintainer-only work outside the ordinary benchmark run. The run consumes the frozen strict `catalog.json`, scanner-independent `oracle.json`, ratchet, and cycle policy; it does not regenerate source evidence, cross-checks, adjudication, catalog releases, or review captures.

The independent GitHub review has the actual `COMMENTED` state. It is not described as approved. A separate, immutable maintainer disposition from a different authority accepts that review for the exact implementation commit. The benchmark reads these sanitized prepared captures and never contacts GitHub.

The Oracle is scanner-independent vendor truth for these pinned targets, not a market-wide ranking. Coverage remains explicit: `covered`, `unknown`, `unsupported`, and `incomplete` are scored without converting unsupported or unknown observations into clean findings.

## Focused offline verification

Use this small local check while changing the benchmark implementation:

```sh
make sca-accuracy-test
```

It does not acquire databases, run scanners, materialize frozen inputs, or execute a trusted benchmark.

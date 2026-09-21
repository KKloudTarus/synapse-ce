# SCA accuracy benchmark

The SCA benchmark measures Synapse's owned matcher alongside Grype, Trivy, and OSV-Scanner on one frozen CycloneDX SBOM for each reviewed Debian, SLES, and Red Hat Enterprise Linux target. Comparator scanners are benchmark-only: they are not product detection sources and are never added to `SYNAPSE_DETECTION_SOURCES`.

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

The runner derives the fixed Debian/SLES/RHEL by owned/Grype/Trivy/OSV-Scanner matrix from the frozen catalog and Oracle. It executes exactly two repetitions: 12 required cells per repetition and 24 accepted slots in total. Each required cell is captured once per repetition; any required-cell failure fails the entire run. SLES and RHEL with OSV-Scanner are each represented by a distribution-specific, reviewed zero-dispatch unsupported capability record.

The trusted input root contains only prepared, pinned data:

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

The runner builds the owned benchmark binary, rebinds its generated capture identity, and validates the materialized catalog and ratchet before scanning. Every engine receives the same canonical SBOM bytes. Capture keeps strict decoding, input integrity checks, authenticated bundles, bounded redacted process evidence, and replay validation.

The RHEL target uses the complete pinned canonical UBI 9.8 SBOM without a scanner-specific projection. The benchmark's structural identity includes an RPM `epoch` PURL qualifier when comparing the explicit component version, so epoch-bearing packages remain representable. Owned and every comparator consume the same byte-for-byte SBOM.

## Result and cleanup

Before repeat comparison, both bundles pass strict `ValidateBundle` and replay. Their complete raw identities remain provenance: roots, manifests, raw process streams, artifact digests, and environment evidence are retained until cleanup. Repeat equality uses a claim-bearing projection keyed by `(target_id, engine)`. It compares pins, target/SBOM, capability, state, process outcome, parser and input-integrity status, failure code, parsed version, and canonical findings. It deliberately excludes raw streams, timestamps, duration, pointer addresses, log formatting, and raw bundle identities.

Both repetitions are independently reduced, ratcheted, rendered, and required to produce identical deterministic results. The output root receives one sanitized result directory containing the catalog, Oracle, ratchet, policy, canonical SBOMs, review/disposition captures, `run.json`, `result.json`, and `report.md`. It contains no raw scanner output, protected raw paths, scanner databases, retries, stage ledgers, publication controls, delivery receipts, or synthetic falsifier results.

The command removes its protected raw subtree and Docker containers, volumes, images, and build cache before publishing the sanitized result. Raw cleanup failure prevents publication.

## Oracle and review governance

Oracle preparation is maintainer-only work outside the ordinary benchmark run. The run consumes the frozen strict `catalog.json`, scanner-independent `oracle.json`, ratchet, and cycle policy; it does not regenerate source evidence, cross-checks, adjudication, catalog releases, or review captures.

The independent GitHub review has the actual `COMMENTED` state. It is not described as approved. A separate, immutable maintainer disposition from a different authority accepts that review for the exact implementation commit. The benchmark reads these sanitized prepared captures and never contacts GitHub.

The Oracle is scanner-independent vendor truth for these pinned targets, not a market-wide ranking. Its SLES lifecycle cases come from SUSE's authoritative affected OVAL definitions, including not-yet-fixed package/release relations. Its RHEL labels come from pinned binary-aware Red Hat CSAF VEX records: exact binary and RHEL 9.8 relationships establish the affected cases, while an exact fixed binary EVR establishes the negative case. Comparator output never creates or changes those labels.

Coverage remains explicit: `covered`, `unknown`, `unsupported`, and `incomplete` are scored without converting unsupported or unknown observations into clean findings. The pinned OSV-Scanner profile supports the Debian package projection but has no reviewed SUSE or Red Hat RPM conversion. Those two cells therefore remain distribution-specific `unsupported` observations with zero scanner dispatches rather than synthetic clean results.

The accepted historical ratchet is byte-pinned. Candidate catalog and Oracle identities may migrate with a reviewed target addition, but the Debian and SLES comparator policy thresholds remain unchanged. The sole historical-floor disposition is SLES Owned: `maximum_unknown` changes from 0 to 537 while `minimum_recall` tightens from 0 to 1 and `maximum_false_negatives` tightens from 16 to 0. This is an exact, tested exception, not a general threshold-relaxation mechanism.

## Focused offline verification

Use this small local check while changing the benchmark implementation:

```sh
make sca-accuracy-test
```

It does not acquire databases, run scanners, materialize frozen inputs, or execute a trusted benchmark.

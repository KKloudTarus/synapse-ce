# SCA accuracy benchmark

The SCA benchmark measures Synapse's owned matcher alongside Grype, Trivy, and OSV-Scanner on one frozen CycloneDX SBOM for each reviewed Debian, SLES, and Red Hat Enterprise Linux target. Comparator scanners are benchmark-only: they are not product detection sources and are never added to `SYNAPSE_DETECTION_SOURCES`.

## Run the benchmark

A trusted Linux runner uses one command:

```sh
bash scripts/run-sca-cycle-delegated.sh run \
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
  tools/{grype,trivy,osv-scanner,syft}
  databases/{owned-debian,owned-sles,owned-redhat,grype,trivy,osv}
  evidence-assets/environment/environment-attestation.json
  repository/
    capability/...
    reviews/github/<one commented review>.json
    reviews/dispositions/github/<one maintainer disposition>.json
```

The runner builds the owned benchmark binary, rebinds its generated capture identity, and validates the materialized catalog and ratchet before scanning. Every engine receives the same canonical SBOM bytes. Capture keeps strict decoding, input integrity checks, authenticated bundles, bounded redacted process evidence, and replay validation.

The RHEL target uses the complete pinned canonical UBI 9.8 SBOM without a scanner-specific projection. The benchmark's structural identity includes an RPM `epoch` PURL qualifier when comparing the explicit component version, so epoch-bearing packages remain representable. Owned and every comparator consume the same byte-for-byte SBOM.

## Unsigned candidate measurement

From the root of a clean Linux checkout, with a prepared review-free offline input root, an existing evidence directory outside the checkout and offline inputs (not group- or world-writable on Linux), and the same delegated cgroup/sandbox prerequisites as the trusted runner. Before hashing or building, the candidate bounds the offline root to 10,000 members, depth 32, 3 GiB per file, and 8 GiB total, with stricter 64 MiB SBOM and 4 MiB environment-attestation file limits:

```sh
bash scripts/run-sca-cycle-delegated.sh candidate \
  --offline-input-root /protected/sca-inputs \
  --evidence-root /protected/sca-candidates
```

To replay pinned materialized inputs from an earlier candidate evidence directory, use the bundle directly. The command verifies its archived catalog, bindings, manifest, and every content-addressed object, restores once into the new candidate's retained `capture-input/`, replaces the archived environment attestation with the supplied current-host file, then runs the same diagnostic candidate path. The attestation must be captured independently on the host that performs this run; the command cannot establish its freshness from bytes alone.

```sh
bash scripts/run-sca-cycle-delegated.sh candidate \
  --input-bundle /protected/earlier-candidate \
  --environment-attestation /protected/current-host/environment-attestation.json \
  --evidence-root /protected/sca-candidates
```

The bundle is the extracted candidate evidence directory containing `candidate-corpus/`, `input-archive.json`, and `input-cas/`. Use a verified copy of the retained evidence archive. The new candidate evidence retains its restored input root, a freshly collected verified input archive, and the run's attestation, including when an interrupted run leaves partial evidence. This path reuses pinned bytes and does not fetch a vendor's latest release.

The command derives the corpus path and exact implementation commit from the clean checkout, generates a unique run key, and retains a bounded Git-object source archive for that commit. It builds the owned benchmark binary with source paths trimmed and freezes the original corpus from the extracted source snapshot, not from subsequent working-tree reads. The archive, built binary, prepared capture inputs, and any raw bundles produced stay under the printed protected evidence path so a failed run can be inspected and replayed. The CLI prints each target/engine's TP, FP, FN, unknown count, and gate reason alongside the evidence path, including on a numeric failure. The commit binds the owned binary and corpus; it is not an independent attestation of the already-running cycle controller. Its result declares the retention policy and counts actual retained attempt records, including after partial capture; the inherited `cycle-policy.json` digest records the source policy for the fixed matrix, but its `delete_after_verification` cleanup rule is not applied to candidate evidence. It does not require trusted GitHub review/disposition captures, sign results, or publish an accepted baseline. The candidate's current-input policy and its pre-rebind identity comparison are reported separately: binding new bytes for a diagnostic comparison never makes them the old bytes, and a numeric failure returns nonzero without deleting evidence. A successful candidate command still means only that its **diagnostic** gate passed; it is not historical acceptance. The Oracle's existing citations are not reapproved by a successful capture. An independent maintainer review of the evidence and a prospective baseline disposition are still required before accepting new scores.

When prepared database bytes differ from the committed pin, the candidate records `database_build` as `content-sha256:<digest>` instead of carrying forward the old upstream build label. The inherited catalog reference and origin identify the input slot and original acquisition path; a changed digest does not prove that the new bytes came from that origin. The content identity establishes which bytes were measured, not their publisher or release date. Verify provenance independently before proposing a new trusted baseline.

## Result and cleanup

Before repeat comparison, both bundles pass strict `ValidateBundle` and replay. Their complete raw identities remain provenance: roots, manifests, raw process streams, artifact digests, and environment evidence are retained until cleanup. Repeat equality uses a claim-bearing projection keyed by `(target_id, engine)`. It compares pins, target/SBOM, capability, state, process outcome, parser and input-integrity status, failure code, parsed version, and canonical findings. It deliberately excludes raw streams, timestamps, duration, pointer addresses, log formatting, and raw bundle identities.

Both repetitions are independently reduced, ratcheted, rendered, and required to produce identical deterministic results. The output root receives one sanitized result directory containing the catalog, Oracle, ratchet, policy, canonical SBOMs, review/disposition captures, `run.json`, `result.json`, and `report.md`. It contains no raw scanner output, protected raw paths, scanner databases, retries, stage ledgers, publication controls, delivery receipts, or synthetic falsifier results.

The command removes its protected raw subtree and Docker containers, volumes, images, and build cache before publishing the sanitized result. Raw cleanup failure prevents publication.

## Oracle and review governance

Oracle preparation is maintainer-only work outside the ordinary benchmark run. The run consumes the frozen strict `catalog.json`, scanner-independent `oracle.json`, ratchet, and cycle policy; it does not regenerate source evidence, cross-checks, adjudication, catalog releases, or review captures.

The independent GitHub review has the actual `COMMENTED` state. It is not described as approved. A separate, immutable maintainer disposition from a different authority accepts that review for the exact implementation commit. The benchmark reads these sanitized prepared captures and never contacts GitHub.

The Oracle is scanner-independent vendor truth for these pinned targets, not a market-wide ranking. Its SLES lifecycle cases come from SUSE's authoritative affected OVAL definitions, including not-yet-fixed package/release relations. Its RHEL labels come from pinned binary-aware Red Hat CSAF VEX records: exact binary and RHEL 9.8 relationships establish the affected cases, while an exact fixed binary EVR establishes the negative case. Comparator output never creates or changes those labels.

Coverage remains explicit: `covered`, `unknown`, `unsupported`, and `incomplete` are scored without converting unsupported or unknown observations into clean findings. The pinned OSV-Scanner profile supports the Debian package projection but has no reviewed SUSE or Red Hat RPM conversion. Those two cells therefore remain distribution-specific `unsupported` observations with zero scanner dispatches rather than synthetic clean results.

The accepted historical eight-cell ratchet remains byte-pinned in `ratchet-baseline.json` and is not scored by this twelve-cell candidate. The candidate report's `historical_result` is a pre-rebind identity comparison using the twelve-cell `ratchet.json`, including its proposed caps, before input digests are rebound. A `pin_mismatch` there shows that the old identities do not describe the new measured bytes; it is not an accepted-baseline score. The prospective `ratchet.json` records three explicit unknown-cap changes measured on the retained candidate input bytes. These are proposed policy exceptions for independent review, not historical acceptance:

| Target | Engine | Prior cap | Measured unknown | Proposed cap |
| --- | --- | ---: | ---: | ---: |
| Debian | Grype | 255 | 258 | 258 |
| SLES | Grype | 453 | 466 | 466 |
| SLES | Owned | 537 | 582 | 582 |

The previous SLES Owned historical-floor disposition changed `maximum_unknown` from 0 to 537 while tightening `minimum_recall` from 0 to 1 and `maximum_false_negatives` from 16 to 0. The new proposed SLES cap of 582 preserves those recall and false-negative constraints. The 2026-09-24 prospective measurement at implementation SHA `45b07de872eb58622cc81638539124c7fc321bc2` completed 24 observations with 12/12 repeat-equivalent pairs and scored 9/12 against the prior caps; only the three unknown caps in the table failed. It remains diagnostic and `accepted=false`. Numeric passage under the proposed caps still requires independent review, exact-final-SHA review capture, and separate maintainer disposition.

## Historical vendor evidence and retained prospective bytes

A catalog pin records a vendor artifact's digest and its origin, which is enough to detect drift and refuse a
mismatched capture, but it does not preserve the bytes. Vendors serve these feeds from mutable paths rather than
content-addressed archives: Red Hat regenerates a CSAF VEX document in place under the same CVE filename, and
the SUSE OVAL, Debian OVAL, and OSV Debian snapshots change size between fetches of the same advertised build.
Once a document is regenerated, the originally pinned bytes are no longer retrievable from the origin.

Two consequences follow, and both are expected rather than defects:

- A re-capture on fresh infrastructure fails every ratchet floor with `pin_mismatch` on `database_digest`. That
  is the gate working: accuracy numbers measured against different evidence must not silently replace numbers
  measured against the pinned evidence.
- An Oracle case can outlive the evidence it cites. A vendor may withdraw a product from a CVE's affected set,
  after which not reporting that component is correct and the case needs re-labelling against newly captured
  evidence under independent review.

Re-deriving thresholds from drifted feeds without reviewing Oracle provenance would pin scores against evidence
the Oracle's citations may no longer describe. The prospective 2026-09-24 candidate instead retains its exact
materialized inputs, raw bundles, report, seal, and candidate corpus in a versioned evidence archive. Its full
evidence archive is SHA-256 `b7df7153712b096070b1fac63e2f4cda19c4f043cf3eac7c6c6f642f9f1da97f`
at `s3://synapse-sca-benchmark-evidence-116378167742-20260923-e1b6fb88/candidate-prospective/45b07de872eb58622cc81638539124c7fc321bc2/evidence.tar.gz`, S3 version `YTEKJJ131uF46S0zK54ryOEMGJagF8z0`.
The original official Grype v6.1.9 archive is also retained with SHA-256
`a52051769db44825dcab6e6d4c32ffee53cdea0d456d98630b55b15ad52b16f3` under the same prefix.
Two imports of that identical source archive produced different materialized SQLite bytes, so the retained
candidate input archive, rather than reimporting the source, is the byte-exact replay input. The official
archive establishes acquisition lineage; the materialized input pin identifies the measured database bytes.

## Materialized trusted-input archive

The raw-origin archive records bytes fetched from vendor origins. It is distinct from the materialized trusted-input
archive, which snapshots an already prepared `trusted-input-root` after its catalog pins have been verified. The
corpus's `trusted-input-bindings.json` identifies every origin-bearing pin's file or directory in that root. Collection
records the complete directory and file inventory, preserves executable and safe permission bits, stores file objects
in the archive CAS, and binds the result to the canonical catalog digest. Restore rebuilds only into an existing empty
root and re-verifies the inventory and all bindings before accepting it.

This improves future prepared captures; it does not retroactively recover vendor bytes for the committed corpus when
those bytes have already drifted from their origins.

## Focused offline verification

Use this small local check while changing the benchmark implementation:

```sh
make sca-accuracy-test
```

It does not acquire databases, run scanners, materialize frozen inputs, or execute a trusted benchmark.

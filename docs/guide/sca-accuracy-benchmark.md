# SCA accuracy benchmark

The SCA accuracy benchmark provides two deliberately separate capabilities:

1. an **offline historical reducer/regression gate**, and
2. a **fresh evidence-cycle foundation** for an authorized trusted-Linux capture.

It does not make a scanner run part of Synapse product composition. Grype, Trivy, and OSV-Scanner remain benchmark comparators only; they are not product detection sources.

## Historical reference limitations

`internal/usecase/scabench/testdata/reference/` is immutable historical reducer and regression evidence only. It has 16 files, and its content-addressed control is checked in outside that directory at `internal/usecase/scabench/testdata/historical-reference-inventory.json`.

The historical material contains 628 cases and 698 distinct inaccessible historical citation locators. It has no reconstructable capture, accountable-review, bundle, or environment evidence. It therefore cannot establish a new native replay or a new publication decision. Tests fail if any historical fixture path or byte changes.

The historical benchmark is useful for deterministic reducer, ratchet, rendering, and regression checks:

```sh
make sca-bench-verify
```

That command is offline and does not install or invoke scanners. It must not be described as a fresh scanner evaluation.

## Fresh-cycle inputs and freeze

A fresh cycle begins with repository-relative public source snapshots and citations. Every source and citation must be a regular file beneath the selected repository root, must have a SHA-256 digest and exact size, and must resolve without any absolute path, `file://` locator, traversal segment, symlink, or missing asset.

Freeze those inputs before capture with separate strict records:

- **Source freeze**: content-addressed source snapshot inventory.
- **Source-evidence plan**: target/package allowlists, frozen repository-relative vendor assets, and explicit source-package EVR mappings. Each selected binary must bind its PURL type and basename, PURL/component version, target architecture/distro/release, upstream source name, and source EVR. Its Syft component PURL must carry exactly one `arch`, `distro`, and `upstream` qualifier: `arch` matches the target architecture, `distro` is exactly `<product>-<release>` and must also equal `SourceEvidencePackage.distro`, and decoded `upstream` is exactly `<source>@<evr>` for Debian or `<source>-<evr>.src.rpm` for RPM. OVAL source-package objects prefer that source EVR even when the source and binary names are equal. It cannot select a CVE or definition and cannot carry truth labels, dispositions, or version relations.
- **Generated source and native evidence**: scanner-free vendor evaluation and every target-native version predicate derived from the frozen plan. These are write-once records, not trusted inputs.
- **Oracle candidate**: scanner-free proposed truth and citations derived only from generated evidence.
- **Automated scanner-blinded cross-check**: an automated check, explicitly not a human review, which re-derives each case from the generated native predicate set.
- **Adjudication**: resolution of candidate and cross-check records.
- **Accountable review**: a sanitized, immutable repository-backed GitHub review capture with only a schema version, review ID/URL, login, state, submission timestamp, commit ID, and canonical `decision: <value>` body. The repository verifier checks every captured value against the submitted `github:` reviewer identity, timestamp, reviewed commit, review URL/ID, and decision; it rejects tokens, account details, headers, email fields, and all other capture data. Its decision digest must equal the capture digest and bind the exact final-oracle digest. Publication requires this distinct record to be resolved and approved; automation cannot stand in for it. Every final-oracle case names that submitted reviewer.

The candidate, cross-check, adjudication, and accountable-review schemas and command paths intentionally do not accept scanner observations, raw bundles, or scores.

Prepare fresh inputs before any capture:

```sh
make sca-accuracy-prepare \
  SCA_ACCURACY_REPOSITORY_ROOT=/absolute/repository \
  SCA_ACCURACY_PLAN=/protected/cycle-plan.json \
  SCA_ACCURACY_SOURCE_FREEZE=/protected/source-freeze.json \
  SCA_ACCURACY_ORACLE_CANDIDATE=/protected/oracle-candidate.json \
  SCA_ACCURACY_CROSS_CHECK=/protected/cross-check.json \
  SCA_ACCURACY_ADJUDICATION=/protected/adjudication.json \
  SCA_ACCURACY_ACCOUNTABLE_REVIEW=/protected/accountable-review.json \
  SCA_ACCURACY_FINAL_ORACLE_FREEZE=/protected/final-oracle-freeze.json
```

`synapse-sca-cycle` first runs `source-native-evidence`, which reads strict frozen assets, evaluates a bounded benchmark-only OVAL subset, and writes both generated source cases and complete per-target native evidence once. Any matching OVAL definition, test, object, or state whose semantics cannot safely be evaluated is retained as a diagnostic that blocks candidate construction; guards for another product, release, architecture, or package are non-applicable rather than failures for relevant branches. `oracle-candidate`, `oracle-cross-check`, `oracle-adjudicate`, and `oracle-freeze` then form the review chain; `oracle-freeze` consumes a separately supplied accountable decision, verifies every truth-bearing candidate field against the final oracle, and never invents an approval. Each `cell` invocation requires the complete generated `-native-evidence` set and `-capture-record-output`; invoke `ledger` with every retained generated `-capture-record` after all sixteen slots complete.

The checked-in matrix specification is `internal/usecase/scabench/testdata/cycle-matrix-spec.json`. It is intentionally marked as requiring a fresh source and oracle freeze rather than pretending unavailable live evidence exists. It declares two repetitions of eight cells: 14 complete scanner dispatches and two SLES plus OSV-Scanner unsupported records with zero scanner dispatch. The strict plan and ledger are data-configurable; they reject missing, extra, duplicate, unknown, incomplete final, or unplanned unsupported cells. Failed and retry attempts remain retained instead of being discarded to select convenient repetitions.

## Trusted-Linux capture and native comparison

A normal capture is Linux-only and requires the hardened `bubblewrap+seccomp+cgroup-v2` control set. A capability record is zero-dispatch and only valid for the planned unsupported cell. Inputs remain argv data; no target or version value becomes command source text.

Capture one planned cell only after the freeze succeeds. Retention input identifies only the protected destination and policy; after validating the written bundle, capture derives its retained-reference digest from the full bundle root and never accepts an operator-supplied digest. A cell exits `0` only after it has written an accepted capture record; it exits `2` after writing a retained post-dispatch failed-attempt record, which must be uploaded to the audit-safe controls channel before the workflow fails or retries; it exits `1` for pre-dispatch or input-invalid failure.

```sh
make sca-accuracy-cell \
  SCA_ACCURACY_PLAN=/protected/cycle-plan.json \
  SCA_ACCURACY_CATALOG=/protected/catalog.json \
  SCA_ACCURACY_NATIVE_EVIDENCE=/protected/generated-native-evidence.json \
  SCA_ACCURACY_CAPTURE_MANIFEST=/protected/cell-manifest.json \
  SCA_ACCURACY_OUTPUT=/protected/bundles/repetition-1-cell \
  SCA_ACCURACY_REPETITION=1 \
  SCA_ACCURACY_RETENTION_LOCATOR=protected://retention/location \
  SCA_ACCURACY_RETENTION_POLICY=governed-retention
```

Before an authorized capture, validate each supplied frozen SBOM without regenerating it:

```sh
make sca-accuracy-frozen-sbom-verify \
  SCA_ACCURACY_FROZEN_SBOM=/protected/sboms/target.cdx.json \
  SCA_ACCURACY_FROZEN_SBOM_DIGEST=sha256:...
```

The checked byte stream must already be canonical `jq -S -c` CycloneDX JSON, contain exactly the target catalog's PURL/version component set, and match the catalog identity. Syft provenance is an externally supplied, reviewable preparation input, not an evaluation action.

Fresh package truth must use target-native comparison:

- Debian comparisons execute `dpkg --compare-versions` in a digest-pinned target OCI boundary.
- RPM comparisons execute a fixed target-native RPM Lua program. An absent epoch is normalized to `0`; exact epoch, version, and release values are environment data, never Lua source.
- The OCI boundary inspects and attests the exact local RepoDigest plus `linux/amd64` OS/architecture before use, invokes only validated `/usr/bin/dpkg` or `/usr/bin/rpm` through Docker `--entrypoint`, and uses no pull, no network, a read-only filesystem, dropped capabilities, no-new-privileges, and bounded memory/PIDs.
- Complete generated target evidence is reused by every engine for that target and is bound into every accepted bundle identity. Source-package objects use an explicit mapped source EVR, never a binary component version by assumption.
- Non-Linux operation and unavailable target-native mechanisms fail closed. There is no host-side or Go semantic fallback.

## Bundle comparison and falsifiers

Successful and failed full capture bundles, scanner databases, tool caches, generated corrupt trees, and OCI layers stay in protected retention. They are referenced by digest, locator, and retention policy but are not committed.

The full-bundle comparator validates both existing bundles first. It calculates a derived manifest and root identity without adding a second capture format, retains both raw roots, and fails on every unclassified difference. The per-engine policies are intentionally narrow:

- Owned: exact raw output.
- Grype: only the descriptor timestamp.
- Trivy: only top-level `CreatedAt` and `ReportID` plus direct vulnerability `Fingerprint` values.
- OSV-Scanner: only declared non-nil pointer metadata in diagnostics and a correctly shaped terminal timing line.

`internal/usecase/scabench/testdata/semantic-comparison-falsifiers.json` is a capability-level falsifier specification derived exactly from the authoritative 41 historical comparison keys. It records a deterministic baseline, mutation, expected outcome, and operation, never a stored `passed` boolean. The executable runner derives each observed outcome by using synthetic full bundles with the real decoder, archive validator, semantic comparator, and final repetition reducer. Synthetic fixtures prove current behavior only; they do not claim to recover historical capture replay.

## Finalization and publication identity

Finalization reduces and ratchets **every** planned repetition independently, then rejects a result or rendering mismatch. It runs the bundle comparator and falsifier runner before output. Numeric scores remain normalized, while the publication manifest binds both repetitions' full identities:

- derived bundle manifest and raw root;
- raw stdout, stderr, or raw-output digest;
- normalized observation and canonical SBOM;
- target-native comparison;
- process evidence and environment identity.

The single publication manifest also binds the generated source evidence and complete native evidence. The accepted sanitized publication artifact is limited to resolvable public source snapshots, pins, canonical SBOMs, scanner-free review records, normalized observations, native comparison records, compact process/control identities, comparison and falsifier results, result, ratchet, report, and ledger. It rejects raw bundle and scanner-cache artifact categories. Freeze and publication records use write-once paths.

Finalization writes the measured comparison, falsifier, result, and report before publication assembly. `sca-accuracy-publication` then hashes those actual regular files, builds the manifest, and writes the candidate evidence summary that binds the manifest identity. The summary is deliberately not an artifact within that same manifest: including its own digest would create an unverifiable self-reference.

Use the two explicit output stages only with all retained trusted inputs:

```sh
make sca-accuracy-finalize
make sca-accuracy-publication
```

They fail closed until every required path, comparison pair, falsifier specification, immutable publication control, and review decision has been supplied. Pull requests can verify the checked-in benchmark contract and historical regression inputs without scanners:

```sh
make sca-accuracy-verify
```

This command does not consume or attest a current generated publication. The trusted run verifies and publishes its own exact-source candidate artifact.

## Workflow modes and commit binding

`.github/workflows/engine-accuracy.yml` has no top-level path filters. Its always-running route job checks out and asserts the exact source SHA, then routes work as follows:

- Pull requests run offline smoke and benchmark-contract verification only; they never receive trusted capture execution or claim that checked-in files are current run evidence.
- A branch push with code, specification, or workflow changes is only a trusted full-control request when repository variable `ENGINE_ACCURACY_TRUSTED_ENABLED` equals `true` **and** its ref is exactly `refs/heads/main` or exactly equals repository variable `ENGINE_ACCURACY_TRUSTED_REF`. The reusable branch trigger avoids maintained feature-branch names without granting privileged execution to every branch while the gate is enabled. Disabled or non-authorized refs are explicit non-evaluation modes in the aggregate.
- The trusted runner proves a real direct-cgroup plus Bubblewrap no-op child before capture. Its wrapper captures the delegated **service** cgroup root before the benchmark process enters `synapse-manager` and supplies it as `SCA_ACCURACY_DELEGATED_CGROUP_ROOT`; the runner rejects missing, non-writable, non-service-root, memory/pids-disabled, or non-allocatable roots. It receives this root, pinned Bubblewrap, Docker images, review capture, pre-frozen SBOM provenance, and retained-input bootstrap as an explicit external ephemeral-runner contract; it does not use a host `/proc/self/status` seccomp assertion.
- It consumes only one pre-frozen, canonical, filtered CycloneDX JSON SBOM for each exact target, verifies its byte digest against the catalog, and rewrites every target's capture manifest to use those same bytes. `syft-probe.json` and `syft-config.json` attest the version, offline/update policy, and configuration digest used by the separate authorized preparation phase; evaluation does not invoke Syft or regenerate an SBOM. No engine gets an independently generated SBOM invocation.
- Generated source/native evidence, observations, bundles, results, reports, and publication manifests never enter Git. Before the ephemeral runner exits, an accepted run uploads only the sanitized candidate controls and results to GitHub Actions artifact storage with an explicit 90-day retention period. Protected raw scanner material stays outside that artifact and is removed after verification.
- The trusted job first requires Linux, Bubblewrap, active seccomp, cgroup-v2 memory and pids controllers, immutable review/source/pin inputs, frozen canonical SBOMs, and protected raw retention. It initializes an audit-safe status and accepted-attempt mapping before runner preflight, then updates that bounded control state through source preparation and capture. It attempts every planned slot up to three times, preserving each exit-2 failed-attempt record and protected bundle; finalization resolves observations and comparison pairs only through the bounded accepted-attempt mapping. It uploads only auditable controls and records before issuing a failure verdict when no accepted retry exists. Only sixteen accepted planned slots (14 dispatches and two designated zero-dispatch SLES/OSV records) permit ledger construction, finalization, publication assembly, and bounded control/result uploads. Raw bundles are never uploaded.
- The scheduled and manual modes use the same full-control route once the workflow is present on the default branch.

The candidate full run is pre-merge evidence bound to the exact reviewed source commit **S**. After upload succeeds, the PR discussion records the run and artifact references, manifest and result digests, verified outcome, and cleanup disposition without copying protected raw material. Removing the ephemeral runner and AWS host does not remove the accepted 90-day GitHub Actions artifact. Candidate-branch evidence is not relabeled as exact-final-main evidence.

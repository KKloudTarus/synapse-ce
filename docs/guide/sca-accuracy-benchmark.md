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
- **Accountable review**: a sanitized, immutable repository-backed GitHub review capture with only a schema version, review ID/URL, login, state, submission timestamp, commit ID, and canonical `decision: <value>` body. The repository verifier checks every captured value against the submitted `github:` reviewer identity, timestamp, reviewed commit, review URL/ID, and decision; it rejects tokens, account details, headers, email fields, and all other capture data. Its decision digest must equal the capture digest and bind the exact final-oracle digest. Materialization copies those exact reviewed bytes into the sanitized candidate and the publication index re-hashes them. Publication requires this distinct record to be resolved and approved; automation cannot stand in for it. Every final-oracle case names that submitted reviewer.

The candidate, cross-check, adjudication, and accountable-review schemas and command paths intentionally do not accept scanner observations, raw bundles, or scores.

The reviewed roots live in `internal/usecase/scabench/corpus/`: the catalog, Oracle, strict ratchet, source-selection templates, capture-manifest templates, cycle/retry/retention policy, and falsifier policy. Generated evidence and delivery artifacts do not live there and must not enter Git.

`cmd/synapse-sca-inputs` closes the dependency graph before capture instead of asking an operator to copy hashes, counts, or paths between JSON files. Its stages:

1. hash the repository-backed source assets and bind the generated source-evidence plan;
2. derive one capture manifest per target/engine cell, including the zero-dispatch capability statement and its physical digest;
3. bind the unique sanitized GitHub review capture to the adjudication, final Oracle, reviewer, and exact reviewed commit;
4. derive the cycle plan, repetitions, cells, dispatch count, unsupported count, and retention controls from the reviewed roots; and
5. later derive publication indexes, cleanup receipt, candidate inventory, delivery receipt, and PR-summary Markdown from files that actually exist.

After materialization, the low-level freeze gate remains available:

```sh
make sca-accuracy-prepare \
  SCA_ACCURACY_REPOSITORY_ROOT=/absolute/repository \
  SCA_ACCURACY_PLAN=/generated/control/plan.json \
  SCA_ACCURACY_SOURCE_FREEZE=/generated/control/source-freeze.json \
  SCA_ACCURACY_ORACLE_CANDIDATE=/generated/control/oracle-candidate.json \
  SCA_ACCURACY_CROSS_CHECK=/generated/control/cross-check.json \
  SCA_ACCURACY_ADJUDICATION=/generated/control/adjudication.json \
  SCA_ACCURACY_ACCOUNTABLE_REVIEW=/generated/control/accountable-review.json \
  SCA_ACCURACY_FINAL_ORACLE_FREEZE=/generated/control/final-oracle-freeze.json
```

`synapse-sca-cycle` first runs `source-native-evidence`, which reads strict frozen assets, evaluates a bounded benchmark-only OVAL subset, and writes both generated source cases and complete per-target native evidence once. Any matching OVAL definition, test, object, or state whose semantics cannot safely be evaluated is retained as a diagnostic that blocks candidate construction; guards for another product, release, architecture, or package are non-applicable rather than failures for relevant branches. `oracle-candidate`, `oracle-cross-check`, `oracle-adjudicate`, and `oracle-freeze` then form the review chain; `oracle-freeze` consumes the materialized accountable decision, verifies every truth-bearing candidate field against the final Oracle, and never invents an approval. Each `cell` invocation requires the complete generated `-native-evidence` set and `-capture-record-output`; `ledger` consumes every retained generated capture record only after every policy-derived slot has an accepted attempt.

The matrix is derived from catalog targets, all four benchmark engines, and the Oracle's expected coverage rather than duplicated in a checked-in row list. The cycle contract requires exactly two accepted repetitions; the current reviewed roots therefore produce two repetitions of eight cells, 14 complete scanner dispatches, and two SLES plus OSV-Scanner unsupported records with zero scanner dispatch. The strict plan and ledger reject missing, extra, duplicate, unknown, incomplete final, or unplanned unsupported cells. Failed and retry attempts remain auditable instead of being discarded to select convenient repetitions.

## Trusted-Linux capture and native comparison

A normal capture is Linux-only and requires the hardened `bubblewrap+seccomp+cgroup-v2` control set. A capability record is zero-dispatch and only valid for the planned unsupported cell. Inputs remain argv data; no target or version value becomes command source text.

Capture one planned cell only after the freeze succeeds. Retention input identifies only the protected destination and policy; after validating the written bundle, capture derives its retained-reference digest from the full bundle root and never accepts an operator-supplied digest. A cell exits `0` only after it has written an accepted capture record; it exits `2` after writing a retained post-dispatch failed-attempt record, which must be uploaded to the audit-safe controls channel before the workflow fails or retries; it exits `1` for pre-dispatch or input-invalid failure.

```sh
make sca-accuracy-cell \
  SCA_ACCURACY_PLAN=/generated/control/plan.json \
  SCA_ACCURACY_CATALOG=/generated/control/catalog.json \
  SCA_ACCURACY_NATIVE_EVIDENCE=/generated/control/native-evidence.json \
  SCA_ACCURACY_CAPTURE_MANIFEST=/generated/control/capture-manifests/target--engine.json \
  SCA_ACCURACY_OUTPUT=/protected/run/repetition-1-cell \
  SCA_ACCURACY_REPETITION=1 \
  SCA_ACCURACY_RETENTION_LOCATOR=protected://engine-accuracy/run/attempt/repetition-1-cell \
  SCA_ACCURACY_RETENTION_POLICY=delete_after_verification
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

Successful and failed full capture bundles remain in protected raw retention only until verification finishes. Scanner databases, tool caches, generated corrupt trees, OCI layers, and raw bundles are never committed or uploaded in the accepted artifact. Audit-safe failed-attempt records may be uploaded under the shorter retention policy; the dedicated runner cleanup removes the run's protected raw subtree and all Docker containers, images, volumes, and build cache before delivery receipt generation.

The full-bundle comparator validates both existing bundles first. It calculates a derived manifest and root identity without adding a second capture format, keeps both raw roots available for the comparison phase, and fails on every unclassified difference. The per-engine policies are intentionally narrow:

- Owned: exact raw output.
- Grype: only the descriptor timestamp.
- Trivy: only top-level `CreatedAt` and `ReportID` plus direct vulnerability `Fingerprint` values.
- OSV-Scanner: only declared non-nil pointer metadata in diagnostics and a correctly shaped terminal timing line.

`internal/usecase/scabench/testdata/semantic-comparison-falsifiers.json` is a capability-level falsifier specification derived exactly from the authoritative 41 historical comparison keys. It records a deterministic baseline, mutation, expected outcome, and operation, never a stored `passed` boolean. The executable runner derives each observed outcome by using synthetic full bundles with the real decoder, archive validator, semantic comparator, and final repetition reducer. Synthetic fixtures prove current behavior only; they do not claim to recover historical capture replay.

## Finalization and publication identity

Finalization reduces and ratchets **every** planned repetition independently, then rejects a result or rendering mismatch. It runs the bundle comparator and falsifier runner before output. Numeric scores remain normalized, while the publication manifest binds every planned repetition's full identity (two repetitions under the current reviewed policy):

- derived bundle manifest and raw root;
- raw stdout, stderr, or raw-output digest;
- normalized observation and canonical SBOM;
- target-native comparison;
- process evidence and environment identity.

The single publication manifest also binds the generated source evidence and complete native evidence. The accepted sanitized publication artifact is limited to resolvable public source snapshots, the exact sanitized review-capture bytes, pins, canonical SBOMs, scanner-free review records, normalized observations, native comparison records, compact process/control identities, comparison and falsifier results, result, ratchet, report, and ledger. It rejects unexpected candidate files in addition to raw bundle and scanner-cache artifact categories. Freeze and publication records use write-once paths.

Finalization writes the measured comparison, falsifier, result, and report before publication assembly. `sca-accuracy-publication` then hashes those actual regular files, builds the manifest, and writes the candidate evidence summary that binds the manifest identity. The summary is deliberately not an artifact within that same manifest: including its own digest would create an unverifiable self-reference.

The trusted workflow invokes the low-level finalization and publication targets only after the materializer has derived accepted bundle selection, observation paths, comparison pairs, publication indexes, and policy counts:

```sh
make sca-accuracy-finalize
make sca-accuracy-publication
go run ./cmd/synapse-sca-inputs -mode cleanup ...
go run ./cmd/synapse-sca-inputs -mode receipt ...
```

These stages fail closed until every required generated path, comparison pair, falsifier specification, accountable review, cleanup result, and exact implementation commit forms one bound cycle. The publication control contains one content-addressed index per required artifact kind; each index deterministically covers all actual files of that kind without relying on a hand-maintained inventory. The final receipt revalidates every indexed file before hashing the complete sanitized candidate. Pull requests can verify the checked-in benchmark contract and historical regression inputs without scanners:

```sh
make sca-accuracy-verify
```

This command does not consume or attest a current generated publication. The trusted run verifies and publishes its own exact-source candidate artifact.

## Workflow modes and commit binding

`.github/workflows/engine-accuracy.yml` has no top-level path filters. Its always-running route job checks out and asserts the exact source SHA, then routes work as follows:

- Pull requests run offline smoke and benchmark-contract verification only; they never receive trusted capture execution or claim that checked-in files are current run evidence.
- A branch push with code, specification, or workflow changes is only a trusted full-control request when repository variable `ENGINE_ACCURACY_TRUSTED_ENABLED` equals `true` **and** its ref is exactly `refs/heads/main` or exactly equals repository variable `ENGINE_ACCURACY_TRUSTED_REF`. The reusable branch trigger avoids maintained feature-branch names without granting privileged execution to every branch while the gate is enabled. Disabled or non-authorized refs are explicit non-evaluation modes in the aggregate.
- The trusted runner proves a real direct-cgroup plus Bubblewrap no-op child before capture. Its wrapper captures the delegated **service** cgroup root before the benchmark process enters `synapse-manager` and supplies it as `SCA_ACCURACY_DELEGATED_CGROUP_ROOT`; the runner rejects missing, non-writable, non-service-root, memory/pids-disabled, or non-allocatable roots. It receives this root, pinned Bubblewrap, Docker images, review capture, pre-frozen SBOM provenance, and retained-input bootstrap as an explicit external ephemeral-runner contract; it does not use a host `/proc/self/status` seccomp assertion.
- It consumes only one pre-frozen, canonical, filtered CycloneDX JSON SBOM for each exact target, verifies its byte digest against the catalog, and materializes one target/engine capture manifest that points to those same bytes. `syft-probe.json` and `syft-config.json` attest the version, offline/update policy, and configuration digest used by the separate authorized preparation phase; evaluation does not invoke Syft or regenerate an SBOM. No engine gets an independently generated SBOM invocation.
- Generated source/native evidence, observations, bundles, results, reports, publication manifests, inventories, and receipts never enter Git. Before the ephemeral runner exits, an accepted run uploads only the sanitized candidate controls and results to GitHub Actions artifact storage. The accepted retention is read from the reviewed cycle policy (currently 90 days), not duplicated in workflow logic. Protected raw scanner material stays outside that artifact and is removed after verification.
- The trusted job first requires Linux, Bubblewrap, active seccomp, cgroup-v2 memory and pids controllers, immutable review/source/pin inputs, frozen canonical SBOMs, and protected raw retention. It initializes an audit-safe status and accepted-attempt mapping before runner preflight, then updates that bounded control state through source preparation and capture. Repetition count, retry bound, retention, logical slots, scanner dispatches, and unsupported slots all come from the generated plan and reviewed cycle policy. Each exit-2 failed-attempt record remains audit-safe while its protected bundle is available for the run; finalization resolves observations and comparison pairs only through the bounded accepted-attempt mapping. The current roots derive sixteen accepted planned slots, 14 dispatches, and two designated zero-dispatch SLES/OSV records, but the workflow contains no duplicated cell list or fixed count assertion. Raw bundles are never uploaded and are deleted before the delivery receipt can pass.
- The scheduled and manual modes use the same full-control route once the workflow is present on the default branch.

The candidate full run is pre-merge evidence bound to the exact reviewed source commit **S**. The generated candidate-file inventory, delivery receipt, and Markdown summary bind the derived matrix counts, manifest/result identities, passing gate, cleanup receipt, artifact name, and policy retention. After upload succeeds, the PR discussion adds the immutable Actions run, artifact ID/URL/digest, and verified outcome without copying protected raw material. Removing the ephemeral runner and AWS host does not remove the accepted 90-day GitHub Actions artifact. Candidate-branch evidence is not relabeled as exact-final-main evidence.

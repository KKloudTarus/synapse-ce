# Engine-neutral benchmark core

The benchmark core (`internal/usecase/benchcore`, #1640) scores any engine that an adapter can describe, through one scorer that never sees which engine produced the observations. It replaces engine-specific floors with absolute criteria that every enrolled engine is graded against the same way.

## Documents

| Document | Schema | Who writes it |
| --- | --- | --- |
| Closure manifest | `synapse-benchmark-closure-manifest-v1` | maintainers, before any run; `docs/benchmarks/closure-manifest-v1.json` |
| Truth set | `synapse-benchmark-truth-v1` | the oracle owner; subjects with digests, labels, provenance, alternate identities |
| Observation | `synapse-benchmark-observation-v1` | an adapter, per engine and subject; no label, count or verdict field |
| Run-start receipt | `synapse-benchmark-run-start-receipt-v1` | the runner, before scoring |
| Scorecard | `synapse-benchmark-scorecard-v1` | the core only |

Every document decodes strictly: an unknown field is refused, so an adapter cannot slip a label or a verdict into an observation.

The manifest freezes, per profile, the corpus, the truth set, the scorer and the matching policy by digest, the unit kinds, the absolute thresholds, the minimum truth support, and each enrolled engine with its declared capabilities. A receipt copies those digests at run start. `BindScorecard` computes the cells itself, runs the control suites itself, and refuses:

- an engine that is not enrolled with the same adapter and scored component;
- a truth set, corpus, scorer or enrollment other than the one the receipt and the profile froze;
- a truth set whose `closed_world` differs from the profile's;
- an observation normalized under another matching policy, or of a subject whose digest differs from the one the truth labels.

A truth correction is a new manifest revision; `ValidateSuccession` refuses a revision that downgrades a required profile without disclosing it.

## Scoring

`Score` matches findings to truth units by subject, unit kind and identity, or any alternate identity the truth declares. Identity keys and unit kinds must be lower-case and trimmed, and values are compared byte for byte: folding case in a value is the adapter's published normalization, because only the adapter knows which parts of an identifier are case-sensitive. A subject may have one observation. Each unit lands in exactly one state, and `Score` checks that the states add up to the denominator:

| State | When |
| --- | --- |
| `true_positives`, `false_negatives` | a positive the engine reported or missed, on a complete observation |
| `false_positives`, `true_negatives` | a negative the engine reported or did not |
| `unknown` | a unit labelled unknown (open world only), or a subject the observation reports unknown |
| `unsupported` | a unit of a kind the engine did not declare, or a subject the observation reports unsupported |
| `incomplete`, `execution_failed`, `abstained` | an incomplete or truncated run, a failed run, or no observation for the subject |

Findings that match no unit are counted apart from units: `unmatched_findings` in a closed world, where they are false reports, and `unadjudicated_findings` in an open world, where they wait for adjudication. Both count distinct identities, so one issue reported under two identities the truth does not relate counts twice. A finding on a subject or unit kind the truth does not contain lands in no cell; the scorecard reports it as `out_of_scope_findings`.

Only a complete, untruncated observation's findings are evidence. Each unit kind gets two cells, end to end (every unit) and assessed only (declared kinds), reported side by side and never pooled. Recall is true positives over every labelled positive in the cell, so a positive the engine did not assess counts against it end to end. Precision is true positives over true positives, false positives and unmatched findings.

## Grades and validity

Validity is about the measurement: a scorecard is valid when every control suite in the manifest passed when `BindScorecard` ran it. Grade is about the engine:

- `ungraded`: the measurement is invalid.
- `descriptive`: some unit kind of the profile has fewer labelled positives or negatives than the profile's minimum truth support.
- `pass` or `fail`: every unit kind's end-to-end cell is held to the thresholds; one failing kind fails the profile. An engine that reported nothing judgeable fails a precision threshold above zero, and in a closed-world profile any out-of-scope finding fails the grade. The unknown ceiling applies only to closed-world profiles, where `unknown` counts units only.

## Control suites

Two suites validate the scorer itself (#1640 work package D). Both run over `internal/usecase/benchcore/controls/known-outcome-v1.json`, whose expected cells were written from the scoring rules above:

- `benchcore-known-outcome`: 15 cases. Correct, missing-positive, noisy (closed and open world), unsupported, failed, abstained, incomplete, truncated, alias, case-sensitive value and out-of-scope kind reproduce their expected cells; a non-canonical identity key, a duplicate subject and an unknown state are refused.
- `benchcore-identity-invariance`: renaming the engine and reversing observation, finding and truth order changes no cell.

The manifest freezes the fixture digest and the expected-outcome digest. A suite run against any other fixture fails. A caller cannot supply control results: `BindScorecard` runs the suites.

## Closure manifest revision 1

`docs/benchmarks/closure-manifest-v1.json` enters one profile, `sca.component-advisory.v1`: the legacy SCA oracle (91 relations on three pinned images; 1 Debian and 18 RPM positives, 72 negatives), open world, with the owned engine, Grype, Trivy and OSV-Scanner enrolled. Their declared capabilities come from the oracle's expected coverage: OSV-Scanner declares only the Debian kind. The matching policy is the bridge's identity rule (`scabench.BenchmarkKey`), identified by `scabridge.NormalizationDigest`.

The profile needs 30 positives and 30 negatives per unit kind before it grades: with n of n positives found, the one-sided 95% Clopper-Pearson lower bound on recall is 0.05^(1/n), and n = 30 keeps it at 0.905. The bound assumes independently sampled units and holds per kind; relations clustered on three images are fewer independent samples than their count. Revision 1 therefore grades every engine `descriptive` on this profile, a perfect one included.

Work packages B, E, F and G have no required profile in revision 1, so `status` reports them `not_entered` and the manifest cannot report closure. They enter through later revisions. A profile counts as executed only when every engine it enrolls has a valid scorecard bound to this manifest's digest whose id matches its content. Scorecards are content-addressed, not signed: `status` checks that they are consistent with the manifest; `verify` recomputes a scorecard from its receipt, truth and observations and fails unless the id matches.

`TestClosureManifestIsFrozen` rebuilds the manifest from the committed oracle, catalog, matching policy and control fixture, and a scorer digest over every non-test source file of the core, the SCA bridge and `scabench`'s key normalization. Changing any of them fails the test until a new revision is published with `UPDATE_CLOSURE_MANIFEST=1`.

## Running it

`synapse-benchcore` executes no scanner. It turns captured outputs into a scorecard:

```bash
M=docs/benchmarks/closure-manifest-v1.json
P=sca.component-advisory.v1
synapse-benchcore controls -manifest $M
synapse-benchcore truth-from-scabench -oracle internal/usecase/scabench/corpus/oracle.json \
  -catalog internal/usecase/scabench/corpus/catalog.json -profile $P -version oracle@same-sbom-linux-20260922 > truth.json
synapse-benchcore receipt -manifest $M -profile $P -run-key run-1 -commit "$(git rev-parse HEAD)" -runner ci > receipt.json
synapse-benchcore observe-scabench -observations observation-set.json -manifest $M -profile $P -engine owned > owned.json
synapse-benchcore score -manifest $M -receipt receipt.json -truth truth.json -observations owned.json > owned-card.json
synapse-benchcore verify -manifest $M -receipt receipt.json -truth truth.json -observations owned.json -card owned-card.json
synapse-benchcore status -manifest $M owned-card.json grype-card.json trivy-card.json osv-scanner-card.json
```

`observe-scabench` takes the engine's capabilities from the manifest enrollment, reads no oracle, and refuses an observation set of another catalog than the profile froze. `controls` prints the control results for inspection; `score` runs them itself. `status` takes its flags before the scorecard paths and exits 3 while the manifest is not closed. Exit 2 is a usage error and exit 1 any other failure.

The legacy reduction in `internal/usecase/scabench` keeps running unchanged. `TestBridgeReproducesLegacyCells` scores the same observations through both, for all four engines, over a scenario with an aliased relation, a duplicated finding, an invalid purl, an incomplete run, declared-unsupported targets and a missing engine, and requires equal counts. The legacy reduction folds three core states into its own: a covered relation with no observation is legacy `incomplete` and core `abstained`, and an unmatched or unnormalizable finding is legacy `unknown` and core `unadjudicated_findings` or `unmapped`. The legacy reduction counts unnormalizable findings once per advisory; the core counts each one.

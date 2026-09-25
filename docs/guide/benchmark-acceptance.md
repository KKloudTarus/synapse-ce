# Benchmark acceptance

Use one exact `main` commit for EPIC #1034 acceptance. The seven capability workflows remain active after acceptance as normal regression checks. A green aggregate counts only when its required measurements and artifacts ran; a skipped audit job is never benchmark evidence.

## Select the subject

1. Merge the intended changes to `main` and record its full 40-character SHA as `ACCEPTANCE_SHA`.
2. Run `engine-accuracy.yml`, `reachability-benchmark.yml`, `security-accuracy.yml`, `dynamic-security-benchmark.yml`, `performance-benchmark.yml`, `sast-benchmark.yml`, and `owned-default-readiness.yml` for that SHA. Use the workflows' `main` push runs or dispatch them from `main` while it still points at `ACCEPTANCE_SHA`.
3. Record each run URL, attempt, source SHA, aggregate conclusion, artifact ID, artifact SHA-256, and input identity. Reject a pull-request merge ref, a later `main` SHA, a missing artifact, or a skipped required job.

## Check each result

| Workflow | Required evidence |
| --- | --- |
| `engine-accuracy.yml` | Hosted owned scanner measured the embedded corpus and the three pinned same-SBOM targets, passed committed owned floors and oracle checks, and published a sanitized result. The Grype/Trivy/OSV comparison in the accepted 24-observation capture is labelled frozen; this workflow does not claim a fresh vendor run. |
| `reachability-benchmark.yml` | Hosted lifecycle, Go owned/competitor scorecards, and Python owned/competitor scorecards succeeded. OSV output is a pinned frozen capture; Semgrep CE runs from the pinned image without network access. Corpus, Unknown accounting, recall, and no-false-suppression gates passed. |
| `security-accuracy.yml` | Hosted accuracy and Gitleaks/Checkov differentials passed with pinned tools and nonempty artifacts. |
| `dynamic-security-benchmark.yml` | Hosted DAST and CSPM accuracy jobs, ratchets, and aggregate passed. |
| `performance-benchmark.yml` | Hosted measurements produced nonzero samples for each required target class. Allocation ratchets consume the six committed numeric baselines. Each baseline records measured throughput. Latency is compared with the fixed, reviewed control revision measured on the same hosted runner; the six committed baseline JSONs bind its SHA, dataset, and sampling policy. p95 and peak memory are recorded in the artifact. |
| `sast-benchmark.yml` | OWASP, Juliet, Securibench, Semgrep comparison, Python/sanitizer adversarial tests, and fresh deterministic proof-triage precision gate passed. The job generates both historical and current scorecards from pinned scanner and corpus revisions; it does not replay the earlier model-assisted capture. |
| `owned-default-readiness.yml` | Readiness result names `ACCEPTANCE_SHA`, reports current SCA evidence, comparator-relative parity, unsupported gaps, and graph parity. It cannot infer currency from a skipped audit or source-code marker. |

For each row, inspect the required job results as well as the aggregate. Preserve the sanitized machine-readable artifact and its digest before retention expires. A benchmark that cannot access a required pinned asset must fail and report why.

The performance gate applies the committed allocation ceilings directly. Its latency ceiling is
`max(1.5 × control p50, control p50 + 5 ms)` using a pinned control revision run beside the candidate on
the same hosted runner. The committed latency numbers record the reviewed control measurement; they are not
cross-hardware thresholds. Changing the control revision requires a reviewed workflow pin and matching
remeasured baseline JSONs. p95 and process-wide peak memory remain reported diagnostics.

The earlier Securibench model transcripts and verifier artifacts are local audit material under `.git/taurus/sast-post-triage-artifacts`; they are not CI inputs or committed benchmark files. The required SAST gate uses `syntactic-proof-v1` on fresh blinded proposals and requires the candidate's measured precision improvement over the pinned historical scanner, while retaining every oracle-positive finding.

## Optional formal capture

`engine-accuracy-audit.yml` and `reachability-audit.yml` are manual lanes for baseline refresh or formal evidence. They may require protected infrastructure, exact authorization, controller material, or independent review under their own contracts. Their `accepted` result is distinct from the hosted regression result. Do not require an audit run for ordinary PR/main regression, and do not treat an audit run with skipped work as a pass.

Keep the seven required regression workflows and their branch-protection checks enabled after EPIC closure. Record the final `main` run URLs and dispositions in #1034, then close #1043 before closing the parent issue.

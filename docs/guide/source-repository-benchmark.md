# Source-repository benchmark

This benchmark answers one question: on the same public source tree, what does Synapse find that Trivy,
gitleaks and OSV-Scanner find, and what does each find that the others do not? It complements the
[SCA accuracy benchmark](sca-accuracy-benchmark.md), which measures the owned matcher over frozen
container-image SBOMs, by covering the other case a user actually runs: a working copy of an application
repository, scanned in a pipeline.

Comparator scanners are benchmark-only. They are not product detection sources and are never added to
`SYNAPSE_DETECTION_SOURCES`.

## Corpus

Seven repositories across six ecosystems, each cloned at depth 1 from its public default branch.

| Repository | Language | What it exercises |
| --- | --- | --- |
| `terraform-aws-modules/terraform-aws-eks` | Terraform | IaC rules, rendered user-data fixtures |
| `spring-projects/spring-petclinic` | Java | Maven resolution with no local repository |
| `prometheus/prometheus` | Go | a large Go module tree, `testdata` secret fixtures |
| `vitejs/vite` | JavaScript, TypeScript | pnpm workspace, documentation assets |
| `apache/superset` | Python | a polyglot tree: Python, TypeScript, Docker, Helm |
| `monicahq/monica` | PHP | Laravel with Vue single-file components |
| `pixelfed/pixelfed` | PHP | Laravel with 368 Blade templates |

## Method

Every tool reads the same working copy. No tool is given a warmed cache the others do not have, and none is
given credentials.

```sh
synapse-cli scan "$repo" --json --fail-on critical
trivy fs --scanners vuln,misconfig,secret --format json "$repo"
gitleaks dir "$repo" --report-format json
osv-scanner scan source --recursive --format json "$repo"
```

Two normalisations make the counts comparable:

- **Advisory identity.** The three tools report an advisory under different ids: Synapse uses the CVE where
  one exists and the GHSA id where none does, OSV-Scanner uses `GO-` and `GHSA-` ids, and Trivy uses the GHSA
  id for a language-ecosystem advisory. The OSV report is the only artefact that states the mapping, so its
  `aliases` build a GHSA-to-CVE table that is applied to every tool's ids before they are compared. Both
  halves of this matter: without it the `prometheus` overlap with OSV-Scanner reads as 3 of 63 rather than 63
  of 63, and `monica` shows 5 advisories Trivy found and Synapse missed when all five are advisories Synapse
  reports under their CVE aliases.
- **Absent capability.** A dimension a tool does not cover is recorded as absent, never as zero. gitleaks
  reports secrets only; OSV-Scanner reports dependency advisories only. Reading a missing capability as a
  clean result is the error this benchmark exists to avoid.

Every number below comes from one sweep with one Synapse build, with a single exception that cannot move a
row: `superset` was re-scanned after the GCP service-account rule was tightened, and that rule reported
nothing on any other repository even in its looser form.

## Results

Synapse:

| Repository | Packages | SCA | Secret | IaC | SAST | Code quality |
| --- | --- | --- | --- | --- | --- | --- |
| terraform-aws-eks | 0 | 0 | 0 | 96 | 1 | 0 |
| spring-petclinic | 154 | 44 | 0 | 56 | 0 | 52 |
| prometheus | 2171 | 63 | 0 | 105 | 447 | 53 |
| vite | 1304 | 19 | 0 | 8 | 84 | 416 |
| superset | 4218 | 15 | 26 | 176 | 500 | 0 |
| monica | 781 | 148 | 5 | 38 | 33 | 467 |
| pixelfed | 1180 | 49 | 2 | 39 | 223 | 277 |

Two `superset` numbers are floors rather than totals, and the scan says so in its own output rather than
presenting them as complete. It reaches the whole-tree SAST cap of 500, so its code-quality count is 0
because the security class takes the budget first; and its `pyproject.toml` tree did not resolve because the
machine has no `poetry` on `PATH`, so its component and advisory counts come from the pinned
`requirements/*.txt` files and the JavaScript side only.

Comparators, on the same trees:

| Repository | Trivy SCA | Trivy secret | Trivy IaC | gitleaks secret | OSV-Scanner SCA |
| --- | --- | --- | --- | --- | --- |
| terraform-aws-eks | 0 | 0 | 107 | 0 | no package source |
| spring-petclinic | no result | no result | no result | 0 | no result |
| prometheus | 17 | 0 | 38 | 20 | 63 |
| vite | 4 | 0 | 0 | 0 | 0 |
| superset | 8 | 8 | 26 | 226 | 15 |
| monica | 52 | 0 | 2 | 0 | 148 |
| pixelfed | 32 | 0 | 2 | 1 | 49 |

Advisory overlap, on the normalised identifier space:

| Repository | Synapse and Trivy | Trivy only | Synapse and OSV | OSV only |
| --- | --- | --- | --- | --- |
| prometheus | 17 | 0 | 63 | 0 |
| vite | 4 | 0 | 0 | 0 |
| superset | 8 | 0 | 15 | 0 |
| monica | 51 | 0 | 148 | 0 |
| pixelfed | 32 | 0 | 49 | 0 |

## What the numbers say

**Advisory matching agrees exactly with OSV-Scanner where both resolve the tree.** On `prometheus` all 63
advisories match, on `superset` all 15, on `monica` all 148 and on `pixelfed` all 49, with nothing found by
only one of the two. Trivy resolves a strict subset on every tree: 17 of 63, 4 of 19, 8 of 15, 51 of 148 and
32 of 49, with nothing Trivy finds that Synapse does not.

**A throttled registry stops two of the three scanners outright.** On `spring-petclinic` Maven Central
answered `429 Too Many Requests` while resolving `spring-boot-starter-parent`. Trivy exited fatally on it and
OSV-Scanner returned zero advisories; neither degrades to a partial answer. Synapse hit the same `429`, and
its result records it:

```
maven repository repo.maven.apache.org rate-limited this scan (Retry-After: 1800);
the dependency tree resolved from it is a lower bound
```

It still resolved 154 components, 129 of them to a version, and 44 advisories. How many it retrieves before
the throttle lands varies between runs, which is why the tree is reported as a lower bound rather than a
total. Three properties of the POM fetcher produce that: the scanned project's own declared repositories are tried before Central, a coordinate
answered "not here" is never asked for again, and a host that throttles stops being asked for the rest of the
scan without failing it. The result is a stated lower bound rather than a crash, which is the difference
between a pipeline that reports something and one that reports nothing.

**Reading every secret finding against its rule removed 293 of 326.** Each of the five repositories that
reported a secret was triaged finding by finding, and nine false-positive classes came out of it, every one a
shape that is high-entropy or credential-shaped by construction: a base64 CA certificate, a CDN asset URL, a
webfont content hash, a codec alphabet, a translation catalogue, a documented connection-URI template in two
forms, a documented GCP key format, an empty key reaching onto the next line, and a keyword binding to the
next line's attribute. Secret counts went from 19 to 0 on `terraform-aws-eks`, 6 to 0 on `vite`, 8 to 5 on
`monica`, 26 to 2 on `pixelfed` and 267 to 26 on `superset`. Every guard carries a test that fails without it
and a second test pinning the real credential it must still report.

What remains was read too. On `monica` and `pixelfed` it is one genuine committed Laravel `APP_KEY`, reported
once per file that sets it, plus one hit inside a vendored Yarn bundle that this deliberately does not skip: a
credential in build output is still a leak, and one false positive is a cheaper price than that blind spot. On
`superset` the 26 are 14 keyword-anchored credentials, 5 high-entropy values, 3 connection strings, 3 basic
authorization headers and a kubeconfig token, and none of them sits under a test path.

**A secret-scanning difference can be a policy difference, or a recall difference.** gitleaks reports 20
secrets on `prometheus` where Synapse reports none by default. All 20 sit in `testdata/` and `*_test.go`,
which Synapse classifies as background scope and holds out of the gate; `--include-test` reports 45 of them
across 33 files. That gap is about which findings a pipeline should fail on rather than what either tool can
see. It runs the other way on `monica`, where gitleaks reports nothing and Synapse reports a committed
Laravel `APP_KEY` in four files, and on `superset`, where Synapse reports 267 secrets against gitleaks' 226.

**IaC coverage differs in shape, not only in count.** Trivy reports 107 misconfigurations on
`terraform-aws-eks` against Synapse's 96, and the difference is mostly not extra defects: 24 of Trivy's 107
are two EKS control-plane logging findings (`controllerManager` and `scheduler`) repeated across the twelve
example and test trees that instantiate the module, every one resolving to the same `main.tf` line. Synapse reports GitHub Actions workflow findings (19 unpinned actions, 5 workflows with no
explicit permissions) and 17 IAM wildcard-resource findings that Trivy's filesystem scan does not cover at
all.

## Known gap

Trivy's EKS control-plane logging check requires the full log-type set, so it reports the two types
`terraform-aws-eks` omits (`controllerManager`, `scheduler`). Synapse's `terraform-eks-no-logging` only
checks that `enabled_cluster_log_types` is declared, and the module declares it through a variable. Closing
this needs list-valued variable resolution in the Terraform resolver, which today substitutes unambiguous
scalar literals only; a rule that judged an unresolved list would be guessing. The gap is recorded here
rather than closed with a rule that cannot fire on the repository that motivated it.

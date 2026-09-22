> Canonical source: [`docs/adr/0010-red-hat-advisory-feed-breadth.md`](https://github.com/KKloudTarus/synapse-ce/blob/main/docs/adr/0010-red-hat-advisory-feed-breadth.md). Do not edit this published mirror directly.

# ADR 0010: Red Hat advisory feed breadth

- Status: Accepted (decision: **do not broaden; correct the oracle citation instead**)
- Date: 2026-09-22
- Issue: #1314 item 2 (EPIC #1034, wave 2 item 7); relates to #1035, #1043

## Context

The SCA accuracy benchmark measures the owned matcher against Grype, Trivy and OSV-Scanner on a frozen
SBOM per reviewed target. On the `rhel-9-8-ubi-amd64` target the owned engine measures recall 0.5 with
one false negative, and that single miss is the `CVE-2026-22185` / `openldap` relation, which Grype
reports. PR #1313 proposed that Grype likely finds it because it consumes Red Hat's security-data/OVAL
publication rather than the pinned CSAF VEX, and explicitly marked that as unverified.

That attribution is now verified. Measured 2026-09-22, both feeds fetched live:

| Feed | RHEL 9 bare `openldap` for CVE-2026-22185 |
|---|---|
| CSAF VEX v3, `security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-22185.json` | absent from every `product_status` state |
| Security Data API, `access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-22185.json` | `package_state` lists it, `fix_state: "Fix deferred"` |

The CSAF document contains only a `known_affected` state, and its RHEL 9 entries are exactly
`openldap-clients`, `openldap-compat`, `openldap-devel` and `openldap.src`. Bare `openldap` is listed
for RHEL 6, 7 and 8 but not 9 or 10. So the two authoritative Red Hat publications disagree at exactly
the granularity the benchmark compares.

Three further measurements bound how that disagreement may be read:

- **The omission is not a negative determination.** Red Hat uses the exact product key
  `red_hat_enterprise_linux_9:openldap` in `known_not_affected` when it means not-affected; verified on
  CVE-2022-29155 and CVE-2023-2953, where that key appears in that state. Here the key appears in no
  state at all, while the other feed says "Fix deferred".
- **The omission is not a code-presence judgement.** RHEL 9 `openldap-devel` (headers and `.so`
  symlinks) and `openldap-compat` (compatibility libraries) are both `known_affected`, and neither
  ships the vulnerable `mdb_load` utility. RHEL 8 bare `openldap` is also `known_affected`. If the
  affected set encoded which RPM contains the flawed code, those entries would be absent too.
- **The vulnerable code is in neither package.** CVE-2026-22185 is a heap buffer underflow in LMDB's
  `mdb_load` (CWE-191, Moderate, CVSS 6.8 `AV:L`). On RHEL 9 `mdb_load` ships in the separate `lmdb`
  RPM from the `lmdb` source RPM in CodeReady Builder. The `openldap-2.6.8-4.el9` binary RPM in the
  pinned image contains 58 files and no executables, and `lmdb` is not in the benchmark catalog at all.

The repository's ingestion posture is the constraint that decides this. `docs/guide/vulnerability-intelligence.md:115-121`
records that Red Hat's public provider metadata advertises directory URLs and a signed weekly tar.zst
archive with change and deletion indexes, **not** the ROLIE distribution the CSAF adapter consumes, and
that Synapse deliberately does not acquire or reconcile that protocol in this release. Red Hat VEX is
therefore usable only as independently reviewed benchmark evidence or through an operator-maintained
explicit signed document list. There is no Red Hat Security Data API adapter: `AdapterType` enumerates
`osv`, `csaf`, `oval`, `nvd`, `ghsa`, `gitlab`, `cisa_kev`, `first_epss`, `public_exploit` and
`vulncheck_kev` (`internal/domain/vulnerabilitysource/source.go:20-30`), and no code references the
`hydra/rest/securitydata` endpoint, `package_state` or `affected_release`.

Unbounded Red Hat RPM ranges are admitted only through the authoritative-snapshot boundary, which
requires full synchronization plus a pinned OpenPGP key or trusted provider metadata
(`source.go:144-155`), and which excludes `.src` products and modular AppStream builds
(`docs/guide/vulnerability-intelligence.md:103-113`).

## Decision

**Do not broaden the Red Hat feed set.** Specifically:

1. No Security Data API adapter is added. Consuming `package_state` would mean ingesting a feed whose
   granularity is the source package, then matching it against SBOM components that are binary RPMs.
   Every binary built from an affected source RPM would match, which raises recall on this one relation
   by making the matcher structurally less precise everywhere. That is the "looser matcher" route
   #1314 rules out, and it would regress the precision 1.0 / zero-false-positive result the owned
   engine currently holds across all 24 cells.
2. The authoritative-snapshot boundary is unchanged. It is what keeps an unbounded RPM range from being
   widened past the platform the vendor stated, and nothing here argues for relaxing it.
3. The owned engine's non-report of this relation is **correct under the method the oracle cites**. The
   oracle's labeler id is `method:scanner-free-vendor-csaf-vex-binary-v1`; under binary-aware CSAF VEX,
   RHEL 9 bare `openldap` is not asserted affected.
4. **The oracle case's citation is wrong and is corrected separately.** The case asserts
   `truth: affected` with the rationale that "binary-aware VEX marks the exact `openldap` binary
   affected with no applicable fixed boundary". That is not what the cited document says. The truth
   label stands, because Red Hat does assert the package as affected and unfixed; what must change is
   the cited evidence and the stated method, which should be the package-granular Security Data API
   record. Tracked as wave 2 item 8.
5. Red Hat remains benchmark-only evidence, consistent with `vulnerability-intelligence.md:115-121`.
   This ADR does not authorize pointing `provider_metadata_url` at the tar.zst archive.

## Consequences

- The `rhel-9-8-ubi-amd64` owned floor stays unmet. This is deliberate and is not resolved by any
  labelling of this case: `not_affected` breaks `minimum_affected_relations: 2`, and `incomplete`
  breaks both `minimum_covered: 3` and `maximum_incomplete: 0`. The floor requires the owned engine to
  detect both RHEL affected relations while it detects one, so closing it requires matcher capability
  the repository has decided not to buy at the cost of precision — or a reviewed floor amendment. It is
  not a labelling problem, and PR #1315 was right not to relax the floor toward the capture.
- Grype's advantage on this cell is now attributed rather than unexplained: it derives from feed
  breadth and package-granular matching, not from a better matcher over the same evidence. A comparator
  out-recalling the owned engine on a cell where the vendor feeds disagree is an honest measurement.
- The oracle's per-case rationale becomes citable at the granularity it actually rests on. An oracle
  case whose rationale misdescribes its own evidence is a worse defect than a hard floor, because it
  misleads every later reader of the corpus.
- Correcting the case moves `oracle_digest`, which forces a `ratchet.json` repin and a regenerated
  result and report on the next trusted capture (`internal/infrastructure/scabench/run.go:387-405`,
  `:1151-1198`).
- A reader of the benchmark can no longer assume the RHEL labels come from one feed. The corpus will
  carry citations at two granularities, which must be stated rather than implied.

## Alternatives rejected

- **Read the CSAF omission as `not_affected`.** Rejected on measurement: Red Hat expresses that
  conclusion with an explicit `known_not_affected` entry for this exact product key on other CVEs, and
  did not do so here. Treating an omission as a determination the vendor demonstrably states
  explicitly would put a fabricated vendor position in the oracle.
- **Mark owned coverage `incomplete` or `unknown`.** Rejected in principle. Those coverage values are
  excluded from scoring (`internal/usecase/scabench/reduce.go:125-193`), so this would convert a real
  recall gap into an unscored cell — laundering a miss through the coverage field, which
  `docs/guide/sca-accuracy-benchmark.md:57` forbids.
- **Retarget the case to a VEX-listed sibling binary.** Rejected as impossible: the pinned
  `rhel-9-8-ubi-amd64` target has 206 components and exactly one matching `ldap`, the bare
  `pkg:rpm/redhat/openldap@2.6.8-4.el9`. Neither `openldap-clients`, `openldap-compat` nor
  `openldap-devel` is installed in the image.
- **Add `lmdb` to the catalog and label the relation there.** Rejected as out of scope and unsupported
  by the target: `lmdb` is not installed in the pinned UBI 9.8 image, so no case can be written against
  it. This would also change the frozen catalog, which is maintainer work outside this decision.
- **Consume Red Hat OVAL through the existing generic adapter.** Rejected for this release. The OVAL
  adapter has no Red Hat-specific handling, Red Hat's OVAL endpoint for this CVE returns 404, and the
  ingestion posture above states the acquisition protocol is not reconciled. Revisiting this needs its
  own decision with a completeness story, not a matcher change.

## Evidence

Fetched 2026-09-22; digests are of the exact bytes received.

- CSAF VEX: HTTP 200, 34,959 bytes, `sha256:7aafd6e77b4b64d333c19b71c2acc94785ca9874b4951667e355920e9712e5f9`.
  Tracking `version: 3`, revisions `1 (2026-01-07) Initial version`, `2 (2026-09-01) Current version`,
  `3 (2026-09-01) Last generated version`. The catalog pins
  `sha256:5a9ca00fdf9276d14ebc66d24dcf5eebaca01bc51368cf18fdc2b8750a6025da`, so the originally cited
  bytes are no longer retrievable from the origin.
- Security Data API: HTTP 200, 4,442 bytes,
  `sha256:5916908d28ad8afbffa29c7ecd3dd62eaed1b2fa372f92a4d9ea05eb274fe9d4`, stable across two fetches.
  `affected_release` is empty; `package_state` carries 9 entries including RHEL 9 `openldap`.

The drift in the CSAF citation is the condition ADR-adjacent work is already addressing: a catalog pin
records a digest and origin but not the bytes, so a corpus can outlive the evidence it cites. The pin
archive added under wave 1 item 6 is what allows a future citation to remain verifiable after the
vendor republishes, and the corrected citation should be archived at pin time.

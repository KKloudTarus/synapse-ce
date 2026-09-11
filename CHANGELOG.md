# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JavaScript/TypeScript interprocedural semantic taint analysis (`SYNAPSE_JSTAINT_ENABLED`, off by default).** Building on the source-only synapse-ast facts extractor, an owned value-flow engine tracks untrusted request, `process.argv`/`process.env`, and Node http values from Express/Koa/Fastify sources through parameter binding and return flow into dangerous sinks, proposing gated CapSAST judgments (propose-only; a distinct verifier confirms). It reuses the Python engine's value-slot, container-granular (no field-sensitivity) model and its class-aware sanitizer walls. The six classes are command injection (`child_process`, CWE-78), code injection (`eval`/`Function`/`vm`, CWE-94), path traversal (`fs`/`fs.promises`, CWE-22), SSRF (`axios`/`http`/`https`/`got`/`fetch`, CWE-918), reflected XSS (`res.send`/`document.write`, CWE-79), and open redirect (`res.redirect`, CWE-601). Every sink is anchored to a resolved import, an unshadowed language global, or the response-object receiver-name convention the Python catalog already uses for `cursor.execute`, tightened for JS to the exact dotted path and a receiver that is a parameter or global (never a locally constructed `const res = {...}` object); a name shadowed by a local function, class, binding, or import (including the TS `import x = require('m')` form) drops the match. The engine emits only positive proposals and never a suppression, and the no-false-positive bar is met by DECLINING every shape that would need value-type or object-field resolution the facts do not carry: SQL `.query`/`.raw` on a runtime connection instance, the `axios({url})`/`fetch(req, opts)` object-config forms, `el.innerHTML =` assignment sinks, `setTimeout` string evaluation, and `res.render` template locals. A missed flow is a coverage gap, the safe direction. This implements EPIC #860 D5.2.
- **Container image scans now catalog the BerkeleyDB rpm database, so RHEL 8 / UBI8 / CentOS / Amazon Linux 2 images are covered, not only the RHEL 9+ sqlite backend.** The owned rpm cataloger read only the sqlite backend (`/var/lib/rpm/rpmdb.sqlite`), so an image whose package database is the older BerkeleyDB backend (`/var/lib/rpm/Packages`) yielded zero OS packages and its installed rpms went unscanned for vulnerabilities. An owned, pure-Go BerkeleyDB HASH parser (no cgo librpm, no third-party rpmdb dependency, so `CGO_ENABLED=0` still builds) now walks the hash pages, reassembles each package header from its overflow-page chain, and hands the blob to the same header decoder the sqlite path uses, in both little- and big-endian on-disk byte orders. The cataloger tries the sqlite backend first, then BerkeleyDB, so a single-backend rootfs is cataloged from whichever database it carries. The database is untrusted (a pulled image), so it is hardened exactly like the sqlite path: a regular-file guard (no symlink follow out of the rootfs), per-blob, total-byte, and package-count budgets, honored context cancellation, and a recover-wrapped parse, so a malformed database contributes nothing rather than crashing the scan or fabricating a package (a misparse would be a wrong CVE match). A malformed page, entry, or overflow chain is skipped, never guessed. Validated against a real UBI8-micro fixture (21 header blobs: 19 packages plus 2 gpg-pubkey pseudo-packages, matching the sqlite backend's output). The openSUSE ndb backend (`/var/lib/rpm/Packages.db`) stays deferred until an ndb fixture is available to validate an owned parser against. This implements EPIC #860 D7.3.
- **Misconfiguration scanning now renders and scans Kustomize overlays, catching a misconfiguration a patch introduces.** A Kustomize overlay patches base manifests, so an insecure setting can be introduced (or removed) by a patch that neither the base nor the patch file shows as a complete resource. Like Helm, a kustomization is now rendered (`kustomize build`) and its output scanned with the Kubernetes rules. Rendering runs only when opted in, sandboxed through the SCA runner on the API path (egress denied, since an overlay can pull remote bases, an SSRF vector) or a direct exec for the trusted-local CLI; with neither, the manifests are scanned raw as before. Double counting is avoided without ever suppressing a finding: only ROOT kustomizations (an overlay no other kustomization references) are rendered, and a manifest is skipped from the raw scan only when it is an explicit resource in the transitive closure of a root whose render succeeded and is not also in a failed or unattempted root's closure. So a render failure, a truncated render, a reference cycle, or a non-referenced file all fall back to the raw scan, and a base shared with a failed overlay is scanned raw (a harmless double) rather than hidden. This completes EPIC #860 D6.5 (the Bicep half shipped earlier).
- **Owned-cataloger container image scans now attribute a vulnerability to the layer that introduced it.** Per-layer attribution (the layer diff_id, base-vs-application classification, and the layer's build command on each finding) worked only for the syft producer; an owned-producer image scan left every finding unattributed. The rootfs extractor now records which layer last wrote each materialized file (a path to layer-diff_id map, the squashed view, index-aligned to the image config's diff_ids), and the owned OS-package (dpkg/apk/rpm) and installed-language (`bincat`) catalogers record each component's on-disk evidence path, so the SCA pipeline stamps each owned component with its introducing layer before the existing layer-join runs. It reuses the same `attributeImageLayers` machinery and never overrides a component syft already attributed. Attribution is disabled cleanly (no change to extraction) when the image config's diff_ids are unavailable or their count disagrees with the layer count. OS-package attribution is at the package-DB granularity (all packages from one DB share that DB file's layer), an estimate that is honest metadata and never a suppression; per-package precision is a follow-up. This implements EPIC #860 D7.8.
- **Misconfiguration scanning now covers raw Azure Bicep source, not only compiled ARM JSON.** Competitors scan `.bicep` directly; Synapse previously covered only the transpiled ARM template. A bounded, text-only Bicep parser now reads each `resource` declaration into the same shape the ARM scanner consumes and runs the identical Azure rule set, so a Bicep storage account, network security group, Key Vault, or AKS cluster produces the same rule ids (`arm-storage-*`, `arm-nsg-*`, `arm-keyvault-*`, `arm-aks-*`, `arm-hardcoded-secret`, ...) as its compiled twin. It keeps the fail-closed discipline of the ARM scanner: a value that is not a plain literal (a parameter or variable reference, a function call, a ternary, an interpolated string) is treated as unknown and never yields an insecure-literal finding, and an unmodeled construct (a resource loop, a child resource, a module) is skipped rather than guessed, so coverage is additive and cannot introduce a false positive. The parser is bounded against malformed input (size, depth, and iteration caps) and never executes or resolves anything. Kustomize overlays are not yet covered. This implements the Bicep half of EPIC #860 D6.5.
- **`synapse-bench` now reduces detection accuracy, not only throughput.** The detection-accuracy reducer (`benchmark.EvaluateAccuracy`: precision, recall, F1, false-discovery and false-negative rates, overall and per group, schema `synapse-accuracy-input-v1`) was reachable only from the in-process golden-corpus gate. `synapse-bench -mode accuracy` now decodes an accuracy input document and emits the precision/recall report deterministically, so the owned engine's own detection rates can be measured from the command line, distinct from the AI-triage metrics. `-mode throughput` (the default) is unchanged. This completes EPIC #860 D8.2.

- **Container image scans now flag image-config and build-history hardening issues.** An owned check over the recovered image config and history reports a container that runs as root (no `USER`, or an explicit root/uid-0), a credential baked into an environment variable, and a sensitive build command (a remote script piped to a shell, or an `ADD` of a remote URL). It reads only `sbom.ImageInfo` (no filesystem walk), and a recognized credential in an env value (and in a build command) is redacted at read time so a baked-in secret never reaches persisted scan data. Findings are ungated presence facts on the same surface as the misconfig scanner. This implements EPIC #860 D7.10.
- **A minimal-upgrade remediation solver names which direct dependencies to bump to remove a transitive vulnerability.** Given a vulnerable transitive component and its fix version, `remediation.Solve` returns the smallest set of DIRECT dependencies whose upgrade removes every path from a root to the vulnerable node. Every root-to-vulnerable path passes through exactly one direct dependency, so the set of direct introducers is provably minimal: dropping any one leaves the paths through it, and upgrading all of them removes the vulnerability. It is pure and offline (it names the direct deps to upgrade, not the exact target versions, which needs registry metadata the graph does not carry). This implements the solver of EPIC #860 D3.8.
- **Python taint analysis now flags log injection.** The value-flow catalog gained a log-injection class (CWE-117): untrusted data reaching a standard-library `logging` module call (`logging.info(msg)`, `logging.log(level, msg)`) is a finding, since a newline in the message can forge or split log lines. Only the resolvable module-level calls are modeled (a bare `logger.info()` receiver is not), and it ships a positive and a sanitized-twin test. NoSQL injection and archive-extraction path traversal are deliberately NOT modeled, because a sound match needs receiver type/kind resolution the value-flow engine does not have: a bare `.find()` model would flag `str.find`/`list.find`, and a `tarfile.open`/`zipfile.ZipFile` path sink would flag `ZipFile(request.files.get('f'))` (a tainted file OBJECT, not a path) as a false CWE-22, which is the one forbidden outcome. This advances EPIC #860 D5.6.
- **Secret scanning now looks inside archives (`.jar`/`.war`/`.zip`/`.tar`/`.tar.gz`/`.gz`).** A credential shipped inside a release tarball or a jar was invisible: those extensions were skipped. The scanner now extracts archive members and runs the same detectors, allowlist, and redaction over each text member, attributing a hit to `<archive>!<member>`. Extraction is fully bounded against a decompression bomb: a per-member byte cap, a per-archive total-decompressed-bytes budget, a per-archive entry-count cap, and a nesting-depth cap (a jar inside a war), with the report marked truncated when a cap is hit. A corrupt archive or member is skipped, never a scan failure. This is the archive coverage trufflehog provides, and completes EPIC #860 D6.9 (the base64/hex decode half shipped earlier).
- **NuGet dependency edges are now recovered from `project.assets.json`, not only the opt-in lockfile.** The owned .NET parser read only `packages.lock.json`, which exists only when a project opts into `RestorePackagesWithLockFile`, so most .NET projects had a flat NuGet component list with no transitivity. `project.assets.json` (the restore graph `dotnet restore` always writes to `obj/`) is now parsed too: each target framework's resolved `<Name>/<Version>` packages become components and their `dependencies` are resolved to concrete versions in the same framework (resolution-as-filter, so an edge is emitted only when its target actually resolved there, never synthesized). Project references are skipped. A transitive NuGet CVE now reports its dependency path even without the lockfile. This completes EPIC #860 D3.7.
- **RHEL rpm packages in a scanned image are no longer flagged as an unkeyable release.** The image OS-package cataloger marked a release `DistroResolved` (keyed to an advisory ecosystem) only for the Rocky/AlmaLinux/Oracle rebuilds, so a Red Hat Enterprise Linux image (`ID=rhel`/`redhat`) emitted a false "OS packages cataloged but the release could not be keyed" warning even though the owned Red Hat CSAF feed matches it. `rhel`/`redhat` now resolve, in lockstep with the `osDistroEcosystem` bridge that maps them to `Red Hat:<major>`. CentOS, Fedora, Amazon Linux, and SUSE stay unresolved (cataloged for inventory, honestly flagged) until their feeds land, so the flag never claims a keying the matcher cannot make. This implements EPIC #860 D7.5.
- **Container image scans now catalog language manifests baked into the image filesystem.** The owned SBOM producer ran only over the OCI layout directory (packed blobs), so an application `package-lock.json`, `requirements.txt`, `go.mod`, or `pom.xml` shipped inside an image was invisible and only its installed packages (node_modules, dist-info, jars, gems, dpkg/apk) were cataloged. An owned-producer image scan now also runs the producer over the materialized rootfs and merges the components and dependency edges it finds (deduped by component identity), so the declared dependency graph in the image is scanned for vulnerabilities and licenses. This runs only under the owned producer (syft already catalogs the squashed image filesystem from the layout) and is best-effort. This implements EPIC #860 D7.1.
- **CSAF advisory documents can now be verified against the provider's OpenPGP signature, so a tampered document is rejected instead of ingested.** No advisory feed was cryptographically checked before. A CSAF (or OVAL) source configured with the provider's armored `public_openpgp_key` now fetches each document's adjacent `.asc` detached signature and verifies it before parsing; a missing, malformed, or mismatched signature fails the sync closed (a tampered or unsigned document is never trusted). Verification uses the maintained `github.com/ProtonMail/go-crypto` OpenPGP implementation. A CSAF source can also set `provider_metadata_url` to the provider's `provider-metadata.json`: Synapse then auto-discovers the ROLIE-listed advisory documents and every published signing key (CSAF trusted-provider discovery), verifying each document against the discovered keys so a document signed by any published key passes and key rotation works; a pinned `public_openpgp_key` always wins over a discovered key. Discovery is fail-closed and end-to-end https: each discovered key is bound to the fingerprint the (TLS-fetched) metadata publishes so a substituted key is rejected, the provider credential is sent only to the provider's own host, discovered key/feed/document URLs must be https, and signatures are restricted to the SHA-2 family. This implements the CSAF-authenticity verification and trusted-provider discovery of EPIC #860 D1.8 (the OSV checksum half shipped earlier).
- **A direct GitLab (gemnasium-db) advisory provider adds coverage the OSV mirror does not carry.** A new `gitlab` vulnerability source downloads the GitLab Advisory Database repository archive (one tar.gz of per-package YAML advisories) and ingests every advisory. GitLab advisories are not mirrored by OSV, so this is genuinely additional coverage. The gemnasium `affected_range` parser is fail-closed on the no-false-positive bar: it splits the `||` OR-groups and `,` AND-clauses, and if any group cannot be expressed soundly (an exclusive lower bound, an open-ended group, an unknown operator, a contradictory group) it drops the whole package rather than emitting a range that could match the wrong versions; an unmapped `package_slug` ecosystem is skipped. Download and per-entry caps and the SSRF-guarded transport match the OSV feed. This implements the GitLab half of EPIC #860 D1.10.
- **A direct GitHub Advisory Database (GHSA) provider ingests GHSA advisories with their GitHub metadata, no longer only through the lagging OSV mirror.** A new `ghsa` vulnerability source syncs the GitHub Advisory Database REST API directly, incrementally by advisory modification time, with an optional GitHub token for a higher rate limit. Each advisory keeps its GHSA id and CVE alias, severity, CVSS vector, GitHub-mapped ecosystem, and now the GitHub CWE weakness ids and reference URLs the OSV mirror drops (carried on new `advisory.Advisory.CWEs`/`References` fields, unioned across feeds by the materializer, so the stored advisory cites the weakness class and upstream links). The version-range parser is fail-closed: a range it cannot express soundly (an exclusive lower bound, an open-ended range, an unknown operator) drops that package rather than emitting a range that could match the wrong versions, and an unmapped ecosystem is skipped, so the provider never introduces a false match. This implements the GHSA half of EPIC #860 D1.10.
- **The OSV bulk download is now verified against its published checksum, so a corrupted feed is rejected instead of ingested.** The remote OSV feed streamed each `all.zip` straight into the store with no integrity check: a truncated or corrupted download would silently poison the advisory corpus. The download is now checked against the crc32c digest GCS publishes in the `x-goog-hash` response header (the digest `gsutil` verifies); a mismatch is fail-closed (the ecosystem's ingest aborts loudly rather than storing corrupt data), while a mirror that publishes no digest proceeds best-effort. This is an integrity check (it catches corruption), not authenticity; cryptographic authenticity of signed CSAF providers remains the larger part of EPIC #860 D1.8.
- **The three NVD CVSS code paths now share one parse model, so CVSS backfill and advisory sync always agree.** The compact-DB builder, the online CVSS enricher, and the `NVDProvider` each carried their own copy of the NVD metric structs and the "pick the strongest CVSS" logic, which drifted (adding CVSS v4.0 required editing all three). They now share one `BestCVSS` parser (v3.1 > v3.0 > v4.0 > v2 with a compute-from-vector fallback), proven by a shared fixture, so a future NVD-format change lands in one place and every path stays consistent (the provider also gains the v2 fallback it lacked). This advances EPIC #860 D1.10 (unified NVD code paths).
- **Ingesting the same CVE from two advisory feeds now keeps the union of affected packages instead of the last feed clobbering the other.** The CLI `sync-advisories` bulk path wrote advisories with a flat `ON CONFLICT DO UPDATE SET data=EXCLUDED.data`, so a CVE present in an OSV dump and in the NVD provider (or two dumps) kept only the last writer's affected ranges and dropped the rest, losing coverage. The bulk path is now a named source (`osv`/`csaf`/`oval`) over the observation materializer, the same provenance-tracked writer the online sync uses: each feed's advisory is recorded as one source's observation and re-materialized through `advisory.Merge`, so the stored advisory is the union of every source's affected ranges with the strongest CVSS. A re-ingest of the same feed still narrows that feed's own contribution (a retracted package takes effect) while other sources' ranges remain. This implements EPIC #860 D1.2 and is covered by a Postgres integration test asserting no range is lost.
- **CVSS v4.0 vectors are now scored, so a v4-only advisory carries a real severity band.** The scorer computed v3.x and v2 base scores but left `CVSS:4.0` vectors unscored, so a v4-only NVD or OSV advisory (a growing share) fell to `Unknown` and degraded severity banding and KEV×CVSS ranking. The owned scorer now implements the full FIRST.org CVSS v4.0 base-score algorithm (the MacroVector lookup with severity-distance interpolation, using the published lookup and max-severity tables), validated against the reference calculator across the max, no-impact, single-dimension, and threat/environmental cases. The NVD provider and compact-DB ingester read the `cvssMetricV40` group (v3.x is still preferred so an existing corpus keeps its published band, with v4.0 as the fallback), the owned OSV ingester accepts a `CVSS:4.0` vector, and the offline scan path derives a band from any stored vector version. This implements EPIC #860 D1.6 and completes the v4 part of D1.5.
- **Container image scans now run secret and misconfiguration scanning over the image filesystem.** A credential baked into an image layer, or a misconfigured Dockerfile / Kubernetes / Terraform file shipped inside an image, was invisible: the secret and misconfig scanners ran only over the scanned source layout, not the materialized rootfs. Both now also scan the image rootfs when one is present, so an embedded secret (a top container finding class) or a baked-in misconfig is caught. The image-filesystem pass is best-effort (a failure is a warning, never a scan failure), reuses the same precise detectors, allowlist, redaction, and DoS caps as the workspace scan, and runs only for an image target. This implements EPIC #860 D7.9.
- **Go taint analysis treats the Go 1.22 path parameter and header accessors as untrusted sources.** The Go source set covered form values, cookies, and `Header.Get`, but not `r.PathValue` (the Go 1.22 routing path parameter, now a common user-controlled input) or the `Referer`/`User-Agent` header accessors. All three are now sources, so a flow from a path parameter or one of those headers into an existing sink (SQL, command, path, SSRF) is detected. This extends EPIC #860 D5.6.
- **Custom Python taint rules can be loaded from a config file (Semgrep-style user rules).** A deployment can now point `SYNAPSE_TAINT_RULES_FILE` at a reviewable YAML file declaring its own Python taint sources and sinks (`python.sources` with module/name patterns; `python.sinks` with module/name, taint class, CWE, rule id, and tainted argument), which are merged additively into the built-in catalog at startup. Custom rules can only ADD detection: there are deliberately no custom sanitizers, so a rule can never suppress a built-in flow, and false positives on a custom sink are managed with the existing accepted-risk mechanisms. The loader is bounded, rejects a misspelled key or an unknown taint class rather than silently dropping rules, and caps the total rule count. This implements EPIC #860 D5.5.
- **Python taint deserialization coverage now spans the wider pickle-backed loader ecosystem.** The CWE-502 class flagged pickle/dill/cloudpickle/marshal/jsonpickle/yaml loaders but missed the data-science and stdlib loaders that are equally pickle-backed remote-code-execution sinks. It now also flags `pandas.read_pickle`, `torch.load`, `joblib.load`, `shelve.open`, and the `pickle.Unpickler` constructor. The safe alternatives stay out: `json.load`/`loads` and `numpy.load` (whose default `allow_pickle=False` is safe) are deliberately not modeled, so the additions raise recall without a false positive on a safe loader. This extends EPIC #860 D5.6.
- **Go taint analysis covers more filesystem and SSRF sinks.** The Go injection catalog flagged `os.Open`/`ReadFile`/`Create` for path traversal and `http.Get`/`Post`/`Head` (and their `Client` methods) for SSRF, but missed the mutating filesystem operations and a few request helpers competitors flag. It now also treats `os.Remove`, `os.RemoveAll`, `os.Mkdir`, `os.MkdirAll`, `os.ReadDir`, `os.Rename`, and `os.Symlink` as CWE-22 path sinks, and `http.PostForm`, `http.Client.Head`, and `http.Client.PostForm` as CWE-918 SSRF sinks. Only symbols whose dangerous argument is a path or URL are added, so the function-level match cannot false-positive on a tainted content argument: `os.WriteFile`, whose data argument is often the tainted value, is deliberately left out. This extends EPIC #860 D5.6 to the Go catalog.
- **Cadence-driven vulnerability-sync scheduler keeps the advisory corpus fresh automatically.** `Cadence` and `StaleAfter` were stored on each vulnerability source but read only by the health projection, so the corpus was only as fresh as the last manual `sync-advisories` trigger. A new leader-gated worker maintenance task now, on `SYNAPSE_VULNERABILITY_SYNC_SCHEDULER_INTERVAL`, enqueues a sync for every enabled source whose last successful run is older than its `Cadence`, and reclaims runs stranded in queued/running past `SYNAPSE_VULNERABILITY_SYNC_STALE_AFTER`. The due-source query is O(sources) per tick, the enqueue is idempotent per source per hour (so a duplicate tick or a non-leader worker cannot double-enqueue), and the scheduler honors the same provider-sync rollout gate as a manual sync, doing nothing while sync is disabled. It is off by default (interval 0) and requires `SYNAPSE_VULNERABILITY_PROVIDER_SYNC_ENABLED`. This implements EPIC #860 D1.1.
- **VEX export gains per-statement timestamps, content-addressed identity, and a CSAF 2.0 profile.** The OpenVEX export hardcoded `version: 1` with a timestamp-derived `@id` that changed on every export and carried no per-statement timing. Each OpenVEX statement now carries its own assertion timestamp (the finding's evaluation time, else the document time), and the document `@id` is content-addressed: an unchanged re-export is byte-identical (idempotent), while any change to the assertions yields a new id. A re-exporter can declare `?supersedes=<prior @id>` to chain document identities without a server-side export store. A new `GET /api/v1/engagements/{id}/export/csaf` route emits the same publishable findings as an OASIS CSAF 2.0 VEX document (the enterprise-standard companion to OpenVEX), templated from stored data with no model in the report path; both formats read one shared, sorted record set, so they assert exactly the same exploitability posture over the same advisories. This implements EPIC #860 D8.5.
- **Terraform misconfiguration checks now resolve variables, locals, and .tfvars before matching.** A misconfiguration expressed through a variable, such as `storage_encrypted = var.enc` where `enc` defaults to false, or `cidr_blocks = [var.cidr]` with `cidr = "0.0.0.0/0"` in a `.tfvars` file, was missed because the checks matched literal values only and deliberately skipped `var.`/`local.` references to avoid false positives. The scanner now collects variable defaults, `locals` literals, and `*.tfvars` assignments across the whole workspace in a first pass, then scans each `.tf` file with those references substituted, catching the cross-file case where a value lives in a separate `.tfvars`. Resolution is conservative: a variable is substituted only when every source agrees on a single literal, so a variable whose default and `.tfvars` disagree stays unresolved and no false positive is produced from a guessed value. This implements EPIC #860 D6.4.
- **Secret scanning now decodes base64 and hex values to find secrets hidden inside them.** A credential carried inside an encoded value (a Kubernetes `Secret`, whose `data` fields are base64 by design; a base64- or hex-wrapped token) was invisible to the detectors, which only saw the encoded blob. A bounded decode pass now finds each base64/hex token in a scanned file, decodes it one level, and re-runs the detectors over the decoded bytes, reporting any hit at the ENCODED token's line where a reader edits it. It is purely additive: a finding requires a real detector (with its distinctive keyword) to fire on the decoded bytes, so a hash, an id, or minified data produces nothing. The pass is capped (per-token size, tokens per file, and aggregate decoded volume) so it cannot become a decode-bomb amplifier, skips values that decode to binary, and honors an inline `synapse:allow` annotation on the encoded line. This implements EPIC #860 D6.9 (base64/hex decoding).
- **Python value-flow taint now models SSTI, XXE, LDAP injection, and XPath injection.** The owned Python taint engine covered SQL, command, path, SSRF, XSS, deserialization, and open-redirect flows but was blind to four more injection classes competitors model. It now flags server-side template injection (compiling request-controlled text through `jinja2`/`mako`/`django`/`tornado` `Template` and `Environment.from_string`, CWE-1336), XML external entity processing (the entity-resolving `lxml.etree` and stdlib `xml.*` parsers, CWE-611), LDAP injection (a tainted `search_filter` reaching `ldap`/`ldap3` search, CWE-90), and XPath injection (a tainted expression reaching `lxml` `xpath` or `ElementTree` `find`/`findall`, CWE-643). Each is a precise value-flow sink modeling only the dangerous argument (the template text, not a render variable; the filter, not the base DN; the expression, not a parameterized variable), so passing user input through the safe shape is not flagged. The LDAP filter/DN escapers (`escape_filter_chars`, `escape_dn_chars`) are class-specific sanitizers, the hardened `defusedxml` parser is deliberately not a sink, and a primitive conversion neutralizes every class. Findings remain propose-only gated CapSAST judgments carrying the CWE and rule id. This implements EPIC #860 D5.6.
- **JavaScript Tier-2 reachability now resolves a named re-export to its exact symbol.** The Tier-2 analyzer treated every re-export (`export ... from 'pkg'`) as fully opaque: it marked the package as possibly reaching ANY export, so a vulnerability in an export the module never actually re-exports could not be ruled not-reachable. A NAMED re-export republishes exactly the exports it names, so `export {template} from 'lodash'` now records a use of `template` only, letting a vulnerability in a different lodash export be provably not reached through that module. A namespace or default re-export (`export * from 'pkg'`, `export {default} from 'pkg'`) still republishes the whole module object under names the scanner cannot enumerate and stays opaque, so no not-reachable negative is ever issued for it, preserving the analyzer's core safety property (an unknown never suppresses a finding). This is a step of EPIC #860 D4.7 toward the fuller interprocedural reachable-path analysis.
- **JVM class-reachability is now an auditable reachability judgment, not just a finding tag.** The owned JVM analyzer tags each dependency with whether the application's class-reference closure reaches its classes, and that tag deprioritized a finding but lived only on the finding, never entering the propose-verify judgment ledger or the OpenVEX export. A new Tier-1.5 recorder now mints one auditable reachability judgment per JVM finding from those in-scan tags: a reachable verdict feeds the VEX export and raises the deterministic SLA/risk score, and an unreachable verdict is recorded for audit. It mints at Tier-1.5, which is never a promotable deterministic proof, so a JVM unreachable verdict can NEVER become a VEX `not_affected` suppression, correct for a coarse, reflection-blind signal that must only deprioritize and never hide a vulnerability (reflection, dependency injection, and ServiceLoader are invisible to it). A stronger prior proof (a Tier-2 call-graph result) still stands, so the JVM judgment never downgrades a real proof. It reuses the existing reserved-identity propose-verify gate with distinct JVM scan/engine actors, is opt-in with the existing `SYNAPSE_JVM_REACHABILITY_ENABLED` flag, and requires the judgment lifecycle. This implements EPIC #860 D4.4.
- **A monorepo dependency graph now forms one connected tree with a single root.** A repo whose dependencies come from several manifests, or whose direct dependencies form independent trees, projected as a disconnected forest with many top-level roots and no navigable project root. The project dependency graph now detects when the graph has more than one weakly-connected component and links every top-level dependency under one synthetic project-root node, so the graph reads as a single tree rooted at the project. A single connected graph is left exactly as before (no synthetic root), and the synthetic node is not a real component: it carries no PURL, version, license, or vulnerability, is excluded from the component summary, and the real components keep their direct/depth exactly as computed. The dashboard renders it as a distinct "Project root" with no package chrome. This implements EPIC #860 D3.9.
- **The same vulnerability under non-overlapping ids no longer double-reports across sources.** When two detection sources found one issue on a component but each carried a different id, one only `GHSA-…` and the other only its `CVE-…`, correlation could not link them (it clusters by shared advisory id), so the one vulnerability reported twice. The owned advisory store already records each advisory's cross-feed aliases; a new transitive alias resolver (`advisory.AliasGraph`) now widens each finding's alias set with the store's closure before correlation, so the GHSA-only and CVE-only findings share the CVE and merge into one. Because every alias maps to a single canonical (enforced on ingest), the closure never merges two distinct CVEs, and two CVEs that share only a boilerplate description still stay separate (the full-description fallback is unchanged). The lookup is bounded to the scan's finding ids and backed by a new GIN index on the advisories alias array (migration 0145), so it is O(matching advisories), not a corpus scan, and it is best-effort: a store without the alias capability, or an alias-edge query error, leaves correlation exactly as before. `CorrelationVersion` is bumped to 7 so a scan manifest explains the changed dedup. This implements EPIC #860 D2.5.
- **Debian/Ubuntu binary packages now match their source-package advisories.** A Debian security advisory is keyed by the SOURCE package (one `openssl` advisory covers the `libssl1.1`, `libcrypto1.1`, … binaries built from it), so the owned matcher, which looked a component up only by its own binary name, missed every such binary and under-reported OS-package CVEs on a default Debian/Ubuntu scan. The owned advisory source now also matches a deb component by its source-package name, read from Syft's `upstream=` PURL qualifier (`<source>` or `<source>@<version>`), in the same release-versioned ecosystem. A deb binary and its source share the version, so the existing dpkg range comparator applies unchanged, and a binary that also matches by its own name is de-duplicated to one finding. Only deb is mapped: an rpm's source is a source-RPM filename needing NEVRA parsing, and the owned Red Hat CSAF feed is already binary-keyed, so no rpm source-mapping is needed. This implements EPIC #860 D2.8.
- **Gradle scans now resolve the transitive dependency tree with a dependency path per finding.** The owned Gradle resolver printed a flat list of resolved runtime modules with no edges, so a transitive Gradle CVE had no dependency path and no introducing direct dependency, the same gap Maven had. The init script now also walks the resolution-result graph and prints each edge (`SYNAPSE_EDGE parent|child`, with a sentinel root for a direct dependency), and a new `ports.GradleGraphResolver` capability parses those into `sbom.Dependency` edges keyed by PURL. The SCA pipeline prefers it and folds the edges over syft's Maven subgraph, so `PathToRoot`, `IsDirect`, and `IntroducedBy` light up for Gradle: a transitive Gradle CVE now reports its path and every introducing direct dependency. The graph is rootless (direct deps are the graph roots, matching Maven and the native parsers), an edge is kept only when both endpoints are resolved components (dropping platform/BOM and project edges), and every edge is runtime scope because the resolver resolves only runtimeClasspath. The parser is fixture-tested offline; the live `gradle` run is sandbox-confined and opt-in as before, and a build that fails or emits a malformed line fails closed to no edges. This implements EPIC #860 D3.5, reusing the Maven transitive-tree edge merge.
- **Maven scans now resolve the full transitive dependency tree with per-edge scope.** The owned Maven resolver ran `mvn dependency:list`, a FLAT set with no edges, so a transitive Maven CVE (spring-core, snakeyaml, tomcat-embed-core) had no dependency path and no introducing direct dependency, the largest gap versus Snyk and Sonatype for enterprise Java. The resolver now also offers `mvn dependency:tree` through a new `ports.MavenGraphResolver` capability: its parser (pure, fixture-tested) turns the tree into `sbom.Dependency` EDGES keyed by PURL, capturing each edge's Maven scope (compile/runtime/provided; the test subtree is dropped as before), and the SCA pipeline folds those edges over syft's Maven subgraph so `PathToRoot`, `IsDirect`, and `IntroducedBy` light up for Maven: a transitive Maven CVE now reports its dependency path and every direct dependency that introduces it. The graph is rootless (the direct dependencies are the roots, matching the native lockfile parsers), so the introducers are the direct deps rather than the project node. To support this, `sbom.Dependency` gained `Scope` and `Optional` fields and a new `sbom.ReachableScopes`/`ProductionReachable` graph function that narrows scope along the graph (a component reachable from a root only through provided/test edges is not production-reachable), and vulnerability classification now deprioritizes a graph-proven non-production transitive one tier below its file-path scope, a downgrade only, and a no-op for ecosystems whose edges carry no scope. This implements EPIC #860 D3.2 and the graph-scope core of D3.3. The live `mvn` run is sandbox-confined and opt-in as before; a missing `mvn` is a best-effort no-op.
- **A transitive vulnerability now shows every direct dependency that introduces it.** The finding detail rendered a single dependency path, but a transitive package is often pulled in through several direct dependencies, and removing the vulnerability means bumping all of them. The complete set was already computed on the backend (`sbom.IntroducedBy`, carried on the vulnerability) but never reached the UI. The scan mapper now surfaces it, and the finding detail lists an "Introduced By" section naming each introducing direct dependency (with a tooltip explaining that all of them must be bumped) whenever a package has more than one, matching how Snyk shows every path. This completes EPIC #860 D3.4 end to end.
- **CSAF advisories keyed by PURL now match language-ecosystem components.** The owned CSAF parser resolved affected products only through the CPE bridge (Python, npm, Rust) and the Red Hat rpm relationship path, so a GitHub Security Advisory CSAF export, and any VEX that names npm, PyPI, Maven, Go, RubyGems, or NuGet packages by PURL, matched nothing. `ParseCSAF` now reads `product_identification_helper.purl` for language ecosystems and resolves it to the owned `(ecosystem, package, version)` key through the same logic the SBOM producer applies to a scanned component, so a CSAF-resolved advisory keys identically to the component it must match (a Maven `groupId:artifactId`, a Go module path, an `@scope/name`, a PEP 503-folded PyPI name). Because a PURL is unambiguous, this is a faithful mapping rather than the CPE bridge's best-effort one; a PURL with no concrete version or an ecosystem without a faithful owned key is skipped, fail-closed, so no advisory is ever mis-keyed. The conservative CPE allow-list is unchanged (a CPE product cannot equal a Maven or Go key, so those stay on the PURL path). This implements EPIC #860 D1.9.
- **A stale owned advisory corpus now warns instead of scanning silently.** The scan freshness policy warned on the KEV, EPSS, and Grype DB dates but never on the owned advisory store's own age, so a scan against a six-month-old synced corpus under-reported without a word, contradicting the no-silent-gap posture. The owned advisory source now reports its corpus freshness as a `<count> advisories@<date>` provenance marker (from a new store query for the newest advisory timestamp and the row count), which the freshness policy checks like any other dated DB: a corpus older than the configured freshness window emits a warning naming the store and its sync date, and the report lists it as this feed's provenance. The marker is empty when the store cannot report freshness or the corpus is empty, so no false freshness is ever claimed. This implements EPIC #860 D1.7.
- **Reachability folds into the SLA/risk urgency score.** The deterministic SLA scorer ordered findings by severity, exploitability, threat intel, exposure, criticality, and feasibility but ignored reachability, so a proven-reachable and a proven-unreachable critical landed in the same SLA window (Snyk's Priority Score and Sonatype fold reachability in). The scorer now takes a reachability input: a publishable reachable verdict raises urgency, a publishable deterministic not-reachable verdict lowers it, bounded by a new weight (default 15, outside the sum-to-100 core factors) and scaled by the proving tier (deterministic Tier-2 call-graph full, import-level Tier-1 half), recorded in the breakdown and audit trail. The authoritative verdict is read from the finding's reachability judgments during the vulnerability-intelligence SLA reassessment: a reachable verdict at any publishable tier raises urgency, and a not-reachable verdict lowers it only when it is a deterministic proof (matching the promotion gate), so a heuristic or an inconclusive scan never moves the score. The unknown default is neutral, so a finding with no verdict is scored exactly as before, and the reader fails neutral on any error. This implements EPIC #860 D4.5.
- **A labeled match-quality corpus gates the owned advisory matcher on precision and recall.** The advisory tests were per-comparator table tests, with no way to prove the matcher as a whole competes with Grype or OSV-scanner, or to catch a comparator regression that silently drops a real match or invents a false one. A new gate (`ownadvisory/matchquality_test.go` over `testdata/corpus/`) runs the whole owned matching path (ecosystem derivation, canonical naming, and every ECOSYSTEM/SEMVER comparator) against a ground-truth corpus of `component@version -> expected advisory ids` spanning npm, PyPI, Maven, Go, Debian, and Alpine, with known-negatives (a fixed or higher version, an in-gap version between two fixed ranges, a below-introduction version, a wrong release, and an unrelated package). It computes precision and recall and fails below a checked-in ratchet (currently a perfect 1.0 on both). The language-ecosystem entries carry real published CVE ranges (Log4Shell's three ranges, the lodash prototype-pollution fix, the urllib3 ReDoS range, the golang.org/x/text fix), verified against upstream advisories; the distro entries are construction-correct against the dpkg and apk comparators. A regression in any comparator, ecosystem key, or range walk now drops the metric below the ratchet and fails the build. This is the matcher-unit measurement EPIC #860 D2.6 calls for.
- **Source-only Tier-1 import reachability runs by default.** The five source-only Tier-1 reachability scanners (Python, JavaScript/TypeScript, Rust, PHP, Ruby) now default ON (`SYNAPSE_PYREACH_ENABLED`, `SYNAPSE_JSREACH_ENABLED`, `SYNAPSE_REACH_RUST`, `SYNAPSE_REACH_PHP`, `SYNAPSE_REACH_RUBY`), so a default scan turns a declared direct dependency that first-party source never imports into an OpenVEX `not_affected` with a proof, the prioritization Grype and Trivy do not do and Snyk gates behind a paid tier. This is safe by construction: each scanner fails to "unknown" on any coverage gap (a scan error, a dynamic import, an unreadable or truncated file, a transitive subject), and a not-reachable verdict never removes a finding or sets `not_affected` on its own. Its only automated effect is a bounded, independently propose-verify-confirmed one-step priority de-escalation that leaves the finding fully visible and still subject to the `--fail-on` gate, so default-on can never hide a real vulnerability. The scanners auto-skip (with a warning) when judgments are disabled, and each stays opt-out via its env flag. This completes the source-only tier of EPIC #860 D4.2.
- **Python import reachability now refuses on degraded coverage.** The owned Python import scanner (`pyimports`) previously skipped an unreadable first-party file, truncated a file at the per-file byte cap, and stopped at the file-count cap without signalling, so a real import in an unscanned region could yield a false "not imported". It now reports `CoverageDegraded`, and the Tier-1 analyzer refuses a reachability verdict when it is set, matching the `Complete()`/`Coverage` refusal the Rust, PHP, Ruby, and JavaScript scanners already perform. This removes the one path by which default-on Python reachability could have deprioritized a still-reachable dependency.
- **Discord webhook URL detector.** The owned secret scanner now flags a hardcoded Discord webhook URL (`https://discord.com/api/webhooks/<id>/<token>`, including the `ptb.`/`canary.` and `discordapp.com` host variants), matching gitleaks. The token length (60 to 110 url-safe characters) after the fixed host and numeric id makes a false positive on an ordinary URL near impossible, and it ships a positive fixture and a too-short near-miss. Severity is Medium (a webhook can post to one channel, not take over an account), matching the Slack webhook rule.
- **Four more provider secret detectors.** The owned secret scanner adds detectors for Airtable personal access tokens (`pat<14>.<64 hex>`), SonarQube tokens (`sqp_`/`squ_`/`sqa_`), Dropbox access tokens (`sl.<135>`), and Cloudinary URL credentials (`cloudinary://<key>:<secret>@<cloud>`), continuing toward gitleaks parity. Each uses the provider's real token shape, verified against the provider docs, so a false positive on ordinary code is near impossible, and each ships a positive fixture and a near-miss negative. The Dropbox rule reports the token via a capture group so the trailing boundary is not included. The catalog-parity and golden-key drift guards keep the detector set and the rule catalog in lockstep.
- **Five more provider secret detectors.** The owned secret scanner adds distinctive-prefix detectors for Flutterwave secret keys (`FLWSECK_TEST-`/`FLWSECK-`), Alibaba Cloud AccessKey IDs (`LTAI`), Adafruit IO keys (`aio_`), Sourcegraph access tokens (`sgp_`), and Replicate API tokens (`r8_`), moving the catalog from 68 toward gitleaks parity. Each uses the provider's real token shape at its documented length, so the prefix plus length make a false positive on ordinary code near impossible, and each ships a positive fixture and a near-miss negative. The catalog-parity and golden-key drift guards keep the detector set and the rule catalog in lockstep.
- **Red Hat RPM advisories match RHEL base (non-modular) container and host packages, offline.** The owned CSAF parser resolved only CPE-keyed language products and skipped every rpm binding, so a Red Hat security advisory could not match a RHEL `openssl` or `kernel` rpm and RHEL scans depended on a third-party matcher. `ParseCSAF` now walks the `product_tree.relationships[]` Red Hat uses to bind a package version (a `product_version` branch carrying the rpm PURL) to a platform (a `product_name` branch carrying the RHEL CPE), joining them into a release-versioned `Red Hat:<major>` advisory with an rpm ECOSYSTEM range: a fixed NEVR closes the range exclusively (`[0, fixed)`, the standard "fixed implies prior-affected" distro model), and a `known_affected` product with no fix bounds it inclusively at the highest observed affected build (`[0, last_affected]`, never an open `[0, ∞)` that would sweep in a later unaffected build). The major comes from the platform CPE (`cpe:/o:redhat:enterprise_linux:9::baseos`, both 2.2-URI and 2.3 forms), never a guessed release tag, and the scan side keys a RHEL rpm the same way from its `distro=rhel-9.2` qualifier, so the feed and the scan meet exactly. Epoch is normalized to an explicit `epoch:version-release` on both sides (Red Hat and Syft carry it in the PURL `epoch=` qualifier), and the version is percent-decoded, so neither an asymmetric epoch nor an encoded character can over-match a patched build into a false positive. Three narrowings keep the arch-less, stream-less `(major, package)` key sound under the no-false-positive bar: AppStream **modular** packages (release `...module+el...`) are skipped on both the feed and the scan, because a module's streams (`nodejs:16` vs `nodejs:20`) are parallel version lines a single linear range would conflate; a `(major, package)` that also appears in `known_not_affected` is dropped, because that arch- or variant-specific case cannot be bounded soundly by an arch-less key; and the minimum fixed EVR is kept across variants so a higher build is never falsely flagged. Each narrowing trades a possible miss for the guarantee of no false positive. CentOS is not mapped to Red Hat (CentOS Stream drifts ahead of RHEL); Rocky, AlmaLinux, and Oracle key to their own rebuild ecosystems. The advisories load through the existing `synapse-cli sync-advisories --csaf <dir>` path with no migration, and the owned rpm comparator matches them with no third-party engine. Stream-aware modular matching (via modularity labels) is a documented follow-up.
- **Curated symbol overlay for offline reachability beyond Go.** Only the Go vuln DB publishes affected symbols, so a non-Go or NVD/CSAF-only advisory had none and could not drive symbol-level Tier-2 reachability. A new curated overlay (`SYNAPSE_SYMBOL_OVERLAY_DIR`, a directory of `advisory-id -> [importPath.Symbol, ...]` JSON files) is merged onto matched findings by the owned advisory matcher, looked up by the advisory's id and every alias. It is a side table: it never changes which advisories match (no ranges, no matching), only enriches a matched finding's symbols, and a symbol curated for the wrong language is inert (it simply never matches that language's call graph, so it cannot cause a false reachable verdict). The loader is bounded and best-effort (a malformed or oversized file is skipped, a load error is a warning, never a scan failure). With the Go-vuln-DB symbols from the prior change, the owned offline path now supplies reachability symbols across ecosystems.
- **Tenant-scoped notification and webhook framework.** Administrators can create write-only encrypted signed-webhook, Slack incoming-webhook, and email channels; bind durable rules to vulnerability actions, scan completion, quality-gate failures, SLA deadlines, offline fleet agents, and correlated incidents; test each channel; and inspect per-destination attempt history in Settings → Alerting. `synapse-worker` performs fenced at-least-once delivery with exponential backoff, `Retry-After`, terminal classification, dead-letter state, event/delivery identifiers for webhook deduplication, and cancellation when an SLA or offline episode is no longer relevant. PostgreSQL RLS and composite foreign keys isolate every tenant-owned row.
- **The owned advisory store carries affected symbols for offline reachability.** Symbol-level (Tier-2) reachability needs the vulnerable functions an advisory marks, but the owned scan path never carried them, so only the live OSV adapter had symbols and an air-gapped scan could not drive symbol reachability. The owned OSV ingester now parses `affected[].ecosystem_specific.imports[].symbols` (the Go vuln DB's affected functions) into a new `advisory.AffectedPackage.AffectedSymbols`, qualified as `importPath.Symbol` exactly as the live adapter and the call-graph reachability engine expect, and the owned matcher carries the matched package's symbols onto each finding (correlation already merges them into `vulnerability.AffectedSymbols`). The symbols ride in the existing advisory JSON, so both the CLI `sync-advisories` corpus and the provider-sync materializer persist them with no migration. `CorrelationVersion` is bumped to 6. This closes the offline-vs-live symbol asymmetry for Go; a curated cross-ecosystem symbol overlay is the next step.
- **Four more provider secret detectors.** The owned secret scanner adds distinctive-prefix detectors for Slack app-level tokens (`xapp-`), 42/Intra client secrets (`s-s4t2ud-`/`s-s4t2af-`), Yandex API keys (`AQVN`), and Notion integration tokens (`ntn_`), continuing toward gitleaks parity (catalog now 68). Each uses the provider's real token shape, ships a positive fixture and a near-miss negative, and is kept in lockstep with the rule catalog by the catalog-parity and golden-key drift guards.
- **Git-history secret scanning.** A secret committed and later removed is gone from the working tree but still recoverable from the repository's object database, and HEAD-only scanning missed it. The owned secret scanner now also walks git history: `SYNAPSE_SECRET_HISTORY_ENABLED=true` scans every blob reachable from all refs (`git rev-list --objects --all` streamed through `git cat-file --batch`, argv-only, read-only), deduping each blob by its object id and applying the same detectors, size caps, and redaction as the working-tree scan. Each history hit is attributed to the commit that FIRST introduced it, with the author and date: a bounded `git log --all --topo-order --reverse --raw` walk maps every blob to its earliest-introducing commit (topological order, so a date-skewed child never masks its parent), and the scan runs oldest-first so a secret is credited to where it entered, not a later commit that merely carried it. Attribution is best-effort (a blob it cannot resolve simply carries none, never a fabricated commit). It is off by default (heavier, and it reports credentials no longer in the tree), best-effort (a non-git workspace or a git failure is a warning, never a scan failure), and reaches both the server pipeline (via scacompose) and the CLI. This is the history coverage gitleaks and trufflehog provide.
- **Maven versions order by Apache's `ComparableVersion` dash-nesting, not a flat token list.** The owned Maven comparator tokenized a version into a flat list, so it treated `-` and `.` identically and mis-ordered the equal-core tie-breaks Apache Maven distinguishes by starting a NESTED sub-list on `-` (and on a digit<->letter transition): for example `1-1 < 1.1`, `1a1 == 1-alpha-1`, `1-0 == 1`, and (MNG-6964) `1-0.1 > 1`. `compareMaven` is now a port of `ComparableVersion` (nested item tree, the qualifier ladder with its aliases, trailing-null normalization, and whole-list null comparison), tracking long-stable Maven 3.x. It does not implement two niche later refinements (a `.` before a non-numeric qualifier stays flat rather than nesting; Maven 4's CombinationItem) because they only reorder exotic forms absent from real advisory ranges. The existing qualifier-ladder vectors are unchanged (no regression) and the nesting vectors are covered.
- **Distinct CVEs no longer collapse on a shared description prefix.** When two findings on the same component@version share no advisory id, correlation falls back to matching their descriptions. That fallback compared only the first 80 characters, so two different advisories with the same boilerplate lead-in merged into one vulnerability, hiding a real finding. The fallback now requires the FULL normalized description to match (lowercased, whitespace-collapsed, not truncated), so only genuinely identical descriptions merge; findings that share an advisory id still merge as before. `CorrelationVersion` is bumped to 5 so a scan manifest explains the changed dedup.
- **Source-only Python taint runs in the default scan.** Synapse's interprocedural Python value-flow taint (the synapse-ast sidecar, tree-sitter, no compile or execute of the target) was wired only in synapse-api and gated off, so a default scan competed on regex plus a heuristic while Semgrep and CodeQL run dataflow by default. The wiring now lives in `scacompose.ConfigureJudgmentScanners`, shared by synapse-api and synapse-worker, so a worker-run queued scan gets the same analysis instead of a regex-only pass; and `SYNAPSE_PYTAINT_ENABLED` now defaults to `true`. Default-on is safe: the analyzer is source-only (it parses the target, never builds or runs it), degrades to a clean no-op when the synapse-ast sidecar is not installed, and mints only propose-only CapSAST judgments that a distinct verifier gates. It still requires the judgment lifecycle (`SYNAPSE_JUDGMENTS_ENABLED`, on by default); with judgments off it attaches nothing. Set `SYNAPSE_PYTAINT_ENABLED=false` to opt out.
- **Six more provider secret detectors.** The owned secret scanner adds distinctive-prefix detectors for Prefect Cloud API keys (`pnu_`/`pnb_`), Contentful personal access tokens (`CFPAT-`), Shippo API tokens (`shippo_live_`/`shippo_test_`), 1Password service account tokens (`ops_eyJ`, Critical), GitLab runner registration tokens (`GR1348941`), and EasyPost API tokens (`EZAK`/`EZTK`), moving the catalog from 58 toward gitleaks parity. Each uses the real provider format at its documented length, so the prefix plus length make a false positive on ordinary code near impossible, and each ships a positive fixture and a near-miss negative. The catalog-parity and golden-key drift guards keep the detector set and the rule catalog in lockstep.
- **Go Tier-2 reachability runs on the owned call-graph builder by default.** The deterministic Go reachability proof depended on the third-party `govulncheck` to build the call graph. It now defaults to Synapse's own go/ssa builder (run through the sandboxed `synapse-callgraph` binary, the same owned analysis that already backs taint), selectable with `SYNAPSE_REACHABILITY_BUILDER` (`owned` default, or `govulncheck`). Both builders emit the same normalized `importPath.Symbol` call graph, so `reachability.Service` consumes either unchanged; the owned CHA graph over-approximates the call set, which is sound for reachability because it never reports a genuinely-reachable symbol as not-reachable (it can only be less precise, never a false suppression). Combined with the OSV-sourced affected symbols, Go reachability now stands without a third-party engine on the default scan. An integration test proves `reachability.Service` over the owned builder marks a called symbol reachable with a proof path and an uncalled one not-reachable.
- **Six more provider secret detectors.** The owned secret scanner gains distinctive-prefix detectors for Atlassian (Jira/Confluence) API tokens (`ATATT3xFfGF0`), OpenShift / Kubernetes ServiceAccount OAuth tokens (`sha256~`), Duffel API tokens (`duffel_test_`/`duffel_live_`), Frame.io developer tokens (`fio-u-`), Defined Networking nebula API keys (`dnkey-`), and Typeform personal access tokens (`tfp_`), moving the catalog from 52 toward gitleaks parity. Each has a long, unique prefix so false-positive risk is near zero, and each ships a positive fixture plus a near-miss negative (the prefix with a too-short body). The catalog-parity and golden-key drift guards keep the detector set and the rule catalog in lockstep.
- **The owned uv parser emits the Python dependency graph.** `ownsbom.UV` read `uv.lock` for components only and deferred edges. It now emits `sbom.Dependency` edges from each package's resolved `dependencies = [{ name = "..." }, ...]` array (single- or multi-line), resolving every edge against the emitted components (resolution-as-filter): an edge to a name that is not an emitted registry component (a local/editable/git source), or to a name that resolves ambiguously to more than one version in a universal lock, is dropped so a wrong edge is never invented. A dependency entry's `name` is uv's always-first field, read as the first quoted string of the inline table, so a `marker` or `extra` on the same entry is ignored. uv projects now get transitivity and introducing-path data (`sbom.PathToRoot`, `sbom.IntroducedBy`) like npm, yarn, pnpm, poetry, and NuGet. `Pipfile.lock`, which records resolved versions but no per-package dependency lists, still emits no edges (never synthesized).
- **Owned image cataloging finds installed Java, Node.js, and Ruby packages without a lockfile.** A production image installs language dependencies on disk with no manifest to parse, so a lockfile walk missed every jar, `node_modules` package, and installed gem in the rootfs. The owned installed-package cataloger (`bincat`, already reading Go binaries and Python dist-info from a materialized image rootfs) now also inventories Java archives from the embedded Maven `META-INF/maven/.../pom.properties` (a fat/shaded jar yields one component per bundled dependency), installed Node.js packages from `node_modules/<pkg>/package.json` (scope preserved, so a scoped package keys as `pkg:npm/%40scope/name`), and installed Ruby gems from the serialized `specifications/*.gemspec`. Each emits a component keyed exactly as the owned advisory matcher expects (`pkg:maven`/`pkg:npm`/`pkg:gem`), so an existing OSV/GHSA advisory matches it with no producer change. Parsing is conservative and offline: a component is emitted only when the name and a concrete version parse cleanly (a jar with no `pom.properties` is skipped rather than guessed from a network SHA1 lookup), the zip walk is entry- and byte-capped against a decompression bomb, and the rootfs walk stays symlink-safe. This is the installed-layer coverage Trivy and Syft recover from image layers.
- **Assessment Cycle historical backfill.** The previously shipped tenant-owned
  Cycle schema is now backed by its domain, persistence, and a resumable operator
  command that creates deterministic singleton Cycles for eligible historical
  Assessments. Durable leases, checkpoints, per-item outcomes, dry-run support,
  and atomic audit publication make reruns safe; hidden Project/host contexts are
  excluded and PostgreSQL RLS remains enforced.
- **Immutable uploaded-source lifecycle for Assessment Re-tests.** Both Re-test entry points can reuse
  the selected predecessor's verified archive or attach a new revision to the child Assessment, while
  preserving original upload attribution and older history. Scan jobs and run manifests pin source
  versions for read-only provenance. Migrations `0159`/`0160` retain tenant-owned source metadata and
  immutable bindings; archive storage uses shared S3/MinIO or a persistent filesystem fallback.

- **Owned image cataloging finds installed Java, Node.js, and Ruby packages without a lockfile.** A production image installs language dependencies on disk with no manifest to parse, so a lockfile walk missed every jar, `node_modules` package, and installed gem in the rootfs. The owned installed-package cataloger (`bincat`, already reading Go binaries and Python dist-info from a materialized image rootfs) now also inventories Java archives from the embedded Maven `META-INF/maven/.../pom.properties` (a fat/shaded jar yields one component per bundled dependency), installed Node.js packages from `node_modules/<pkg>/package.json` (scope preserved, so a scoped package keys as `pkg:npm/%40scope/name`), and installed Ruby gems from the serialized `specifications/*.gemspec`. Each emits a component keyed exactly as the owned advisory matcher expects (`pkg:maven`/`pkg:npm`/`pkg:gem`), so an existing OSV/GHSA advisory matches it with no producer change. Parsing is conservative and offline: a component is emitted only when the name and a concrete version parse cleanly (a jar with no `pom.properties` is skipped rather than guessed from a network SHA1 lookup), the zip walk is entry- and byte-capped against a decompression bomb, and the rootfs walk stays symlink-safe. This is the installed-layer coverage Trivy and Syft recover from image layers.
- **Bounded automatic correlation and incident-scoped governed response.** Sealed detection batches now drain deterministic, bounded correlation state to forward progress, and incident response derives authoritative incident provenance before preparing a governed action.
- **Scan runs now support tenant-owned, sealed provenance v1.** Native execution headers can be
  sealed once with normalized producer lanes, versions, stages, canonical target identities, and
  reproducible SHA-256 manifests. Migration 0134 is expand-only for migrate-first rollouts,
  keeps legacy writers visible through a transitional tenant bridge, protects retained engagement
  history, and enables forced tenant RLS on the new child provenance tables.

- **KEV/EPSS reach the offline scan path from the owned corpus.** The advisory materializer projected only `canonical.Advisory`, so the merged CISA KEV / FIRST EPSS / public-exploit signals stayed on `advisory_canonical` and reached only host correlation; an air-gapped scan got no exploitation-priority data and fell back to the live `risk.Enricher`'s network fetch. The materializer now projects KEV, EPSS, EPSS percentile, and public-exploit onto the scan-time `advisories` projection (JSON, no migration), the owned matcher (`ownadvisory.Source`) carries KEV/EPSS onto each finding, and `Correlate` merges them across sources (any KEV promotes, the highest EPSS wins). So an offline scan over a synced corpus orders findings by KEV and EPSS with no network. The live risk enricher still runs online and only RAISES these values, so it refreshes them when reachable and never lowers a corpus value.
- **One canonical direct-vs-transitive rule.** Three inconsistent rules decided whether a dependency was "direct": two paths used `len(PathToRoot) <= 2`, which mislabels a depth-1 transitive (a dependency of a direct dependency) as direct because the native lockfile parsers emit no synthetic project-root node. A new `sbom.IsDirect(deps, componentIDs, target)` (target is in the graph and no real COMPONENT depends on it) is now the single rule used by the vulnerability DTO (`attachDependencyPaths`), the component dependency evidence, and the MCP reachability facts; it agrees with the project dependency graph's existing depth-0 definition. Being component-aware, it is correct for both graph shapes the scanner produces: a native lockfile graph with no synthetic root (a direct dependency is a graph root) and an imported CycloneDX graph carrying a project-root node (a direct dependency's only dependent is that non-component root). Unlike a bare `len(PathToRoot)==1` it also treats a cycle-only node as not-direct. A depth-1 transitive is no longer flagged as a direct dependency.
- **Vulnerabilities list every introducing direct dependency, not one path.** `sbom.PathToRoot` returns a single chain from a top-level dependency down to a component, but a transitive package is often pulled in through several direct dependencies, and fixing it means bumping all of them. A new `sbom.IntroducedBy(deps, target)` returns the COMPLETE set of direct (top-level) dependencies through which a target is reachable (every root with a path down to it, cycle-safe, sorted). It is populated on `vulnerability.Vulnerability.Introducers`, surfaced on the MCP reachability facts (`introducers`), and typed on the web `Vulnerability` (`introducers?`). A diamond where a package is reachable via two direct deps now reports both, matching how Snyk shows every path.
- **The owned NuGet parser emits the dependency graph.** `ownsbom.NuGet` read `packages.lock.json` for components only; it now also emits `sbom.Dependency` edges from each package's `dependencies` map. Each dependency name is a version range in the lockfile, so it is resolved to the concrete version restored under the SAME target framework (never the range), dropping a `Project` reference or an unresolved dependency (resolution-as-filter). A package resolved under several frameworks merges its edges by source package, deduped and deterministic. `.NET` projects now get transitivity and introducing-path data (`sbom.PathToRoot`) like npm, yarn, and pnpm.
- **The owned pnpm parser emits the dependency graph.** `ownsbom.Pnpm` previously read `pnpm-lock.yaml` for components only and dropped the resolved dependency graph the lockfile carries. It now emits `sbom.Dependency` edges from each package's `dependencies:`/`optionalDependencies:` sub-maps, which live in the `packages:` block (lockfile v5/v6) or the `snapshots:` block (v9), resolving every edge against the emitted-component index (resolution-as-filter, so an edge to a range, `link:`/`file:` path, or `npm:` alias that is not an emitted component is dropped) and stripping the `(peers)` suffix from both keys and dependency values. Edges are package-to-package, matching the npm parser; a direct (top-level) dependency is one nothing else depends on (`sbom.PathToRoot`), so transitivity and the introducing-path light up for pnpm projects as they already do for npm and yarn.
- **VEX consume accepts CSAF 2.0, not only OpenVEX.** The VEX apply endpoint and the in-repo `.synapse.vex.json` loader previously parsed OpenVEX only. `vex.ParseAny` now auto-detects the format (CSAF by `document.csaf_version`, OpenVEX otherwise) and `vex.ParseCSAF` maps a CSAF `vulnerabilities[].product_status` document onto the same `Document`/`Statement` shape, so the existing suppress/match core (`MatchesFinding`, `Suppresses`) and the audit-recorded apply flow are reused unchanged. Product ids resolve through the `product_tree` (full product names, nested branches, and `default_component_of` relationships to the underlying component), preferring the PURL helper; a `known_not_affected` product carries its OpenVEX justification, read from the CSAF `flags[].label` (the five labels are identical strings across the two formats). A supplier can now ship either format and have Synapse suppress the matching finding. As part of this, the shared VEX finding matcher (used by the OpenVEX path too) is now npm-scope aware: a statement about a scoped package (`pkg:npm/%40scope/name`) matches its own `@scope/name` finding instead of collapsing to the bare leaf and wrongly suppressing a different unscoped package of the same name.
- **Three more provider secret detectors.** The owned secret scanner gains distinctive-prefix detectors for Sentry auth tokens (`sntrys_`), ReadMe (`rdme_`), and Figma (`figd_`), continuing the move toward gitleaks parity. Each has a long, unique prefix and a genuinely variable-length body, so a lower-bound length is correct rather than a guessed fixed length (fixed-length API keys with short prefixes were deliberately left out to avoid a mis-sized regex that would over- or under-match). Each ships a positive fixture and a near-miss negative; the catalog-parity and golden-key drift guards keep the ruleset and catalog in lockstep.
- **Explicit-version advisory matching is ecosystem-aware.** An OSV `affected[].versions` enumeration previously matched only by exact string (after trimming a leading `v`), so a PyPI advisory listing `1.0` missed a `1.0.0` component even though PEP 440 treats them as equal. `advisory.AffectedVersionList` now also compares with the ecosystem's owned comparator (PEP 440 trailing zeros, Maven qualifier folding, and the other owned schemes), recovering recall on the most authoritative signal an advisory carries. An ecosystem with no owned comparator still matches exactly (fail-closed, no guessed order).
- **Inline secret-suppression annotation.** A line carrying a `synapse:allow` comment (or `gitleaks:allow`, for drop-in migration) no longer reports the secret on that line, matching gitleaks' `gitleaks:allow`. The annotation is read from the pre-comment-mask line, so a trailing `# synapse:allow` is honored even though comment bodies are blanked before matching.
- **Five more provider secret detectors.** The owned secret scanner gains distinctive-prefix detectors for Docker Hub PATs (`dckr_pat_`), Stripe restricted keys (`rk_live`/`rk_test`), GitLab pipeline trigger tokens (`glptt-`), Pulumi access tokens (`pul-`), and Clojars deploy tokens (`CLOJARS_`), moving the catalog from 44 toward gitleaks parity. Each has a unique prefix, so false-positive risk is near zero, and each ships a positive fixture plus a negative one (an allow-listed placeholder for the base64/alnum tokens, a wrong-shape near-miss for the fixed hex/length tokens); the catalog-parity and golden-key drift guards keep the detector set and the rule catalog in lockstep.
- **Container rootfs materialization handles zstd layers.** OCI images increasingly ship zstd-compressed layers (Wolfi/Chainguard and newer builders); the rootfs extractor detected the zstd magic and rejected the image, so nothing downstream could scan it. It now decompresses zstd layers (via the already-vendored `klauspost/compress`) as well as gzip and raw tar, mixed in any order, with the same decompressed-output byte/entry caps bounding a compression bomb for either codec. Detection is by magic bytes, so a mislabeled layer mediaType is tolerated.
- **Offline severity banding for label-only advisories.** A GHSA/OSV advisory that carries only a curated `database_specific.severity` label (no CVSS vector) landed at severity Unknown on the owned offline path, while the live OSV adapter already read the label. `ownadvisory.ParseOSV` now reads the label into a new `advisory.Advisory.Severity` band (via a shared `shared.SeverityFromLabel`, which the live OSV adapter now also uses), the matcher prefers a score-derived band and falls back to the label (a curated label overrides, matching the live adapter), and `Merge` carries the most-severe band through materialization. Offline and live now agree on the band for a shared advisory.
- **The owned scan matches NVD-only CVEs via CPE on the default scan.** The primary scan path (`ownadvisory.Source`) matched only by package key (OSV ecosystems), so an NVD-only CVE on a system/OS library with no OSV package block was invisible on a default scan, the single largest recall gap versus Grype's NVD matcher. `Source.Scan` now also matches every component that carries a CPE against the NVD/CSAF applicability index (`ByCPE`), sharing one comparator (`advisory.CPEMatches`, lifted out of the reconciliation path so both use it) and deduplicating a package + CPE hit on the same advisory. Withdrawn advisories are skipped here too.
- **Withdrawn advisories no longer produce false positives.** A retracted upstream advisory (OSV `withdrawn`, NVD `REJECTED`) is a guaranteed false positive. `advisory.Advisory` now carries a `Withdrawn` flag: `ownadvisory.ParseOSV` sets it from the OSV `withdrawn` timestamp, the materializer projects it from the canonical status (`withdrawn`/`rejected`), and the owned matcher (`ownadvisory.Source.Scan`) skips any withdrawn advisory, so it never becomes a finding on either the CLI ingest or the provider-sync path. A golden-corpus case asserts a withdrawn advisory whose range covers the component still yields no match. Matches how OSV-scanner and Grype treat withdrawn advisories.
- **CPE/NVD version ranges now match real NVD version forms (recall fix).** The CPE reconciliation matcher (`internal/usecase/vulnerabilitycorrelation`) rejected any bound or component version that was not strict SemVer, so 4-part (`9.0.62.1`), qualifier-bearing (`3.0.0-M4`, `1.2.3.RELEASE`), and date-like NVD versions made the whole range non-evaluable and the CVE was missed. A new pure fuzzy comparator (`advisory.CompareFuzzy` / `advisory.OrderableFuzzy`) orders by numeric segments first with a lexical qualifier tail and fails closed only on input with no leading numeric component, so those ranges now evaluate. This is a direct recall gain on CPE/NVD-only advisories, where Grype and Trivy already match.
- **The owned scanner's detection accuracy is now measured and gated.** Adds a pure precision/recall/F1/false-positive-rate/false-negative-rate reducer (`internal/usecase/benchmark/accuracy.go`) and a golden detection corpus (`internal/usecase/sca/testdata/detection-golden-v1/`) that runs Synapse's own `advisory-store` engine (`ownadvisory.Source`) over a pinned advisory snapshot and fails CI when precision or recall on any ecosystem drops below a checked-in ratchet (`detection-accuracy-debt.json`, floors only rise). The initial corpus spans npm, PyPI, Go, Maven, RubyGems, crates.io, Debian, and Alpine with patched-version and version-boundary negatives, and the owned engine holds precision 1.0 / recall 1.0 on it. This makes the claim that the owned engine stands on its own regression-proof and offline, with no third-party scanner in the loop.
- **The synapse-cli scanner reaches the first-party engine too.** The CLI (the dogfood/CI scanner) previously hard-wired syft and offered only Grype/OSV, silently ignoring `SYNAPSE_SBOM_PRODUCER=ownsbom` and having no owned-advisory option. It now selects the SBOM producer from config (syft or Synapse's own `ownsbom` parsers, unknown values rejected) and offers the owned `advisory-store` as a detection source when a Postgres corpus is configured, resolved through the same `scacompose.ResolveDetectionSources` the server uses. A repo scan can now run fully first-party from the CLI (`SYNAPSE_SBOM_PRODUCER=ownsbom` with `SYNAPSE_DETECTION_SOURCES=advisory-store` over a synced corpus), no Anchore binaries.
- **Config-driven vulnerability detection sources (drop the Grype lock-in without adding a vendor).** The scan-time matchers are now selected and ordered by `SYNAPSE_DETECTION_SOURCES` (a comma list of `grype`, `osv`, `advisory-store` — Synapse's own advisory corpus), resolved through one shared registry used by the API, worker, and CLI (the CLI previously had a separate hard-wired list). Empty preserves the legacy default; when set it is authoritative, so an operator can drop Anchore's Grype entirely (e.g. `osv,advisory-store`) and run on Synapse's owned advisory store plus live OSV for an Anchore-free posture. Unknown names fail closed at startup. Detection is no longer fail-hard: a source that errors (a transient OSV.dev outage, an advisory-store read blip) is skipped with a `SourceWarning` and the remaining sources still run, matching how Grype already degrades; `SYNAPSE_STRICT_SOURCES=true` restores fail-closed. The live OSV source is also hardened: transient 429/5xx and network errors are retried with bounded exponential backoff (honoring `Retry-After`), and the per-advisory detail fetch runs bounded-concurrently so latency no longer scales linearly with the vulnerability count. New vars are documented in `docs/guide/configuration.md`.
- **DAST, detection provenance, occurrence risk, and batch auto-verify reach the dashboard.** Four more engagement routes that were wired non-nil had no UI. A new **DAST** tab under Offensive runs the authenticated scanner as a governed workflow (propose with an egress preview, approve under separation of duties, then run and read the proofs) and proposes, approves, and runs a per-judgment runtime-verification probe. A new **Provenance** tab under Runtime shows each sealed detection's hash-chained lifecycle (`GET /engagements/{id}/detection-provenance` and per-detection transitions). The Vuln Posture occurrences are now expandable into their event log, current risk assessment, and risk history (`/vulnerability/occurrences/{oid}/events`, `/risk`, `/risk/history`). The review queue gains a batch **Auto-verify all** action (`POST /judgments/auto-verify`) that runs the verifier model over every proposed judgment it can. Write actions are role-gated client-side (operate to propose and run, review to approve and auto-verify) and re-enforced server-side.
- **The technical asset relationship graph reaches the dashboard.** The asset-edge routes (`GET`/`POST /assets/edges`) had no UI. A new **Asset Graph** page under Fleet renders the technical asset relationships (host runs workload, workload depends on image, exposure reaches workload) with the source observation on each edge and observed-vs-inferred drawn as solid-vs-dashed. An operator can add an edge from an observation. `POST /assets/edges` now answers `204` instead of a bodyless `201`, so a JSON client no longer fails parsing an empty response.
- **Fleet agent management and per-host capability surfaces reach the dashboard.** Several fleet routes were wired non-nil in `cmd/synapse-api` but had no UI. A new **Agents** page (`/fleet/agents`) mints single-use enrolment tokens, revokes agents, lists and revokes their signing keys, and drives the staged agent binary rollout per channel (read the plan, set target and canary groups, promote, pause, resume). The host detail view gains two tabs: **Capabilities** declares and reconciles the desired capabilities for a host (`GET`/`PUT`/`DELETE /fleet/assets/{id}/desired-capabilities`, reconciled against the observed gaps), and **Processes** lists the running-process projection that feeds the behavior baseline and resets that baseline (`GET /fleet/assets/{id}/processes`, `POST /fleet/assets/{id}/behavior-baseline/rebaseline`). Write actions are gated to the operator and administrator roles client-side and re-enforced server-side.


- **Provider-neutral external CI/CD integrations.** Adds tenant-isolated, write-only encrypted Jenkins
  credentials; bounded SSRF-resistant test, discovery, and polling operations; Project bindings and
  exact-commit correlation; durable scheduled work; normalized run history; and an operator-controlled,
  default-off exception for approved private Jenkins origins.
- **Container CVEs can be traced to the Kubernetes workload that runs them.** A container vulnerability is found on an image digest, but operators need to know which workload it came from. A new **Workloads** view under Runtime Security (`GET /api/v1/fleet/workloads`) lists every Kubernetes workload mapped to the image digests it runs, from the cluster-inventory asset graph (`workload depends_on image`), grouped by namespace with the controller kind (Deployment / StatefulSet / DaemonSet). An image shared by several workloads is flagged on each, so a CVE on that digest is attributed to every deployment or statefulset that runs it. Empty until a cluster agent ingests a snapshot.

- **Per-branch Code Quality analysis.** A Project's analysis history is now keyed by branch, not just
  labelled with one. `GET /projects/{key}/analyses` and `GET /projects/{key}/overview` accept an
  optional `branch` query parameter that restricts history and the overview to one branch (omitted =
  latest across all branches, the prior behavior). The New-Code baseline for a recorded analysis is
  the previous analysis on the same branch, so a feature branch diffs against its own history rather
  than whichever branch scanned last. A new `GET /projects/{key}/branches` route lists the distinct
  branches a Project has analyses on. Migration `0136` adds and backfills the `branch` column on
  `project_analyses` with a branch-scoped history index.

- **Dashboard, attack-path, and metric-strip UI polish.** The Security Operations metric strip now spreads evenly across the width and moves each figure's definition into an info tooltip instead of a second line of small print, which also removes the stray "fleet capability checks" line under Coverage gaps. The attack-path view is reworked into a cleaner exposure-to-finding flow with colored node rails, canonical severity badges, relationship-labelled edges, and the "why uncertain" reasons behind a tooltip. `listHosts` degrades to an empty list instead of throwing when the endpoint answers a non-array shape.

- **Cloud posture, write-up drafts, coverage windows, and host retro-hunt reach the dashboard.** Four more routes were wired non-nil in `cmd/synapse-api` but had no UI. New surfaces consume them: a **Cloud Posture** tab runs a bounded read-only CSPM scan (`POST`/`GET /engagements/{id}/cspm/runs`); a **Write-up Drafts** tab lists AI-proposed finding write-ups with reviewer accept/edit/reject under separation of duties (`/engagements/{id}/writeup-drafts`); a **Coverage Windows** page shows the immutable per-asset telemetry coverage revisions with per-class sensor state (`GET /fleet/coverage-windows`); and a host **Timeline** tab re-hunts a window of the host timeline around a pivot (`POST /fleet/assets/{id}/retro-hunt`).

- **Tenant telemetry-privacy governance in the dashboard.** The fleet source-privacy policy routes
  (`GET /fleet/privacy-policies/active`, `GET/POST /fleet/privacy-policies`, `POST
  /fleet/privacy-policies/activate`) had no UI. A new **Telemetry Privacy** settings page shows the
  active policy as a field-by-field disposition matrix (allow/redact/hash/drop, with limits and the
  content digest), admits a new policy from a form (with an "admit and activate" shortcut), and rolls
  a policy out from the admission history behind a confirm. The hash salt never crosses this human plane.


- **Per-engagement tool credentials in the dashboard.** The vault-sealed credential routes
  (`GET/POST/DELETE /engagements/{id}/credentials`) had no UI. A new **Credentials** tab (under
  Governance) lists the stored placeholders with their timestamps, adds one through a collapsible form
  (the secret is write-only, sealed in the vault, and never shown again), and deletes one behind an
  inline confirm. Referenced from tool config as `{{secret:NAME}}` and resolved server-side only at
  tool-execution time.


- **Runtime detections feed the behavior baseline (#822).** The statistical baseline behind a host's
  Behavior risk factor only ever saw its process snapshot, so the network, privilege and file features
  stayed at zero and anomaly scoring never ran over runtime telemetry. The baseline now folds the host's
  per-class detection rate (network / privilege / file) from the sealed detection ledger over a recent
  window into the observation, alongside the process features. A new `ClassCountsByAsset` read on the
  detection store backs it (memory and Postgres, no schema change). The detection source is optional and
  best-effort: a store error or a deployment without the ledger leaves those features at zero.


- **Sequence detection rules (#822).** The detection engine matched single events and, since the rate
  window, bursts; it now also matches an ordered *sequence* of events of one class within a span, grouped
  per host. A new `Sequence` rule type (mutually exclusive with a rate `Window`) carries the ordered step
  matchers; the per-class evaluator tracks each group's partial match under the same `MaxWindowGroups`
  memory bound, allocates a group only on a first-step match, re-anchors on a repeated first step so a
  restaged tool is not missed, and fires once with the ordered evidence. The shipped catalogue gains
  `det.tool_staging_sequence`: a downloader (curl/wget/tftp/ftp) followed by a remote-shell tool
  (nc/ncat/socat) on one host within two minutes, which neither process alone reveals.


- **Attack paths, SLA policy, offensive policy, and alerting reach the dashboard.** Four capabilities
  were wired non-nil in `cmd/synapse-api` but had no UI, so operators could not reach them. A new
  **Attack paths** tab under Vulnerability Intelligence renders the exposure-to-finding graph
  (`GET /attack-paths`) as an evidence-carrying chain per path with a confident/inferred verdict and the
  reasons a path is uncertain. Three new Settings tabs cover the rest: **SLA policy** reads the active
  scoring policy and lets an admin activate a new version (`GET`/`POST /sla/policies`) through an editor
  that mirrors the server rules; **Offensive policy** renders the read-only technique register
  (`GET /redteam/policy`) with risk class, blast radius, approval, and legal review; **Alerting** runs the
  sink self-test (`POST /alerts/test`) and shows the per-count outcome, including the no-acknowledgement
  (502) case.


- **Chained exploitation is reachable as a governed rehearsal.** The exploitation state machine (per-step
  admission through the offensive policy, sealed per-step evidence, a distinct verifier, cleanup
  obligations) and its kill-switch registry existed and were tested, but nothing constructed a chain outside
  tests, so the kill switch guarded an empty registry and the capability was unreachable. `POST
  /api/v1/engagements/{id}/exploitation/rehearsals` (operate-gated) now rehearses an operator-declared chain
  through the SAME governance the rest of the offensive pillar uses, registering the running chain with the
  kill switch so `POST /api/v1/redteam/halt` can stop it mid-run. The rehearsal executes with a no-host
  simulation executor and a distinct system verifier, so it proves a chain is policy-admissible and its
  chain of custody is sound without touching a host. It is a simulation, not a claim of real compromise; a
  real host executor and an independent verifier stay a deliberate, review-gated extension point.

- **Adversary emulation is reachable and produces purple-team coverage.** The emulation catalogue, its
  run store, the offensive governance policy, and the purple-coverage read route all existed and were
  tested, but nothing ran an emulation: no composition root constructed the producer, so the purple panel
  read an empty store. `POST /api/v1/engagements/{id}/emulation` (operate-gated) now runs the technique
  catalogue against a target asset, admitting each technique through the engagement's offensive rules of
  engagement (the same #418 governance the exploitation chains use), then computes and persists the purple
  coverage the dashboard reads. A technique the rules of engagement do not permit is recorded as not
  executed (verdict unknown), never run. Emulation executes through a no-host simulation executor, so the governed measurement is
  honest and testable without touching a host; the real host executor stays a deliberate extension point.
  This also constructs the offensive governance service for the first time, which enforces an engagement's
  risk ceiling, authorization window, and recorded approvals on every technique.

- **Engagements carry their offensive rules of engagement.** The offensive governance policy refuses
  adversary emulation and exploitation chains until an engagement declares its customer and emergency
  contacts, a risk ceiling (`low`/`medium`/`high`/`prohibited`), and that the out-of-scope list was
  reviewed. The `Engagement` aggregate now holds these fields, `PUT /api/v1/engagements/{id}/offensive-roe`
  sets them (operate-gated, tenant-scoped, audited), and every engagement response returns them under
  `offensive_roe`. Migration `0135` adds the columns backward-compatibly (defaults leave the offensive
  pillar refused until an operator fills them in) with a `risk_ceiling` CHECK. This is the foundation the
  offensive/purple pillar (emulation, purple coverage, exploitation chains) needs to become reachable.


- **Governed DAST verification runs execute on the worker (#823).** An approved DAST probe used to run on
  the API request thread. With the Postgres job queue it now runs as a durable, lease-executed job: the
  run route (`POST /engagements/{id}/judgments/{jid}/runtime-verification/proposals/{aid}/run`) enqueues
  it and answers `202` with a queued run, `synapse-worker` executes the SAME approval-gated, sandboxed,
  evidence-sealing probe (so the single-use consume and the evidence seal still happen exactly once), and
  `GET /engagements/{id}/dast/runs/{rid}` polls the run to a terminal state. The run record is secret-free
  (verdict class, observed HTTP status, sealed-evidence id). Without the queue (in-memory dev) the probe
  stays synchronous. Backed by a new `dast_runs` table with tenant RLS. A redelivered job never re-runs a
  probe that may already have consumed its single-use approval: the outcome is written with a
  compare-and-set that only fires from `running`, so a late delivery cannot overwrite a recorded success,
  and an interrupted run terminalizes `interrupted` instead. A worker that has no live scoped-egress
  broker still claims the job and fails the run `egress_unavailable` rather than leave it orphaned at
  `queued`, so an enqueued run is always visible to the poller.


- **Per-engagement vulnerability posture in the dashboard.** The reconciled advisory occurrences and the
  governed action queue for an engagement (`GET /engagements/{id}/vulnerability/occurrences` and
  `.../vulnerability/actions`, with `.../actions/{aid}/acknowledge` and `/resolve`) had no UI. A new
  **Vuln Posture** tab (under Findings) lists the action queue with in-place acknowledge/resolve and the
  reconciled occurrences with fix version and reachability, surfaced where the operator works the engagement.

- **Reconciliation run results in the dashboard.** A tenant could start a vulnerability reconciliation
  but could not see its outcome. Starting a full reconciliation now opens a run panel that polls the run
  to completion and shows its counts (processed/added/updated/unchanged/unmatchable/retired) and its
  per-item diffs, filterable by class (missing/changed/stale/in-sync) with cursor paging.

- **Per-asset risk stories in the dashboard.** The server assembles one correlated risk narrative per
  asset (`GET /engagements/{id}/risk-stories`), joining identity, exposure, findings, attack paths and
  detections into a single ranked score, but no UI consumed it. A new **Risk Stories** tab (under
  Findings) shows one card per asset ranked by risk, with each finding's corroboration (reachable, on an
  attack path, seen under attack) that raised it.

- **Purple-team detection coverage in the dashboard.** The server computes, for each executed attack
  technique, whether its expected detection fired (`GET /engagements/{id}/purple-coverage`, and
  `?run=<id>` for a run's gap work items), but no dashboard surface consumed it. A new **Purple
  Coverage** tab (under Offensive) shows the latest emulation run's coverage percentage and its
  covered/gap/not-run/out-of-reach breakdown, a per-run coverage trend, and the detection gaps (one
  work item per executed-but-undetected technique) to close.

- **Scan-run history and run-to-run drift in the dashboard.** Every SCA scan already sealed a manifest
  of its inputs (tool and database versions, the SBOM hash, a reproducibility score) and the finding
  keys it produced, and the server exposed `GET /engagements/{id}/scan-runs` and
  `.../scan-runs/compare?a=&b=`, but no dashboard surface consumed them. A new **Scan Runs** tab (under
  Supply Chain) lists the history with each run's reproducibility score and pinned/live inputs, and
  comparing two runs shows which finding keys were added or removed, how many are unchanged, and the
  manifest deltas (grype-db, vuln-db snapshot, tool versions) that explain a legitimate change.

- **One artifact deploys to native hosts and Kubernetes via `execution.mode`.** The Helm chart gained a
  top-level `execution.mode`: `controlPlaneOnly` (default — offline scanner console that boots on any node,
  including managed EKS and `kind`), `externalNative` (production control plane on k8s, execution tier on
  native EC2 per ADR 0008), and `inClusterBroker` (execution in-cluster via an opt-in privileged
  `synapse-egress-broker` DaemonSet on capable nodes). Render guards fail closed with a clear message instead
  of shipping a chart that CrashLoopBackOffs, and the `synapse-egress-broker` binary now ships in the
  production image. Added `deploy/kind/` (a control-plane smoke: `make kind-smoke`) and `make
  helm-render-test`. Documented the three placements and the requirement that the runtime DB role be
  `NOSUPERUSER NOBYPASSRLS` (Synapse refuses to serve on a superuser role because it bypasses RLS).

- **Private repositories can be scanned through source-control connectors.** A server-initiated scan
  could only clone a public repository: the acquirer blanked every git credential. A tenant can now
  configure a source-control connector (a git host, a username, and a personal access token) at
  `GET/POST /api/v1/connectors` and `DELETE /api/v1/connectors/{id}` (administer permission; the token
  is sealed AES-256-GCM at rest and is write-only). When a Project's git source host matches a
  connector, the acquirer authenticates the clone by supplying the token through `GIT_ASKPASS`, so it
  never enters argv, the URL, the workspace `.git/config`, or a log. GitHub, GitLab, Bitbucket and a
  generic host are supported; a self-hosted host may be an IP. Manage connectors in Settings.

- **Container images can be scanned from the server and the dashboard.** Image scanning (crane pull,
  OS-package and language cataloging, layer attribution) already ran through the CLI, but the server
  route `POST /api/v1/sca/scans` rejected `kind=image` at the edge, so the dashboard's image button
  4xx'd. The edge now validates a container-image reference and forwards it to the acquirer; the
  engagement scope still gates the image server-side as a `TargetImage`.

- **A drifted behavior baseline can be re-baselined.** A behavior baseline that latched on drift (or
  was refused as poisoned) abstained from scoring forever, because the reset the domain supports had no
  route. `POST /api/v1/fleet/assets/{id}/behavior-baseline/rebaseline` now drives it through a clean
  reset (reset_pending -> learning) so it re-learns from fresh windows. PermOperate, audited.

- **The behavior baseline finally has input.** The statistical baseline that scores a host's Behavior
  risk factor never saw an observation, because the shipped agent reported host packages but never its
  processes. The VM agent now reports its running processes on the inventory-sweep cadence (read-only
  procfs: pid, comm, exe path) via the new agent-plane route `POST /api/v1/fleet/processes`; the
  control plane resolves the host asset from the authenticated agent (never the request), stores the
  running-process projection, and folds the profile into the asset's behavior baseline (#594 D). On by
  default, disable with `SYNAPSE_PROCESS_REPORT_ENABLED=false`.

- **Governed defensive response is operable.** The response subsystem (issue #425) was fully modelled
  — three reversible action kinds, an admission gate, a blast-radius check, a telemetry-verified
  post-condition — but had no route and no caller. It is now wired: `POST
  /api/v1/blueteam/engagements/{id}/response/{plan,apply}`, `POST /api/v1/blueteam/response/{id}/revert`
  and `GET /api/v1/blueteam/response` drive the full admission -> human approval -> apply -> verify ->
  revert ledger through the same gate exploitation and DAST use, and the `/api/v1/redteam/halt` kill
  switch now cancels pending response actions. A pending second-approval returns the action's id so an
  operator can find it; the reversal enforces the same blast-radius rule as apply. The default executor records every state without a host
  effect; a real host executor stays a deliberate, review-gated extension point, so the platform never
  applies a real isolation without an explicit execution-safety decision.

- **Engagement rows carry their findings and their last scan.** `GET /api/v1/engagements` now
  returns `findings_count` (open findings of every kind by severity) and `last_scan_date` with
  `last_scan_status` on every row, read in two batched queries (one GROUP BY over the rows' findings,
  one latest-job lookup) whatever the number of engagements. The console's Engagements table showed
  "not reported" and the creation time in those columns against a real server; it now shows the counts,
  "Scanned 2h ago", "Failed 1d ago", or "Not scanned".

- **Pipeline results reach the console.** `synapse-cli scan --server URL --project KEY` records the
  scan result on the server as the project's next analysis, through the same recorder a server-run
  analysis uses, so it appears in the history, moves the trend, is evaluated against the project's
  managed quality gate, and carries ratings, issues and hotspots. The analysis is marked `origin: ci`
  and shows the branch, run and actor the pipeline reported, with a link to the run. The new route is
  `POST /api/v1/projects/{key}/analyses/import`; the GitHub Action gains `server`, `project` and
  `api-token` inputs. Before this, the CLI was a self-contained gate whose result died with the
  process and the console was fed only by scans the server ran itself.

- **Fleet hosts get CVE findings.** A host agent already reported its installed OS packages with
  distro-qualified package URLs; the control plane counted them and dropped the list. It now records
  the list as the host's SBOM in a hidden per-host engagement (`engagements.host_asset_id`, migration
  0130) and runs the SCA imported-SBOM pipeline against it, so host CVEs get the same advisory
  matching, OS version comparison, KEV/EPSS ranking, dedup and reconciliation as a repository or
  image. Recording is idempotent per package set. New routes `GET /api/v1/assets/hosts`,
  `GET /api/v1/assets/{assetID}/vulnerabilities` and `GET /api/v1/assets/{assetID}/packages` (the
  recorded package list, as the scan saw it); the host inventory response reports the scan outcome;
  the console gains Fleet, Hosts with a per-host vulnerability and package view.

- **Incidents exist without a human calling an endpoint.** A detection batch that seals new detections
  now runs correlation for its engagement at once, so an incident is open as soon as the detections behind
  it are durable. The correlate route stays for on-demand runs; a correlator failure is audited and
  reported in the ingest response, never fails the ingest.

- **Operator alerting.** `SYNAPSE_ALERT_WEBHOOK_URL` (with an optional `SYNAPSE_ALERT_WEBHOOK_SECRET`
  and `SYNAPSE_ALERT_MIN_SEVERITY`) posts a signed JSON alert for every incident correlation opens, with
  bounded retries and a per-sink audit entry. `POST /api/v1/alerts/test` proves the path works. Before
  this, nothing in the repository told anyone an incident existed.

- **Detection rules can fire on a rate.** A rule may carry a window (count, span, group-by fields); the
  evaluator counts matching events per group inside the span and fires once with the burst as evidence.
  `det.suspicious_dns_beacon` is v2: 120 DNS datagrams to one destination within a minute, where v1
  fired on every DNS packet. The agent engine, retro hunts and release evidence share the evaluator.

- **The offensive policy register is loaded by the binary.** `synapse-api` parses and validates
  `policy.yaml` at startup and refuses to start on an invalid register; `GET /api/v1/redteam/policy`
  shows every technique with its risk class, approval mode, blast radius and whether it is prohibited or
  production-safe, so the console shows what the running binary enforces rather than what a document says.

- **Imported findings are visible.** Findings a pipeline sent through the SARIF route landed in a
  table no page rendered. The engagement's Findings group gains an Imported tab that lists them with
  tool, version, location and provenance.

### Changed

- **Dashboard theme fidelity.** The Code Quality measures table now labels bug, vulnerability, code-smell
  and hotspot columns with icons instead of emoji; the project-activity trend chart, the code-viewer
  syntax highlighter, the modern badge addon, and the dependency-graph minimap now draw from semantic
  theme tokens so they render correctly in both light and dark themes.

- **Console pages read as one operational surface.** The Hosts list is a dense table (host, OS,
  packages, open findings by severity, fixable, KEV, scan state, recorded) with a filter row; the host
  detail shows the facts in the header, one metric strip, and Vulnerabilities and Packages tabs whose
  empty states name the missing stage (no inventory, reported but not recorded, scan pending, scan
  failed, clean). The framed stat cards on Dashboard, Assets, Engagements and Rules are replaced by
  the same compact metric strip, and loading and empty states share one component across pages.

- **The dashboard leads with a Needs attention queue.** The radar and donut panels are replaced by a
  table of what an operator acts on today, built from data the page already loads: critical or
  high-risk assets, engagements whose last scan failed, fleet coverage gaps, and active engagements
  that were never scanned, each with owner, age and a link to the page where the action happens. The
  metric strip carries action counters (critical open, high open, high-risk assets, coverage gaps,
  needs attention); the finding trend moves below the queue.

- **Incidents and Hosts read as operational tables.** Incidents gains a metric strip (open, critical
  open, in progress, resolved), state chips with counts, an Opened column, a table skeleton while
  loading, and framed empty and error states that say what fills the table and how to retry. The Hosts
  list shows the open total next to the severity buckets (with an unrated remainder so the row adds up
  to the host page), folds the recorded time into the Scan column, and reports "Needs attention" as one
  count, and gains a Coverage gaps tab that lists what the agent could not inventory and why (the
  host asset now records `coverage_gap_kinds` and `coverage_gap_details`, not only the count). Low
  severity is blue in both themes; green now only marks a healthy or successful state.

- **Dashboard queue is full-width and decision-grade.** The Needs attention queue moved to its own
  row so the issue text (two lines, untruncated), the owner, and the next action are all visible;
  Assessment Activity sits below the trend. The Coverage gaps metric is scoped ("fleet capability
  checks") so it no longer reads as the same count as a host's coverage gaps, and a running
  engagement scan reads "Scanning · started 1h ago" rather than a stale-looking "1h ago".

### Fixed

- **A bulk advisory re-sync no longer clobbers exploitation-risk enrichment.** The owned advisory store has two writers into the same `advisories` row: the canonical materializer, which merges CISA KEV, FIRST EPSS, and public-exploit signals from provider observations, and the bulk feed ingester (`synapse-cli sync-advisories`), which carries only the base advisory. The ingester's `Upsert` replaced the whole JSONB blob, so a bulk re-sync after an enrichment pass silently reset `KEV`, `EPSS`, `EPSSPercentile`, and `PublicExploit` to zero, dropping a finding's exploitation priority for an offline scan. `Upsert` now carries those four signals forward raise-only (a new pure `advisory.Advisory.PreserveEnrichment`), matching the invariant already documented on the type: the risk signals only ever raise, never lower a corpus value, and a feed that carries a stronger signal still wins. Writers of one advisory identity serialize on a transaction-scoped `pg_advisory_xact_lock` (the same primitive the materializer takes per identity), so the read-then-merge holds even for two concurrent inserts of a not-yet-stored id, which a plain `SELECT ... FOR UPDATE` cannot lock. The base advisory (identity, aliases, summary, CVSS, affected ranges, severity, withdrawal) still fully refreshes, so a feed that narrows or retracts an advisory still takes effect. The in-memory store mirrors the behavior. This closes the enrichment-clobber half of EPIC #860 D1.2; cross-feed union of affected ranges, which needs per-source provenance, stays with the observation/canonical materializer path.
- **Assessment Cycle scans retain every supported IaC family.** Native observation
  preparation now accepts Dockerfile, Compose, GitHub Actions and ARM findings in
  addition to Terraform, CloudFormation and Kubernetes (including rendered Helm).
  Findings without approved resource identity remain provisional and require review
  on every re-scan, including repeated source fingerprints;
  incomplete IaC coverage cannot imply Fixed. Repository paths reject URL locators
  before normalization so embedded credentials cannot enter source identities.

- **Python Tier-1 reachability no longer suppresses transitive dependencies.** The Python import-reachability analyzer (`SYNAPSE_PYREACH_ENABLED`, opt-in) minted a `not_reachable` judgment (an OpenVEX `not_affected` that exempts a finding from the gate) for any PyPI component its first-party import scan did not see, including transitive dependencies that a lockfile-resolved SBOM enumerates. First-party source never imports a package it receives through a parent, so this suppressed real transitive findings. It now carries the declared-direct-dependency guard its Rust/PHP/Ruby siblings already had: it reads the always-installed main dependencies from `pyproject.toml` (PEP 621 `[project]` and Poetry `[tool.poetry.dependencies]`) and `Pipfile` `[packages]` — never a `pip freeze`/`pip-compile` `requirements.txt`, optional/dev groups, or a conditional entry (a PEP 508 environment marker, or any Poetry/Pipfile inline-table or multiple-constraints value, since a table can carry an `optional`/`markers`/environment gate), any of which could name a package that is only present transitively — and refuses to answer, rather than mark unreachable, any package that is not an always-installed declared direct dependency or when no such manifest is present.
- **The production Helm chart's values schema parses again.** A merge of the external CI/CD
  integrations work duplicated the top-level `properties` block in
  `deploy/helm/synapse/values.schema.json`, leaving malformed JSON that made `helm lint` and `helm
  template` fail on every install of the production chart. The schema is restored to one block that
  keeps the strict posture (`objectStore.useSSL` fixed to `true`, `worker.integrationScheduler`
  required, the `existingSecrets.egressGrant.authorityToken` secret) together with the newer
  `execution` and `egressBroker` definitions. The chart lints under `--strict` and renders against
  `tests/production-values.yaml` again.
- **The running-process projection retires exited processes.** The agent reports only live processes
  and the store upserted them, so a process that exited between reports lingered as running forever and
  the behavior baseline's process-count feature climbed every sweep, self-poisoning into false drift. A
  complete agent report (it enumerated every process, under the cap) now REPLACES the host's running set
  in one transaction: the reported set is upserted and any other running row for that host is retired.
  Found by the verification-gate QA and Codex reviews.
- **A configured alert webhook requires a signing secret.** With `SYNAPSE_ALERT_WEBHOOK_URL` set but no
  secret, alerts were delivered unsigned, which a receiver cannot distinguish from a spoof. A secret is
  now required unless the operator explicitly opts into unsigned delivery with
  `SYNAPSE_ALERT_WEBHOOK_ALLOW_UNSIGNED=true`.
- **Response blast-radius violations persist reliably.** The violation-state write on a response
  apply/revert was best-effort (`_ = put`); a lost write is now joined to the violation error so the
  kill switch and the list always see a halted action. The operator process-report and
  behavior-baseline rebaseline routes now verify the path id is a live host asset before mutating.

- **Process snapshots upsert in one round trip.** The Postgres endpoint-process store issued one
  statement per process, so a host at the 4096-process cap made thousands of sequential round trips
  holding a pooled connection; a synchronized fleet restart could saturate the connection pool. It is
  now a single multi-row upsert over `unnest` (measured ~5x faster), and the agent's inventory sweep
  gains a boot jitter so a fleet restarted together does not report in lockstep.

- **Open counts exclude triaged-away findings.** The per-engagement summaries behind the host pages
  and the engagement list skip findings marked false positive or remediated, so "open findings" means
  open.

- **The per-agent host cap holds under concurrent syncs.** The 16-host cap was checked before the
  write, so two syncs from one agent that both counted 15 could both create a host. A `fleet_assets`
  trigger (migration 0132) now recounts under a per-agent advisory lock inside the insert and refuses
  the row past the cap; the in-memory store does the same under its lock. The refusal is audited and
  returned as 403 like the fast-path one.

- **A rejected pipeline import no longer leaves a succeeded job.** `POST /api/v1/projects/{key}/analyses/import`
  wrote the `ci-import` scan job as succeeded before the recorder ran, so a payload the recorder refused
  (a duplicate file path in the inventory, for instance) left a succeeded job with no analysis behind it.
  The job is now marked failed with the rejection reason, and a failure to write the import's audit
  record is returned to the caller instead of being dropped.

- **CVSS v2-only advisories get a score.** Host findings whose advisory carries only a CVSS v2 vector
  (older CVEs on distro packages) showed no score because only v3 vectors were scored. The read side now
  scores v2 vectors with the v2 formula, and grype's CVSS selection prefers a v3 vector over a
  higher-scored v2 one so the vector recorded is the one every consumer can score.

- **SAST precision on a real repository.** A full scan of this repository produced 623 findings, 140 of
  them high-severity SAST, most of them noise: Go rules matched code quoted in `CHANGELOG.md`,
  `reflected-response-write` flagged `fmt.Fprintln(os.Stderr, err)` in every CLI, `go-sql-dynamic-query`
  flagged `r.URL.Query().Get("q")`, `path-traversal-file-access` flagged any `os.Open(path)` in code no
  request reaches, `hardcoded-credential` flagged `MetricNewSecret = "new_secret"`,
  `jwt-hardcoded-secret-or-none` flagged `NoSamplingAlgorithm = "none"`, `redos-vulnerable-regex` flagged
  `(?:\.[0-9]+)*`, and the secret scanner's private-key rule flagged its own rule catalogue. Prose files
  are no longer source; the request-sink rules run only in files that handle requests; the Go
  `Fprint*` branch needs a response writer; the SQL rule ignores the request URL's `Query()`; label
  identifiers are not credentials; `algorithm` is a whole word; a separator-led nested group is not
  ambiguous; a one-line quoted PEM header is a delimiter, not a key. Test files stay reported (the gate
  already classifies them as background scope).

- **Asset exposure no longer reads every asset as clean.** `exposurereader` filtered an asset's
  vulnerability occurrences by comparing project and fleet-asset ids with SBOM component ids, two id
  namespaces that never match, so the join dropped every occurrence and the asset scored as a
  trustworthy clean (#819). The reader now resolves the engagements that belong to the asset (the ones
  assigned to it, each linked project's analysis context, each linked host's vulnerability context)
  and reads their occurrences directly. With the component inventory wired it abstains when nothing
  was scanned instead of reporting clean.

- **Review fixes on the fleet host and alerting work.** A host whose scan start failed after its package
  set was recorded is scanned on the next sweep instead of being read as unchanged; a windowed detection
  rule ignores events stamped before its span and treats the span as exclusive; alert delivery runs off
  the ingest path with a bounded queue and a per-tenant rate limit, and its error never carries the
  webhook URL; correlation runs asynchronously per engagement and also after provenance reconciliation
  completes detections; host contexts are excluded from business-asset assignment on Postgres, included
  in advisory-revision reconciliation, and pinned to their asset by a RESTRICT foreign key (migration
  0131, which also adds the operator-engagement partial index); the hosts list is five round trips for
  the whole fleet, reads SBOM metadata without the document body and counts findings in one aggregate;
  the latest-scan batch read is one index probe per engagement; the host page receives a finding
  projection instead of full records; `synapse-cli scan --server` requires https unless loopback or
  `--insecure-http`, and validates the project key.

- **OS-package findings carry CVSS.** Distro advisories (Ubuntu, Debian, Alpine) rarely publish a
  CVSS vector of their own; grype puts the NVD vector and score on the related upstream CVE. The
  grype adapter read only the primary record, so every OS-package finding arrived without a vector
  and a risk score of 0. It now falls back to the related records; the advisory's own CVSS still
  wins when present.

### Security

- **Global vulnerability sources now require the platform operator.** The source registry has no
  tenant column and decides which advisories every tenant's detection reads, so mutating it needs
  the bootstrap principal from `SYNAPSE_API_TOKEN` in addition to the administer permission. The
  per-source `allow_private_network` switch also needs a deployment opt-in,
  `SYNAPSE_VULNERABILITY_SOURCE_ALLOW_PRIVATE_NETWORK`, which defaults to off.

- **The bootstrap operator is immutable through user management, including by itself.** Startup
  refreshes that row from `SYNAPSE_API_TOKEN`, so a key rotated through the API authenticated only
  until the next restart while the environment token stopped working in the meantime. Changing the
  variable and restarting is the one path that moves the credential.

- **The static analyzer no longer drops first-party code silently.** Every `.js` under `static/`,
  `assets/` or `public/` was skipped as vendored, which is where a Flask or Django application keeps
  its own scripts, a bare corporate copyright header read as a third-party banner, and a short file
  holding one long constant tripped the minified probe. Both were
  dropped with the report still saying the scan was complete. A web asset in those trees is now
  skipped only when the file itself says third-party: a distributed-library banner, a vendor or build
  directory in its path, or a line long enough to be build output. Files excluded by policy are
  counted in a new `SkippedFiles` field rather than folded into `Truncated`, and the SCA scan turns
  both into a source warning, which nothing consumed before.

- **Two rules stopped matching their highest-signal shape.** `exec.Command(args[0], args[1:]...)`,
  where the binary itself is attacker-controlled, and `w.Write([]byte(s))`, the idiomatic Go response
  write, both fell through the bare-argument pattern because of the subscript and the conversion.

- **Three cross-line false positives are closed.** `||` is logical-or everywhere but SQL and PL/SQL,
  so `opts.sql || DEFAULT_SQL` was reported as SQL injection; the ten-line look-back reached over a
  function boundary and attributed one function's assignment to another's sink; and
  `redirect_to <model>`, the canonical safe Rails idiom, was reported as an open redirect.

- **The bootstrap operator can no longer be seized by a tenant admin.** The bootstrap principal is
  stored with an empty tenant, which normalizes to the default tenant, so it appeared in that
  tenant's roster and its admins could rotate its API key and read the new plaintext from the
  response. That key is the platform principal every global-resource guard tests for. Updating,
  disabling and rotating the bootstrap identity are now refused for anybody but the bootstrap
  principal itself; the credential is owned by `SYNAPSE_API_TOKEN`.

- **The private-network gate now covers every egress path.** Checking it only on create and update
  left the connection test, re-enabling a stored source, and the sync scheduler resolving a source
  row created while the switch was on. The gate now sits in the provider registry, which is the
  single point every caller resolves a source through.

- **The last-admin guard is safe under concurrency.** It counted a tenant's other enabled admins and
  then wrote, so two concurrent demotions each saw the other admin still enabled, both passed, and
  the tenant was left with nobody who could administer it. The count and the write now run in one
  transaction, the roster read takes a row lock, and an in-process mutex serializes a single replica.

- **Request bodies and connection lifetimes are bounded on the human API plane.** Every mutation
  route carries a 1 MiB ceiling, with larger explicit ceilings for the routes that accept an upload:
  source publish, engagement and project creation, coverage upload, bundle import, SARIF, SBOM,
  evidence and OpenVEX. A guard now reads every handler that bounds a body and fails when the
  handler asks for more than its route allows, which is how the OpenVEX gap was found. API listeners now set a write and an idle timeout alongside the
  existing header timeout, and the two server-sent-event handlers release the write deadline so a
  live log stream is not cut off at the listener timeout. The Compose dashboard's nginx gains a
  matching body ceiling and read timeout plus baseline security response headers.

- **An audit entry is written on the caller's transaction.** A business write that rolls back no
  longer leaves a committed audit row claiming it happened. The append runs inside a savepoint, so
  a chain conflict can be retried without aborting the caller's transaction, and the assessment
  cycle paths propagate an audit failure instead of discarding it. The VEX apply and the approval
  decision now run inside one tenant transaction, so a document that retires many findings is
  applied in full or not at all, and an operator is never told a decision failed while it stands.
  `golang.org/x/image` moves to v0.45.0, clearing the one vulnerability govulncheck reported as
  reachable.

- **Database-enforced tenant isolation for the project, quality-gate and agent tables.** `projects`,
  `project_analyses`, `project_analysis_hotspots`, `project_hotspots`, `project_hotspot_review_events`,
  `project_issues`, `project_issue_review_events`, `quality_gates`, `quality_profiles`, `threat_models`,
  `agent_sessions`, `agent_approvals` and `agent_plans` now run under forced Postgres row level
  security, and every repository that touches them routes reads and writes through a tenant-bound
  transaction while keeping an explicit `tenant_id` predicate. Two stores previously dropped the
  tenant predicate when the caller supplied none (project analyses widened to a project-wide read,
  approvals keyed decisions on the action id alone); both now fail closed, and an approval decision
  or consume cannot be applied across tenants. `agent_approvals.tenant_id` and `agent_plans.tenant_id`
  are backfilled from the owning engagement and pinned `NOT NULL`.

  Operators must deploy the binaries before applying migration `0129`, which inverts this project's
  usual migrate-then-deploy order; the migration header states the required sequence.

### Added

- **Operator key revocation and role management.** `PATCH /api/v1/users/{id}` changes a name and
  role, `POST /api/v1/users/{id}/disable` and `/enable` revoke and restore access, and
  `POST /api/v1/users/{id}/rotate-key` issues a new API key and invalidates the previous one. Every
  mutation is audited and requires the `administer` capability. Deleting a user is deliberately not
  offered: an identity owns its audit, evidence, and finding attribution, so access is revoked by
  disabling the account or rotating its key. Disabling or demoting a tenant's last enabled admin is
  refused, so a tenant cannot lock itself out.

- **Deployment capability catalog.** `GET /api/v1/capabilities` reports every optional subsystem
  with a stable key, a human name, whether this deployment enables it, the `SYNAPSE_*` variable that
  controls it, and the capabilities it depends on. An optional subsystem registers its routes only
  when its switch is on, so a disabled subsystem and a broken one previously both answered `404`; a
  client can now render "disabled" and name the switch. The route is gated at the view floor and
  returns configuration booleans and variable names only, never a configured value.

- **Navigation reflects the deployment's capabilities.** The sidebar reads
  `GET /api/v1/capabilities` and renders a subsystem the server reports as off as an inert row
  naming the `SYNAPSE_*` switch that turns it on, rather than a link that answers `404`. A server
  that does not serve the route, or cannot answer it, keeps the previous behaviour of showing
  everything.

- **Project dependency graph and subtree export.** Project analyses now expose a bounded, deterministic
  dependency projection from the stored SBOM with direct/transitive relationships, reverse paths,
  vulnerability matches, license policy risk, and reachability annotations. A new interactive Project
  view supports tree exploration, package/PURL search, risk filters, vulnerable-path highlighting,
  package details, and full or selected-subtree CycloneDX export without changing scan or matching logic.

- **Python Tier-2 semantic reachability and interprocedural taint analysis.** An opt-in, source-only
  tree-sitter sidecar now emits bounded semantic facts without importing or executing target Python;
  pure Go resolution proves affected-symbol call paths and precise value flow across assignments,
  arguments, receivers, and returns. Flask, Django, FastAPI, SQL, command, path, SSRF, XSS,
  deserialization, and redirect models produce gated, propose-only SAST judgments with class-specific
  sanitizers. Scan results distinguish complete, partial, unavailable, and not-applicable coverage;
  confirmed findings retain a bounded source-to-sink trace that SARIF exports as `codeFlows`.

- **Independent signed agent detection delivery.** Confirmed detections now drain from an isolated P1
  WAL lane into crash-recoverable batches, using an agent-owned Ed25519 key registered with
  proof-of-possession. Pending sequence/membership survives restart and lost responses, local records
  are ACKed only after complete server admission, rejected or expiring keys rotate without changing
  the pending batch sequence, and a live-path test covers WAL → HTTP → key resolution → signature and
  content verification → exactly-once evidence sealing.

- **Native amd64 and arm64 eBPF sensor artifacts with capability-based CO-RE probing.** The agent now
  embeds only architecture-matched objects, detects kernel BTF and required network types without
  kernel-version gating, reports unsupported capability as an explicit coverage gap, and validates
  both architectures in a native load/attach workflow. A repository-owned minimal CO-RE header and
  reproducible build target replace the uncommitted, build-host-specific vmlinux.h dependency.

- **Deterministic release evidence and verification.** Release signing now binds the complete asset
  set to its repository, tag, and exact source revision in a signed, provenance-attested manifest.
  The local verifier rejects identity drift, tampered/missing/unlisted assets, non-canonical input,
  unsafe paths, and symlinks; the operator guide separates checksum integrity, publisher signatures,
  and GitHub workflow provenance.

- **Crash-recoverable priority telemetry spool for the host agent.** Normalized eBPF events and
  confirmed detections now enter checksummed, per-priority WAL segments before downstream use. The
  spool resumes sequence incarnations after restart, commits exact-epoch ACKs, evicts only P3 under
  quota pressure, persists queryable gap evidence before any loss, repairs torn/corrupt frames, and
  exports bounded-cardinality depth, oldest-age, eviction, corruption, and fsync metrics. P0–P2 apply
  backpressure instead of silently shedding; A3 will consume the exposed peek/ACK and retry contract.

- **Signed RulePack detection-content lifecycle and deterministic release gates.** Runtime detection
  content can now bind rules, compatibility requirements, ATT&CK mappings, positive/negative replay
  fixtures, per-rule cost budgets, rollout cohorts, and rollback metadata into a canonical signed
  RulePack. The `synapse-cli rulepack verify|replay|gate` release surface pins an external Ed25519 trust
  key and gates candidate, canary, and production promotion on deterministic replay, compatibility,
  retro-hunt completeness, purple/emulation coverage, false-positive quality, required-field
  availability, suppression/disposition rates, detection density, latency, and CPU evidence.

- **Authority-surface precondition on AI-triage promotion.** Evaluation reports record
  `gate_reachable_pairs`, and the promotion boundary requires at least one counterfactual pair the
  deterministic policy could actually exempt (`--minimum-gate-reachable-counterfactual-pairs`,
  default 1). The counterfactual flip-rate criteria are satisfied by a zero numerator, and a corpus
  whose adversarial challenges all sit above a human-review floor produces that zero for every
  candidate; the precondition stops those criteria passing without having measured anything. The
  precondition reports pair counts in dedicated `*_count` failure fields, so the basis-point fields
  of a promotion failure always mean a rate.

- **Operator-owned human approver allowlist on AI-triage releases.** Recording a promotion or rollback
  now requires `--human-approvers`, a private operator-owned allowlist an approver identity must appear
  in. The release manifest names its own PM and Security approvers, so previously the only test of their
  humanness was a reserved machine-prefix denylist, which by construction cannot recognise an identity
  scheme it has never seen; the allowlist admits identities from outside the artifact being validated.
  It is enforced when a decision is admitted, not when stored history is re-validated, so an approver
  leaving the allowlist never invalidates a ledger they already signed.

- **AI-triage escape rate measured against the exemptible population.** Evaluation reports now carry
  `exemptible_true_positives` and `exemptible_escape_rate` alongside the corpus-wide rate, and the
  promotion boundary reads the exemptible denominator. A true positive a human-review floor holds
  back can no longer dilute the safety rate, so a corpus cannot look safer by adding findings the
  gate was never allowed to release. Reports move to `synapse-ai-triage-evaluation-v4`; the default
  zero-basis-point limit is unchanged and behaves identically, while any configured non-zero
  tolerance now applies to the smaller, meaningful denominator and should be re-approved.

- **Gate-reachable adversarial coverage for AI-triage robustness.** The golden dataset now binds
  prompt-injection challenges to controls the deterministic policy could actually exempt, so
  `PolicyFlip` and `UnsafePolicyFlip` measure a non-empty population instead of being pinned to
  `false` by the human-review floor. A regression test proves the metrics are falsifiable — a triager
  that obeys an injection registers an unsafe flip, an honest one does not — and a coverage test
  fails if a future dataset edit leaves no adversarial case able to reach the gate.

### Changed

- **Breaking: engagements and projects serialize in snake_case.** Both aggregates were written to
  the wire straight from their domain structs, so they answered with Go field names (`ID`,
  `TenantID`, `SourceBinding`, `Scope.InScope`, `Audit.CreatedAt`) while scans, analyses, findings,
  and every newer resource answered in snake_case, and a client had to special-case per resource.
  Engagement and project responses now go through explicit view types in the HTTP layer:
  `id`, `tenant_id`, `name`, `client`, `status`, `scope.in_scope[].kind`, `scope.in_scope[].value`,
  `roe`, `authorized_from`, `authorized_to`, `live_recon_enabled`, `source_binding`,
  `default_profile_by_lang`, `gate_id`, and the former nested `Audit` flattened to `created_at` and
  `updated_at`. Go cannot emit two names for one field, so the old keys are gone rather than
  duplicated. Affected routes: `GET|POST /api/v1/engagements`, `GET /api/v1/engagements/{id}`,
  `PATCH /api/v1/engagements/{id}`, `PUT /api/v1/engagements/{id}/status|scope|authorization-window|roe|live-recon`,
  `POST /api/v1/engagements/import`, `GET /api/v1/appsec/assets/{id}/engagements`, and
  `GET|POST /api/v1/projects`, `GET /api/v1/projects/{key}`, `PUT /api/v1/projects/{key}/gate`.
  `api/openapi.yaml` documents the new shape.

- **Workflow-oriented sidebar navigation.** Reorganizes shipped dashboard capabilities around security operations, exposure management, engineering, runtime, and governance; separates engagement creation from the active navigation state; and removes unavailable placeholder destinations.

- **Breaking Asset API consolidation.** Removed `POST|GET /api/v1/assets/services`, `asset.BusinessService`, and the unused `member_of` fleet edge. Business-level Asset reads and writes now use `/api/v1/appsec/assets`; technical/fleet `/api/v1/assets` remains unchanged. Existing business-service rows retain their IDs and owners and receive stable keys during migration.

- Release gates use the owned SBOM engine, provision their pinned Syft and Grype dependencies, and can
  be dispatched manually.

- **`synapse-cli scan --offline` now means no network egress.** It previously dropped only the live
  OSV.dev source while the npm, composer, poetry, Bundler, Maven and Gradle resolvers still reached
  their registries and the KEV/EPSS, online NVD, and deps.dev/PyPI enrichers still made HTTP calls.
  Offline (and `SYNAPSE_OFFLINE=true`) now disables all of them, plus the Maven Central JAR SHA-1
  lookup and AI false-positive triage. Target acquisition is unchanged: a registry image reference or
  a remote git URL is still fetched.

### Fixed

- **The dashboard reads engagements and projects again.** The API moved both resources to
  snake_case (`engagementView` and `projectView` in `internal/adapter/httpapi/resource_view.go`)
  while the web client still mapped Go field names, so against a real server the engagements list
  crashed on an undefined id and every project rendered with a blank name, key and source. The
  client now maps the served keys, the MSW fixtures carry the server's shape, and a contract test
  pins fixture, mapper and mock to the Go view types together.

- **Documented the fleet operator-plane routes.** Fifteen shipped `/api/v1/fleet/*` operations were
  registered by the router but absent from `api/openapi.yaml`, so no generated client could reach
  them: retro-hunt, desired capabilities and their gaps, legal holds, privacy export, endpoint
  processes, the asset state timeline, detection-data deletion, engagement correlation, and incident
  risk reassessment. Each is now described with the parameters, request body, and status codes its
  handler actually produces, including the PascalCase payloads the domain structs serialize.

- **Documented engagement lifecycle route.** `PUT /api/v1/engagements/{id}/status` answered `404`:
  the transition was reachable only as `PATCH /api/v1/engagements/{id}`, which no guide described.
  Both spellings now apply the same change through the same `operate` gate, and both are described
  in `api/openapi.yaml` and the governed-assessments guide.

- **Cross-tenant user management.** `POST /api/v1/users` accepted a `tenant_id` from the request
  body without comparing it with the caller's tenant, so a tenant-A admin could provision an admin
  into tenant B and receive that admin's API key, and `GET /api/v1/users` listed every tenant's
  operators on all three persistence backends. User reads and writes now carry their tenant
  explicitly through the repository port and apply it as a query predicate, independent of row level
  security. Provisioning into another tenant is refused unless the caller is the bootstrap principal
  from `SYNAPSE_API_TOKEN`, the one identity that may seed a new tenant's first admin. The hostile
  tenant-isolation harness now covers both routes.

- Standalone CLI scans bind the default tenant before persisting results.
- Release-signing CI uses the corrected provenance action and uploads the checksum signature once.
- `synapse-cli quality` no longer fails with `unknown code-analysis finding kind` on any tree that
  contains HTML or CSS. The AST language packs report `security` and `maintainability` rule classes,
  which now map to the SAST and quality finding kinds; an unrecognized class degrades to quality
  instead of failing the command.
- `synapse-cli quality --sarif` writes the SARIF report even when `--fail-on` then fails the run, so a
  redirected stdout keeps the findings the non-zero exit is about.

## [0.1.8] - 2026-08-15

This release expanded Synapse from its SCA and code-quality foundation into a governed, multi-pillar
security control plane.

### Added

- Continuous vulnerability-intelligence synchronization, reconciliation, risk assessment, and review.
- Risk-based remediation SLA policy, deterministic deadlines, immutable assessment history, and governed
  `open` / `mitigating` / `remediated` / `accepted_risk` transitions.
- AI false-positive triage with evidence-bound proposals, an independent verifier, human review,
  evaluation datasets, drift detection, promotion/rollback ledgers, and adversarial-invariance gates.
- Asset-centric correlation, unified risk stories, and judgment-gated cross-pillar promotion.
- Read-only AWS, Azure, and Google Cloud posture collection through a sandboxed helper.
- VM and Kubernetes fleet agents, certificate identity, host/cluster inventory, health and coverage views,
  signed work orders, governed response actions, rollout control, and safe decommissioning.
- Runtime detection, retro-hunting telemetry, purple-team coverage, governed adversary emulation, and
  chained exploitation with a fleet-wide kill switch.
- Governed DAST sessions, imported SARIF findings, source-snapshot publishing, JavaScript reachability,
  and additional first-party code-quality language packs.

### Changed

- Engagement creation and scan queueing became separate operations.
- The landing page, primary guides, and release infrastructure were refreshed for the expanded platform.

### Fixed

- AI and triage paths fail closed on malformed, truncated, unverifiable, or self-confirmed model output.
- Fleet, Kubernetes, DAST, reachability, source-snapshot, and web-navigation review findings were closed.
- CI lint and dependency updates restored the complete release gate.

## [0.1.7] - 2026-07-23

### Added

- Standalone RPM/deb package scans extract package payloads before scanning bundled binaries.
- Automatic remote-vs-local acquisition selection for package inputs.

### Changed

- The CI Action and release workflow verify scanner archives and support package artifacts consistently.

## [0.1.6] - 2026-07-23

### Added

- Standalone Python wheel and egg scans catalog package metadata and bundled native binaries.

## [0.1.5] - 2026-07-23

### Added

- Standalone deb scans infer the target distribution so OS-package CVE matching uses the correct release.

## [0.1.4] - 2026-07-23

### Added

- Standalone RPM, deb, and MSI package-file scanning with package-specific metadata extraction.
- Windows amd64 release archives.

### Fixed

- Release artifacts exclude unsupported Windows arm64 builds and use valid workflow identifiers.

## [0.1.3] - 2026-07-23

### Added

- XML injection code-quality rules.

### Changed

- Findings with unknown component versions no longer gate CI unless an advisory explicitly covers an
  unknown version.

### Fixed

- Container-image and finding-handler regressions found during the release review.

## [0.1.2] - 2026-07-22

### Fixed

- Image scans read `.synapseignore` and accepted-risk policy from the CI repository rather than an
  extracted image filesystem.

## [0.1.1] - 2026-07-22

### Fixed

- OS-package advisory matching is scoped to the detected distribution release.
- Release publishing skips the currently disabled Docker-image build.
- GolangCI-Lint passes in the release pipeline.

## [0.1.0] - 2026-07-22

### Added

- Initial tagged release of the deterministic security and code-quality scanner.
- Source and container-image scanning through the reusable GitHub Action.
- SCA, first-party code-quality rules, secrets and IaC checks, SARIF output, and severity-based CI gates.
- Air-gapped scanning of local `docker save` archives and offline NVD CVSS enrichment.

[Unreleased]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.8...HEAD
[0.1.8]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/KKloudTarus/synapse-ce/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/KKloudTarus/synapse-ce/releases/tag/v0.1.0

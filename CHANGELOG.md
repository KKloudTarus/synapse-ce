# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

// Package config loads runtime configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWorkerConcurrency       = 1
	maxWorkerConcurrency           = 64
	defaultFPTriageMaxFindings     = 100
	maxFPTriageMaxFindings         = 1000
	defaultFPTriageConcurrency     = 6
	maxFPTriageConcurrency         = 32
	defaultFPTriageMaxTokens       = int64(1_000_000)
	maxFPTriageMaxTokens           = int64(100_000_000)
	defaultFPTriageCircuitFailures = 5
	maxFPTriageCircuitFailures     = 100
)

// Config holds runtime configuration.
type Config struct {
	HTTPAddr string
	// MetricsEnabled turns on the Prometheus /metrics endpoint on a SEPARATE,
	// uninstrumented, non-bearer-protected listener. Off by default.
	MetricsEnabled bool
	// MetricsAddr is the loopback-by-default listen address for the metrics endpoint.
	MetricsAddr string
	// AccessLogEnabled turns on the single structured access-log event per HTTP
	// request (method, matched route, status, latency, request id). On by default.
	AccessLogEnabled bool
	Environment      string
	LogLevel         string
	SingleTenant     bool

	// APIToken protects all API + UI routes; required (no anonymous access).
	APIToken string
	// OIDCEnabled enables the browser-based OIDC authorization-code BFF flow.
	OIDCEnabled          bool
	OIDCIssuer           string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCFrontendURL      string
	OIDCTenantID         string
	OIDCGroupRoleMapping []string
	OIDCTransactionTTL   time.Duration
	OIDCSessionTTL       time.Duration
	// AUPVersion is the current Acceptable-Use Policy version.
	AUPVersion string
	// AUPFile is where first-run AUP acceptance is recorded (file-backed until Postgres).
	AUPFile string
	// AuditFile is the append-only audit log (file-backed until Postgres).
	AuditFile string
	// DBDSN, when set, enables PostgreSQL persistence; empty = in-memory (dev).
	DBDSN string
	// DBMigrationDSN, when set, is used only for schema migrations and runtime-role grants.
	// It must be a DDL owner credential; DBDSN remains the least-privilege application credential.
	DBMigrationDSN string
	// DBAutoMigrate controls embedded migrations for long-running services. A dedicated
	// synapse-migrate job may own migrations while services rely on readiness instead.
	DBAutoMigrate bool
	// SyftBin is the Syft executable used for SBOM generation (shell-out).
	SyftBin string
	// SBOMProducer selects the SBOM-generation producer: "syft" (default – the pinned
	// binary, full ecosystem coverage + dep-graph edges via CycloneDX) or "ownsbom" (the detection-
	// independent owned per-ecosystem parsers – no third-party scanner, but components-only + Tier-1 ecosystems).
	SBOMProducer string
	// GrypeBin is the Grype executable for the second detection source;
	// missing binary degrades gracefully to OSV-only.
	GrypeBin string
	// GrypeDBDir pins Grype's vulnerability DB to a pre-synced cache directory and
	// disables auto-update (E7/CRA): offline + reproducible scans against a fixed DB
	// build. Empty = Grype's default (online).
	GrypeDBDir string
	// OSVBaseURL overrides the OSV.dev API base (mainly for tests); empty = OSV.dev.
	OSVBaseURL string
	// OSVBulkURL overrides the OSV bulk-data bucket base for the owned-advisory ingester;
	// empty = the public OSV bucket. Mainly for tests/mirrors.
	OSVBulkURL string
	// DepsDevURL overrides the deps.dev API base for license enrichment (tests).
	DepsDevURL string
	// KEVURL / EPSSURL override the CISA KEV feed + FIRST EPSS API (tests); empty = defaults.
	KEVURL  string
	EPSSURL string
	// NVDAPIURL overrides the NVD CVE API base for severity backfill (tests/mirrors); empty =
	// the public NVD API. NVDAPIKey is the optional NVD API key (raises the rate limit so more
	// unknown-severity CVEs are backfilled per scan); NEVER logged. NVDBudget
	// caps the per-scan time the backfill may spend (best-effort); raise it (with a key) to
	// resolve more of a large unknown set.
	NVDAPIURL string
	NVDAPIKey string
	NVDBudget time.Duration
	// ScanTimeout bounds a single SCA scan; 0 disables.
	ScanTimeout time.Duration
	// ProjectAnalysisCompletionTimeout bounds immutable Project snapshot persistence
	// after a scan completes. It must remain positive even when scan timeout is disabled.
	ProjectAnalysisCompletionTimeout time.Duration
	// FindingMinSeverity is the lowest vuln severity promoted to a finding.
	FindingMinSeverity string
	// IgnoreUnfixed, when true, does NOT promote vulnerabilities that have no available fix
	// (FixedVersion empty – not-fixed / wont-fix / deferred) to findings, matching Trivy's
	// --ignore-unfixed. Default false (show everything); they remain in the vuln inventory.
	IgnoreUnfixed bool
	// Offline, when true, omits detection sources that require network egress (the live OSV.dev
	// source), running only offline sources – Grype's pre-synced DB and the owned advisory store.
	// Trades some recall for a fast, air-gapped scan (no live HTTP per scan). Default false.
	Offline bool
	// MaxWorkspaceBytes caps the total size of a prepared SCA workspace: the
	// acquirer rejects a target whose files exceed it. <=0 keeps the 2 GiB default.
	MaxWorkspaceBytes int64
	// ProjectUploadDir retains uploaded Project source archives for repeat analysis.
	ProjectUploadDir string
	// ProjectSourceArtifactDir retains immutable, analysis-owned Code source snapshots.
	// It must be operator-owned; source contents are never fetched again at read time.
	ProjectSourceArtifactDir  string
	ProjectSourceRetention    time.Duration
	ProjectSourceMaxFileBytes int64
	ProjectSourceMaxFiles     int
	ProjectSourceMaxBytes     int64
	// ProjectGitComparisonDepth bounds history fetched to resolve an immutable
	// Code comparison base; comparison degrades gracefully when insufficient.
	ProjectGitComparisonDepth int
	// Evidence artifact blob store: when BlobEndpoint is set, artifacts go to
	// MinIO/S3; empty = in-memory (dev). Bucket defaults to synapse-evidence.
	BlobEndpoint  string
	BlobAccessKey string
	BlobSecretKey string
	BlobBucket    string
	BlobUseSSL    bool
	// Recon: bounds for the argv ToolRunner + worker pool. Timeout
	// kills a run; MaxOutput caps captured stdout/stderr; Concurrency/QueueSize size
	// the bounded pool that replaces the P1 bare goroutine.
	ReconTimeout     time.Duration
	ReconMaxOutput   int
	ReconConcurrency int
	ReconQueueSize   int
	// ReconAllowCapabilitySensitive permits capability-sensitive tools (naabu – raw
	// sockets) to run. Default false: they stay behind the sandbox.
	ReconAllowCapabilitySensitive bool
	// EvidenceSigningSeed is the ed25519 seed (64 hex chars or base64 of 32 bytes)
	// used to attest evidence chain heads (non-repudiation). Empty = an ephemeral
	// key is generated per start (attestations still self-verify, but the key id is not
	// stable across restarts). Never logged.
	EvidenceSigningSeed string
	// TSAURL is an RFC-3161 timestamp authority. When set, verified evidence +
	// audit chain heads are externally anchored (tamper-PROOF), out-of-band so report
	// bytes are unchanged. Empty = signed-but-not-externally-anchored (tamper-evident).
	TSAURL string
	// SandboxEnabled selects the bubblewrap SandboxRunner for tool execution. When
	// true on a host without bubblewrap, startup FAILS CLOSED (never silently runs
	// unsandboxed). Default false. NOTE: the sandbox is egress default-deny until the
	// scope-derived allowlist lands, so network recon tools won't reach targets
	// until then. SandboxMemMax/PidsMax are the per-run cgroup limits (via systemd-run).
	SandboxEnabled bool
	SandboxMemMax  int64
	SandboxPidsMax int
	// ToolHashes are operator-supplied authoritative sha256 pins for tool binaries,
	// format "name=hex,/abs/path=hex,…". When set, the SandboxRunner refuses to execute a
	// binary whose hash does not match its pin – closing the initial-supply-chain gap that
	// trust-on-first-use alone cannot (TOFU only detects post-first-run replacement). Empty
	// = TOFU only. Parsed from SYNAPSE_TOOL_HASHES.
	ToolHashes map[string]string
	// DAST authenticated scan execution ceilings. Per-run values may only lower these.
	DASTHelperBin    string
	DASTMaxReauth    int
	DASTRatePerSec   int
	DASTConcurrency  int
	DASTMaxDepth     int
	DASTMaxPages     int
	DASTMaxRequests  int
	DASTMaxWallClock time.Duration
	// VaultMasterKey is the AES-256 master key for the credential vault: 64 hex
	// chars or base64 of 32 bytes. Empty = an ephemeral key (dev only; stored secrets do
	// not survive restart). Required in production. Never logged.
	VaultMasterKey string
	// ReconViaWorker routes recon runs through the durable queue: the API enqueues
	// and the non-root synapse-worker claims and executes them. Scoped egress is
	// configured by a separate root-owned broker. Requires Postgres. Default false
	// = the API runs recon in-process (dev).
	ReconViaWorker bool
	// EgressBrokerSocket is the root-owned scoped-egress broker Unix socket. The
	// non-root worker is only a protocol client and receives no network-admin capabilities.
	EgressBrokerSocket string
	// EgressGrantAuthorityAddr is the private control-plane listener used only for
	// machine-authenticated egress grant issuance. It is separate from human API/AUP auth.
	EgressGrantAuthorityAddr string
	// EgressGrantAuthorityURL and EgressGrantAuthorityToken configure the worker's
	// machine-only grant client. The token must not reuse the human bootstrap API token.
	EgressGrantAuthorityURL   string
	EgressGrantAuthorityToken string
	// EgressGrantIssuerToken authenticates workers to the private issuer listener.
	// EgressGrantSigningSeed is a dedicated Ed25519 seed and must not reuse evidence signing.
	EgressGrantIssuerToken string
	EgressGrantSigningSeed string
	// ToolExecutionMode is the explicit process execution posture. Empty selects a
	// role- and environment-safe default in ResolveToolExecution.
	ToolExecutionMode string
	// AgentEnabled turns on the AI orchestrator. Default false (fail-safe): no
	// LLM is contacted and no agent endpoints are active unless explicitly enabled.
	AgentEnabled bool
	// LLM provider: OpenAI-compatible Chat Completions. BaseURL defaults to
	// the LLM gateway; APIKey is a Bearer token (NEVER logged);
	// Model is the provider model id. Empty BaseURL + AgentEnabled fails closed at wiring.
	LLMBaseURL string
	LLMAPIKey  string
	LLMModel   string
	// LLMProvider is an explicit audit identity, not a value inferred from the URL. A gateway may
	// route several providers and distinct URLs may still address the same provider.
	LLMProvider string
	LLMTimeout  time.Duration

	// FPTriageEnabled turns on opt-in LLM false-positive analysis. A proposer may mark a finding
	// suspected-FP, but it remains advisory unless a distinct verifier agrees and the deterministic
	// human-review floor permits a gate exemption. High/critical, secrets, and dangerous CWEs always gate.
	// Off by default; needs an LLM.
	// FPTriageModel is the model to critique with (defaults to LLMModel).
	FPTriageEnabled bool
	FPTriageModel   string
	// FPTriageProvider defaults to LLMProvider but may identify a provider routed specifically for
	// the triage proposer model.
	FPTriageProvider string
	// FPTriageMode is shadow|enforce. Shadow is the fail-closed default: decisions are persisted for
	// evaluation but can never set gate_exempt. Enforce requires a deliberate operator choice.
	FPTriageMode               string
	FPTriageMaxFindings        int
	FPTriageConcurrency        int
	FPTriageMaxTokens          int64
	FPTriageMaxCostMicroUSD    int64
	FPTriageProposerInputRate  int64
	FPTriageProposerOutputRate int64
	FPTriageVerifierInputRate  int64
	FPTriageVerifierOutputRate int64
	FPTriageCircuitFailures    int
	FPTriageCircuitCooldown    time.Duration
	FPTriageAlertMinSamples    int
	FPTriageDisagreeBaseBPS    int
	FPTriageExemptBaseBPS      int
	FPTriageParseFailBaseBPS   int
	FPTriageAlertDeltaBPS      int
	// FPTriageIndependence is model_family (default) or provider. Provider mode additionally
	// requires a different explicit provider identity; invalid values disable verifier authority.
	FPTriageIndependence string

	// Agent orchestration policy. ApprovalMode: manual|filter|auto (manual is
	// the safe default – a human approves every action). The rest bound a run.
	AgentApprovalMode    string
	AgentApprovalTimeout time.Duration
	AgentMaxSteps        int
	AgentTokenBudget     int
	AgentMaxDuration     time.Duration

	// Agent runtime/ops. DB pool sizing (the durable agent path
	// holds a connection-bearing advisory lock per active run, so the pool must be sized).
	DBMaxConns        int
	DBMinConns        int
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration
	// AgentViaWorker routes agent runs to synapse-worker durably (requires ReconViaWorker +
	// Postgres); else the API runs them inline-bounded. Concurrency/QueueDepth bound admission
	// (backpressure → 503). ApprovalSweepInterval drives the prod timeout sweeper. MaxParallel
	// caps in-flight plan nodes (P5). ReconConcurrency sizes the agent's dedicated recon pool.
	// PromotionReconcileInterval schedules server-only recovery of confirmed promotions and audits.
	AgentViaWorker             bool
	AgentConcurrency           int
	AgentQueueDepth            int
	AgentMaxParallel           int
	AgentReconConcurrency      int
	ApprovalSweepInterval      time.Duration
	PromotionReconcileInterval time.Duration

	// JudgmentsEnabled turns on the AI judgment lifecycle HTTP routes; off by default.
	JudgmentsEnabled bool
	// FleetAssetsEnabled turns on the multi-tenant fleet asset model (assets, edges, business
	// services) and its HTTP routes; off by default. When on with Postgres, startup refuses to
	// serve unless the DB role can enforce Row Level Security (not SUPERUSER/BYPASSRLS).
	FleetAssetsEnabled bool
	// CSPM enables read-only live cloud posture connectors. Providers is an allowlist;
	// Rate is requests per second, with zero selecting provider defaults.
	CSPMEnabled     bool
	CSPMProviders   []string
	CSPMRate        int
	CSPMEgressHosts []string
	CSPMHelperBin   string
	// Attack-path traversal is bounded by length, retained paths per target, and wall clock.
	AttackPathMaxLen    int
	AttackPathMaxPaths  int
	AttackPathWallClock time.Duration
	// FleetEnabled turns on the agent-facing transport (#409: enrol/heartbeat/work) plus the
	// operator agent-admin routes; off by default. When on with Postgres, startup fails closed
	// unless the DB role can enforce RLS.
	FleetEnabled bool
	// FleetClusterIngestEnabled turns on the cluster-inventory ingest endpoint (#446), where an agent
	// POSTs a Kubernetes snapshot that is persisted into the asset model. Off by default. It requires
	// both FleetEnabled (transport) and FleetAssetsEnabled (persistence); it is a no-op otherwise.
	FleetClusterIngestEnabled bool
	// FleetHostIngestEnabled turns on the host-inventory ingest endpoint (#446), where a VM agent POSTs
	// its collected host inventory (facts + packages + coverage) to be persisted as a Kind=host asset.
	// Off by default; requires FleetEnabled + FleetAssetsEnabled.
	FleetHostIngestEnabled bool
	// FleetTelemetryIngestEnabled turns on the agent→control-plane telemetry batch ingest endpoint
	// (A3, #624): an enrolled agent ships a signed TelemetryBatchManifest which the control plane verifies
	// (identity + signing key + schema, fail-closed), sequences idempotently, and acks. Off by default;
	// requires FleetEnabled.
	FleetTelemetryIngestEnabled bool
	// FleetDetectionIngestEnabled turns on the agent→control-plane detection batch ingest endpoint (A4,
	// #625): an enrolled agent ships a signed AgentBatch which the control plane verifies (identity +
	// signing key + per-detection content digest, fail-closed) and seals once into the evidence chain.
	// Off by default; requires FleetEnabled.
	FleetDetectionIngestEnabled bool
	// FleetKeyRegistrationEnabled turns on the agent-plane signing-key registration endpoint plus the
	// operator key management routes (A4, #625, A0.2): an agent registers its Ed25519 signing key with a
	// proof-of-possession. Off by default; requires FleetEnabled.
	FleetKeyRegistrationEnabled bool
	// FleetAgentStaleAfter is how long since an agent's last heartbeat before it is reported stale in
	// the coverage/agent-health views (#413, SYNAPSE_FLEET_STALE_AFTER). <=0 disables the staleness
	// check. Default 10m, per the issue spec.
	FleetAgentStaleAfter time.Duration
	// FleetCoverageFreshnessTarget is the default per-capability freshness target (#413): an assessment
	// older than this is reported stale, not covered. <=0 means no freshness requirement. Default 24h.
	FleetCoverageFreshnessTarget time.Duration
	// FleetMinAgentVersion is the minimum supported agent version (#412 version skew). An agent whose
	// reported version is below it is refused work with an instruction to update. Empty = no floor. A
	// malformed value is treated as no floor (a config typo must not brick the fleet). Parsed loosely
	// as major.minor.patch (see domain/fleetversion).
	FleetMinAgentVersion string
	// FleetSignerKey is the HMAC key that signs agent work orders. Required and at least 32 bytes
	// when FleetEnabled; a missing/short key fails startup closed rather than boot a forgeable signer.
	FleetSignerKey string
	// FleetCACertPEM / FleetCAKeyPEM are the control-plane CA that issues agent client certificates
	// (#408). When both are set and FleetEnabled, enrolment with a CSR returns a client certificate.
	FleetCACertPEM string
	FleetCAKeyPEM  string
	// FleetCertTTL is the issued client certificate lifetime (default 720h).
	FleetCertTTL time.Duration
	// FleetClientCertHeader, when set, is the header a trusted mutual-TLS-terminating proxy uses to
	// pass the verified client certificate to the agent plane. Empty = certificate auth disabled
	// (bearer token only). Trust it ONLY behind a proxy that strips any client-supplied value.
	FleetClientCertHeader string
	// LeaderElectionEnabled runs the fenced-lease leader elector (#406). Off by default. Postgres
	// only (a single in-memory process is trivially the leader). Renewing < Term/2 is enforced.
	LeaderElectionEnabled bool
	// LeaderResource is the lease key elected over (default "scheduler").
	LeaderResource string
	// LeaderTerm is the lease term; LeaderRenew is the renewal interval (must be < Term/2).
	LeaderTerm  time.Duration
	LeaderRenew time.Duration
	// WorkerConcurrency is the number of durable-queue claim loops in one synapse-worker process.
	WorkerConcurrency int
	// VulnerabilitySchedulerEnabled dispatches due vulnerability-source syncs and recovers stale
	// runs. Postgres deployments must also enable fenced leader election to prevent duplicate work.
	VulnerabilitySchedulerEnabled      bool
	VulnerabilitySchedulerPollInterval time.Duration
	VulnerabilitySchedulerStaleAfter   time.Duration
	VulnerabilitySchedulerJitter       int
	VulnerabilitySchedulerDispatch     int
	VulnerabilitySchedulerQueueDepth   int
	VulnerabilitySchedulerRecovery     int
	// Vulnerability rollout gates default off. Tenant-scoped mutations additionally require
	// an explicit tenant allowlist entry; "*" enables all tenants. Dry-run records correlation
	// differences without mutating occurrences, findings, actions, or notification outbox rows.
	VulnerabilityProviderSyncEnabled      bool
	VulnerabilityOccurrenceWritesEnabled  bool
	VulnerabilityFindingProjectionEnabled bool
	VulnerabilityActionsEnabled           bool
	VulnerabilityNotificationsEnabled     bool
	VulnerabilityDryRunEnabled            bool
	VulnerabilityTenantAllowlist          []string
	// SLAEnabled turns on durable risk-based remediation deadlines, versioned tenant policy, and
	// human lifecycle APIs. Default false until an operator explicitly opts into the new schema/path.
	SLAEnabled bool
	// SASTEnabled turns on the deterministic pattern-SAST analyzer in the scan pipeline; off by default.
	SASTEnabled bool
	// SecretScanEnabled turns on the deterministic secret scanner in the scan pipeline; off by default.
	// It reads workspace files and redacts every match, so nothing sensitive reaches logs or the report.
	SecretScanEnabled bool
	// MisconfigEnabled turns on the deterministic IaC/config misconfig scanner (Dockerfile, Kubernetes
	// manifests) in the scan pipeline; off by default. Read-only, first-party checks, no policy engine.
	MisconfigEnabled bool
	// SuppressionEnabled turns on the repo-committed .synapseignore accepted-risk policy; off by default.
	// Suppressed findings are always retained + surfaced in the result, never silently dropped.
	SuppressionEnabled bool
	// VEXEnabled turns on consuming an in-repo OpenVEX doc (.synapse.vex.json) at scan time; off by default.
	// A not_affected/fixed statement gate-exempts the matched finding (still reported + sealed), never removes it.
	VEXEnabled bool
	// ComplianceEnabled attaches the owned AppSec-baseline benchmark (per-control PASS/FAIL over the scan's
	// findings, LLM-free) to each scan result; off by default.
	ComplianceEnabled bool
	// DetectionPriority is the default vulnerability detection priority: "comprehensive" (default; every
	// detected vuln is actionable) or "precise" (single-source, non-KEV vulns are quarantined into a
	// needs-verify queue – reported + sealed, exempt from the --fail-on gate). Empty = comprehensive.
	DetectionPriority string
	// DBMaxAgeDays warns (non-fatal, SourceWarning) when a dated reference DB (CISA KEV / EPSS catalog, or a
	// pinned vuln DB) is older than this many days – so a scan on stale advisory data can't silently
	// under-report (Trivy uses a stale DB silently). 0 disables the check.
	DBMaxAgeDays int
	// ScanCacheEnabled turns on the content-addressed generated-SBOM and AI-triage caches. An SBOM hit
	// skips cataloging; an AI hit reuses only typed claims and still reapplies policy + seals new evidence.
	ScanCacheEnabled bool
	// ScanCacheDir is where cached scan artifacts live when ScanCacheEnabled. Empty preserves the existing
	// "synapse-sbom" per-user default; AI claims use its own owner-only subdirectory. It MUST be
	// operator-owned and not writable by untrusted users: cache poisoning could create a false negative.
	ScanCacheDir string
	// ImageRootFSEnabled materializes a container image's assembled root filesystem from the pulled OCI
	// layout (applying layers + whiteouts), so the owned parsers can read on-disk OS-package DBs and
	// /etc/os-release. Off by default; extraction is hardened but adds disk + time to an image scan.
	ImageRootFSEnabled bool
	// OwnedAdvisoryEnabled wires the owned advisory DetectionSource: match the SBOM
	// against the owned normalized-advisory store (offline, reproducible) ALONGSIDE live OSV/Grype. Off by
	// default; opt-in. An empty store yields no findings (a harmless no-op) until the advisory ingester
	// populates it – so enabling it without a populated store changes nothing.
	OwnedAdvisoryEnabled bool
	// ReachabilityEnabled turns on deterministic Tier-2 call-graph reachability proof: post-scan,
	// it proves which findings' affected symbols are actually called and mints Tier-2 judgments that
	// supersede weaker LLM claims. Off by default; opt-in + best-effort (a no-coverage/un-buildable target
	// leaves the prior tier standing). GovulncheckBin is the pinned builder binary.
	ReachabilityEnabled bool
	GovulncheckBin      string

	// PyReachabilityEnabled turns on deterministic Tier-1 Python import-reachability: post-scan, it mints a
	// not_reachable judgment for a declared PyPI package that first-party code never imports (a dead
	// dependency) → an OpenVEX not_affected justification. Weaker than the Go Tier-2 call-graph proof
	// (import-level, not a reached call path). Off by default; opt-in + best-effort (a non-Python /
	// dynamic-import / no-coverage target leaves the prior tier standing, never a false "not reachable").
	// Also requires the judgment lifecycle (SYNAPSE_JUDGMENTS_ENABLED).
	PyReachabilityEnabled bool

	// JSReachabilityEnabled turns on deterministic Tier-1 JavaScript/TypeScript import-reachability: a
	// declared npm dependency that first-party source never imports becomes not_reachable, which the
	// export path turns into an OpenVEX not_affected justification. Source-only (nothing is executed or
	// installed), best-effort and opt-in, and it answers only for DIRECT dependencies because a
	// first-party import graph cannot prove a transitive package unused. Also requires the judgment
	// lifecycle (SYNAPSE_JUDGMENTS_ENABLED).
	JSReachabilityEnabled bool

	// JSSymbolReachabilityEnabled turns on the TIER-2 JavaScript/TypeScript pass: not "is this package
	// imported" but "is the affected EXPORT reached". It is a strictly stronger and strictly more
	// dangerous claim — a wrong negative suppresses a real vulnerability — so it is separately gated and
	// refuses to answer whenever a binding escapes observation.
	JSSymbolReachabilityEnabled bool

	// RustReachabilityEnabled, PHPReachabilityEnabled and RubyReachabilityEnabled turn on deterministic
	// Tier-1 import-reachability for those ecosystems: a declared dependency that first-party source
	// never references becomes not_reachable, which the export path turns into an OpenVEX not_affected
	// justification. All are source-only (nothing is executed, installed or resolved over the network),
	// best-effort and opt-in, and each refuses a verdict whenever a dynamic construct could hide a
	// reference. All require the judgment lifecycle (SYNAPSE_JUDGMENTS_ENABLED).
	RustReachabilityEnabled bool
	PHPReachabilityEnabled  bool
	RubyReachabilityEnabled bool
	// TaintCallgraphBin is the pinned synapse-callgraph binary: the sandboxed go/ssa call-graph builder
	// the taint analyzer shells out to. In-repo cmd (built by `make build` into bin/); pin its hash via
	// SYNAPSE_TOOL_HASHES, like any other tool binary.
	TaintCallgraphBin string
	// TaintEnabled turns on deterministic taint-analysis CapSAST proposals: post-scan, build the
	// workspace call graph, assemble the taint FlowGraph over the injection catalog, and PROPOSE gated
	// CapSAST judgments for a distinct verifier to gate. Off by default; opt-in + best-effort. Requires
	// JudgmentsEnabled (it mints judgments) AND the SCA sandbox (it compiles untrusted target source).
	TaintEnabled bool
	// GoModGraphEnabled turns on transitive Go dependency-edge resolution via `go mod graph`:
	// post-SBOM, add pkg:golang edges between existing components (go.mod alone has no edge graph). Off by
	// default; opt-in + best-effort (a non-Go target / no module cache adds no edges, never fails the scan).
	// GoBin is the go executable. Low-risk (go mod graph only reads go.mod files, never compiles the target).
	GoModGraphEnabled bool
	GoBin             string
	// MavenResolveEnabled turns on full Maven dependency-tree resolution via `mvn dependency:list`
	// (best-effort + opt-in): a from-source Maven scan otherwise sees only direct deps with UNKNOWN
	// (parent-BOM-managed) versions and no transitive tree, under-reporting vs a build-artifact scan.
	// Off by default – it runs the Maven toolchain over untrusted project config + reaches the Maven
	// repo, so production MUST run it sandbox-confined. MvnBin is the mvn executable.
	MavenResolveEnabled bool
	MvnBin              string
	// MavenRepoHosts are extra Maven-repository hosts (comma-separated) the sandboxed resolver may reach
	// beyond Maven Central – e.g. a corporate mirror or the Apache plugin repo. Empty = Central only.
	MavenRepoHosts []string
	// MavenLocalRepo pins Maven's local repository to a PERSISTENT dir so the resolved tree is cached
	// across scans instead of re-downloaded. Empty = ephemeral (under the sandbox tmpfs HOME).
	MavenLocalRepo string
	// GradleResolveEnabled turns on full Gradle dependency-tree resolution via `gradle dependencies`
	// (best-effort + opt-in). HIGHER risk than Maven – evaluating build.gradle runs arbitrary build
	// logic – so production MUST run it sandbox-confined and it never invokes the project's./gradlew.
	// GradleBin is the pinned gradle executable; GradleHome is an optional persistent GRADLE_USER_HOME
	// cache. MavenRepoHosts (above) extends the egress allow-list for both resolvers (shared JVM repos).
	GradleResolveEnabled bool
	GradleBin            string
	GradleHome           string
	// NPMResolveEnabled turns on npm dependency resolution via `npm install --package-lock-only` for a
	// package.json with no committed lockfile (best-effort + opt-in). It runs --ignore-scripts (no project
	// code executes) against a throwaway copy, but reaches the registry, so production MUST run it
	// sandbox-confined. NPMBin is the pinned npm executable; NPMRegistryHosts extends the egress allow-list.
	NPMResolveEnabled bool
	NPMBin            string
	NPMRegistryHosts  []string
	// ManifestResolveEnabled turns on lockfile-less manifest resolution for composer.json / Gemfile /
	// pyproject.toml via each ecosystem's own lock tool (no scripts). Reaches the registry, so production
	// MUST run it sandbox-confined. Bins default to composer/bundle/poetry; ManifestRegistryHosts extends
	// the egress allow-list (private mirror).
	ManifestResolveEnabled bool
	ComposerBin            string
	BundleBin              string
	PoetryBin              string
	ManifestRegistryHosts  []string
	// JVMReachabilityEnabled turns on coarse JVM class-reachability tagging: after resolving the
	// dependency tree, tag each component with whether the app's own compiled classes (transitively)
	// reference its classes, so a finding on an unreferenced dependency can be deprioritized. Read-only
	// bytecode parsing (no exec); best-effort + opt-in; never emits "unreferenced" for a not-built target.
	JVMReachabilityEnabled bool
	// JarHashOnlineEnabled turns on SHA-1 coordinate recovery for shaded/metadata-less JARs
	// via an EGRESS call to Maven Central's SHA-1 search API. Recovers CVEs for JARs whose in-file
	// identity was stripped. Off by default (it reaches the network); best-effort + rate-limit disciplined.
	// JarHashBaseURL overrides the search endpoint (tests/mirrors); empty = search.maven.org.
	// JarHashDBPath points at a local trivy-java-db-format SQLite index: OFFLINE SHA-1
	// coordinate recovery, no rate limit, air-gap friendly. When BOTH are set, the offline DB is tried
	// first and the online API is the fallback for its misses. Empty = no offline DB.
	JarHashOnlineEnabled bool
	JarHashBaseURL       string
	JarHashDBPath        string
	// CrossCheckEnabled turns on cross-check disagreement judgments: post-scan, where the run
	// detection sources disagree on a vuln, mint an ungated CapCorrelation judgment for human review. Off by
	// default; opt-in + best-effort. Requires JudgmentsEnabled (it mints judgments).
	CrossCheckEnabled bool
	// SBOMCrossCheckEnabled turns on SBOM-PRODUCER cross-check judgments: a 2nd SBOM producer runs
	// alongside the primary and components only one producer emits are minted as ungated CapCorrelation
	// judgments (subject = component) for human review. Off by default; opt-in + best-effort. Requires
	// JudgmentsEnabled (it mints judgments).
	SBOMCrossCheckEnabled bool
	// WriteupDraftsEnabled turns on the propose_writeup_draft agent tool: the agent can DRAFT a
	// finding's write-up prose as a proposal; a human edits/signs off out of band. Off by default; opt-in.
	// Requires AgentEnabled (the tool is advertised only on the agent catalog).
	WriteupDraftsEnabled bool
	// The verifier may use an independent endpoint, credential, provider, and model. Endpoint/key
	// default to the proposer transport for backwards compatibility; the key is never logged.
	VerifierBaseURL  string
	VerifierAPIKey   string
	VerifierProvider string
	VerifierModel    string

	// MeasureCursorSecret is the HMAC-SHA256 key used to sign pagination cursors for
	// the Measures API. Must be at least 32 bytes (hex or raw). Never logged.
	// Required in production; in development an ephemeral key is generated.
	MeasureCursorSecret string

	// MCP server: exposes the agent tool catalog to external MCP clients,
	// bearer-locked (role "mcp") and pinned to one engagement. Token is never logged.
	MCPToken        string
	MCPAddr         string
	MCPEngagementID string
}

// Load reads configuration from environment variables with sane defaults.
func Load() Config {
	maxReauth := getint("SYNAPSE_DAST_MAX_REAUTH", 2)
	ratePerSec := getint("SYNAPSE_DAST_RATE_PER_SEC", 5)
	concurrency := getint("SYNAPSE_DAST_CONCURRENCY", 4)
	maxDepth := getint("SYNAPSE_DAST_MAX_DEPTH", 8)
	maxPages := getint("SYNAPSE_DAST_MAX_PAGES", 2000)
	maxRequests := getint("SYNAPSE_DAST_MAX_REQUESTS", 20000)
	maxWallClock := getduration("SYNAPSE_DAST_MAX_WALL_CLOCK", 30*time.Minute)
	if maxReauth < 0 || maxReauth > 2 || ratePerSec < 1 || ratePerSec > 5 || concurrency < 1 || concurrency > 4 || maxDepth < 1 || maxDepth > 8 || maxPages < 1 || maxPages > 2000 || maxRequests < 1 || maxRequests > 20000 || maxWallClock < time.Second || maxWallClock > 30*time.Minute {
		maxReauth, ratePerSec, concurrency, maxDepth, maxPages, maxRequests, maxWallClock = 2, 5, 4, 8, 2000, 20000, 30*time.Minute
	}
	scanTimeout := getduration("SYNAPSE_SCAN_TIMEOUT", 10*time.Minute)
	completionTimeout := scanTimeout
	if completionTimeout <= 0 {
		completionTimeout = time.Minute
	}
	completionTimeout = getduration("SYNAPSE_PROJECT_ANALYSIS_COMPLETION_TIMEOUT", completionTimeout)
	if completionTimeout <= 0 {
		completionTimeout = time.Minute
	}
	return Config{
		HTTPAddr:                         getenv("SYNAPSE_HTTP_ADDR", ":8080"),
		MetricsEnabled:                   getbool("SYNAPSE_METRICS_ENABLED", false),
		MetricsAddr:                      getenv("SYNAPSE_METRICS_ADDR", "127.0.0.1:9090"),
		AccessLogEnabled:                 getbool("SYNAPSE_ACCESS_LOG_ENABLED", true),
		Environment:                      normalizeEnv(getenv("SYNAPSE_ENV", "development")),
		LogLevel:                         getenv("SYNAPSE_LOG_LEVEL", "info"),
		SingleTenant:                     getbool("SYNAPSE_SINGLE_TENANT", true),
		APIToken:                         getenv("SYNAPSE_API_TOKEN", ""),
		OIDCEnabled:                      getbool("SYNAPSE_OIDC_ENABLED", false),
		OIDCIssuer:                       getenv("SYNAPSE_OIDC_ISSUER", ""),
		OIDCClientID:                     getenv("SYNAPSE_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:                 getenv("SYNAPSE_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:                  getenv("SYNAPSE_OIDC_REDIRECT_URL", ""),
		OIDCFrontendURL:                  getenv("SYNAPSE_OIDC_FRONTEND_URL", ""),
		OIDCTenantID:                     getenv("SYNAPSE_OIDC_TENANT_ID", ""),
		OIDCGroupRoleMapping:             splitList(getenv("SYNAPSE_OIDC_GROUP_ROLE_MAPPING", "")),
		OIDCTransactionTTL:               getduration("SYNAPSE_OIDC_TRANSACTION_TTL", 10*time.Minute),
		OIDCSessionTTL:                   getduration("SYNAPSE_OIDC_SESSION_TTL", 8*time.Hour),
		AUPVersion:                       getenv("SYNAPSE_AUP_VERSION", "1.0"),
		AUPFile:                          getenv("SYNAPSE_AUP_FILE", "data/aup-accepted.json"),
		AuditFile:                        getenv("SYNAPSE_AUDIT_FILE", "data/audit.jsonl"),
		DBDSN:                            getenv("SYNAPSE_DB_DSN", ""),
		DBMigrationDSN:                   getenv("SYNAPSE_DB_MIGRATION_DSN", ""),
		DBAutoMigrate:                    getbool("SYNAPSE_DB_AUTO_MIGRATE", true),
		SyftBin:                          getenv("SYNAPSE_SYFT_BIN", "syft"),
		SBOMProducer:                     getenv("SYNAPSE_SBOM_PRODUCER", "syft"),
		GrypeBin:                         getenv("SYNAPSE_GRYPE_BIN", "grype"),
		GrypeDBDir:                       getenv("SYNAPSE_GRYPE_DB_DIR", ""),
		OSVBaseURL:                       getenv("SYNAPSE_OSV_URL", ""),
		OSVBulkURL:                       getenv("SYNAPSE_OSV_BULK_URL", ""),
		DepsDevURL:                       getenv("SYNAPSE_DEPSDEV_URL", ""),
		KEVURL:                           getenv("SYNAPSE_KEV_URL", ""),
		EPSSURL:                          getenv("SYNAPSE_EPSS_URL", ""),
		NVDAPIURL:                        getenv("SYNAPSE_NVD_API_URL", ""),
		NVDAPIKey:                        getenv("SYNAPSE_NVD_API_KEY", ""),
		NVDBudget:                        getduration("SYNAPSE_NVD_BUDGET", 20*time.Second),
		ScanTimeout:                      scanTimeout,
		ProjectAnalysisCompletionTimeout: completionTimeout,
		// Promote EVERY detected vulnerability by default (info = lowest rank), matching
		// Grype/Trivy/OSV-Scanner – a higher floor silently hides detected vulns and reads as
		// "missing vulns". Prioritization is done by risk priority (KEV→EPSS×CVSS), not by
		// dropping findings; raise this floor explicitly to trim a report's actionable set.
		FindingMinSeverity:        getenv("SYNAPSE_FINDING_MIN_SEVERITY", "info"),
		IgnoreUnfixed:             getbool("SYNAPSE_IGNORE_UNFIXED", false),
		Offline:                   getbool("SYNAPSE_OFFLINE", false),
		MaxWorkspaceBytes:         getint64("SYNAPSE_MAX_WORKSPACE_BYTES", 2<<30),
		ProjectUploadDir:          getenv("SYNAPSE_PROJECT_UPLOAD_DIR", "data/project-uploads"),
		ProjectSourceArtifactDir:  projectSourceArtifactDir(),
		ProjectSourceRetention:    getduration("SYNAPSE_PROJECT_SOURCE_RETENTION", 90*24*time.Hour),
		ProjectSourceMaxFileBytes: getint64("SYNAPSE_PROJECT_SOURCE_MAX_FILE_BYTES", 2<<20),
		ProjectSourceMaxFiles:     getint("SYNAPSE_PROJECT_SOURCE_MAX_FILES", 10_000),
		ProjectSourceMaxBytes:     getint64("SYNAPSE_PROJECT_SOURCE_MAX_BYTES", 500<<20),
		ProjectGitComparisonDepth: getint("SYNAPSE_PROJECT_GIT_COMPARISON_DEPTH", 256),
		BlobEndpoint:              getenv("SYNAPSE_BLOB_ENDPOINT", ""),
		BlobAccessKey:             getenv("SYNAPSE_BLOB_ACCESS_KEY", ""),
		BlobSecretKey:             getenv("SYNAPSE_BLOB_SECRET_KEY", ""),
		BlobBucket:                getenv("SYNAPSE_BLOB_BUCKET", "synapse-evidence"),
		BlobUseSSL:                getbool("SYNAPSE_BLOB_USE_SSL", false),
		ReconTimeout:              getduration("SYNAPSE_RECON_TIMEOUT", 3*time.Minute),
		ReconMaxOutput:            getint("SYNAPSE_RECON_MAX_OUTPUT", 8<<20),
		ReconConcurrency:          getint("SYNAPSE_RECON_CONCURRENCY", 3),
		ReconQueueSize:            getint("SYNAPSE_RECON_QUEUE", 64),

		ReconAllowCapabilitySensitive: getbool("SYNAPSE_RECON_ALLOW_CAPABILITY_SENSITIVE", false),

		EvidenceSigningSeed:       getenv("SYNAPSE_EVIDENCE_SIGNING_SEED", ""),
		TSAURL:                    getenv("SYNAPSE_TSA_URL", ""),
		SandboxEnabled:            getbool("SYNAPSE_SANDBOX_ENABLED", false),
		SandboxMemMax:             int64(getint("SYNAPSE_SANDBOX_MEM_MAX", 512<<20)),
		SandboxPidsMax:            getint("SYNAPSE_SANDBOX_PIDS_MAX", 256),
		DASTHelperBin:             getenv("SYNAPSE_DAST_HELPER_BIN", "synapse-dast-helper"),
		DASTMaxReauth:             maxReauth,
		DASTRatePerSec:            ratePerSec,
		DASTConcurrency:           concurrency,
		DASTMaxDepth:              maxDepth,
		DASTMaxPages:              maxPages,
		DASTMaxRequests:           maxRequests,
		DASTMaxWallClock:          maxWallClock,
		VaultMasterKey:            getenv("SYNAPSE_VAULT_MASTER_KEY", ""),
		ReconViaWorker:            getbool("SYNAPSE_RECON_VIA_WORKER", false),
		EgressBrokerSocket:        getenv("SYNAPSE_EGRESS_BROKER_SOCKET", "/run/synapse-egress-broker/egress-broker.sock"),
		EgressGrantAuthorityAddr:  getenv("SYNAPSE_EGRESS_GRANT_AUTHORITY_ADDR", ""),
		EgressGrantAuthorityURL:   getenv("SYNAPSE_EGRESS_GRANT_AUTHORITY_URL", ""),
		EgressGrantAuthorityToken: getenv("SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN", ""),
		EgressGrantIssuerToken:    getenv("SYNAPSE_EGRESS_GRANT_ISSUER_TOKEN", ""),
		EgressGrantSigningSeed:    getenv("SYNAPSE_EGRESS_GRANT_SIGNING_SEED", ""),
		ToolExecutionMode:         getenv("SYNAPSE_TOOL_EXECUTION_MODE", ""),
		ToolHashes:                parsePins(getenv("SYNAPSE_TOOL_HASHES", "")),
		AgentEnabled:              getbool("SYNAPSE_AGENT_ENABLED", false), // needs LLM creds → stays opt-in
		// Analysis capabilities default ON so the tool is fully effective out of the box (the UI and a
		// bare scan get every deterministic, best-effort feature without hunting env flags). Each is
		// safe to default on: file/compute-based, no external service, and a no-op when its input is
		// absent. Set the flag to false to opt out. Capabilities that need external setup or would be
		// unsafe unsandboxed stay OFF by default (sandbox, agent/LLM, taint, maven/gradle resolvers,
		// jarhash egress) – see their fields below.
		JudgmentsEnabled:                      getbool("SYNAPSE_JUDGMENTS_ENABLED", true),
		SASTEnabled:                           getbool("SYNAPSE_SAST_ENABLED", true),
		SecretScanEnabled:                     getbool("SYNAPSE_SECRET_SCAN_ENABLED", true),
		MisconfigEnabled:                      getbool("SYNAPSE_MISCONFIG_ENABLED", true),
		SuppressionEnabled:                    getbool("SYNAPSE_SUPPRESSION_ENABLED", true),
		VEXEnabled:                            getbool("SYNAPSE_VEX_ENABLED", true),
		ComplianceEnabled:                     getbool("SYNAPSE_COMPLIANCE_ENABLED", true),
		DetectionPriority:                     os.Getenv("SYNAPSE_DETECTION_PRIORITY"),
		DBMaxAgeDays:                          getint("SYNAPSE_DB_MAX_AGE_DAYS", 30),
		ScanCacheEnabled:                      getbool("SYNAPSE_SCAN_CACHE_ENABLED", true),
		ScanCacheDir:                          os.Getenv("SYNAPSE_SCAN_CACHE_DIR"),
		ImageRootFSEnabled:                    getbool("SYNAPSE_IMAGE_ROOTFS_ENABLED", true),
		OwnedAdvisoryEnabled:                  getbool("SYNAPSE_OWNED_ADVISORY", true),
		ReachabilityEnabled:                   getbool("SYNAPSE_REACHABILITY_ENABLED", true),
		PyReachabilityEnabled:                 getbool("SYNAPSE_PYREACH_ENABLED", false),
		JSReachabilityEnabled:                 getbool("SYNAPSE_JSREACH_ENABLED", false),
		JSSymbolReachabilityEnabled:           getbool("SYNAPSE_JSREACH_TIER2_ENABLED", false),
		RustReachabilityEnabled:               getbool("SYNAPSE_REACH_RUST", false),
		PHPReachabilityEnabled:                getbool("SYNAPSE_REACH_PHP", false),
		RubyReachabilityEnabled:               getbool("SYNAPSE_REACH_RUBY", false),
		CrossCheckEnabled:                     getbool("SYNAPSE_CROSSCHECK_ENABLED", true),
		SBOMCrossCheckEnabled:                 getbool("SYNAPSE_SBOM_CROSSCHECK_ENABLED", true),
		WriteupDraftsEnabled:                  getbool("SYNAPSE_WRITEUP_DRAFTS_ENABLED", false), // needs agent → opt-in
		FleetAssetsEnabled:                    getbool("SYNAPSE_FLEET_ASSETS_ENABLED", false),
		CSPMEnabled:                           getbool("SYNAPSE_CSPM_ENABLED", false),
		CSPMProviders:                         splitList(getenv("SYNAPSE_CSPM_PROVIDERS", "")),
		CSPMRate:                              boundedNonNegative(getint("SYNAPSE_CSPM_RATE", 0), 100),
		CSPMEgressHosts:                       splitList(getenv("SYNAPSE_CSPM_EGRESS_HOSTS", "")),
		CSPMHelperBin:                         getenv("SYNAPSE_CSPM_HELPER_BIN", "synapse-cspm"),
		AttackPathMaxLen:                      getint("SYNAPSE_ATTACKPATH_MAX_LEN", 12),
		AttackPathMaxPaths:                    getint("SYNAPSE_ATTACKPATH_MAX_PATHS", 100),
		AttackPathWallClock:                   getduration("SYNAPSE_ATTACKPATH_WALLCLOCK", 2*time.Second),
		FleetEnabled:                          getbool("SYNAPSE_FLEET_ENABLED", false),
		FleetClusterIngestEnabled:             getbool("SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED", false),
		FleetHostIngestEnabled:                getbool("SYNAPSE_FLEET_HOST_INGEST_ENABLED", false),
		FleetTelemetryIngestEnabled:           getbool("SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED", false),
		FleetDetectionIngestEnabled:           getbool("SYNAPSE_FLEET_DETECTION_INGEST_ENABLED", false),
		FleetKeyRegistrationEnabled:           getbool("SYNAPSE_FLEET_KEY_REGISTRATION_ENABLED", false),
		FleetMinAgentVersion:                  strings.TrimSpace(os.Getenv("SYNAPSE_FLEET_MIN_AGENT_VERSION")),
		FleetAgentStaleAfter:                  getduration("SYNAPSE_FLEET_STALE_AFTER", 10*time.Minute),
		FleetCoverageFreshnessTarget:          getduration("SYNAPSE_FLEET_COVERAGE_FRESHNESS_TARGET", 24*time.Hour),
		FleetSignerKey:                        getenv("SYNAPSE_FLEET_SIGNER_KEY", ""),
		FleetCACertPEM:                        getenv("SYNAPSE_FLEET_CA_CERT", ""),
		FleetCAKeyPEM:                         getenv("SYNAPSE_FLEET_CA_KEY", ""),
		FleetCertTTL:                          getduration("SYNAPSE_FLEET_CERT_TTL", 720*time.Hour),
		FleetClientCertHeader:                 getenv("SYNAPSE_FLEET_CLIENT_CERT_HEADER", ""),
		LeaderElectionEnabled:                 getbool("SYNAPSE_LEADER_ENABLED", false),
		LeaderResource:                        getenv("SYNAPSE_LEADER_RESOURCE", "scheduler"),
		LeaderTerm:                            getduration("SYNAPSE_LEADER_TERM", 15*time.Second),
		LeaderRenew:                           getduration("SYNAPSE_LEADER_RENEW", 5*time.Second),
		WorkerConcurrency:                     getint("SYNAPSE_WORKER_CONCURRENCY", defaultWorkerConcurrency),
		VulnerabilitySchedulerEnabled:         getbool("SYNAPSE_VULNERABILITY_SCHEDULER_ENABLED", false),
		VulnerabilitySchedulerPollInterval:    getduration("SYNAPSE_VULNERABILITY_SCHEDULER_POLL", time.Minute),
		VulnerabilitySchedulerStaleAfter:      getduration("SYNAPSE_VULNERABILITY_SCHEDULER_STALE_AFTER", 30*time.Minute),
		VulnerabilitySchedulerJitter:          getint("SYNAPSE_VULNERABILITY_SCHEDULER_JITTER_PERCENT", 10),
		VulnerabilitySchedulerDispatch:        getint("SYNAPSE_VULNERABILITY_SCHEDULER_DISPATCH_LIMIT", 10),
		VulnerabilitySchedulerQueueDepth:      getint("SYNAPSE_VULNERABILITY_SCHEDULER_MAX_QUEUE_DEPTH", 100),
		VulnerabilitySchedulerRecovery:        getint("SYNAPSE_VULNERABILITY_SCHEDULER_RECOVERY_LIMIT", 10),
		VulnerabilityProviderSyncEnabled:      getbool("SYNAPSE_VULNERABILITY_PROVIDER_SYNC_ENABLED", false),
		VulnerabilityOccurrenceWritesEnabled:  getbool("SYNAPSE_VULNERABILITY_OCCURRENCE_WRITES_ENABLED", false),
		VulnerabilityFindingProjectionEnabled: getbool("SYNAPSE_VULNERABILITY_FINDING_PROJECTION_ENABLED", false),
		VulnerabilityActionsEnabled:           getbool("SYNAPSE_VULNERABILITY_ACTIONS_ENABLED", false),
		VulnerabilityNotificationsEnabled:     getbool("SYNAPSE_VULNERABILITY_NOTIFICATIONS_ENABLED", false),
		VulnerabilityDryRunEnabled:            getbool("SYNAPSE_VULNERABILITY_DRY_RUN_ENABLED", true),
		VulnerabilityTenantAllowlist:          splitList(getenv("SYNAPSE_VULNERABILITY_TENANT_ALLOWLIST", "")),
		SLAEnabled:                            getbool("SYNAPSE_SLA_ENABLED", false),
		GovulncheckBin:                        getenv("SYNAPSE_GOVULNCHECK_BIN", "govulncheck"),
		GoModGraphEnabled:                     getbool("SYNAPSE_GOMODGRAPH_ENABLED", true),
		GoBin:                                 getenv("SYNAPSE_GO_BIN", "go"),
		MavenResolveEnabled:                   getbool("SYNAPSE_MAVEN_RESOLVE_ENABLED", false),
		MvnBin:                                getenv("SYNAPSE_MVN_BIN", "mvn"),
		MavenRepoHosts:                        splitList(getenv("SYNAPSE_MAVEN_REPO_HOSTS", "")),
		MavenLocalRepo:                        getenv("SYNAPSE_MAVEN_LOCAL_REPO", ""),
		GradleResolveEnabled:                  getbool("SYNAPSE_GRADLE_RESOLVE_ENABLED", false),
		GradleBin:                             getenv("SYNAPSE_GRADLE_BIN", "gradle"),
		GradleHome:                            getenv("SYNAPSE_GRADLE_HOME", ""),
		NPMResolveEnabled:                     getbool("SYNAPSE_NPM_RESOLVE_ENABLED", false),
		NPMBin:                                getenv("SYNAPSE_NPM_BIN", "npm"),
		NPMRegistryHosts:                      splitList(getenv("SYNAPSE_NPM_REGISTRY_HOSTS", "")),
		ManifestResolveEnabled:                getbool("SYNAPSE_MANIFEST_RESOLVE_ENABLED", false),
		ComposerBin:                           getenv("SYNAPSE_COMPOSER_BIN", "composer"),
		BundleBin:                             getenv("SYNAPSE_BUNDLE_BIN", "bundle"),
		PoetryBin:                             getenv("SYNAPSE_POETRY_BIN", "poetry"),
		ManifestRegistryHosts:                 splitList(getenv("SYNAPSE_MANIFEST_REGISTRY_HOSTS", "")),
		JVMReachabilityEnabled:                getbool("SYNAPSE_JVM_REACHABILITY_ENABLED", true),
		JarHashOnlineEnabled:                  getbool("SYNAPSE_JARHASH_ONLINE_ENABLED", false),
		JarHashBaseURL:                        getenv("SYNAPSE_JARHASH_BASE_URL", ""),
		JarHashDBPath:                         getenv("SYNAPSE_JARHASH_DB_PATH", ""),
		TaintCallgraphBin:                     getenv("SYNAPSE_TAINT_CALLGRAPH_BIN", "synapse-callgraph"),
		TaintEnabled:                          getbool("SYNAPSE_TAINT_ENABLED", false),
		LLMBaseURL:                            getenv("SYNAPSE_LLM_BASE_URL", "http://localhost:20128/v1"),
		LLMAPIKey:                             getenv("SYNAPSE_LLM_API_KEY", ""),
		LLMModel:                              getenv("SYNAPSE_LLM_MODEL", ""),
		LLMProvider:                           normalizeProvider(getenv("SYNAPSE_LLM_PROVIDER", "openai-compatible")),
		LLMTimeout:                            getduration("SYNAPSE_LLM_TIMEOUT", 60*time.Second),
		FPTriageEnabled:                       getbool("SYNAPSE_FP_TRIAGE_ENABLED", false),
		FPTriageModel:                         getenv("SYNAPSE_FP_TRIAGE_MODEL", getenv("SYNAPSE_LLM_MODEL", "")),
		FPTriageProvider:                      normalizeProvider(getenv("SYNAPSE_FP_TRIAGE_PROVIDER", getenv("SYNAPSE_LLM_PROVIDER", "openai-compatible"))),
		FPTriageMode:                          normalizeFPTriageMode(getenv("SYNAPSE_FP_TRIAGE_MODE", "shadow")),
		FPTriageMaxFindings:                   boundedPositive(getint("SYNAPSE_FP_TRIAGE_MAX_FINDINGS", defaultFPTriageMaxFindings), defaultFPTriageMaxFindings, maxFPTriageMaxFindings),
		FPTriageConcurrency:                   boundedPositive(getint("SYNAPSE_FP_TRIAGE_CONCURRENCY", defaultFPTriageConcurrency), defaultFPTriageConcurrency, maxFPTriageConcurrency),
		FPTriageMaxTokens:                     boundedPositive64(getint64("SYNAPSE_FP_TRIAGE_MAX_TOKENS", defaultFPTriageMaxTokens), defaultFPTriageMaxTokens, maxFPTriageMaxTokens),
		FPTriageMaxCostMicroUSD:               boundedNonNegative64(getint64("SYNAPSE_FP_TRIAGE_MAX_COST_MICRO_USD", 0), 1_000_000_000_000),
		FPTriageProposerInputRate:             boundedNonNegative64(getint64("SYNAPSE_FP_TRIAGE_PROPOSER_INPUT_MICRO_USD_PER_MILLION", 0), 1_000_000_000_000),
		FPTriageProposerOutputRate:            boundedNonNegative64(getint64("SYNAPSE_FP_TRIAGE_PROPOSER_OUTPUT_MICRO_USD_PER_MILLION", 0), 1_000_000_000_000),
		FPTriageVerifierInputRate:             boundedNonNegative64(getint64("SYNAPSE_FP_TRIAGE_VERIFIER_INPUT_MICRO_USD_PER_MILLION", 0), 1_000_000_000_000),
		FPTriageVerifierOutputRate:            boundedNonNegative64(getint64("SYNAPSE_FP_TRIAGE_VERIFIER_OUTPUT_MICRO_USD_PER_MILLION", 0), 1_000_000_000_000),
		FPTriageCircuitFailures:               boundedPositive(getint("SYNAPSE_FP_TRIAGE_CIRCUIT_FAILURES", defaultFPTriageCircuitFailures), defaultFPTriageCircuitFailures, maxFPTriageCircuitFailures),
		FPTriageCircuitCooldown:               boundedPositiveDuration(getduration("SYNAPSE_FP_TRIAGE_CIRCUIT_COOLDOWN", time.Minute), time.Minute, 24*time.Hour),
		FPTriageAlertMinSamples:               boundedPositive(getint("SYNAPSE_FP_TRIAGE_ALERT_MIN_SAMPLES", 10), 10, 10000),
		FPTriageDisagreeBaseBPS:               boundedNonNegative(getint("SYNAPSE_FP_TRIAGE_DISAGREEMENT_BASELINE_BPS", 1500), 10000),
		FPTriageExemptBaseBPS:                 boundedNonNegative(getint("SYNAPSE_FP_TRIAGE_EXEMPTION_BASELINE_BPS", 1000), 10000),
		FPTriageParseFailBaseBPS:              boundedNonNegative(getint("SYNAPSE_FP_TRIAGE_PARSE_FAILURE_BASELINE_BPS", 200), 10000),
		FPTriageAlertDeltaBPS:                 boundedNonNegative(getint("SYNAPSE_FP_TRIAGE_ALERT_DEVIATION_BPS", 1000), 10000),
		FPTriageIndependence:                  normalizeFPTriageIndependence(getenv("SYNAPSE_FP_TRIAGE_INDEPENDENCE", "model_family")),

		AgentApprovalMode:    getenv("SYNAPSE_AGENT_APPROVAL_MODE", "manual"),
		AgentApprovalTimeout: getduration("SYNAPSE_AGENT_APPROVAL_TIMEOUT", 30*time.Minute),
		AgentMaxSteps:        getint("SYNAPSE_AGENT_MAX_STEPS", 16),
		AgentTokenBudget:     getint("SYNAPSE_AGENT_TOKEN_BUDGET", 0),
		AgentMaxDuration:     getduration("SYNAPSE_AGENT_MAX_DURATION", 10*time.Minute),

		DBMaxConns:                 getint("SYNAPSE_DB_MAX_CONNS", 32),
		DBMinConns:                 getint("SYNAPSE_DB_MIN_CONNS", 0),
		DBMaxConnLifetime:          getduration("SYNAPSE_DB_MAX_CONN_LIFETIME", time.Hour),
		DBMaxConnIdleTime:          getduration("SYNAPSE_DB_MAX_CONN_IDLE", 30*time.Minute),
		AgentViaWorker:             getbool("SYNAPSE_AGENT_VIA_WORKER", false),
		AgentConcurrency:           getint("SYNAPSE_AGENT_CONCURRENCY", 8),
		AgentQueueDepth:            getint("SYNAPSE_AGENT_QUEUE_DEPTH", 256),
		AgentMaxParallel:           getint("SYNAPSE_AGENT_MAX_PARALLEL", 1), // serial by default; operators raise it to parallelize
		AgentReconConcurrency:      getint("SYNAPSE_AGENT_RECON_CONCURRENCY", 3),
		ApprovalSweepInterval:      getduration("SYNAPSE_APPROVAL_SWEEP_INTERVAL", time.Minute),
		PromotionReconcileInterval: getduration("SYNAPSE_PROMOTION_RECONCILE_INTERVAL", time.Minute),
		VerifierBaseURL:            getenv("SYNAPSE_VERIFIER_BASE_URL", getenv("SYNAPSE_LLM_BASE_URL", "http://localhost:20128/v1")),
		VerifierAPIKey:             getenv("SYNAPSE_VERIFIER_API_KEY", getenv("SYNAPSE_LLM_API_KEY", "")),
		VerifierProvider: normalizeProvider(getenv("SYNAPSE_VERIFIER_PROVIDER",
			getenv("SYNAPSE_FP_TRIAGE_PROVIDER", getenv("SYNAPSE_LLM_PROVIDER", "openai-compatible")))),
		VerifierModel: getenv("SYNAPSE_VERIFIER_MODEL", getenv("SYNAPSE_LLM_MODEL", "")),

		MeasureCursorSecret: getenv("SYNAPSE_MEASURE_CURSOR_SECRET", ""),

		MCPToken:        getenv("SYNAPSE_MCP_TOKEN", ""),
		MCPAddr:         getenv("SYNAPSE_MCP_ADDR", ":8081"),
		MCPEngagementID: getenv("SYNAPSE_MCP_ENGAGEMENT_ID", ""),
	}
}

// splitList parses a comma-separated env value into a trimmed, non-empty list ("" → nil).
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePins parses "name=hex,/abs/path=hex" into a pin map (operator hashes).

func parsePins(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	m := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			if k = strings.TrimSpace(k); k != "" {
				m[k] = strings.ToLower(strings.TrimSpace(v))
			}
		}
	}
	return m
}

// normalizeEnv canonicalizes a SYNAPSE_ENV value: trim surrounding whitespace and
// lowercase it, so "Production", " production\n", and "PRODUCTION" are one value.
func normalizeEnv(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func normalizeFPTriageMode(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "enforce") {
		return "enforce"
	}
	return "shadow"
}

func boundedPositive(value, fallback, max int) int {
	if value < 1 || value > max {
		return fallback
	}
	return value
}

func boundedPositive64(value, fallback, max int64) int64 {
	if value <= 0 || value > max {
		return fallback
	}
	return value
}

func boundedNonNegative64(value, max int64) int64 {
	if value < 0 || value > max {
		return 0
	}
	return value
}

func boundedPositiveDuration(value, fallback, max time.Duration) time.Duration {
	if value <= 0 || value > max {
		return fallback
	}
	return value
}

func normalizeProvider(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func normalizeFPTriageIndependence(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "model_family":
		return "model_family"
	case "provider":
		return "provider"
	default:
		return "disabled"
	}
}

func boundedNonNegative(value, max int) int {
	if value < 0 || value > max {
		return 0
	}
	return value
}

// IsProduction reports whether this is a production-grade deployment, in which the
// security gates (credential-vault master key, evidence/audit chain-head signing,
// sandbox requirement) MUST fail closed. It is the single authority for that decision –
// never compare cfg.Environment to a string literal directly.
//
// It fails CLOSED: only an explicitly recognized non-production environment is treated
// as non-production; any other value (a typo like "prod"/"prodution", "staging", an
// empty/unset-then-overridden value, trailing whitespace) is treated as production, so a
// misconfigured environment lands in the STRICT gates rather than silently in lax,
// ephemeral-key dev behavior. The value is also normalized (trim + lowercase) here so the
// guarantee holds even if the field was not normalized at Load.
func (c Config) IsProduction() bool {
	switch normalizeEnv(c.Environment) {
	case "development", "dev", "local", "test", "ci":
		return false
	default: // production, prod, staging, or any unrecognized/misspelled value → fail closed
		return true
	}
}

// ValidateSandboxPosture rejects a production configuration that would execute tools without containment.
func (c Config) ValidateSandboxPosture() error {
	if c.IsProduction() && !c.SandboxEnabled {
		return errors.New("SYNAPSE_SANDBOX_ENABLED is required in production")
	}
	return nil
}

// ToolExecution is the resolved authority over whether a process may execute external
// tools against untrusted input itself, or must hand that work to the durable queue.
// It replaces inferring the boundary from a growing family of per-feature "via worker"
// booleans, which could not express "this process must never exec a tool".
type ToolExecution string

const (
	// ToolExecutionDispatchOnly forbids constructing tool runners in this process: work is
	// validated, authorized, and enqueued for an execution-capable worker to claim.
	ToolExecutionDispatchOnly ToolExecution = "dispatch-only"
	// ToolExecutionWorker executes queued work inside the hardened sandbox.
	ToolExecutionWorker ToolExecution = "worker"
	// ToolExecutionInProcess runs tools in the serving process. Development and CLI only.
	ToolExecutionInProcess ToolExecution = "in-process"
)

// ProcessRole names the composition root resolving its execution posture. The role is a
// property of the binary, not of the environment, so it is passed in rather than guessed.
type ProcessRole string

const (
	ProcessRoleAPI    ProcessRole = "api"
	ProcessRoleWorker ProcessRole = "worker"
	ProcessRoleCLI    ProcessRole = "cli"
)

// ResolveToolExecution decides how role may execute tools, failing closed on any
// combination that would let a production API run an untrusted tool locally.
//
// Production API pods are dispatch-only: they must not build a sandbox runner, and a
// missing queue is a startup failure rather than a silent fall back to local execution.
// The worker is always execution-capable, and the CLI always runs in process because it
// is the operator's own single-process scanner.
func (c Config) ResolveToolExecution(role ProcessRole) (ToolExecution, error) {
	requested := ToolExecution(normalizeEnv(c.ToolExecutionMode))
	switch role {
	case ProcessRoleWorker:
		if requested != "" && requested != ToolExecutionWorker {
			return "", fmt.Errorf("synapse-worker cannot run as %q: it exists to execute queued work", requested)
		}
		if c.DBDSN == "" {
			return "", errors.New("synapse-worker requires SYNAPSE_DB_DSN: queued execution cannot use process-local persistence")
		}
		if c.IsProduction() && !c.SandboxEnabled {
			return "", errors.New("production synapse-worker requires SYNAPSE_SANDBOX_ENABLED=true")
		}
		return ToolExecutionWorker, nil
	case ProcessRoleCLI:
		if requested != "" && requested != ToolExecutionInProcess {
			return "", fmt.Errorf("the CLI scanner cannot run as %q: it has no durable queue", requested)
		}
		return ToolExecutionInProcess, nil
	case ProcessRoleAPI:
	default:
		return "", fmt.Errorf("unknown process role %q", role)
	}

	if requested == "" && (c.ReconViaWorker || c.AgentViaWorker) {
		requested = ToolExecutionDispatchOnly
	}
	switch requested {
	case ToolExecutionWorker:
		return "", errors.New("SYNAPSE_TOOL_EXECUTION_MODE=worker is not valid for synapse-api; run synapse-worker instead")
	case ToolExecutionInProcess:
		if c.IsProduction() {
			return "", errors.New("SYNAPSE_TOOL_EXECUTION_MODE=in-process is refused in production: the API must not execute untrusted tools; use dispatch-only with synapse-worker")
		}
		return ToolExecutionInProcess, nil
	case ToolExecutionDispatchOnly:
		if c.DBDSN == "" {
			return "", errors.New("SYNAPSE_TOOL_EXECUTION_MODE=dispatch-only requires SYNAPSE_DB_DSN: the durable queue is the only path to an execution worker")
		}
		return ToolExecutionDispatchOnly, nil
	case "":
		if !c.IsProduction() {
			return ToolExecutionInProcess, nil
		}
		if c.DBDSN == "" {
			return "", errors.New("production synapse-api requires SYNAPSE_DB_DSN: tool execution is dispatched to synapse-worker through the durable queue")
		}
		return ToolExecutionDispatchOnly, nil
	default:
		return "", fmt.Errorf("unknown SYNAPSE_TOOL_EXECUTION_MODE %q (want dispatch-only, worker, or in-process)", c.ToolExecutionMode)
	}
}

// ValidateEgressGrantPosture fails closed unless production APIs and workers use
// a distinct machine credential and a dedicated signing authority.
func (c Config) ValidateEgressGrantPosture(role ProcessRole) error {
	if !c.IsProduction() {
		return nil
	}
	switch role {
	case ProcessRoleAPI:
		if strings.TrimSpace(c.EgressGrantAuthorityAddr) == "" || strings.TrimSpace(c.EgressGrantIssuerToken) == "" || strings.TrimSpace(c.EgressGrantSigningSeed) == "" {
			return errors.New("production synapse-api requires SYNAPSE_EGRESS_GRANT_AUTHORITY_ADDR, SYNAPSE_EGRESS_GRANT_ISSUER_TOKEN, and SYNAPSE_EGRESS_GRANT_SIGNING_SEED")
		}
		if c.EgressGrantIssuerToken == c.APIToken {
			return errors.New("SYNAPSE_EGRESS_GRANT_ISSUER_TOKEN must not reuse SYNAPSE_API_TOKEN")
		}
		if c.EgressGrantSigningSeed == c.EvidenceSigningSeed {
			return errors.New("SYNAPSE_EGRESS_GRANT_SIGNING_SEED must not reuse SYNAPSE_EVIDENCE_SIGNING_SEED")
		}
	case ProcessRoleWorker:
		if strings.TrimSpace(c.EgressGrantAuthorityURL) == "" || strings.TrimSpace(c.EgressGrantAuthorityToken) == "" {
			return errors.New("production synapse-worker requires SYNAPSE_EGRESS_GRANT_AUTHORITY_URL and SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN")
		}
		if c.EgressGrantAuthorityToken == c.APIToken {
			return errors.New("SYNAPSE_EGRESS_GRANT_AUTHORITY_TOKEN must not reuse SYNAPSE_API_TOKEN")
		}
	default:
		return fmt.Errorf("unknown process role %q for egress grant posture", role)
	}
	return nil
}

// ValidateNetworkExecutionPosture rejects production network execution kinds that do not yet
// have a trusted control-plane issuer branch. Development may use the local test egress applier.
func (c Config) ValidateNetworkExecutionPosture(role ProcessRole) error {
	if !c.IsProduction() {
		return nil
	}
	switch role {
	case ProcessRoleAPI, ProcessRoleWorker:
		if c.CSPMEnabled {
			return errors.New("production CSPM execution requires authoritative signed CSPM grants and is not yet supported")
		}
		return nil
	default:
		return fmt.Errorf("unknown process role %q for network execution posture", role)
	}
}

// ValidateMigrationPosture keeps DDL credentials out of long-running production services.
// Production migrations are owned by the dedicated synapse-migrate command.
func (c Config) ValidateMigrationPosture() error {
	if c.IsProduction() && c.DBAutoMigrate {
		return errors.New("SYNAPSE_DB_AUTO_MIGRATE=false is required in production; run synapse-migrate before starting services")
	}
	if c.IsProduction() && c.OIDCEnabled && c.DBDSN == "" {
		return errors.New("SYNAPSE_DB_DSN is required when OIDC is enabled in production")
	}
	return nil
}

// ValidateWorkerConcurrency bounds in-process queue claim loops so a configuration typo cannot
// create an unbounded number of privileged executions.
func (c Config) ValidateWorkerConcurrency() error {
	if c.WorkerConcurrency < 1 || c.WorkerConcurrency > maxWorkerConcurrency {
		return fmt.Errorf("SYNAPSE_WORKER_CONCURRENCY must be between 1 and %d (got %d)", maxWorkerConcurrency, c.WorkerConcurrency)
	}
	return nil
}

// ValidateOIDCPosture fails closed when the browser OIDC BFF cannot bind identity/session state to a fixed tenant.
func (c Config) ValidateOIDCPosture() error {
	if !c.OIDCEnabled {
		return nil
	}
	if strings.TrimSpace(c.OIDCIssuer) == "" || strings.TrimSpace(c.OIDCClientID) == "" || strings.TrimSpace(c.OIDCClientSecret) == "" || strings.TrimSpace(c.OIDCRedirectURL) == "" || strings.TrimSpace(c.OIDCTenantID) == "" || len(c.OIDCGroupRoleMapping) == 0 || c.OIDCTransactionTTL <= 0 || c.OIDCSessionTTL <= 0 {
		return errors.New("OIDC requires issuer, client id, client secret, redirect URL, fixed tenant, group-role mapping, and positive lifetimes")
	}
	if !validOIDCFrontendURL(c.OIDCFrontendURL) {
		return errors.New("OIDC requires an absolute HTTPS SYNAPSE_OIDC_FRONTEND_URL without query or fragment")
	}
	return nil
}

func validOIDCFrontendURL(value string) bool {
	u, err := url.Parse(strings.TrimSpace(value))
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// MigrationDSN returns the DDL credential when configured, falling back to the runtime
// credential only for development convenience.
func (c Config) MigrationDSN() string {
	if c.DBMigrationDSN != "" {
		return c.DBMigrationDSN
	}
	return c.DBDSN
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getbool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// ResolveScanCacheDir returns the shared scan-cache root, defaulting to the backward-compatible
// "synapse-sbom" subdir of the OS user cache dir. Empty only when no cache dir can be determined.
func (c Config) ResolveScanCacheDir() string {
	if c.ScanCacheDir != "" {
		return c.ScanCacheDir
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "synapse-sbom")
}

func getduration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getint(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getint64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

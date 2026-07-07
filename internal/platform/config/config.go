// Package config loads runtime configuration from the environment.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration.
type Config struct {
	HTTPAddr     string
	Environment  string
	LogLevel     string
	SingleTenant bool

	// APIToken protects all API + UI routes; required (no anonymous access).
	APIToken string
	// AUPVersion is the current Acceptable-Use Policy version.
	AUPVersion string
	// AUPFile is where first-run AUP acceptance is recorded (file-backed until Postgres).
	AUPFile string
	// AuditFile is the append-only audit log (file-backed until Postgres).
	AuditFile string
	// DBDSN, when set, enables PostgreSQL persistence; empty = in-memory (dev).
	DBDSN string
	// SyftBin is the Syft executable used for SBOM generation (shell-out).
	SyftBin string
	// SBOMProducer selects the SBOM-generation producer: "syft" (default — the pinned
	// binary, full ecosystem coverage + dep-graph edges via CycloneDX) or "ownsbom" (the detection-
	// independent owned per-ecosystem parsers — no third-party scanner, but components-only + Tier-1 ecosystems).
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
	// FindingMinSeverity is the lowest vuln severity promoted to a finding.
	FindingMinSeverity string
	// IgnoreUnfixed, when true, does NOT promote vulnerabilities that have no available fix
	// (FixedVersion empty — not-fixed / wont-fix / deferred) to findings, matching Trivy's
	// --ignore-unfixed. Default false (show everything); they remain in the vuln inventory.
	IgnoreUnfixed bool
	// Offline, when true, omits detection sources that require network egress (the live OSV.dev
	// source), running only offline sources — Grype's pre-synced DB and the owned advisory store.
	// Trades some recall for a fast, air-gapped scan (no live HTTP per scan). Default false.
	Offline bool
	// MaxWorkspaceBytes caps the total size of a prepared SCA workspace: the
	// acquirer rejects a target whose files exceed it. <=0 keeps the 2 GiB default.
	MaxWorkspaceBytes int64
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
	// ReconAllowCapabilitySensitive permits capability-sensitive tools (naabu — raw
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
	// binary whose hash does not match its pin — closing the initial-supply-chain gap that
	// trust-on-first-use alone cannot (TOFU only detects post-first-run replacement). Empty
	// = TOFU only. Parsed from SYNAPSE_TOOL_HASHES.
	ToolHashes map[string]string
	// VaultMasterKey is the AES-256 master key for the credential vault: 64 hex
	// chars or base64 of 32 bytes. Empty = an ephemeral key (dev only; stored secrets do
	// not survive restart). Required in production. Never logged.
	VaultMasterKey string
	// ReconViaWorker routes recon runs through the durable queue: the API enqueues
	// and the privileged synapse-worker (with CAP_NET_ADMIN for egress) claims + executes
	// them. Requires Postgres. Default false = the API runs recon in-process (dev).
	ReconViaWorker bool
	// AgentEnabled turns on the AI orchestrator. Default false (fail-safe): no
	// LLM is contacted and no agent endpoints are active unless explicitly enabled.
	AgentEnabled bool
	// LLM provider: OpenAI-compatible Chat Completions. BaseURL defaults to
	// the LLM gateway; APIKey is a Bearer token (NEVER logged);
	// Model is the provider model id. Empty BaseURL + AgentEnabled fails closed at wiring.
	LLMBaseURL string
	LLMAPIKey  string
	LLMModel   string
	LLMTimeout time.Duration

	// Agent orchestration policy. ApprovalMode: manual|filter|auto (manual is
	// the safe default — a human approves every action). The rest bound a run.
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
	AgentViaWorker        bool
	AgentConcurrency      int
	AgentQueueDepth       int
	AgentMaxParallel      int
	AgentReconConcurrency int
	ApprovalSweepInterval time.Duration

	// JudgmentsEnabled turns on the AI judgment lifecycle HTTP routes; off by default.
	JudgmentsEnabled bool
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
	// ScanCacheEnabled turns on the content+version-addressed generated-SBOM cache; off by default. A hit on
	// an unchanged tree skips the cataloging step; a producer version bump invalidates the entry.
	ScanCacheEnabled bool
	// ScanCacheDir is where cached SBOMs live when ScanCacheEnabled. Empty ⇒ a "synapse-sbom" subdir of the
	// OS user cache dir. It MUST be operator-owned and not writable by untrusted users: an attacker who can
	// write there and compute a scan's content+producer key could pre-seed a lossy SBOM (a silent
	// false-negative). The default per-user cache dir satisfies this.
	ScanCacheDir string
	// OwnedAdvisoryEnabled wires the owned advisory DetectionSource: match the SBOM
	// against the owned normalized-advisory store (offline, reproducible) ALONGSIDE live OSV/Grype. Off by
	// default; opt-in. An empty store yields no findings (a harmless no-op) until the advisory ingester
	// populates it — so enabling it without a populated store changes nothing.
	OwnedAdvisoryEnabled bool
	// ReachabilityEnabled turns on deterministic Tier-2 call-graph reachability proof: post-scan,
	// it proves which findings' affected symbols are actually called and mints Tier-2 judgments that
	// supersede weaker LLM claims. Off by default; opt-in + best-effort (a no-coverage/un-buildable target
	// leaves the prior tier standing). GovulncheckBin is the pinned builder binary.
	ReachabilityEnabled bool
	GovulncheckBin      string
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
	// Off by default — it runs the Maven toolchain over untrusted project config + reaches the Maven
	// repo, so production MUST run it sandbox-confined. MvnBin is the mvn executable.
	MavenResolveEnabled bool
	MvnBin              string
	// MavenRepoHosts are extra Maven-repository hosts (comma-separated) the sandboxed resolver may reach
	// beyond Maven Central — e.g. a corporate mirror or the Apache plugin repo. Empty = Central only.
	MavenRepoHosts []string
	// MavenLocalRepo pins Maven's local repository to a PERSISTENT dir so the resolved tree is cached
	// across scans instead of re-downloaded. Empty = ephemeral (under the sandbox tmpfs HOME).
	MavenLocalRepo string
	// GradleResolveEnabled turns on full Gradle dependency-tree resolution via `gradle dependencies`
	// (best-effort + opt-in). HIGHER risk than Maven — evaluating build.gradle runs arbitrary build
	// logic — so production MUST run it sandbox-confined and it never invokes the project's./gradlew.
	// GradleBin is the pinned gradle executable; GradleHome is an optional persistent GRADLE_USER_HOME
	// cache. MavenRepoHosts (above) extends the egress allow-list for both resolvers (shared JVM repos).
	GradleResolveEnabled bool
	GradleBin            string
	GradleHome           string
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
	// VerifierModel is the model for the adversarial finding verifier (defaults to LLMModel).
	VerifierModel string

	// MCP server: exposes the agent tool catalog to external MCP clients,
	// bearer-locked (role "mcp") and pinned to one engagement. Token is never logged.
	MCPToken        string
	MCPAddr         string
	MCPEngagementID string
}

// Load reads configuration from environment variables with sane defaults.
func Load() Config {
	return Config{
		HTTPAddr:     getenv("SYNAPSE_HTTP_ADDR", ":8080"),
		Environment:  normalizeEnv(getenv("SYNAPSE_ENV", "development")),
		LogLevel:     getenv("SYNAPSE_LOG_LEVEL", "info"),
		SingleTenant: getbool("SYNAPSE_SINGLE_TENANT", true),
		APIToken:     getenv("SYNAPSE_API_TOKEN", ""),
		AUPVersion:   getenv("SYNAPSE_AUP_VERSION", "1.0"),
		AUPFile:      getenv("SYNAPSE_AUP_FILE", "data/aup-accepted.json"),
		AuditFile:    getenv("SYNAPSE_AUDIT_FILE", "data/audit.jsonl"),
		DBDSN:        getenv("SYNAPSE_DB_DSN", ""),
		SyftBin:      getenv("SYNAPSE_SYFT_BIN", "syft"),
		SBOMProducer: getenv("SYNAPSE_SBOM_PRODUCER", "syft"),
		GrypeBin:     getenv("SYNAPSE_GRYPE_BIN", "grype"),
		GrypeDBDir:   getenv("SYNAPSE_GRYPE_DB_DIR", ""),
		OSVBaseURL:   getenv("SYNAPSE_OSV_URL", ""),
		OSVBulkURL:   getenv("SYNAPSE_OSV_BULK_URL", ""),
		DepsDevURL:   getenv("SYNAPSE_DEPSDEV_URL", ""),
		KEVURL:       getenv("SYNAPSE_KEV_URL", ""),
		EPSSURL:      getenv("SYNAPSE_EPSS_URL", ""),
		NVDAPIURL:    getenv("SYNAPSE_NVD_API_URL", ""),
		NVDAPIKey:    getenv("SYNAPSE_NVD_API_KEY", ""),
		NVDBudget:    getduration("SYNAPSE_NVD_BUDGET", 20*time.Second),
		ScanTimeout:  getduration("SYNAPSE_SCAN_TIMEOUT", 10*time.Minute),
		// Promote EVERY detected vulnerability by default (info = lowest rank), matching
		// Grype/Trivy/OSV-Scanner — a higher floor silently hides detected vulns and reads as
		// "missing vulns". Prioritization is done by risk priority (KEV→EPSS×CVSS), not by
		// dropping findings; raise this floor explicitly to trim a report's actionable set.
		FindingMinSeverity: getenv("SYNAPSE_FINDING_MIN_SEVERITY", "info"),
		IgnoreUnfixed:      getbool("SYNAPSE_IGNORE_UNFIXED", false),
		Offline:            getbool("SYNAPSE_OFFLINE", false),
		MaxWorkspaceBytes:  getint64("SYNAPSE_MAX_WORKSPACE_BYTES", 2<<30),
		BlobEndpoint:       getenv("SYNAPSE_BLOB_ENDPOINT", ""),
		BlobAccessKey:      getenv("SYNAPSE_BLOB_ACCESS_KEY", ""),
		BlobSecretKey:      getenv("SYNAPSE_BLOB_SECRET_KEY", ""),
		BlobBucket:         getenv("SYNAPSE_BLOB_BUCKET", "synapse-evidence"),
		BlobUseSSL:         getbool("SYNAPSE_BLOB_USE_SSL", false),
		ReconTimeout:       getduration("SYNAPSE_RECON_TIMEOUT", 3*time.Minute),
		ReconMaxOutput:     getint("SYNAPSE_RECON_MAX_OUTPUT", 8<<20),
		ReconConcurrency:   getint("SYNAPSE_RECON_CONCURRENCY", 3),
		ReconQueueSize:     getint("SYNAPSE_RECON_QUEUE", 64),

		ReconAllowCapabilitySensitive: getbool("SYNAPSE_RECON_ALLOW_CAPABILITY_SENSITIVE", false),

		EvidenceSigningSeed:    getenv("SYNAPSE_EVIDENCE_SIGNING_SEED", ""),
		TSAURL:                 getenv("SYNAPSE_TSA_URL", ""),
		SandboxEnabled:         getbool("SYNAPSE_SANDBOX_ENABLED", false),
		SandboxMemMax:          int64(getint("SYNAPSE_SANDBOX_MEM_MAX", 512<<20)),
		SandboxPidsMax:         getint("SYNAPSE_SANDBOX_PIDS_MAX", 256),
		VaultMasterKey:         getenv("SYNAPSE_VAULT_MASTER_KEY", ""),
		ReconViaWorker:         getbool("SYNAPSE_RECON_VIA_WORKER", false),
		ToolHashes:             parsePins(getenv("SYNAPSE_TOOL_HASHES", "")),
		AgentEnabled:           getbool("SYNAPSE_AGENT_ENABLED", false),
		JudgmentsEnabled:       getbool("SYNAPSE_JUDGMENTS_ENABLED", false),
		SASTEnabled:            getbool("SYNAPSE_SAST_ENABLED", false),
		SecretScanEnabled:      getbool("SYNAPSE_SECRET_SCAN_ENABLED", false),
		MisconfigEnabled:       getbool("SYNAPSE_MISCONFIG_ENABLED", false),
		SuppressionEnabled:     getbool("SYNAPSE_SUPPRESSION_ENABLED", false),
		ScanCacheEnabled:       getbool("SYNAPSE_SCAN_CACHE_ENABLED", false),
		ScanCacheDir:           os.Getenv("SYNAPSE_SCAN_CACHE_DIR"),
		OwnedAdvisoryEnabled:   getbool("SYNAPSE_OWNED_ADVISORY", false),
		ReachabilityEnabled:    getbool("SYNAPSE_REACHABILITY_ENABLED", false),
		CrossCheckEnabled:      getbool("SYNAPSE_CROSSCHECK_ENABLED", false),
		SBOMCrossCheckEnabled:  getbool("SYNAPSE_SBOM_CROSSCHECK_ENABLED", false),
		WriteupDraftsEnabled:   getbool("SYNAPSE_WRITEUP_DRAFTS_ENABLED", false),
		GovulncheckBin:         getenv("SYNAPSE_GOVULNCHECK_BIN", "govulncheck"),
		GoModGraphEnabled:      getbool("SYNAPSE_GOMODGRAPH_ENABLED", false),
		GoBin:                  getenv("SYNAPSE_GO_BIN", "go"),
		MavenResolveEnabled:    getbool("SYNAPSE_MAVEN_RESOLVE_ENABLED", false),
		MvnBin:                 getenv("SYNAPSE_MVN_BIN", "mvn"),
		MavenRepoHosts:         splitList(getenv("SYNAPSE_MAVEN_REPO_HOSTS", "")),
		MavenLocalRepo:         getenv("SYNAPSE_MAVEN_LOCAL_REPO", ""),
		GradleResolveEnabled:   getbool("SYNAPSE_GRADLE_RESOLVE_ENABLED", false),
		GradleBin:              getenv("SYNAPSE_GRADLE_BIN", "gradle"),
		GradleHome:             getenv("SYNAPSE_GRADLE_HOME", ""),
		JVMReachabilityEnabled: getbool("SYNAPSE_JVM_REACHABILITY_ENABLED", false),
		JarHashOnlineEnabled:   getbool("SYNAPSE_JARHASH_ONLINE_ENABLED", false),
		JarHashBaseURL:         getenv("SYNAPSE_JARHASH_BASE_URL", ""),
		JarHashDBPath:          getenv("SYNAPSE_JARHASH_DB_PATH", ""),
		TaintCallgraphBin:      getenv("SYNAPSE_TAINT_CALLGRAPH_BIN", "synapse-callgraph"),
		TaintEnabled:           getbool("SYNAPSE_TAINT_ENABLED", false),
		LLMBaseURL:             getenv("SYNAPSE_LLM_BASE_URL", "http://localhost:20128/v1"),
		LLMAPIKey:              getenv("SYNAPSE_LLM_API_KEY", ""),
		LLMModel:               getenv("SYNAPSE_LLM_MODEL", ""),
		LLMTimeout:             getduration("SYNAPSE_LLM_TIMEOUT", 60*time.Second),

		AgentApprovalMode:    getenv("SYNAPSE_AGENT_APPROVAL_MODE", "manual"),
		AgentApprovalTimeout: getduration("SYNAPSE_AGENT_APPROVAL_TIMEOUT", 30*time.Minute),
		AgentMaxSteps:        getint("SYNAPSE_AGENT_MAX_STEPS", 16),
		AgentTokenBudget:     getint("SYNAPSE_AGENT_TOKEN_BUDGET", 0),
		AgentMaxDuration:     getduration("SYNAPSE_AGENT_MAX_DURATION", 10*time.Minute),

		DBMaxConns:            getint("SYNAPSE_DB_MAX_CONNS", 32),
		DBMinConns:            getint("SYNAPSE_DB_MIN_CONNS", 0),
		DBMaxConnLifetime:     getduration("SYNAPSE_DB_MAX_CONN_LIFETIME", time.Hour),
		DBMaxConnIdleTime:     getduration("SYNAPSE_DB_MAX_CONN_IDLE", 30*time.Minute),
		AgentViaWorker:        getbool("SYNAPSE_AGENT_VIA_WORKER", false),
		AgentConcurrency:      getint("SYNAPSE_AGENT_CONCURRENCY", 8),
		AgentQueueDepth:       getint("SYNAPSE_AGENT_QUEUE_DEPTH", 256),
		AgentMaxParallel:      getint("SYNAPSE_AGENT_MAX_PARALLEL", 1), // serial by default; operators raise it to parallelize
		AgentReconConcurrency: getint("SYNAPSE_AGENT_RECON_CONCURRENCY", 3),
		ApprovalSweepInterval: getduration("SYNAPSE_APPROVAL_SWEEP_INTERVAL", time.Minute),
		VerifierModel:         getenv("SYNAPSE_VERIFIER_MODEL", getenv("SYNAPSE_LLM_MODEL", "")),

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

// IsProduction reports whether this is a production-grade deployment, in which the
// security gates (credential-vault master key, evidence/audit chain-head signing,
// sandbox requirement) MUST fail closed. It is the single authority for that decision —
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

// ResolveScanCacheDir returns the SBOM cache directory, defaulting to a "synapse-sbom" subdir of the OS
// user cache dir when SYNAPSE_SCAN_CACHE_DIR is unset. Empty only when no cache dir can be determined.
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

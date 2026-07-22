// Package ports declares the interfaces (driven ports) that use cases depend on.
// Infrastructure adapters implement these; the dependency arrow points inward.
package ports

import (
	"context"
	"io"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ignore"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
)

// Clock abstracts wall-clock time for testability.
type Clock interface {
	Now() time.Time
}

// IDGenerator issues new domain identifiers.
type IDGenerator interface {
	NewID() shared.ID
}

// ProjectRepository persists tenant-scoped Project aggregates.
type ProjectRepository interface {
	Create(ctx context.Context, p *project.Project) error
	List(ctx context.Context, tenantID shared.ID) ([]*project.Project, error)
	GetByKey(ctx context.Context, tenantID shared.ID, key string) (*project.Project, error)
	GetByID(ctx context.Context, tenantID, projectID shared.ID) (*project.Project, error)
	UpdateGate(ctx context.Context, tenantID shared.ID, key, gateID string) error
	CountByGate(ctx context.Context, tenantID shared.ID, gateID string) (int, error)
	DeleteByKey(ctx context.Context, tenantID shared.ID, key string) error
	// AssignProfile sets (or clears, with an empty profileKey) the quality profile assigned to a
	// language for a project (project.DefaultProfileByLang[language]).
	AssignProfile(ctx context.Context, tenantID shared.ID, projectKey, language, profileKey string) error
}

// QualityGateStore persists tenant-scoped custom gate definitions.
type QualityGateStore interface {
	Create(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate) error
	List(ctx context.Context, tenantID shared.ID) ([]qualitygate.Gate, error)
	Get(ctx context.Context, tenantID shared.ID, key string) (qualitygate.Gate, error)
	Update(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate) error
	Delete(ctx context.Context, tenantID shared.ID, key string) error
	DeleteIfUnassigned(ctx context.Context, tenantID shared.ID, key string) error
}

// QualityProfileStore persists tenant-scoped custom quality profiles (named, per-language rule sets).
// Built-in profiles are generated from the rule catalog and are never stored.
type QualityProfileStore interface {
	Create(ctx context.Context, tenantID shared.ID, profile qualityprofile.Profile) error
	List(ctx context.Context, tenantID shared.ID) ([]qualityprofile.Profile, error)
	Get(ctx context.Context, tenantID shared.ID, key string) (qualityprofile.Profile, error)
	Update(ctx context.Context, tenantID shared.ID, profile qualityprofile.Profile) error
	Delete(ctx context.Context, tenantID shared.ID, key string) error
}

// QualityGateMutator coordinates managed-gate writes, audit records, and safe custom-gate Project references.
type QualityGateMutator interface {
	CreateGate(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate, audit AuditEntry) error
	UpdateGate(ctx context.Context, tenantID shared.ID, gate qualitygate.Gate, audit AuditEntry) error
	DeleteGate(ctx context.Context, tenantID shared.ID, key string, audit AuditEntry) error
	AssignProjectGate(ctx context.Context, tenantID shared.ID, projectKey, gateID string, audit AuditEntry) error
	CreateProjectWithGate(ctx context.Context, p *project.Project) error
}

// ProjectAnalysisStore persists immutable, tenant-scoped Project analysis snapshots.
type ProjectAnalysisStore interface {
	Save(ctx context.Context, analysis projectanalysis.Analysis) error
	SaveWithResult(ctx context.Context, analysis projectanalysis.Analysis, result []byte) error
	LatestWithResult(ctx context.Context, tenantID, projectID shared.ID) (projectanalysis.Analysis, []byte, error)
	LatestForProjects(ctx context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]projectanalysis.Analysis, error)
	List(ctx context.Context, tenantID, projectID shared.ID, limit int, beforeCreatedAt time.Time, beforeID shared.ID) ([]projectanalysis.Analysis, bool, error)
	Get(ctx context.Context, tenantID, projectID, analysisID shared.ID) (projectanalysis.Analysis, error)
}

// ProjectAnalysisProjectionStore is the atomic write capability used when a
// completed Project analysis also contains Security Hotspot candidates. It is
// optional on the legacy analysis port so focused test doubles can keep their
// smaller contract; production stores implement it.
type ProjectAnalysisProjectionStore interface {
	SaveWithResultAndHotspots(ctx context.Context, analysis projectanalysis.Analysis, result []byte, candidates []hotspot.Candidate) error
}

// ProjectIssueProjectionStore is the atomic write capability for projecting a
// completed analysis's non-hotspot findings into Project issue records. A store that
// implements it persists the analysis, its hotspots, and its issues together.
type ProjectIssueProjectionStore interface {
	SaveWithResultAndProjections(ctx context.Context, analysis projectanalysis.Analysis, result []byte, hotspots []hotspot.Candidate, issues []issue.Candidate) error
}

// ProjectIssueStore reads and mutates tenant- and Project-scoped code-quality issue
// projections and their append-only triage lifecycle. It mirrors ProjectHotspotStore.
type ProjectIssueStore interface {
	ListIssues(ctx context.Context, tenantID, projectID shared.ID, filter issue.ListFilter) (issue.Page, error)
	GetIssue(ctx context.Context, tenantID, projectID, issueID shared.ID) (issue.Issue, error)
	TransitionIssue(ctx context.Context, cmd issue.TransitionCommand) (issue.Issue, issue.ReviewEvent, error)
	IssueHistory(ctx context.Context, tenantID, projectID, issueID shared.ID) ([]issue.ReviewEvent, error)
	// ResolvedIssueKeys returns the projection keys currently in a resolved (gate-exempt)
	// status for a Project, so a subsequent analysis can carry the triage forward.
	ResolvedIssueKeys(ctx context.Context, tenantID, projectID shared.ID) (map[string]bool, error)
}

// ProjectHotspotStore reads tenant- and Project-scoped hotspot projections.
// Review mutations are intentionally outside this PR's port.
type ProjectHotspotStore interface {
	ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error)
	GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error)

	TransitionHotspot(ctx context.Context, cmd hotspot.TransitionCommand) (hotspot.Hotspot, hotspot.ReviewEvent, error)
	HotspotHistory(ctx context.Context, tenantID, projectID, hotspotID shared.ID) ([]hotspot.ReviewEvent, error)
	ListAnalysisHotspots(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens, filter hotspot.ListFilter) (hotspot.Page, hotspot.Summary, error)
	CurrentAnalysisHotspotSummary(ctx context.Context, tenantID, projectID, analysisID shared.ID, lens hotspot.Lens) (hotspot.Summary, error)
}

// ProjectArchiveStore retains uploaded source archives so a Project can be re-analyzed.
type ProjectArchiveStore interface {
	Save(ctx context.Context, projectID shared.ID, filename string, src io.Reader) (string, error)
	Delete(ctx context.Context, projectID shared.ID) error
}

// EngagementRepository persists engagements. Returned aggregates are read-only –
// callers must not mutate them (implementations may return shared instances).
type EngagementRepository interface {
	Create(ctx context.Context, e *engagement.Engagement) error
	// GetByID loads an engagement by id WITHOUT a tenant predicate. It is reserved for INTERNAL
	// execution paths that act on an engagement a queued/authorized run already belongs to – the
	// scope/window execution gate, recon start/run, and agent orchestration – where tenancy was
	// already proven when the work was admitted. It is NOT a user-facing read: every request-driven
	// access (HTTP handlers and the usecase reads they call) MUST go through GetByIDInTenant so a
	// caller can only reach engagements in their own tenant. Adding a new GetByID caller on a
	// request path reintroduces a cross-tenant read – use GetByIDInTenant instead.
	GetByID(ctx context.Context, id shared.ID) (*engagement.Engagement, error)
	// GetByIDInTenant loads an engagement by id scoped to tenantID – the tenant-isolated read
	// for user-facing access. A caller's tenant '' (single-tenant / default-tenant
	// admin) matches any row; a non-empty tenant matches only its own, so tenant A cannot reach
	// tenant B's engagement (returns shared.ErrNotFound – existence is not revealed).
	GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
	// GetByProjectID loads the hidden Project analysis context scoped to tenantID.
	// It is only for Project use-case internals; normal engagement reads must use GetByIDInTenant.
	GetByProjectID(ctx context.Context, tenantID, projectID shared.ID) (*engagement.Engagement, error)
	ProjectContexts(ctx context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]*engagement.Engagement, error)
	List(ctx context.Context, tenantID shared.ID) ([]*engagement.Engagement, error)
	// Update persists changes to an existing engagement aggregate – its row
	// (name/client/status/authorization window/timezone) and its full scope target
	// set, replaced atomically. Returns shared.ErrNotFound if it does not exist.
	Update(ctx context.Context, e *engagement.Engagement) error
	// Delete removes an engagement and (via ON DELETE CASCADE) its children. Used to
	// roll back a partially-materialized import; idempotent (no error if absent).
	Delete(ctx context.Context, id shared.ID) error
}

// JudgmentStore is the broad read/create repository for AI judgments. The
// score/state MOVER is deliberately NOT here – it lives on the analysis use case's narrow Store
// interface + the concrete repo, so a read-only consumer (e.g. the agent tool catalog) cannot move
// a judgment's score. Reads are engagement-scoped (tenant-isolated via the
// engagement gate).
type JudgmentStore interface {
	// Save persists a proposed judgment (idempotent by id; never moves an existing row's score).
	Save(ctx context.Context, j judgment.Judgment) error
	// ListByEngagement returns the engagement's judgments (deterministic order).
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
	// ListBySubject returns the engagement's judgments about a given subject id.
	ListBySubject(ctx context.Context, engagementID, subjectID shared.ID) ([]judgment.Judgment, error)
}

// WriteupDraftStore persists AI-proposed, human-gated finding write-up drafts. Unlike a
// Judgment (insert-only), a Draft is mutable working data – a human edits it and then accepts/rejects
// it – so Save is an UPSERT by draft id (last write wins). Reads are engagement-scoped; tenant isolation
// is enforced upstream at the route (withEngTenant), so Get/List take no tenant argument. A Draft is NOT
// append-only and NEVER renders into a report by itself; the append-only record of each
// change is the audit log written by the use case.
type WriteupDraftStore interface {
	// Save upserts a draft by id (create on first write, replace on edit/accept/reject).
	Save(ctx context.Context, d writeupdraft.Draft) error
	// Get returns the engagement's draft by id, or shared.ErrNotFound if absent in that engagement.
	Get(ctx context.Context, engagementID, id shared.ID) (writeupdraft.Draft, error)
	// ListByEngagement returns the engagement's drafts in a deterministic order.
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error)
}

// FindingRepository upserts findings (idempotent by engagement + dedup key) and
// lists them for an engagement.
type FindingRepository interface {
	Upsert(ctx context.Context, findings []finding.Finding) error
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
	// ListPublishableByEngagement returns ONLY the findings that may appear in a
	// customer-facing deliverable – the evidence gate applied via
	// finding.Publishable/CanPromote. Every client-facing reader (report PDF/HTML/DOCX,
	// SARIF, OpenVEX, engagement bundle) MUST read through this, never ListByEngagement,
	// so an unproven exploitation finding (EvidenceScore < EvidenceThreshold) cannot leak
	// into any exported artifact. ListByEngagement remains for internal processing
	// (dedup, quality metrics, triage) that legitimately needs the full set.
	ListPublishableByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error)
	// UpdateStatus sets a finding's triage status (scoped to its engagement) with
	// optimistic concurrency: expectedVersion must match the stored version or
	// shared.ErrConflict is returned (lost-update guard). shared.ErrNotFound if no
	// such finding. The stored version is incremented on success.
	UpdateStatus(ctx context.Context, engagementID, findingID shared.ID, status finding.Status, expectedVersion int) (finding.Finding, error)
	// SetAssignee sets a finding's assignee with the same optimistic-concurrency
	// guard as UpdateStatus.
	SetAssignee(ctx context.Context, engagementID, findingID shared.ID, assignee string, expectedVersion int) (finding.Finding, error)
}

// CommentRepository persists the per-finding comment thread – the human
// collaboration record, distinct from the append-only audit log. Reads are scoped
// to the engagement (no cross-engagement comment access).
type CommentRepository interface {
	Add(ctx context.Context, c finding.Comment) error
	ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Comment, error)
}

// RetestRepository persists the per-finding retest history, engagement-scoped.
type RetestRepository interface {
	Add(ctx context.Context, r finding.Retest) error
	ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error)
}

// Provenance is the static tool/library version context captured at startup for
// scan reproducibility. Syft's version is read per scan from the SBOM.
type Provenance struct {
	ToolVersions map[string]string // e.g. {"go-enry": "v2.x", "synapse": "devel"}
	VulnDBSource string            // e.g. "osv.dev"
}

// ScanSnapshot is the reproducibility record persisted with a scan: the tool
// versions used and the vulnerability-DB snapshot marker (source + query time).
type ScanSnapshot struct {
	ToolVersions   map[string]string
	VulnDBSnapshot string
	GrypeDBVersion string // Grype vulnerability-DB build/schema (reproducibility); empty if unused
}

// ScanManifest captures everything needed to explain + replay a scan result
// (reproducibility / chain-of-custody). Stored per run.
type ScanManifest struct {
	ToolVersions       map[string]string `json:"tool_versions"`       // syft/grype/enry/synapse + *-db
	VulnDBSnapshot     string            `json:"vuln_db_snapshot"`    // osv.dev@<time> (live source marker)
	GrypeDBVersion     string            `json:"grype_db_version"`    // pinned grype DB schema@built
	CorrelationVersion int               `json:"correlation_version"` // bumped when merge logic changes
	SBOMSHA256         string            `json:"sbom_sha256"`         // hash of the generator's raw SBOM
	ReproScore         int               `json:"repro_score"`         // 0..100, fraction of pinned inputs
	PinnedInputs       []string          `json:"pinned_inputs"`       // which inputs are version-pinned
	UnpinnedInputs     []string          `json:"unpinned_inputs"`     // which are live (e.g. osv.dev)
}

// ScanRun is one persisted scan execution: its manifest plus the finding identity
// keys, enough to list history and compute drift between two runs.
type ScanRun struct {
	ID           string       `json:"id"`
	EngagementID string       `json:"engagement_id"`
	CreatedAt    time.Time    `json:"created_at"`
	Manifest     ScanManifest `json:"manifest"`
	FindingKeys  []string     `json:"finding_keys"` // dedup keys present in this run
}

// ScanRunStore persists scan-run manifests + finding keys for history + drift.
type ScanRunStore interface {
	Save(ctx context.Context, run ScanRun) error
	List(ctx context.Context, engagementID shared.ID) ([]ScanRun, error)
	Get(ctx context.Context, runID string) (ScanRun, error)
}

// ScanRepository persists an SCA scan's SBOM (with its components) and the
// vulnerabilities found against them, as an immutable snapshot.
type ScanRepository interface {
	// SaveScan persists the snapshot and returns the count of vulns that could not
	// be linked to an SBOM component (skipped, never orphaned).
	SaveScan(ctx context.Context, engagementID shared.ID, doc *sbom.SBOM, vulns []vulnerability.Vulnerability, snap ScanSnapshot) (int, error)
}

// ScanStatus is the lifecycle of an asynchronous SCA scan.
type ScanStatus string

const (
	ScanRunning   ScanStatus = "running"
	ScanSucceeded ScanStatus = "succeeded"
	ScanFailed    ScanStatus = "failed"
)

// ScanDebugStatus is the lifecycle state of one diagnostic scan step.
type ScanDebugStatus string

const (
	ScanDebugRunning   ScanDebugStatus = "running"
	ScanDebugSucceeded ScanDebugStatus = "succeeded"
	ScanDebugFailed    ScanDebugStatus = "failed"
)

// ScanDebugEvent is a safe diagnostic timeline entry for an SCA scan. It must
// contain only metadata/counts suitable for UI/API display: never raw tool
// output, environment values, file contents, secrets, or unredacted command text.
type ScanDebugEvent struct {
	Stage      string          `json:"stage"`
	Step       string          `json:"step"`
	Status     ScanDebugStatus `json:"status"`
	Message    string          `json:"message,omitempty"`
	Tool       string          `json:"tool,omitempty"`
	Counts     map[string]int  `json:"counts,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	Error      string          `json:"error,omitempty"`
}

// ScanJob tracks the progress of an asynchronous scan so the UI can show a
// progress bar and survive a page reload (the pipeline runs server-side).
type ScanJob struct {
	ID           string           `json:"id"`
	EngagementID string           `json:"engagement_id"`
	Target       string           `json:"target"`
	Kind         string           `json:"kind"`
	Status       ScanStatus       `json:"status"`
	Stage        string           `json:"stage"`
	Progress     int              `json:"progress"` // 0..100
	Error        string           `json:"error,omitempty"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   *time.Time       `json:"finished_at,omitempty"`
	DebugEvents  []ScanDebugEvent `json:"debug_events"`
}

// ScanJobStore persists scan-job status (upserted as the pipeline progresses).
type ScanJobStore interface {
	CreateRunning(ctx context.Context, job ScanJob) error
	Save(ctx context.Context, job ScanJob) error
	LatestForEngagement(ctx context.Context, engagementID shared.ID) (ScanJob, error)
	LatestForEngagements(ctx context.Context, engagementIDs []shared.ID) (map[shared.ID]ScanJob, error)
	// GetJob returns a scan job by its own id (shared.ErrNotFound if absent). Used to
	// finalize a SPECIFIC dead-lettered job rather than the engagement's latest, so a newer
	// scan for the same engagement cannot mislead the dead-letter terminal-guard.
	GetJob(ctx context.Context, id string) (ScanJob, error)
	// ListStaleRunning returns scan jobs still in status 'running' that started before
	// olderThan (bounded by limit) – the input to the stale-scan sweeper, which reclaims scans
	// a crashed worker stranded `running` without a dead-letter event.
	ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]ScanJob, error)
}

// ScanResultStore caches the latest full scan result (JSON) per engagement so the
// UI can re-display the SBOM / vulnerabilities / dependency graph / languages /
// provenance after a page reload. The normalized ScanRepository is write-only and
// omits languages + graph edges, so this stores the whole result verbatim.
type ScanResultStore interface {
	SaveResult(ctx context.Context, engagementID shared.ID, result []byte) error
	LatestResult(ctx context.Context, engagementID shared.ID) ([]byte, error)
}

// ImportedSBOMStore persists the active client-supplied SBOM for an engagement.
// Reads are tenant-scoped so request paths never disclose cross-tenant existence.
type ImportedSBOMStore interface {
	SaveActive(ctx context.Context, record importedsbom.Record) error
	LatestByEngagement(ctx context.Context, tenantID, engagementID shared.ID) (importedsbom.Record, error)
}

// EvidenceStore appends to and reads the per-engagement hash-chained evidence
// ledger. Append-only – never UPDATE/DELETE in app code.
type EvidenceStore interface {
	Append(ctx context.Context, items []evidence.Evidence) error
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]evidence.Evidence, error)
	// Head returns the last sealed hash for an engagement ("" if the chain is empty).
	Head(ctx context.Context, engagementID shared.ID) (string, error)
}

// BlobStore stores and retrieves binary artifacts content-addressed by their
// lowercase-hex SHA-256, so identical content dedups and tampering is detectable
// against the evidence chain (the same hash is sealed into the chain). Used by the
// evidence vault for screenshots, raw tool output, request/response captures, etc.
// . Put is idempotent for the same key+content.
type BlobStore interface {
	Put(ctx context.Context, sha256hex string, data []byte) error
	Get(ctx context.Context, sha256hex string) ([]byte, error)
}

// ChainSigner signs an evidence chain head, producing a detached attestation that
// proves origin (non-repudiation) on top of the chain's integrity, reinforcing the
// append-only audit trail. Implemented in infrastructure (ed25519); the evidence vault holds
// it optionally. Signing needs the private key; VERIFYING an attestation needs only
// its embedded public key (evidence.VerifyAttestation), so it is not part of this
// port. Sign must be deterministic for a given (key, head) so the report stays
// byte-reproducible.
type ChainSigner interface {
	Sign(ctx context.Context, head string) (evidence.Attestation, error)
	// PublicKey is the base64-std raw public key; KeyID is its short fingerprint.
	PublicKey() string
	KeyID() string
}

// TimestampAuthority binds a chain head to a trusted time source (RFC 3161), so a
// custody chain can prove it existed BEFORE a given instant – independent of the
// signer's own clock. Implemented in P3 (infrastructure/timestamp). Implementations
// must not block the seal path on an unreachable TSA (the vault times the call out).
type TimestampAuthority interface {
	// Timestamp returns an opaque RFC-3161 token over digest (the chain head bytes).
	Timestamp(ctx context.Context, digest []byte) (TimestampToken, error)
}

// TimestampToken is an opaque RFC-3161 timestamp token plus the authority that
// issued it. Verified by a TSA-aware client (infrastructure/timestamp.VerifyToken).
type TimestampToken struct {
	Authority string `json:"authority"`
	Token     string `json:"token"` // base64-std of the DER-encoded token
}

// TimestampStore persists external RFC-3161 tokens for chain heads OUT-OF-BAND from
// the (byte-deterministic) report – keyed by chain ("evidence"|"audit") + engagement
// + head, so a head is anchored at most once. Get returns nil when the head is not yet
// anchored. This is the side-channel that keeps the report bytes unchanged whether or
// not a TSA is configured.
type TimestampStore interface {
	Get(ctx context.Context, chain string, engagementID shared.ID, head string) (*TimestampToken, error)
	Put(ctx context.Context, chain string, engagementID shared.ID, head string, token TimestampToken) error
	// LatestHead returns the most-recently-anchored head for a chain (ok=false if none). It is
	// the RETAINED head used for out-of-band tail-truncation detection: every sealed head is
	// anchored, so if the latest retained head is no longer present in the current chain, the
	// tail was truncated (e.g. a superuser disabled the append-only trigger and deleted links).
	LatestHead(ctx context.Context, chain string, engagementID shared.ID) (head string, ok bool, err error)
}

// AUPStore persists acceptable-use-policy acceptances.
type AUPStore interface {
	Accepted(ctx context.Context, version string) (bool, error)
	Save(ctx context.Context, a aup.Acceptance) error
}

// AuditEntry is one append-only audit record.
// Hash/PreviousHash form a tamper-evident chain (same as evidence):
// the writer computes them on append and the reader returns them; they are NOT set
// by callers of Record and are excluded from the hashed content (audit.ComputeHash).
type AuditEntry struct {
	Actor        string            `json:"actor"`
	Action       string            `json:"action"`
	Target       string            `json:"target"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	At           time.Time         `json:"at"`
	Hash         string            `json:"hash,omitempty"`
	PreviousHash string            `json:"previous_hash,omitempty"`
}

// AuditLogger appends immutable, attributable audit records. The implementation
// chains each record to the previous one (Hash/PreviousHash) so the log is
// tamper-evident; callers leave those fields zero.
type AuditLogger interface {
	Record(ctx context.Context, e AuditEntry) error
}

// AuditReader reads the append-only audit log for the audit-trail UI. List
// returns the most recent entries first, capped at limit. Verify re-derives the hash
// chain over the entire log (oldest-first) and reports whether it is intact.
type AuditReader interface {
	List(ctx context.Context, limit int) ([]AuditEntry, error)
	Verify(ctx context.Context) (audit.Report, error)
}

// ReportInsight is the scan-level context the executive report needs beyond the
// findings: license coverage, scan completeness, reproducibility, and the
// evidence-integrity attestation. Assembled from the latest scan + evidence chain.
type ReportInsight struct {
	ScanTarget       string
	HasScan          bool
	ScanTime         time.Time // pinned scan timestamp – the report uses this (not Now) so it is byte-reproducible
	LicenseDetected  int
	LicenseUnknown   int
	LicensePct       float64
	Confident        bool
	CompletenessNote string
	ReproScore       int
	PinnedInputs     []string
	UnpinnedInputs   []string
	VulnDBSnapshot   string
	GrypeDBVersion   string
	EvidenceIntact   bool
	EvidenceHead     string
	EvidenceCount    int
	// EvidenceAttested + EvidenceKeyID describe the chain-head origin attestation
	// when Attested, the head is signed (ed25519) by the key with this id.
	EvidenceAttested bool
	EvidenceKeyID    string
	// Finding-quality: third-party vs first-party-historical split +
	// coverage, so the report leads with honest numbers.
	ThirdPartyFindings   int
	FirstPartyHistorical int
	VersionCoveragePct   float64
	PathCoveragePct      float64
	// Scope + priority breakdown.
	RawFindings    int
	Actionable     int
	Background     int
	Production     int
	Development    int
	ExampleTest    int
	PriorityCounts map[int]int
	// RiskRationales + CorrelationNotes are LLM-free projections of ACCEPTED (human-confirmed) AI
	// judgments — closed tokens only (drivers/priority, reporter/missing source names), never model
	// prose — so the report can surface AI risk rationale and cross-check disagreements while the report
	// path stays LLM-free. Empty unless judgments were accepted.
	RiskRationales   []RiskRationale
	CorrelationNotes []CorrelationNote
}

// RiskRationale is a rendered projection of an ACCEPTED risk-narrative judgment: the closed driver tokens
// plus the 1..5 priority. Templated tokens only — never model prose.
type RiskRationale struct {
	Subject  string   `json:"subject"` // "<kind>:<id>" the narrative is about
	Drivers  []string `json:"drivers"`
	Priority int      `json:"priority"`
}

// CorrelationNote is a rendered projection of an ACCEPTED cross-check correlation judgment: which
// detection sources reported a vuln and which did NOT — a data-quality note that never auto-resolves it.
type CorrelationNote struct {
	Subject   string   `json:"subject"`
	Reporters []string `json:"reporters"`
	Missing   []string `json:"missing"`
}

// ReportRenderer renders a deterministic PDF report from stored engagement data
// (templated, no LLM in the report path). generatedAt is supplied
// by the caller so the output – including PDF creation-date metadata – is
// reproducible from the same stored data.
type ReportRenderer interface {
	Render(ctx context.Context, eng *engagement.Engagement, findings []finding.Finding, insight ReportInsight, generatedAt time.Time, version string) ([]byte, error)
}

// ReportInsightProvider supplies the scan-level report context for an engagement
// (implemented by the SCA service, which owns the scan result + evidence chain).
type ReportInsightProvider interface {
	ReportInsight(ctx context.Context, engagementID shared.ID) (ReportInsight, error)
}

// ReportDocument is the format-agnostic, deterministic report the report use case
// assembles from stored data (no LLM in the path). DocRenderers
// turn it into HTML/DOCX bytes; identical input must yield identical bytes.
type ReportDocument struct {
	Title       string
	Subtitle    string
	GeneratedAt time.Time
	Version     string
	Sections    []ReportSection
}

// ReportSection is one ordered section: free-text paragraphs, an optional table,
// and optional inline image exhibits (captured evidence screenshots).
type ReportSection struct {
	Heading    string
	Paragraphs []string
	Table      *ReportTable
	Images     []ReportImage
}

// ReportTable is a simple header + rows grid (e.g. the findings list).
type ReportTable struct {
	Headers []string
	Rows    [][]string
}

// ReportImage is an inline raster image exhibit (a captured evidence screenshot).
// Data is the raw image bytes; MIME is a known raster type (image/png|jpeg|gif) – the
// builder rejects everything else, so renderers never embed SVG/HTML (no script). The
// renderers must keep output deterministic (same bytes -> same seal). SHA256 ties the
// exhibit to the evidence chain so a reader can verify it against the ledger.
type ReportImage struct {
	Caption string
	MIME    string
	Data    []byte
	SHA256  string
}

// EvidenceArtifact is a captured binary artifact's metadata, for embedding evidence
// exhibits in a report. The bytes are fetched separately + content-verified.
type EvidenceArtifact struct {
	Kind     string
	Filename string
	Note     string
	SHA256   string
	Size     int
}

// ReportEvidenceProvider supplies captured evidence artifacts for the report's
// exhibits section. The report use case depends on this; the evidence vault
// implements it. ArtifactBytes is engagement-scoped + re-verifies the bytes (the
// vault's existing read path), so a tampered blob never reaches a report.
type ReportEvidenceProvider interface {
	ListArtifacts(ctx context.Context, engagementID shared.ID) ([]EvidenceArtifact, error)
	ArtifactBytes(ctx context.Context, engagementID shared.ID, sha256hex string) ([]byte, error)
}

// DocRenderer renders a ReportDocument to bytes for one format (HTML, DOCX). It
// must be deterministic: the same document produces byte-identical output so the
// SHA-256 seal is reproducible (chain-of-custody).
type DocRenderer interface {
	Render(ctx context.Context, doc ReportDocument) ([]byte, error)
}

// ---- Target acquisition ----

// Target kinds for SCA acquisition.
const (
	TargetLocal   = "local"
	TargetGit     = "git"
	TargetArchive = "archive"
	TargetImage   = "image"
)

// AcquireRequest identifies a scan target and how to obtain it.
type AcquireRequest struct {
	Kind  string // local | git | archive | image (default: local)
	Value string // path, git URL, archive path, or image ref
	Ref   string // optional git branch/tag to clone (git kind only)
}

// Workspace is an isolated directory holding a target to analyze (never execute).
// Cleanup, if set, removes any temporary resources and must be called when done.
type Workspace struct {
	Dir          string
	Commit       string   // resolved Git HEAD for cloned sources; empty for local/archive/image targets
	Lockfiles    []string // recognized lockfile basenames present (scan-completeness signal)
	LocalModules []string // module paths declared in the repo (go.mod module, package.json name) – first-party identities
	// UnresolvedEcosystems are build systems present in the repo whose dependencies
	// the SBOM generator cannot fully resolve without a lockfile (e.g. Gradle/Maven),
	// so their dependency tree is likely UNDER-reported. Drives honest completeness.
	UnresolvedEcosystems []string
	// Image carries container-image metadata (manifest digest, platform, ordered
	// layer stack) when the target is an image (acquired as an OCI layout); nil for
	// source/dir/archive targets. Drives Epic D layer attribution + base-image
	// estimation. Best-effort: nil if the image config could not be read.
	Image *sbom.ImageInfo
	// RootFS is the assembled root filesystem of an image target, materialized from the OCI layout (layers
	// applied with whiteouts) when image-rootfs extraction is enabled; empty otherwise and for non-image
	// targets. Owned parsers read it for on-disk OS-package DBs + /etc/os-release. Dir stays the OCI layout
	// (what syft scans); RootFS is the walkable tree. Both live under the same cleaned-up temp dir.
	RootFS string
	// (see OSPackageCataloger for how RootFS is consumed.)
	// RootFSNote records why rootfs materialization was skipped for an image target (unsupported layer
	// compression, a hostile layer the hardening refused, a malformed layout) when extraction was enabled but
	// failed. Empty on success or when not enabled. Rootfs is best-effort – a failure never aborts the scan –
	// so the pipeline surfaces this as a warning (never silently) and a consumer treats an absent RootFS as
	// "not analyzed", never as "no OS packages".
	RootFSNote string
	Cleanup    func() error
}

// OSPackageResult is the outcome of OS-package cataloging: the components plus whether their distro release
// resolved to an advisory-matchable ecosystem. DistroResolved is false when the OS DB was read but the release
// could not be keyed (/etc/os-release absent, garbled, or inconsistent with the DB family) – so the pipeline
// surfaces a completeness warning instead of the packages silently matching zero OS advisories (a falsely-clean
// OS posture). DistroResolved is meaningful only when Components is non-empty.
type OSPackageResult struct {
	Components     []sbom.Component
	DistroResolved bool
}

// OSPackageCataloger reads a materialized image root filesystem (Workspace.RootFS) and returns the installed
// OS packages – Debian/Ubuntu dpkg (/var/lib/dpkg/status) and Alpine apk (/lib/apk/db/installed) – as SBOM
// components, each tagged (when the release resolves) with a Syft-style distro qualifier
// (distro=debian-12/ubuntu-22.04/alpine-3.18.12, from /etc/os-release) so the existing advisory matcher keys
// them to the right OS ecosystem. It is the owned (detection-independent) alternative to relying on the
// generator for OS packages. An empty result means "OS not analyzed", never "no OS packages" (a hostile image
// can legitimately yield an empty rootfs).
type OSPackageCataloger interface {
	Catalog(ctx context.Context, rootfsDir string) (OSPackageResult, error)
}

// InstalledPackageCataloger reads a materialized image root filesystem for installed LANGUAGE packages a
// lockfile would miss: Go module dependencies embedded in compiled binaries (debug/buildinfo) and Python
// distributions installed on disk (dist-info/egg-info). Components carry the language PURL (pkg:golang /
// pkg:pypi) so the advisory matcher keys them. It is the owned, detection-independent inventory of what a
// SHIPPED image actually contains (e.g. a scratch image with one static Go binary and no go.mod). Empty when
// the rootfs has no such artifacts.
type InstalledPackageCataloger interface {
	CatalogInstalled(ctx context.Context, rootfsDir string) ([]sbom.Component, error)
}

// Completeness signals how trustworthy a scan's results are: whether dependency
// versions were actually resolved. Scanning source WITHOUT a lockfile yields
// unresolved versions, so a "0 vulnerabilities" result must NOT be read as clean.
type Completeness struct {
	Lockfiles          []string `json:"lockfiles"`
	ComponentsTotal    int      `json:"components_total"`
	ComponentsResolved int      `json:"components_resolved"`
	Confident          bool     `json:"confident"`
	Warning            string   `json:"warning,omitempty"`
}

// Close runs Cleanup if present (safe on nil).
func (w *Workspace) Close() error {
	if w == nil || w.Cleanup == nil {
		return nil
	}
	return w.Cleanup()
}

// Acquirer prepares an isolated workspace for a target: fetch/validate,
// enforce a size cap, and never execute the artifact.
type Acquirer interface {
	Acquire(ctx context.Context, req AcquireRequest) (*Workspace, error)
}

// GateDecoder parses a repository quality-gate document after SCA acquires its workspace.
type GateDecoder func([]byte) (qualitygate.Gate, error)

// ---- SCA tool ports (implemented by infrastructure/tools adapters) ----

// DetectedLanguage is a language and its share of a scanned target.
type DetectedLanguage struct {
	Name    string
	Percent float64
}

// LanguageDetector detects the source languages of a target (e.g. go-enry).
type LanguageDetector interface {
	Detect(ctx context.Context, targetPath string) ([]DetectedLanguage, error)
}

// SBOMGenerator is the vendor-neutral SBOM-PRODUCER port: an implementation runs
// any producer (Syft today, an owned per-ecosystem parser registry under E33, or another tool) and
// returns the NORMALIZED domain sbom.SBOM – no vendor/CycloneDX type ever crosses this boundary, so
// the business logic stays independent of any one scanner (enforced by the vendor-neutral tripwire in
// internal/domain/sbom). Producer identity + version ride on the returned SBOM (Source, GeneratorVersion).
type SBOMGenerator interface {
	Generate(ctx context.Context, targetRef string) (*sbom.SBOM, error)
}

// SBOMCache is an optional content-addressed cache of GENERATED (pre-enrichment) SBOMs. The key is derived
// from the workspace CONTENT plus the producer VERSION, so an unchanged source re-scanned with the same
// producer reuses the SBOM (skipping the expensive cataloging step), while a producer version bump
// invalidates the entry – Trivy's analyzer-version cache-invalidation model. The implementation owns the
// key derivation (it walks dir) so filesystem I/O stays in the infrastructure layer; the usecase only
// supplies the pure producerVersion string. It preserves SBOM.Raw (which is json:"-") so a cache hit still
// hands a downstream detector (Grype) the EXACT original document, not a lossy reconstruction. Best-effort:
// an empty producerVersion, an uncomputable key, or any cache error is a silent miss, NEVER a scan failure.
type SBOMCache interface {
	// Load returns the cached SBOM for (dir, producerVersion) when present + fresh; ok=false on a miss.
	Load(ctx context.Context, dir, producerVersion string) (*sbom.SBOM, bool, error)
	// Store caches doc for (dir, producerVersion). A store failure is non-fatal to the caller.
	Store(ctx context.Context, dir, producerVersion string, doc *sbom.SBOM) error
}

// ReachabilitySubject is one finding to assess for reachability: its id (the judgment subject) + the
// advisory's affected symbols ("importPath.Symbol"). Lives here (not in a usecase) so a producer like the
// SCA pipeline can feed the reachability recorder without importing the reachproof use case.
type ReachabilitySubject struct {
	FindingID shared.ID
	Symbols   []string
}

// ReachabilityRecorder runs deterministic reachability over a target and records the resulting Tier-2
// judgments. It is the seam the SCA pipeline calls post-scan; reachproof.Coordinator implements
// it. Returns the number of judgments minted. A no-coverage build error is returned (the caller treats
// reachability as a best-effort enhancement – a lower reachability tier stands, never a false negative).
type ReachabilityRecorder interface {
	Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ReachabilitySubject) (int, error)
}

// JVMReachabilityAnalyzer computes COARSE, deterministic JVM class-reachability and tags each
// component's sbom.Reachability IN PLACE: starting from the application's own compiled classes, does the
// closure of class references reach any of a dependency's classes? A dependency the app never references
// is "present but not wired in". Returns the number of components tagged. BEST-EFFORT + CONSERVATIVE: a
// non-JVM / not-built target tags nothing (never emits "unreferenced" without app roots), and it only
// DEPRIORITIZES a finding, never suppresses one (an unreferenced verdict is "no static reference found",
// not proof of dead code – reflection/DI/ServiceLoader are invisible to it). Reads compiled bytecode
// only; never executes it. The SCA pipeline calls it best-effort post-resolve; an error is ignored.
type JVMReachabilityAnalyzer interface {
	Analyze(ctx context.Context, wsDir string, comps []sbom.Component) (int, error)
}

// CallGraphBuilder is the deterministic call-graph PRODUCER port: an implementation
// runs a language's builder (the Go MVP shells govulncheck-class via argv, sandboxed) over a target and
// returns the NORMALIZED domain callgraph.Graph – no tool/analysis type crosses this boundary. The Graph
// is the seam reachability proof + taint consume.
//
// The two "empty" cases must be signaled DISTINCTLY (the soundness of every downstream reachability
// verdict rests on this):
// NO COVERAGE – the target could not be analyzed (un-buildable module, unsupported language, tool
// failure): return a non-nil ERROR. The caller degrades to a lower reachability tier; it must NOT
// read this as "nothing reachable".
// SUCCESSFUL but nothing reached – the analysis ran and the symbol(s) genuinely are not called:
// return a non-nil Graph (possibly with no edges), nil error. This is DEFINITIVE not-reachable.
//
// A successful build must return a non-nil Graph (an empty &callgraph.Graph{}, never nil).
type CallGraphBuilder interface {
	Build(ctx context.Context, targetRef string) (*callgraph.Graph, error)
}

// PyImportGraph is the first-party Python import surface a PyImportScanner extracts (source-only, no
// execution): the top-level modules imported by first-party code, the first-party module roots (provenance
// for the reachability proof), and whether first-party code uses DYNAMIC imports (importlib/__import__),
// which make a static "package not imported" conclusion UNSAFE. Counts bound the evidence.
type PyImportGraph struct {
	ImportedModules   []string // top-level module names appearing in first-party absolute imports
	FirstPartyModules []string // the project's own top-level modules (import roots), for provenance
	DynamicImports    bool     // first-party code uses __import__ / importlib – a not-imported conclusion is unsafe
	FilesScanned      int
}

// PyImportScanner reads a target's FIRST-PARTY Python source and returns its import surface. It is
// SOURCE-ONLY (line/AST parse, never compiles or executes the target) and reads no file contents beyond
// import statements, so — unlike the sandboxed go/ssa call-graph builder (which compiles the target) — it
// runs in-process, like the pure-Go lockfile parsers. It bounds its walk (file count/size) and skips
// vendored/virtualenv trees so installed third-party source never pollutes the first-party import set. A
// target with no Python source returns an error (no coverage), NOT an empty graph.
type PyImportScanner interface {
	ScanImports(ctx context.Context, dir string) (PyImportGraph, error)
}

// TaintScanner is the OPTIONAL taint-analysis hook: given a built target, it runs the
// deterministic taint engine (call-graph + injection catalog) and PROPOSES gated CapSAST judgments – one
// per reported injection path × class – for a distinct verifier to gate. It only proposes; it never
// confirms. The SCA pipeline drives it best-effort post-scan: a no-coverage/un-buildable target returns an
// error that is IGNORED (taint is an enhancement; the scan is never failed). Returns the number proposed.
type TaintScanner interface {
	Scan(ctx context.Context, engagementID shared.ID, targetRef string) (int, error)
}

// DependencyGraphResolver augments a generated SBOM with transitive dependency EDGES that a static
// lockfile/manifest parse cannot provide on its own – e.g. Go modules, whose edge graph is not in go.mod
// but in the module cache, read via `go mod graph`. Unlike SBOMEnricher (pure file reads), an
// implementation MAY run a sandboxed tool. Best-effort: the SCA pipeline calls it post-SBOM; a non-matching
// or un-resolvable target (no module cache, not a Go project) adds no edges and never fails the scan.
// Returns the number of edges (DependsOn targets) added. Implementations must add edges ONLY between
// components already in the SBOM (no phantom edges).
type DependencyGraphResolver interface {
	ResolveEdges(ctx context.Context, dir string, doc *sbom.SBOM) (int, error)
}

// MavenResolver resolves a Maven project's FULL dependency tree (direct + transitive, with the real
// versions) from its pom.xml – which a static parse cannot do, because Maven versions are managed by
// the parent BOM (absent from pom.xml ⇒ syft reports them UNKNOWN) and transitive deps are not listed
// at all. It returns the resolved components for the SCA pipeline to fold into the SBOM, closing the
// "Maven-from-source under-reports" gap (a pom-only scan otherwise misses the transitive CVEs).
//
// SAFETY: unlike a static parse, an implementation RUNS the Maven toolchain over untrusted project
// configuration (parent POMs, the dependency plugin) and reaches a package repository – so a
// production implementation MUST run sandbox-confined with egress restricted to the configured Maven
// repository, exactly like the source-compiling analyzers. Best-effort + OPT-IN: a non-Maven target,
// a missing mvn binary, or any resolution error returns no components and never fails the scan.
type MavenResolver interface {
	Resolve(ctx context.Context, dir string) ([]sbom.Component, error)
}

// GradleResolver resolves a Gradle project's FULL dependency tree (direct + transitive, with the
// resolved versions) from its build script – which a static parse cannot do, because Gradle versions
// are often supplied by a platform/BOM or version catalog (absent from the declaration ⇒ UNKNOWN) and
// transitive deps are not listed. Like MavenResolver it returns versioned pkg:maven components (Gradle
// uses Maven coordinates) for the SCA pipeline to fold in.
//
// SAFETY: even higher-risk than Maven – evaluating build.gradle / settings.gradle RUNS arbitrary
// Groovy/Kotlin build logic during configuration. So a production implementation MUST run sandbox-
// confined with egress restricted to the configured repositories, and it must NOT execute the project's
// own `./gradlew` wrapper (a pinned `gradle` binary only). Best-effort + OPT-IN: a non-Gradle target, a
// missing gradle binary, or any resolution error returns no components and never fails the scan.
type GradleResolver interface {
	Resolve(ctx context.Context, dir string) ([]sbom.Component, error)
}

// NPMResolver resolves an npm project's FULL dependency tree (direct + transitive, with pinned versions)
// from a package.json that has NO committed lockfile — the common raw-source state where the manifest
// declares only semver RANGES and the SBOM otherwise sees no resolvable version to advisory-match. It
// returns versioned pkg:npm components for the SCA pipeline to fold in.
//
// SAFETY: package.json can declare lifecycle scripts (preinstall/install/postinstall) that run arbitrary
// code. A production implementation MUST run sandbox-confined with egress restricted to the registry and
// MUST resolve the lockfile only (--ignore-scripts, no node_modules, no build) so no project code executes.
// Best-effort + OPT-IN: a non-npm target, a committed lockfile, a missing npm binary, or any resolution
// error returns no components and never fails the scan.
type NPMResolver interface {
	Resolve(ctx context.Context, dir string) ([]sbom.Component, error)
}

// ManifestResolver resolves a lockfile-less package manifest (composer.json / Gemfile / pyproject.toml,
// ...) to a pinned component tree by running the ecosystem's own lock tool in a no-scripts, lock-only
// mode over a throwaway copy. Ecosystem() labels it for tracing. Several may be registered; each is a
// no-op when its manifest is absent or a committed lockfile is present. Best-effort + OPT-IN; a
// production implementation MUST run sandbox-confined (untrusted manifest, reaches the registry).
type ManifestResolver interface {
	Ecosystem() string
	Resolve(ctx context.Context, dir string) ([]sbom.Component, error)
}

// SBOMEnrichment is what an SBOMEnricher contributed, for honest provenance.
type SBOMEnrichment struct {
	ComponentsAdded   int      // components the generator missed (Maven/Gradle direct deps)
	EdgesAdded        int      // dependency edges reconstructed (e.g. Gemfile.lock graph)
	ScopesRefined     int      // components re-scoped from workspace attribution (pnpm importers)
	ChecksumsAttached int      // components given a lockfile integrity digest the generator omitted (npm/pnpm/Cargo/Pipfile)
	Sources           []string // which manifest parsers contributed (gemfile, pnpm, maven, gradle, checksums)
}

// SBOMEnricher augments a generator's SBOM from dependency manifests the generator
// under-uses: it reconstructs missing dependency edges (Gemfile.lock), adds
// dependencies the generator couldn't resolve (Maven pom.xml, Gradle version
// catalogs), and refines component scope via workspace attribution (pnpm
// importers). Reads only manifest files already in the workspace – no execution.
type SBOMEnricher interface {
	Enrich(ctx context.Context, dir string, doc *sbom.SBOM) SBOMEnrichment
}

// DetectionSource is one vulnerability detector (OSV, Grype, …). The SCA service
// runs EVERY source against the same Syft SBOM and correlates the results, so
// sources augment – not replace – each other. A source returns raw
// findings; the domain correlator (vulnerability.Correlate) merges them into
// unified vulnerabilities with multi-source confidence.
type DetectionSource interface {
	Name() string
	Scan(ctx context.Context, doc *sbom.SBOM) ([]vulnerability.RawFinding, error)
}

// AdvisoryStore is the OWNED normalized-advisory store: query the advisories that affect a package
// in an ecosystem, so detection matches against our store (offline, reproducible) instead of a live
// third-party service. ByPackage returns the candidate advisories for (ecosystem, name); the caller runs
// the owned matcher (advisory.Match) to decide which actually affect the component's version.
//
// KEY CONTRACT (the ingester normalizes ON WRITE; advisory.Match compares case-sensitively): ecosystem is
// the exact OSV-canonical name ("Go", "npm", "PyPI", "crates.io", "Maven", "RubyGems", "NuGet"); the
// package name is the ecosystem's canonical id matching the SBOM component's Name – notably **Maven is
// "groupId:artifactId"** (colon), Go is the module path. A casing/format divergence between the stored
// AffectedPackage.{Ecosystem,Package} and the query key silently yields no match (a missed CVE), so the
// store + the SBOM producer MUST agree per ecosystem.
type AdvisoryStore interface {
	ByPackage(ctx context.Context, ecosystem, name string) ([]advisory.Advisory, error)
}

// CorrelationRecorder turns a cross-check DISAGREEMENT report into Judgments for human review.
// The SCA pipeline computes the report (vulnerability.CrossCheck over its multi-source
// RawFindings) and hands it here; the recorder proposes one UNGATED CapCorrelation judgment per NEW
// disagreement (idempotent on re-scan), which a human acknowledges via Accept – never auto-resolved.
// crosscheckjudge.Coordinator implements it; injected from the composition root (not agent-reachable).
type CorrelationRecorder interface {
	Record(ctx context.Context, engagementID shared.ID, report vulnerability.CrossCheckReport) (int, error)
}

// SBOMCrossCheckRecorder turns an SBOM-PRODUCER disagreement report into Judgments for human review
// (SBOM side). When ≥2 SBOM producers run (e.g. an owned parser registry + Syft), the
// SCA pipeline computes the report (sbom.CrossCheck over the two component sets) and hands it here; the
// recorder proposes one UNGATED CapCorrelation judgment (subject = component) per NEW disagreement
// (idempotent on re-scan), which a human acknowledges via Accept – never auto-resolved.
// sbomcrosscheckjudge.Coordinator implements it; injected from the composition root (not agent-reachable).
type SBOMCrossCheckRecorder interface {
	Record(ctx context.Context, engagementID shared.ID, report sbom.CrossCheckReport) (int, error)
}

// ConfirmedThreatRecorder promotes a human-ratified STRIDE threat judgment to a persisted Kind=threat
// finding (auto-emit on ratify). The analysis verify path calls it best-effort after a `threat`
// judgment reaches Confirmed; the finding is a deterministic, templated projection (no LLM). Implemented by
// the findings use case and injected from the composition root – the judgment lifecycle never imports it.
type ConfirmedThreatRecorder interface {
	RecordConfirmedThreat(ctx context.Context, verifier string, j judgment.Judgment) error
}

// ConfirmedSASTRecorder promotes a verifier-confirmed CapSAST (taint) judgment to a persisted Kind=sast
// finding (auto-emit on confirm). The analysis verify path calls it best-effort after a `sast`
// judgment reaches Confirmed; the finding is a deterministic, templated projection of the SASTClaim (no
// LLM in the report path). Implemented by the findings use case and injected from the composition root – the
// judgment lifecycle never imports it, and it is never agent-reachable.
type ConfirmedSASTRecorder interface {
	RecordConfirmedSAST(ctx context.Context, verifier string, j judgment.Judgment) error
}

// ConfirmedDASTRecorder promotes a RUNTIME-verifier-confirmed CapSAST judgment to a persisted Kind=dast
// finding (auto-emit on runtime confirm). The analysis runtime-verify path calls it best-effort after a
// `sast` judgment reaches Confirmed VIA A RUNTIME PROBE (as opposed to a static/LLM verdict, which emits
// Kind=sast); the finding is a deterministic, templated projection of the SASTClaim (no LLM). Implemented by
// the findings use case and injected from the composition root – the judgment lifecycle never imports it,
// and it is never agent-reachable (the agent proposes; a distinct verifier confirms).
type ConfirmedDASTRecorder interface {
	RecordConfirmedDAST(ctx context.Context, verifier string, j judgment.Judgment) error
}

// FindingWriteupApplier applies an accepted, human-signed-off write-up draft to its finding: it sets
// the finding's authoritative Description (the draft's prose, composed from description + remediation). The
// writeupdraft accept path calls it; the implementation MUST validate the finding belongs to the engagement
// before mutating (no cross-engagement write) and audit the change. Implemented by the findings use case and
// injected from the composition root – writeupdraftuc reaches findings ONLY through this narrow port.
type FindingWriteupApplier interface {
	ApplyWriteupDraft(ctx context.Context, actor string, engagementID, findingID shared.ID, description, remediation string) error
}

// ThreatModelStore persists the architecture-input threat model per engagement: ONE model
// per engagement (Save upserts). Born tenant-aware (R9) – Save records tenant_id so the row-scoping sweep
// covers it – while Get is engagement-scoped, because the tenant-gated child route verifies engagement∈tenant
// before the handler runs (mirrors the judgment store). Get returns ok=false when no model has been ingested.
type ThreatModelStore interface {
	Save(ctx context.Context, engagementID, tenantID shared.ID, m threatmodel.Model) error
	Get(ctx context.Context, engagementID shared.ID) (threatmodel.Model, bool, error)
}

// AdvisoryWriter loads normalized advisories into the owned store during ingestion. It is deliberately
// SEPARATE from the read-only AdvisoryStore so a read consumer (the owned DetectionSource) cannot reach the
// mutator – only the ingester holds this narrow writer (mirrors how the score-mover is kept off the broad
// JudgmentStore). Upsert is idempotent by advisory id: advisories are re-syncable reference data, so a
// re-ingest REPLACES in place (not append-only). The ingester must pass ingester-NORMALIZED keys per the
// AdvisoryStore KEY CONTRACT.
type AdvisoryWriter interface {
	Upsert(ctx context.Context, a advisory.Advisory) error
}

// AdvisoryFeed streams normalized advisories from a bulk source – a local OSV dump directory today, a remote
// OSV/GHSA bulk snapshot later. It yields DOMAIN advisories: the OSV/feed-format parsing is the
// feed's concern, so the ingester stays feed-agnostic. Each invokes fn once per parseable advisory and
// returns the count of source entries it had to SKIP (unparseable/oversized – best-effort bulk ingest, never
// abort the whole sync for one bad record) plus a fatal source error (I/O, cancellation). An error returned
// by fn aborts iteration and is propagated. Reporting `skipped` keeps a sparse/partial sync visible (no
// silent gap) rather than masquerading as a complete corpus.
type AdvisoryFeed interface {
	Each(ctx context.Context, fn func(a advisory.Advisory) error) (skipped int, err error)
}

// SourceProvenance is implemented by detection sources that can report the tool +
// vulnerability-DB version they used, for reproducibility provenance.
// Optional: the service type-asserts it after a scan.
type SourceProvenance interface {
	Provenance() (version, dbVersion string)
}

// SASTRawFinding is one deterministic SAST hit: a weakness located at file:line by a named
// rule. Severity + CWE are pattern-determined; no CVSS, no LLM, no prose beyond the static description.
type SASTRawFinding struct {
	File        string // path relative to the scanned source root
	Line        int    // 1-indexed
	RuleID      string // e.g. "weak-hash-md5"
	CWE         string // e.g. "CWE-327"
	Severity    shared.Severity
	Title       string
	Description string
	// AppSec proof fields are deterministic, bounded context extracted by the in-tree analyzer.
	// They are not exploit proof by themselves; they give the agent/human a static-analysis-grade
	// validation envelope without sending raw source to an LLM or running active probes.
	OWASP2025             string // best-effort OWASP Top 10 bucket for appsec reporting/triage
	EntryPoint            string // route/handler/function surface, when statically visible
	Source                string // attacker-controlled or lifecycle source, when visible
	SourceEvidence        string // bounded source cue location/label, no raw source bytes
	Sink                  string // dangerous operation/control point inferred from the rule/CWE
	SinkEvidence          string // bounded sink/control location/label, no raw source bytes
	ControlEvidence       string // route/middleware/function cue location/label, no raw source bytes
	RouteMiddleware       string // route-level or inherited middleware cue, no raw source bytes
	AuthEvidence          string // bounded auth/public exposure cue, no raw source bytes
	Exposure              string // public/authenticated/role-scoped/unknown exposure summary
	TrustBoundary         string // inferred boundary crossed by the source->sink path
	Impact                string // static impact hypothesis for validation triage
	Route                 string // nearest route/handler surface, when statically visible
	AuthScope             string // unauthenticated/authenticated/role-scoped/unknown
	RoleCheck             string // nearest role/permission cue, if any
	DataFlow              string // source -> sink summary, or explicit proof gap
	DataFlowEvidence      string // direct/variable/context proof label for source reaching sink
	DataFlowConfidence    string // direct|propagated|interprocedural|cross-file|variable-derived|sanitized|guarded|context-only|not-applicable|missing
	Preconditions         string // attacker/role/deployment conditions still needed for exploitation
	CounterEvidence       string // nearby mitigations or explicit proof gaps that challenge reportability
	ValidationRubric      string // compact source/control/sink/counterevidence checklist
	ValidationMethod      string // e.g. static-code-understanding
	ValidationDisposition string // reportable-static-candidate/deferred-proof-gap/needs-review-counterevidence/needs-runtime-proof/false-positive-static
	Exploitability        string // candidate-level reachability/exploitability calibration
	AttackPath            string // concise attacker story/hypothesis, never runtime-confirmed
	Confidence            string // high/medium/low candidate confidence
	SeverityRationale     string // why severity should or should not be promoted
}

// SASTAnalyzer scans first-party SOURCE for deterministic weaknesses (weak crypto, hardcoded
// secrets, insecure config). It reads the workspace root in-process and NEVER executes anything;
// findings are deterministic (no LLM), so they publish like SCA (ungated – ProposedBy == "").
type SASTAnalyzer interface {
	Name() string
	AnalyzeSource(ctx context.Context, root string) ([]SASTRawFinding, error)
}

// SecretRawFinding is one hardcoded-secret hit located at file:line in the scanned source. The Match is
// ALWAYS a redacted preview (never the raw secret): the scanner masks the value before it leaves the
// adapter, so a leaked credential never re-enters logs, the transcript, the evidence seal, or the report.
type SecretRawFinding struct {
	File     string // path relative to the scanned source root
	Line     int    // 1-indexed
	RuleID   string // e.g. "aws-access-key-id"
	Category string // e.g. "AWS"
	Title    string // human title, e.g. "AWS access key ID"
	Severity shared.Severity
	Match    string // REDACTED preview only (e.g. "AKIA****...**7X"), never the full secret
}

// SecretScanner detects hardcoded secrets (tokens, keys, private-key blocks) in a prepared workspace. It is
// deterministic and READ-ONLY, and it must redact every match before returning it. Best-effort: a walk
// error is a per-file skip, never a scan failure. Results become ungated Kind=secret findings.
type SecretScanner interface {
	Name() string
	ScanFiles(ctx context.Context, root string) ([]SecretRawFinding, error)
}

// MisconfigRawFinding is one insecure infrastructure-as-code / config setting located at file:line, tied
// to the resource it applies to (e.g. "Deployment/api" or "Dockerfile").
type MisconfigRawFinding struct {
	File        string // path relative to the scanned source root
	Line        int    // 1-indexed (best-effort; the resource/instruction line)
	RuleID      string // e.g. "kubernetes-privileged"
	Title       string // human title, e.g. "Privileged container"
	Severity    shared.Severity
	Resource    string // what it applies to, e.g. "Deployment/api" or "Dockerfile FROM"
	Description string // what is wrong + how to fix
}

// SuppressionLoader reads a repo-committed suppression policy (.synapseignore) from a prepared workspace.
// It is READ-ONLY and best-effort: a missing file yields an empty set with no error, and any read/parse
// issue degrades to fewer rules rather than failing a scan. Applying the policy – and SURFACING every
// suppressed finding rather than silently dropping it – is the SCA pipeline's job; this only loads the
// declared accepted-risk decisions.
type SuppressionLoader interface {
	Load(ctx context.Context, dir string) (ignore.Set, error)
}

// VEXLoader reads an in-repo OpenVEX document (.synapse.vex.json) from a prepared workspace: the
// machine-readable accepted-risk counterpart to .synapseignore – a maintainer's not_affected/fixed
// assertions with a justification. READ-ONLY and best-effort: a missing file yields an empty document with
// no error; a malformed/oversized one returns an error the pipeline surfaces (never a scan failure).
// Applying it – annotating matched findings accepted-risk on the SAME retain-and-mark surface, never
// removing them – is the SCA pipeline's job.
type VEXLoader interface {
	Load(ctx context.Context, dir string) (vex.Document, error)
}

// MisconfigScanner detects insecure IaC/config (Dockerfile, Kubernetes manifests, ...) in a prepared
// workspace with owned, deterministic checks (no external policy engine). READ-ONLY and best-effort: a
// parse or walk error is a per-file skip, never a scan failure. Results become ungated Kind=misconfig
// findings.
type MisconfigScanner interface {
	Name() string
	ScanConfigs(ctx context.Context, root string) ([]MisconfigRawFinding, error)
}

// RiskResult is the output of risk enrichment: vulns annotated with KEV + EPSS,
// plus the data-source versions (for reproducibility provenance).
type RiskResult struct {
	Vulns    []vulnerability.Vulnerability
	Versions map[string]string // source versions only, e.g. {"kev-catalog":..., "epss-date":...}
	Matches  map[string]int    // per-scan match counts (kev/epss) – diagnostic, NOT versions
}

// RiskEnricher annotates vulnerabilities with CISA KEV + EPSS so they can be
// ordered by real risk priority (KEV -> EPSS x CVSS). It is BEST-EFFORT: a
// data-source outage leaves the vulns unenriched rather than failing the scan.
type RiskEnricher interface {
	Enrich(ctx context.Context, vulns []vulnerability.Vulnerability) RiskResult
}

// SeverityResult is the output of severity backfill: vulns whose UNKNOWN severity was
// filled in from an authoritative CVSS source, plus a diagnostic match count.
type SeverityResult struct {
	Vulns   []vulnerability.Vulnerability
	Source  string // the CVSS source used, e.g. "nvd"
	Matches int    // how many unknown-severity vulns were backfilled (diagnostic)
}

// SeverityEnricher backfills the severity + CVSS of vulnerabilities the detection sources
// left UNKNOWN (e.g. an OSV-only distro CVE that carries no CVSS) from an authoritative
// CVSS source (NVD). It ONLY fills unknown severities – it never overrides a source's
// verdict – and is BEST-EFFORT + bounded: a slow/absent source leaves them unknown rather
// than failing or hanging the scan. Runs BEFORE risk enrichment so risk priority can use
// the backfilled CVSS.
type SeverityEnricher interface {
	Enrich(ctx context.Context, vulns []vulnerability.Vulnerability) SeverityResult
}

// LicenseVerdict is the policy outcome for a license.
type LicenseVerdict string

const (
	LicenseAllow LicenseVerdict = "allow"
	LicenseWarn  LicenseVerdict = "warn"
	LicenseDeny  LicenseVerdict = "deny"
)

// LicenseFinding is a distinct license across the SBOM, its category, the policy
// verdict, and the components that use it.
type LicenseFinding struct {
	License  string               `json:"license"` // SPDX id or expression
	Category sbom.LicenseCategory `json:"category"`
	Verdict  LicenseVerdict       `json:"verdict"`
	// RiskCategory + Severity are the ADDITIVE industry-standard risk classification
	// (forbidden/restricted/reciprocal/notice/permissive/unencumbered → critical/high/
	// medium/low), derived from SPDX + Google licenseclassifier. They complement (never
	// replace) Verdict; empty when the scanner predates this field.
	RiskCategory string   `json:"risk_category"`
	Severity     string   `json:"severity"`
	Components   []string `json:"components"`
}

// LicenseEnricher fills in missing component licenses from package-registry
// metadata. It is BEST-EFFORT: a registry outage marks the component
// with an UnknownReason rather than failing the scan. It mutates and returns the
// same component slice (license fields populated where resolved).
type LicenseEnricher interface {
	Enrich(ctx context.Context, comps []sbom.Component) []sbom.Component
}

// MavenCoordResolver recovers authoritative Maven coordinates for components whose PURL
// groupId was mis-derived during SBOM generation (e.g. Syft inferring the group from a
// JAR's class namespace), by reading each JAR's embedded pom.properties from the prepared
// workspace. It corrects the component PURL in place (deterministic, offline, read-only)
// so the downstream registry license lookup hits the right package. Returns the number
// of components corrected. Best-effort: never fails the scan.
type MavenCoordResolver interface {
	Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int
}

// JarChecksumResolver captures the artifact SHA-1 of each JVM component's JAR by hashing the file in the
// prepared workspace, when the SBOM generator supplied none (Syft computes a JAR digest but omits it from
// its CycloneDX output). It sets Component.SHA1 + a Checksums entry IN PLACE for components that have a JAR
// on disk and no existing SHA-1, and returns the count set. This both feeds the SBOM checksum quality
// element and unblocks JarHashResolver (which needs a SHA-1 as input). Deterministic, offline, read-only,
// bounded, and symlink-guarded; best-effort – an unreadable JAR is skipped, never fatal.
type JarChecksumResolver interface {
	Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int
}

// JarHashResolver recovers the Maven coordinate of a JVM component that carries NO usable in-file
// identity – a shaded / relocated / renamed JAR whose pom.properties was stripped, which MavenCoordResolver
// therefore cannot fix – by looking its artifact SHA-1 up against a coordinate index.
// It corrects the component PURL + name + version IN PLACE and returns the number of components recovered.
// Only components with a SHA-1 and an UNRESOLVED coordinate are queried; a single unambiguous match is
// adopted, anything else is left unchanged (never guess). Best-effort: a lookup error /
// unreachable index / rate-limit is a no-op that never fails the scan.
type JarHashResolver interface {
	Resolve(ctx context.Context, comps []sbom.Component) int
}

// LicenseFileResolver fills a component's license from the license TEXT embedded in its
// artifact in the prepared workspace (e.g. META-INF/LICENSE inside a JAR), classified to
// an SPDX id. It is the deterministic, OFFLINE fallback for components the registry left
// unknown (Slice 2): read-only, best-effort, never fails the scan. Mutates the
// passed slice in place and returns the number of components resolved.
type LicenseFileResolver interface {
	Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int
}

// LicenseScanner classifies component licenses and evaluates them against policy.
type LicenseScanner interface {
	Scan(ctx context.Context, doc *sbom.SBOM) ([]LicenseFinding, error)
}

// RuleCatalog is the first-party immutable reference data repository for rules.
// It is read-only.
type RuleCatalog interface {
	List(ctx context.Context) ([]rule.Rule, error)
	Get(ctx context.Context, key rule.Key) (rule.Rule, error)
}

package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type IdentityBackfillState string

const (
	IdentityBackfillRunning   IdentityBackfillState = "running"
	IdentityBackfillCompleted IdentityBackfillState = "completed"
	IdentityBackfillCancelled IdentityBackfillState = "cancelled"
	IdentityBackfillFailed    IdentityBackfillState = "failed"
)

// LegacyHumanSnapshot is the bounded legacy source shape consumed by D4. users remains the source
// of truth throughout this phase; projections must never mutate this value or infer identity from
// mutable OIDC/email claims.
type LegacyHumanSnapshot struct {
	TenantID   shared.ID
	UserID     shared.ID
	Name       string
	Role       user.Role
	APIKeyHash string
	Disabled   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type IdentityBackfillRun struct {
	TenantID        shared.ID
	ID              shared.ID
	SchemaVersion   int
	BatchSize       int
	SnapshotAt      time.Time
	CheckpointUser  shared.ID
	State           IdentityBackfillState
	LeaseOwner      string
	LeaseToken      shared.ID
	LeaseExpiresAt  time.Time
	ProcessedCount  int
	ProjectedCount  int
	UnchangedCount  int
	DriftCount      int
	SourceCount     int
	PersonCount     int
	MembershipCount int
	CreatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CompletedAt     *time.Time
}

type IdentityBackfillAcquireRequest struct {
	Run           IdentityBackfillRun
	ResumeAfter   shared.ID
	LeaseDuration time.Duration
}

type IdentityBackfillItem struct {
	TenantID     shared.ID
	RunID        shared.ID
	UserID       shared.ID
	PersonID     shared.ID
	MembershipID shared.ID
	SourceHash   string
	Outcome      string
	ReasonCode   string
	ProcessedAt  time.Time
}

type IdentityBackfillReconciliation struct {
	SourceCount              int
	PersonCount              int
	MembershipCount          int
	DriftCount               int
	CorruptCredentialCount   int
	DuplicateCredentialCount int
	BootstrapMembershipCount int
}

// IdentityBackfillSource exposes only tenant-bound, checkpointed legacy reads. The snapshot bound
// freezes row admission (created_at) while still observing concurrent updates to admitted rows so
// final reconciliation can surface drift instead of silently repairing the legacy source.
type IdentityBackfillSource interface {
	ListLegacyHumans(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) ([]LegacyHumanSnapshot, error)
}

// IdentityBackfillStore owns the lease/fence and commits one legacy projection plus its item record
// atomically. ProjectLegacyHuman may create missing derived rows, but if an existing derived row
// disagrees with users it records drift and MUST NOT rewrite either side.
type IdentityBackfillStore interface {
	AcquireIdentityBackfillRun(ctx context.Context, request IdentityBackfillAcquireRequest) (run IdentityBackfillRun, resumed bool, err error)
	GetIdentityBackfillItem(ctx context.Context, tenantID, runID, userID shared.ID) (IdentityBackfillItem, error)
	ProjectLegacyHuman(ctx context.Context, run IdentityBackfillRun, source LegacyHumanSnapshot, sourceHash string, now time.Time) (item IdentityBackfillItem, created bool, err error)
	AdvanceIdentityBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (IdentityBackfillRun, error)
	ReconcileIdentityBackfill(ctx context.Context, tenantID shared.ID, snapshotAt time.Time) (IdentityBackfillReconciliation, error)
	FinishIdentityBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state IdentityBackfillState, reconciliation IdentityBackfillReconciliation, now time.Time) (IdentityBackfillRun, error)
}

type LegacyOIDCLink struct {
	TenantID shared.ID
	UserID   shared.ID
	Issuer   string
	Subject  string
}

type LegacyOIDCShadowConfig struct {
	TenantID    shared.ID
	Issuer      string
	ClientID    string
	RedirectURL string
	Actor       string
}

type IdentityShadowImportResult struct {
	ConnectionID     shared.ID
	Revision         int64
	ProjectedLinks   int
	UnchangedLinks   int
	DriftedLinks     int
}

// IdentityShadowImporter imports the fixed-cell OIDC configuration and existing approved links as
// non-serving shadow data. It must create a disabled connection with no active revision; D4 never
// changes login authority.
type IdentityShadowImporter interface {
	ImportLegacyOIDCShadow(ctx context.Context, config LegacyOIDCShadowConfig) (IdentityShadowImportResult, error)
}

type IdentityRolloutPhaseRecord struct {
	TenantID                 shared.ID
	ID                       shared.ID
	Phase                    string
	Owner                    string
	SourceOfTruth            string
	AllowedWriters           []string
	SourceCount              int
	ProjectedCount           int
	DriftCount               int
	CorruptCredentialCount   int
	DuplicateCredentialCount int
	DenialCount              int
	ErrorCount               int
	SessionCount             int
	ObservationMinutes       int
	AbortThresholdBPS        int
	LastKnownGoodPhase       string
	RollbackAction           string
	MetricsRecorded          bool
	ApprovalRecorded         bool
	CreatedBy                string
	CreatedAt                time.Time
}

type IdentityRolloutLedger interface {
	AppendIdentityRolloutPhaseRecord(ctx context.Context, record IdentityRolloutPhaseRecord) error
}

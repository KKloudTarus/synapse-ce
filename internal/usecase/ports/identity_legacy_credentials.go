package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type LegacyCredentialClassification string

const (
	LegacyCredentialIssued      LegacyCredentialClassification = "issued"
	LegacyCredentialPlaceholder LegacyCredentialClassification = "placeholder"
	LegacyCredentialAmbiguous   LegacyCredentialClassification = "ambiguous"
)

type LegacyCredentialStatus string

const (
	LegacyCredentialActive      LegacyCredentialStatus = "active"
	LegacyCredentialDisabled    LegacyCredentialStatus = "disabled"
	LegacyCredentialUnavailable LegacyCredentialStatus = "unavailable"
)

// LegacyCredentialProjection is the D5 derived bearer representation. users.api_key_hash remains
// authoritative until read cutover. Placeholder and ambiguous rows therefore intentionally expose
// no digest and cannot be routed through credential_index.
type LegacyCredentialProjection struct {
	TenantID             shared.ID
	ID                   shared.ID
	UserID               shared.ID
	MembershipID         shared.ID
	PersonID             shared.ID
	Classification       LegacyCredentialClassification
	Digest               string
	Status               LegacyCredentialStatus
	ClassificationReason string
	Version              int64
	SourceUpdatedAt      time.Time
	ClassifiedAt         time.Time
	UpdatedAt            time.Time
}

type LegacyCredentialSyncRequest struct {
	TenantID        shared.ID
	UserID          shared.ID
	Digest          string
	Disabled        bool
	SourceUpdatedAt time.Time
	At              time.Time
}

type LegacyCredentialResolutionRequest struct {
	TenantID       shared.ID
	ResolutionID   shared.ID
	UserID         shared.ID
	Resolution     LegacyCredentialClassification
	ExpectedVersion int64
	Reason         string
	Actor          string
	At             time.Time
}

type LegacyCredentialReconciliation struct {
	SourceCount       int
	ProjectedCount    int
	IssuedCount       int
	PlaceholderCount  int
	AmbiguousCount    int
	MissingCount      int
	DriftCount        int
	IndexDriftCount   int
}

// LegacyCredentialProjectionStore is the only D5 mutation surface for the derived legacy bearer.
// Implementations must participate in TenantTransactionRunner: a user rotation/disable that already
// has a projection changes users, this row, credential_index and audit in one commit or not at all.
// A missing projection is not manufactured by a user mutation; the offline classifier owns initial
// classification so a concurrent rotation cannot accidentally turn an unclassified OIDC placeholder
// into a bearer credential.
type LegacyCredentialProjectionStore interface {
	ClassifyAndProjectLegacyCredential(ctx context.Context, tenantID, userID shared.ID, at time.Time) (LegacyCredentialProjection, error)
	SyncIssuedLegacyCredential(ctx context.Context, request LegacyCredentialSyncRequest) (projection LegacyCredentialProjection, projected bool, err error)
	SyncLegacyCredentialDisabled(ctx context.Context, request LegacyCredentialSyncRequest) (projection LegacyCredentialProjection, projected bool, err error)
	ResolveLegacyCredentialClassification(ctx context.Context, request LegacyCredentialResolutionRequest) (LegacyCredentialProjection, error)
	GetLegacyCredentialProjection(ctx context.Context, tenantID, userID shared.ID) (LegacyCredentialProjection, error)
	ReconcileLegacyCredentials(ctx context.Context, tenantID shared.ID) (LegacyCredentialReconciliation, error)
}

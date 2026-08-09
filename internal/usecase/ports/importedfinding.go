package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ImportedFindingStore persists third-party findings under the same tenant scoping as first-party ones.
//
// Persistence is idempotent by (tenant, source digest, rule, location): re-ingesting an identical
// document must not duplicate findings, so a scheduled pipeline can post the same report repeatedly
// without inflating the queue.
type ImportedFindingStore interface {
	// Save persists a batch atomically for the tenant. It returns how many were newly stored and how
	// many already existed, so the caller can report an honest accepted/deduplicated split.
	Save(ctx context.Context, tenantID shared.ID, findings []importedfinding.ImportedFinding) (stored, existing int, err error)
	// ListByEngagement returns the imported findings for an engagement, deterministically ordered.
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]importedfinding.ImportedFinding, error)
	// ExistsDigest reports whether a document with this digest was already ingested for the engagement.
	ExistsDigest(ctx context.Context, tenantID, engagementID shared.ID, digest string) (bool, error)
}

package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

// VEXStatementRepository persists ingested VEX statements per engagement so they can be RE-APPLIED after a
// rescan. A rescan's Upsert overwrites findings back to open, which would silently drop a prior
// apply-and-forget VEX import; retaining the assertions lets the pipeline re-evaluate them against the fresh
// finding set. Tenant-scoped: every method isolates by tenant (Postgres RLS).
type VEXStatementRepository interface {
	// Save persists the statements for the engagement, idempotently by content digest: re-importing an
	// identical assertion is a no-op, a changed assertion is retained as a distinct row.
	Save(ctx context.Context, tenantID, engagementID shared.ID, statements []vex.StoredStatement) error
	// ListByEngagement returns the persisted statements for the engagement in INSERTION order, so a re-apply
	// that walks them applies the most-recent assertion last (newest wins per finding). Insertion order, not a
	// clock timestamp, is authoritative: statements of one document share an ingest time.
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]vex.StoredStatement, error)
}

// VEXReapplier re-evaluates an engagement's persisted VEX statements against its current findings. The SCA
// pipeline calls it after a rescan materializes findings, so a previously-ingested not_affected/fixed
// decision survives re-scanning (subject to the reachability reconciliation). Implemented by usecase/vex.
type VEXReapplier interface {
	Reapply(ctx context.Context, tenantID, engagementID shared.ID) error
}

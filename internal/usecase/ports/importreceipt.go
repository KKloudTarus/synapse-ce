package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ImportReceiptStore persists durable logical-import receipts.
//
// CreateOrGet is the writer seam for #1183, but #1181 does not compose it into any production service.
// A retry with the same tenant, engagement, source identity and digest returns the original receipt.
// Implementations used with TenantTransactionRunner must reuse its context-bound transaction so imported
// rows and the receipt transition can share one commit instead of exposing a completed partial write.
type ImportReceiptStore interface {
	CreateOrGet(ctx context.Context, tenantID shared.ID, receipt importreceipt.Receipt) (persisted importreceipt.Receipt, created bool, err error)
	// Finalize performs the only mutable transition: pending -> complete/partial/failed. Repeating the
	// same finalization is idempotent; attempting to rewrite a terminal outcome is a conflict.
	Finalize(ctx context.Context, tenantID, receiptID shared.ID, outcome importreceipt.Outcome, counters importreceipt.Counters, updatedAt time.Time) (importreceipt.Receipt, error)
	GetByIdentity(ctx context.Context, tenantID, engagementID shared.ID, sourceIdentity, digest string) (importreceipt.Receipt, error)
}

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const importReceiptCols = `id, tenant_id, engagement_id, source_identity, digest, parser_version, outcome, ` +
	`accepted_count, deduplicated_count, refused_count, created_at, updated_at`

// ImportReceiptRepository persists the tenant-scoped import ledger introduced by migration 0178.
type ImportReceiptRepository struct{ pool *pgxpool.Pool }

// NewImportReceiptRepository constructs the PostgreSQL import-receipt repository.
// #1181 deliberately does not wire this repository into a production writer.
func NewImportReceiptRepository(pool *pgxpool.Pool) *ImportReceiptRepository {
	return &ImportReceiptRepository{pool: pool}
}

var _ ports.ImportReceiptStore = (*ImportReceiptRepository)(nil)

// CreateOrGet is one transaction and one idempotency decision. INSERT ... ON CONFLICT DO NOTHING lets
// PostgreSQL serialize concurrent retries; the read in the same transaction returns whichever row won.
func (r *ImportReceiptRepository) CreateOrGet(ctx context.Context, tenantID shared.ID, receipt importreceipt.Receipt) (importreceipt.Receipt, bool, error) {
	if err := receipt.Validate(); err != nil {
		return importreceipt.Receipt{}, false, err
	}
	if receipt.TenantID != tenantID {
		return importreceipt.Receipt{}, false, fmt.Errorf("%w: import receipt %s is stamped with tenant %q but was saved into %q",
			shared.ErrValidation, receipt.ID, receipt.TenantID, tenantID)
	}

	var persisted importreceipt.Receipt
	created := false
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO import_receipts (`+importReceiptCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id, engagement_id, source_identity, digest) DO NOTHING`,
			receipt.ID.String(), tenantID.String(), receipt.EngagementID.String(), receipt.SourceIdentity,
			receipt.Digest, receipt.ParserVersion, string(receipt.Outcome), receipt.Counters.Accepted,
			receipt.Counters.Deduplicated, receipt.Counters.Refused, receipt.CreatedAt.UTC(), receipt.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("insert import receipt: %w", err)
		}
		created = tag.RowsAffected() == 1
		row := tx.QueryRow(ctx, `SELECT `+importReceiptCols+` FROM import_receipts
			WHERE tenant_id=$1 AND engagement_id=$2 AND source_identity=$3 AND digest=$4`,
			tenantID.String(), receipt.EngagementID.String(), receipt.SourceIdentity, receipt.Digest)
		persisted, err = scanImportReceipt(row)
		if err != nil {
			return fmt.Errorf("resolve import receipt: %w", err)
		}
		return nil
	})
	if err != nil {
		return importreceipt.Receipt{}, false, err
	}
	return persisted, created, nil
}

// Finalize transitions a pending receipt to one terminal outcome in a tenant transaction.
func (r *ImportReceiptRepository) Finalize(ctx context.Context, tenantID, receiptID shared.ID, outcome importreceipt.Outcome, counters importreceipt.Counters, updatedAt time.Time) (importreceipt.Receipt, error) {
	if tenantID.IsZero() || receiptID.IsZero() || !outcome.Terminal() || updatedAt.IsZero() {
		return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt finalization needs tenant, receipt, terminal outcome and time", shared.ErrValidation)
	}
	var persisted importreceipt.Receipt
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		persisted, err = scanImportReceipt(tx.QueryRow(ctx, `SELECT `+importReceiptCols+` FROM import_receipts
			WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), receiptID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read import receipt for finalization: %w", err)
		}
		// A duplicate completion is safe only when it repeats the exact durable result.
		// Check terminal state before validating a proposed rewrite so callers always receive
		// the idempotency/conflict result for receipts that can no longer be mutated.
		if persisted.Outcome.Terminal() {
			if persisted.Outcome == outcome && persisted.Counters == counters {
				return nil
			}
			return fmt.Errorf("%w: import receipt %s is already %s", shared.ErrConflict, receiptID, persisted.Outcome)
		}
		if persisted.Outcome != importreceipt.OutcomePending {
			return fmt.Errorf("%w: import receipt %s cannot finalize from %s", shared.ErrConflict, receiptID, persisted.Outcome)
		}
		if updatedAt.Before(persisted.CreatedAt) {
			return fmt.Errorf("%w: import receipt finalization precedes creation", shared.ErrValidation)
		}
		if err := counters.Validate(); err != nil {
			return err
		}
		if outcome == importreceipt.OutcomeComplete && counters.Refused != 0 {
			return fmt.Errorf("%w: a complete import receipt cannot contain refused results", shared.ErrValidation)
		}
		if _, err = tx.Exec(ctx, `UPDATE import_receipts
			SET outcome=$3, accepted_count=$4, deduplicated_count=$5, refused_count=$6, updated_at=$7
			WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), receiptID.String(), string(outcome), counters.Accepted, counters.Deduplicated, counters.Refused, updatedAt.UTC()); err != nil {
			return fmt.Errorf("finalize import receipt: %w", err)
		}
		persisted, err = scanImportReceipt(tx.QueryRow(ctx, `SELECT `+importReceiptCols+` FROM import_receipts WHERE tenant_id=$1 AND id=$2`, tenantID.String(), receiptID.String()))
		if err != nil {
			return fmt.Errorf("read finalized import receipt: %w", err)
		}
		return nil
	})
	if err != nil {
		return importreceipt.Receipt{}, err
	}
	return persisted, nil
}

// GetByIdentity resolves one receipt without leaking whether another tenant owns the same logical key.
func (r *ImportReceiptRepository) GetByIdentity(ctx context.Context, tenantID, engagementID shared.ID, sourceIdentity, digest string) (importreceipt.Receipt, error) {
	if tenantID.IsZero() || engagementID.IsZero() || strings.TrimSpace(sourceIdentity) == "" || strings.TrimSpace(digest) == "" {
		return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt lookup needs tenant, engagement, source identity and digest", shared.ErrValidation)
	}
	var receipt importreceipt.Receipt
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		receipt, err = scanImportReceipt(tx.QueryRow(ctx, `SELECT `+importReceiptCols+` FROM import_receipts
			WHERE tenant_id=$1 AND engagement_id=$2 AND source_identity=$3 AND digest=$4`,
			tenantID.String(), engagementID.String(), sourceIdentity, digest))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return importreceipt.Receipt{}, shared.ErrNotFound
	}
	if err != nil {
		return importreceipt.Receipt{}, fmt.Errorf("get import receipt: %w", err)
	}
	return receipt, nil
}

func scanImportReceipt(row rowScanner) (importreceipt.Receipt, error) {
	var (
		r                      importreceipt.Receipt
		id, tenant, engagement string
		outcome                string
	)
	if err := row.Scan(&id, &tenant, &engagement, &r.SourceIdentity, &r.Digest, &r.ParserVersion, &outcome,
		&r.Counters.Accepted, &r.Counters.Deduplicated, &r.Counters.Refused, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return importreceipt.Receipt{}, err
	}
	r.ID = shared.ID(id)
	r.TenantID = shared.ID(tenant)
	r.EngagementID = shared.ID(engagement)
	r.Outcome = importreceipt.Outcome(outcome)
	return r, nil
}

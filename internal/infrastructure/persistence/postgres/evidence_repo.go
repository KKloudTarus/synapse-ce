package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EvidenceStore persists the per-engagement hash-chained evidence ledger.
type EvidenceStore struct{ pool *pgxpool.Pool }

// NewEvidenceStore returns a store backed by the given pool.
func NewEvidenceStore(pool *pgxpool.Pool) *EvidenceStore { return &EvidenceStore{pool: pool} }

var _ ports.EvidenceStore = (*EvidenceStore)(nil)

// Append inserts sealed evidence items in order, in one transaction (append-only).
func (r *EvidenceStore) Append(ctx context.Context, items []evidence.Evidence) error {
	if len(items) == 0 {
		return nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("tenant context is required")
	}
	return WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		for _, e := range items {
			var findingID any
			if !e.FindingID.IsZero() {
				findingID = e.FindingID.String()
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO evidence (id, tenant_id, finding_id, engagement_id, kind, sha256, previous_hash, storage_ref, content, created_by, created_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
				e.ID.String(), tenantID.String(), findingID, e.EngagementID.String(), e.Kind, e.Hash, e.PreviousHash, e.StorageRef, e.Content, e.CreatedBy, e.CreatedAt); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					return fmt.Errorf("evidence chain: parent already linked: %w", shared.ErrConflict)
				}
				return fmt.Errorf("insert evidence: %w", err)
			}
		}
		return nil
	})
}

// ListByEngagement returns the engagement's evidence in chain order (oldest first).
func (r *EvidenceStore) ListByEngagement(ctx context.Context, engagementID shared.ID) (out []evidence.Evidence, err error) {
	err = WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, COALESCE(finding_id,''), engagement_id, kind, sha256, COALESCE(previous_hash,''), COALESCE(storage_ref,''), content, COALESCE(created_by,''), created_at FROM evidence WHERE engagement_id=$1 ORDER BY seq ASC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list evidence: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e evidence.Evidence
			var id, fid, eid string
			if err := rows.Scan(&id, &fid, &eid, &e.Kind, &e.Hash, &e.PreviousHash, &e.StorageRef, &e.Content, &e.CreatedBy, &e.CreatedAt); err != nil {
				return fmt.Errorf("scan evidence: %w", err)
			}
			e.ID, e.FindingID, e.EngagementID = shared.ID(id), shared.ID(fid), shared.ID(eid)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// Head returns the most recent sealed hash for an engagement ("" if the chain is
// empty). A real query error is returned (NOT swallowed as "empty") so the caller
// never forks the append-only chain on a transient DB failure.
func (r *EvidenceStore) Head(ctx context.Context, engagementID shared.ID) (head string, err error) {
	err = WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT sha256 FROM evidence WHERE engagement_id=$1 ORDER BY seq DESC LIMIT 1`, engagementID.String()).Scan(&head)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("head evidence: %w", err)
		}
		return nil
	})
	return head, err
}

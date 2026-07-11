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
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, e := range items {
		var findingID any
		if !e.FindingID.IsZero() {
			findingID = e.FindingID.String()
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO evidence (id, tenant_id, finding_id, engagement_id, kind, sha256, previous_hash, storage_ref, content, created_by, created_at)
			 VALUES ($1, '', $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			e.ID.String(), findingID, e.EngagementID.String(), e.Kind, e.Hash, e.PreviousHash, e.StorageRef, e.Content, e.CreatedBy, e.CreatedAt); err != nil {
			// Fork guard: the unique(engagement, previous_hash) index rejects a
			// second child for the same parent – surface as ErrConflict so the caller
			// re-reads the advanced head + re-chains (keeps the chain strictly linear).
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("evidence chain: parent already linked: %w", shared.ErrConflict)
			}
			return fmt.Errorf("insert evidence: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListByEngagement returns the engagement's evidence in chain order (oldest first).
func (r *EvidenceStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]evidence.Evidence, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, COALESCE(finding_id,''), engagement_id, kind, sha256, COALESCE(previous_hash,''), COALESCE(storage_ref,''), content, COALESCE(created_by,''), created_at
		 FROM evidence WHERE engagement_id=$1 ORDER BY seq ASC`, engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	defer rows.Close()
	var out []evidence.Evidence
	for rows.Next() {
		var (
			e            evidence.Evidence
			id, fid, eid string
		)
		if err := rows.Scan(&id, &fid, &eid, &e.Kind, &e.Hash, &e.PreviousHash, &e.StorageRef, &e.Content, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		e.ID = shared.ID(id)
		e.FindingID = shared.ID(fid)
		e.EngagementID = shared.ID(eid)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Head returns the most recent sealed hash for an engagement ("" if the chain is
// empty). A real query error is returned (NOT swallowed as "empty") so the caller
// never forks the append-only chain on a transient DB failure.
func (r *EvidenceStore) Head(ctx context.Context, engagementID shared.ID) (string, error) {
	var head string
	err := r.pool.QueryRow(ctx,
		`SELECT sha256 FROM evidence WHERE engagement_id=$1 ORDER BY seq DESC LIMIT 1`,
		engagementID.String()).Scan(&head)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil // genuinely empty chain
	}
	if err != nil {
		return "", fmt.Errorf("head evidence: %w", err)
	}
	return head, nil
}

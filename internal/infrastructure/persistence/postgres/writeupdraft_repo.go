package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// writeupDraftCols is the SELECT projection scanned by scanWriteupDraft (tenant_id is written but not
// read back – it is not part of the domain type; reads are engagement-scoped).
const writeupDraftCols = `id, engagement_id, finding_id, description, remediation, state, proposed_by, decided_by, created_at, updated_at`

// WriteupDraftRepository persists AI-proposed, human-gated finding write-up drafts to
// PostgreSQL, engagement-scoped.
type WriteupDraftRepository struct{ pool *pgxpool.Pool }

// NewWriteupDraftRepository returns a repository backed by the given pool.
func NewWriteupDraftRepository(pool *pgxpool.Pool) *WriteupDraftRepository {
	return &WriteupDraftRepository{pool: pool}
}

var _ ports.WriteupDraftStore = (*WriteupDraftRepository)(nil)

// Save upserts a draft by id under the request or durable-job tenant context.
func (r *WriteupDraftRepository) Save(ctx context.Context, d writeupdraft.Draft) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("tenant context is required")
	}
	return WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO writeup_drafts (id, tenant_id, engagement_id, finding_id, description, remediation, state, proposed_by, decided_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description, remediation = EXCLUDED.remediation, state = EXCLUDED.state, decided_by = EXCLUDED.decided_by, updated_at = EXCLUDED.updated_at`, d.ID.String(), tenantID.String(), d.EngagementID.String(), d.FindingID.String(), d.Description, d.Remediation, string(d.State), d.ProposedBy, d.DecidedBy, d.CreatedAt, d.UpdatedAt); err != nil {
			return fmt.Errorf("save writeup draft: %w", err)
		}
		return nil
	})
}

// Get returns the engagement's draft by id, or shared.ErrNotFound.
func (r *WriteupDraftRepository) Get(ctx context.Context, engagementID, id shared.ID) (out writeupdraft.Draft, err error) {
	err = WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = scanWriteupDraft(tx.QueryRow(ctx, `SELECT `+writeupDraftCols+` FROM writeup_drafts WHERE id=$1 AND engagement_id=$2`, id.String(), engagementID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("writeup draft %s: %w", id, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("get writeup draft: %w", err)
		}
		return nil
	})
	return out, err
}

// ListByEngagement returns the engagement's drafts, oldest first (deterministic order).
func (r *WriteupDraftRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) (out []writeupdraft.Draft, err error) {
	err = WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+writeupDraftCols+` FROM writeup_drafts WHERE engagement_id=$1 ORDER BY created_at ASC, id COLLATE "C" ASC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list writeup drafts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanWriteupDraft(rows)
			if err != nil {
				return fmt.Errorf("scan writeup draft: %w", err)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// scanWriteupDraft scans a writeupDraftCols row into a Draft, fail-closed on a corrupted/hand-edited
// state value (defense-in-depth at the DB read boundary – an unknown state is never returned).
func scanWriteupDraft(row rowScanner) (writeupdraft.Draft, error) {
	var (
		d                     writeupdraft.Draft
		id, eid, fid, stateID string
	)
	if err := row.Scan(&id, &eid, &fid, &d.Description, &d.Remediation, &stateID, &d.ProposedBy, &d.DecidedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return writeupdraft.Draft{}, err
	}
	d.ID = shared.ID(id)
	d.EngagementID = shared.ID(eid)
	d.FindingID = shared.ID(fid)
	d.State = writeupdraft.State(stateID)
	if !d.State.Valid() {
		return writeupdraft.Draft{}, fmt.Errorf("%w: writeup draft %s has invalid stored state %q", shared.ErrValidation, d.ID, stateID)
	}
	return d, nil
}

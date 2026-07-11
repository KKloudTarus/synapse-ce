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

// Save upserts a draft by id. Unlike a Judgment (insert-only), a Draft is mutable working data, so on
// conflict the mutable fields (text, state, decided_by, updated_at) are replaced; the immutable fields
// (engagement_id, finding_id, proposed_by, created_at) are never moved. tenant_id is written as the
// empty-string default tenant (mirrors judgments/findings); reads are tenant-isolated via the engagement
// gate, and the column is present so the P5/E22 row-scoping sweep covers it.
func (r *WriteupDraftRepository) Save(ctx context.Context, d writeupdraft.Draft) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO writeup_drafts (id, tenant_id, engagement_id, finding_id, description, remediation, state, proposed_by, decided_by, created_at, updated_at)
		 VALUES ($1, '', $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (id) DO UPDATE SET
		   description = EXCLUDED.description,
		   remediation = EXCLUDED.remediation,
		   state       = EXCLUDED.state,
		   decided_by  = EXCLUDED.decided_by,
		   updated_at  = EXCLUDED.updated_at`,
		d.ID.String(), d.EngagementID.String(), d.FindingID.String(), d.Description, d.Remediation,
		string(d.State), d.ProposedBy, d.DecidedBy, d.CreatedAt, d.UpdatedAt); err != nil {
		return fmt.Errorf("save writeup draft: %w", err)
	}
	return nil
}

// Get returns the engagement's draft by id, or shared.ErrNotFound.
func (r *WriteupDraftRepository) Get(ctx context.Context, engagementID, id shared.ID) (writeupdraft.Draft, error) {
	d, err := scanWriteupDraft(r.pool.QueryRow(ctx,
		`SELECT `+writeupDraftCols+` FROM writeup_drafts WHERE id=$1 AND engagement_id=$2`,
		id.String(), engagementID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return writeupdraft.Draft{}, fmt.Errorf("writeup draft %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return writeupdraft.Draft{}, fmt.Errorf("get writeup draft: %w", err)
	}
	return d, nil
}

// ListByEngagement returns the engagement's drafts, oldest first (deterministic order).
func (r *WriteupDraftRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+writeupDraftCols+` FROM writeup_drafts WHERE engagement_id=$1 ORDER BY created_at ASC, id COLLATE "C" ASC`,
		engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list writeup drafts: %w", err)
	}
	defer rows.Close()
	out := make([]writeupdraft.Draft, 0)
	for rows.Next() {
		d, err := scanWriteupDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("scan writeup draft: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
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

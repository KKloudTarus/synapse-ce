package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResponseRepository persists governed response actions (migration 0076), tenant-scoped via
// WithTenant/RLS so one tenant's actions are never visible to another.
type ResponseRepository struct{ pool *pgxpool.Pool }

var _ ports.ResponseStore = (*ResponseRepository)(nil)

// NewResponseRepository constructs the repository.
func NewResponseRepository(pool *pgxpool.Pool) *ResponseRepository {
	return &ResponseRepository{pool: pool}
}

// Put upserts a response record under the authenticated tenant.
func (r *ResponseRepository) Put(ctx context.Context, rec rdom.Record) error {
	argv, err := json.Marshal(rec.Action.Argv)
	if err != nil {
		return fmt.Errorf("marshal argv: %w", err)
	}
	reversal, err := json.Marshal(rec.Action.Reversal)
	if err != nil {
		return fmt.Errorf("marshal reversal: %w", err)
	}
	var applied *time.Time
	if !rec.AppliedAt.IsZero() {
		a := rec.AppliedAt.UTC()
		applied = &a
	}
	var evID *string
	if rec.ApprovalEvidenceID != "" {
		e := rec.ApprovalEvidenceID.String()
		evID = &e
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO response_actions
			  (tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state, approved_by, approval_evidence_id, applied_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id, id) DO UPDATE SET
			  state = EXCLUDED.state, approved_by = EXCLUDED.approved_by,
			  approval_evidence_id = EXCLUDED.approval_evidence_id, applied_at = EXCLUDED.applied_at,
			  updated_at = EXCLUDED.updated_at`,
			rec.TenantID.String(), rec.ID.String(), rec.EngagementID.String(), string(rec.Action.Kind),
			rec.Action.Target.String(), string(rec.Action.BlastRadius), argv, reversal, string(rec.State),
			rec.ApprovedBy, evID, applied, rec.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("upsert response action %s: %w", rec.ID, err)
		}
		return nil
	})
}

// Get returns the record for an id in the ctx tenant.
func (r *ResponseRepository) Get(ctx context.Context, id shared.ID) (rdom.Record, bool, error) {
	var rec rdom.Record
	found := false
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state, approved_by, approval_evidence_id, applied_at
			FROM response_actions WHERE id = $1`, id.String())
		var scanned rdom.Record
		if err := scanResponse(row, &scanned); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		rec = scanned
		found = true
		return nil
	})
	return rec, found, err
}

// ListByState returns the ctx tenant's records in a state, deterministically ordered by id.
func (r *ResponseRepository) ListByState(ctx context.Context, state rdom.State) ([]rdom.Record, error) {
	var out []rdom.Record
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state, approved_by, approval_evidence_id, applied_at
			FROM response_actions WHERE state = $1 ORDER BY id ASC`, string(state))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec rdom.Record
			if err := scanResponse(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func scanResponse(row rowScanner, rec *rdom.Record) error {
	var (
		tenant, id, eng, kind, targetStr, radius, state, approvedBy string
		argv, reversal                                              []byte
		evID                                                        *string
		applied                                                     *time.Time
	)
	if err := row.Scan(&tenant, &id, &eng, &kind, &targetStr, &radius, &argv, &reversal, &state, &approvedBy, &evID, &applied); err != nil {
		return err
	}
	var argvSlice []string
	if err := json.Unmarshal(argv, &argvSlice); err != nil {
		return fmt.Errorf("unmarshal argv: %w", err)
	}
	var rev rdom.ReversalSpec
	if err := json.Unmarshal(reversal, &rev); err != nil {
		return fmt.Errorf("unmarshal reversal: %w", err)
	}
	rec.ID = shared.ID(id)
	rec.TenantID = shared.ID(tenant)
	rec.EngagementID = shared.ID(eng)
	rec.State = rdom.State(state)
	rec.ApprovedBy = approvedBy
	if evID != nil {
		rec.ApprovalEvidenceID = shared.ID(*evID)
	}
	if applied != nil {
		rec.AppliedAt = *applied
	}
	rec.Action = rdom.Action{
		ID: shared.ID(id), Kind: rdom.Kind(kind), Target: shared.ID(targetStr),
		BlastRadius: offensivepolicy.Radius(radius), Argv: argvSlice, Reversal: rev,
	}
	return nil
}

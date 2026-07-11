package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// judgmentCols is the SELECT/RETURNING projection scanned by scanJudgment.
const judgmentCols = `id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, version, created_at, updated_at`

// JudgmentRepository persists AI judgments to PostgreSQL, engagement-scoped.
type JudgmentRepository struct{ pool *pgxpool.Pool }

// NewJudgmentRepository returns a repository backed by the given pool.
func NewJudgmentRepository(pool *pgxpool.Pool) *JudgmentRepository {
	return &JudgmentRepository{pool: pool}
}

var _ ports.JudgmentStore = (*JudgmentRepository)(nil)

// Save inserts a proposed judgment (idempotent by id; never clobbers an existing row – score/state
// move only via SetScoreState). The typed claim is stored as its fail-closed discriminated
// envelope (JSONB).
func (r *JudgmentRepository) Save(ctx context.Context, j judgment.Judgment) error {
	claimJSON, err := judgment.MarshalClaim(j.Claim)
	if err != nil {
		return fmt.Errorf("marshal judgment claim: %w", err)
	}
	// tenant_id '' = the seeded default tenant (mirrors findings); reads are tenant-isolated via the
	// engagement gate, and the column is present so the P5/E22 row-scoping sweep covers it.
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, version, created_at, updated_at)
		 VALUES ($1, '', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (id) DO NOTHING`,
		j.ID.String(), j.EngagementID.String(), string(j.Capability), string(j.SubjectKind), j.SubjectID.String(),
		claimJSON, string(j.State), j.EvidenceScore, j.ProposedBy, versionOrDefault(j.Version), j.Audit.CreatedAt, j.Audit.UpdatedAt); err != nil {
		return fmt.Errorf("save judgment: %w", err)
	}
	return nil
}

// ListByEngagement returns the engagement's judgments, oldest first (deterministic order).
func (r *JudgmentRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+judgmentCols+` FROM judgments WHERE engagement_id=$1 ORDER BY created_at ASC, id COLLATE "C" ASC`,
		engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list judgments: %w", err)
	}
	defer rows.Close()
	return scanJudgments(rows)
}

// ListBySubject returns the engagement's judgments about a given subject id, oldest first.
func (r *JudgmentRepository) ListBySubject(ctx context.Context, engagementID, subjectID shared.ID) ([]judgment.Judgment, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+judgmentCols+` FROM judgments WHERE engagement_id=$1 AND subject_id=$2 ORDER BY created_at ASC, id COLLATE "C" ASC`,
		engagementID.String(), subjectID.String())
	if err != nil {
		return nil, fmt.Errorf("list judgments by subject: %w", err)
	}
	defer rows.Close()
	return scanJudgments(rows)
}

// SetScoreState moves a judgment's evidence score + state under optimistic concurrency (the
// verify/accept path): the row updates only if version matches expectedVersion,
// then version is bumped. This is the ONLY path that moves a stored judgment's score/state, and
// it is deliberately off the broad ports.JudgmentStore interface (a read-only consumer cannot
// reach it). On a miss it distinguishes ErrConflict (exists, version moved) from ErrNotFound.
func (r *JudgmentRepository) SetScoreState(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	j, err := scanJudgment(r.pool.QueryRow(ctx,
		`UPDATE judgments SET evidence_score=$1, state=$2, version=version+1, updated_at=now()
		 WHERE id=$3 AND engagement_id=$4 AND version=$5
		 RETURNING `+judgmentCols,
		score, string(state), id.String(), engagementID.String(), expectedVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return judgment.Judgment{}, r.classifyJudgmentMiss(ctx, engagementID, id)
	}
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("set judgment score/state: %w", err)
	}
	return j, nil
}

func (r *JudgmentRepository) classifyJudgmentMiss(ctx context.Context, engagementID, id shared.ID) error {
	var exists bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM judgments WHERE id=$1 AND engagement_id=$2)`,
		id.String(), engagementID.String()).Scan(&exists); err != nil {
		return fmt.Errorf("classify judgment miss: %w", err)
	}
	if exists {
		return fmt.Errorf("judgment %s changed since you loaded it: %w", id, shared.ErrConflict)
	}
	return fmt.Errorf("judgment %s: %w", id, shared.ErrNotFound)
}

func scanJudgments(rows pgx.Rows) ([]judgment.Judgment, error) {
	out := make([]judgment.Judgment, 0)
	for rows.Next() {
		j, err := scanJudgment(rows)
		if err != nil {
			return nil, fmt.Errorf("scan judgment: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// scanJudgment scans a judgmentCols row into a Judgment, decoding the claim FAIL-CLOSED (R8) so a
// tampered/unknown stored claim is rejected at the DB boundary, never rendered.
func scanJudgment(row rowScanner) (judgment.Judgment, error) {
	var (
		j                               judgment.Judgment
		id, eid, capStr, sk, sid, state string
		claimJSON                       []byte
	)
	if err := row.Scan(&id, &eid, &capStr, &sk, &sid, &claimJSON, &state,
		&j.EvidenceScore, &j.ProposedBy, &j.Version, &j.Audit.CreatedAt, &j.Audit.UpdatedAt); err != nil {
		return judgment.Judgment{}, err
	}
	claim, err := judgment.UnmarshalClaim(claimJSON)
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("decode judgment claim: %w", err)
	}
	j.ID = shared.ID(id)
	j.EngagementID = shared.ID(eid)
	j.Capability = judgment.Capability(capStr)
	j.SubjectKind = judgment.SubjectKind(sk)
	j.SubjectID = shared.ID(sid)
	j.State = judgment.State(state)
	j.Claim = claim
	// Fail-closed on a corrupted/hand-edited row: the scalar enums must be known (the claim is
	// already fail-closed via UnmarshalClaim above). Defense-in-depth at the DB read boundary.
	if !j.Capability.Valid() || !j.State.Valid() || !j.SubjectKind.Valid() {
		return judgment.Judgment{}, fmt.Errorf("%w: judgment %s has invalid stored enums (capability=%q state=%q subject_kind=%q)", shared.ErrValidation, j.ID, j.Capability, j.State, j.SubjectKind)
	}
	return j, nil
}

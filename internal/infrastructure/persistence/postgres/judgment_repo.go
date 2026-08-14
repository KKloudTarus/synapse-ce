package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// judgmentCols is the SELECT/RETURNING projection scanned by scanJudgment.
const judgmentCols = `id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, verified_by, verdict_rationale, version, created_at, updated_at`

// JudgmentRepository persists AI judgments to PostgreSQL, engagement-scoped.
// All operations route through WithContextTenant so tenant isolation is enforced
// at the database level. Save validates that the engagement belongs to the
// context tenant before writing.
type JudgmentRepository struct{ pool *pgxpool.Pool }

// NewJudgmentRepository returns a repository backed by the given pool.
func NewJudgmentRepository(pool *pgxpool.Pool) *JudgmentRepository {
	return &JudgmentRepository{pool: pool}
}

var (
	_ ports.JudgmentStore      = (*JudgmentRepository)(nil)
	_ ports.JudgmentAuditStore = (*JudgmentRepository)(nil)
)

// Save inserts a proposed judgment (idempotent by id; never clobbers an existing row – score/state
// move only via SetScoreState). The typed claim is stored as its fail-closed discriminated
// envelope (JSONB). The tenant_id is resolved from context, and the engagement is validated
// to belong to that tenant before the insert.
func (r *JudgmentRepository) Save(ctx context.Context, j judgment.Judgment) error {
	claimJSON, err := judgment.MarshalClaim(j.Claim)
	if err != nil {
		return fmt.Errorf("marshal judgment claim: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// Validate the engagement belongs to this tenant.
		tenantID, _ := shared.TenantFrom(ctx)
		var belongs bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM engagements WHERE id = $1 AND COALESCE(NULLIF(tenant_id, ''), 'default') = $2)`,
			j.EngagementID.String(), tenantID.String()).Scan(&belongs); err != nil {
			return fmt.Errorf("validate engagement tenant: %w", err)
		}
		if !belongs {
			return fmt.Errorf("%w: engagement %s does not belong to tenant %s", shared.ErrNotFound, j.EngagementID, tenantID)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, verified_by, verdict_rationale, version, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			 ON CONFLICT (id) DO NOTHING`,
			j.ID.String(), tenantID.String(), j.EngagementID.String(),
			string(j.Capability), string(j.SubjectKind), j.SubjectID.String(),
			claimJSON, string(j.State), j.EvidenceScore, j.ProposedBy, j.VerifiedBy, j.VerdictRationale,
			versionOrDefault(j.Version), j.Audit.CreatedAt, j.Audit.UpdatedAt); err != nil {
			return fmt.Errorf("save judgment: %w", err)
		}
		return nil
	})
}

// ListByEngagement returns the engagement's judgments, oldest first (deterministic order).
// RLS scopes the query to the context tenant.
func (r *JudgmentRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error) {
	var out []judgment.Judgment
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT `+judgmentCols+` FROM judgments WHERE engagement_id=$1 ORDER BY created_at ASC, id COLLATE "C" ASC`,
			engagementID.String())
		if qErr != nil {
			return fmt.Errorf("list judgments: %w", qErr)
		}
		defer rows.Close()
		var scanErr error
		out, scanErr = scanJudgments(rows)
		return scanErr
	})
	return out, err
}

// ListBySubject returns the engagement's judgments about a given subject id, oldest first.
// RLS scopes the query to the context tenant.
func (r *JudgmentRepository) ListBySubject(ctx context.Context, engagementID, subjectID shared.ID) ([]judgment.Judgment, error) {
	var out []judgment.Judgment
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx,
			`SELECT `+judgmentCols+` FROM judgments WHERE engagement_id=$1 AND subject_id=$2 ORDER BY created_at ASC, id COLLATE "C" ASC`,
			engagementID.String(), subjectID.String())
		if qErr != nil {
			return fmt.Errorf("list judgments by subject: %w", qErr)
		}
		defer rows.Close()
		var scanErr error
		out, scanErr = scanJudgments(rows)
		return scanErr
	})
	return out, err
}

// SetScoreState moves a judgment's evidence score + state under optimistic concurrency (the
// verify/accept path): the row updates only if version matches expectedVersion,
// then version is bumped. This is the ONLY path that moves a stored judgment's score/state, and
// it is deliberately off the broad ports.JudgmentStore interface (a read-only consumer cannot
// reach it). On a miss it distinguishes ErrConflict (exists, version moved) from ErrNotFound.
// RLS scopes the operation to the context tenant.
func (r *JudgmentRepository) SetScoreState(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	return r.setScoreState(ctx, engagementID, id, score, state, "", "", false, expectedVersion)
}

// SetVerdictState persists a verdict's sealed verifier and rationale with its score transition.
func (r *JudgmentRepository) SetVerdictState(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, verifiedBy, verdictRationale string, expectedVersion int) (judgment.Judgment, error) {
	return r.setScoreState(ctx, engagementID, id, score, state, verifiedBy, verdictRationale, true, expectedVersion)
}

func (r *JudgmentRepository) setScoreState(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, verifiedBy, verdictRationale string, setVerdictProvenance bool, expectedVersion int) (out judgment.Judgment, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var scanErr error
		query := `UPDATE judgments SET evidence_score=$1, state=$2, version=version+1, updated_at=now()`
		args := []any{score, string(state)}
		if setVerdictProvenance {
			query = `UPDATE judgments SET evidence_score=$1, state=$2, verified_by=$3, verdict_rationale=$4, version=version+1, updated_at=now()`
			args = append(args, verifiedBy, verdictRationale)
		}
		query += ` WHERE id=$` + strconv.Itoa(len(args)+1) + ` AND engagement_id=$` + strconv.Itoa(len(args)+2) + ` AND version=$` + strconv.Itoa(len(args)+3) + ` RETURNING ` + judgmentCols
		args = append(args, id.String(), engagementID.String(), expectedVersion)
		out, scanErr = scanJudgment(tx.QueryRow(ctx, query, args...))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return classifyJudgmentMiss(ctx, tx, engagementID, id)
		}
		if scanErr != nil {
			return fmt.Errorf("set judgment score/state: %w", scanErr)
		}
		return nil
	})
	return out, err
}

// classifyJudgmentMiss distinguishes ErrConflict (the judgment exists but its version moved)
// from ErrNotFound. Runs inside the caller's transaction.
func classifyJudgmentMiss(ctx context.Context, tx pgx.Tx, engagementID, id shared.ID) error {
	var exists bool
	if err := tx.QueryRow(ctx,
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
		&j.EvidenceScore, &j.ProposedBy, &j.VerifiedBy, &j.VerdictRationale, &j.Version, &j.Audit.CreatedAt, &j.Audit.UpdatedAt); err != nil {
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

// SaveWithProposalAudit persists a proposal with its immutable pending audit entry.
func (r *JudgmentRepository) SaveWithProposalAudit(ctx context.Context, j judgment.Judgment, entry ports.AuditEntry) error {
	claimJSON, err := judgment.MarshalClaim(j.Claim)
	if err != nil {
		return fmt.Errorf("marshal judgment claim: %w", err)
	}
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("marshal proposal audit metadata: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		var belongs bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM engagements WHERE id = $1 AND COALESCE(NULLIF(tenant_id, ''), 'default') = $2)`, j.EngagementID.String(), tenantID.String()).Scan(&belongs); err != nil {
			return fmt.Errorf("validate engagement tenant: %w", err)
		}
		if !belongs {
			return fmt.Errorf("%w: engagement %s does not belong to tenant %s", shared.ErrNotFound, j.EngagementID, tenantID)
		}
		result, err := tx.Exec(ctx, `INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, verified_by, verdict_rationale, version, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT (id) DO NOTHING`, j.ID.String(), tenantID.String(), j.EngagementID.String(), string(j.Capability), string(j.SubjectKind), j.SubjectID.String(), claimJSON, string(j.State), j.EvidenceScore, j.ProposedBy, j.VerifiedBy, j.VerdictRationale, versionOrDefault(j.Version), j.Audit.CreatedAt, j.Audit.UpdatedAt)
		if err != nil {
			return fmt.Errorf("save judgment: %w", err)
		}
		if result.RowsAffected() == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO judgment_proposal_audit_status (tenant_id, judgment_id, engagement_id, actor, action, target, metadata, occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tenantID.String(), j.ID.String(), j.EngagementID.String(), entry.Actor, entry.Action, entry.Target, metadata, entry.At); err != nil {
			return fmt.Errorf("insert judgment proposal audit status: %w", err)
		}
		return nil
	})
}

// SetVerdictStateWithAudit commits the verdict and immutable pending audit entry atomically.
func (r *JudgmentRepository) SetVerdictStateWithAudit(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, verifiedBy, rationale string, expectedVersion int, entry ports.AuditEntry) (out judgment.Judgment, err error) {
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return out, fmt.Errorf("marshal verdict audit metadata: %w", err)
	}
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = scanJudgment(tx.QueryRow(ctx, `UPDATE judgments SET evidence_score=$1, state=$2, verified_by=$3, verdict_rationale=$4, version=version+1, updated_at=now() WHERE id=$5 AND engagement_id=$6 AND version=$7 RETURNING `+judgmentCols, score, string(state), verifiedBy, rationale, id.String(), engagementID.String(), expectedVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyJudgmentMiss(ctx, tx, engagementID, id)
		}
		if err != nil {
			return fmt.Errorf("set judgment verdict state: %w", err)
		}
		tenantID, _ := shared.TenantFrom(ctx)
		if _, err := tx.Exec(ctx, `INSERT INTO judgment_verdict_audit_status (tenant_id, judgment_id, version, engagement_id, actor, action, target, metadata, occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tenantID.String(), id.String(), out.Version, engagementID.String(), entry.Actor, entry.Action, entry.Target, metadata, entry.At); err != nil {
			return fmt.Errorf("insert judgment verdict audit status: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *JudgmentRepository) ListPendingJudgmentAudits(ctx context.Context, engagementID shared.ID) (out []ports.PendingJudgmentAudit, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT 'proposal', judgment_id, 1, engagement_id, actor, action, target, metadata, occurred_at FROM judgment_proposal_audit_status WHERE engagement_id=$1 AND completed_at IS NULL UNION ALL SELECT 'verdict', judgment_id, version, engagement_id, actor, action, target, metadata, occurred_at FROM judgment_verdict_audit_status WHERE engagement_id=$1 AND completed_at IS NULL ORDER BY 1,3,2`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list pending judgment audits: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var kind, jid, eid, actor, action, target string
			var version int
			var metadata []byte
			var at time.Time
			if err := rows.Scan(&kind, &jid, &version, &eid, &actor, &action, &target, &metadata, &at); err != nil {
				return fmt.Errorf("scan pending judgment audit: %w", err)
			}
			entry := ports.AuditEntry{Actor: actor, Action: action, Target: target, At: at}
			if err := json.Unmarshal(metadata, &entry.Metadata); err != nil {
				return fmt.Errorf("decode pending judgment audit metadata: %w", err)
			}
			out = append(out, ports.PendingJudgmentAudit{Kind: ports.JudgmentAuditKind(kind), JudgmentID: shared.ID(jid), Version: version, EngagementID: shared.ID(eid), Entry: entry})
		}
		return rows.Err()
	})
	return out, err
}

func (r *JudgmentRepository) AcknowledgeJudgmentAudit(ctx context.Context, kind ports.JudgmentAuditKind, judgmentID shared.ID, version int) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var query string
		var args []any
		switch kind {
		case ports.JudgmentProposalAudit:
			query, args = `UPDATE judgment_proposal_audit_status SET completed_at=COALESCE(completed_at,now()) WHERE judgment_id=$1`, []any{judgmentID.String()}
		case ports.JudgmentVerdictAudit:
			query, args = `UPDATE judgment_verdict_audit_status SET completed_at=COALESCE(completed_at,now()) WHERE judgment_id=$1 AND version=$2`, []any{judgmentID.String(), version}
		default:
			return fmt.Errorf("%w: unknown judgment audit kind %q", shared.ErrValidation, kind)
		}
		result, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("acknowledge judgment audit: %w", err)
		}
		if result.RowsAffected() == 0 {
			return fmt.Errorf("judgment audit %s/%d: %w", judgmentID, version, shared.ErrNotFound)
		}
		return nil
	})
}

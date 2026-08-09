package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const aiTriageReviewCols = `id, tenant_id, engagement_id, project_id, finding_id, dedup_key, title, severity, cwe, owner,
 state, verdict, driver, confidence, suspected_fp, proposer_model, verifier_model, prompt_version, verified,
 verifier_verdict, verifier_driver, verifier_confidence, policy_version, policy_reason, shadow, would_gate_exempt, gate_exempt,
 review_required, evidence_ref, decided_by, decision_rationale, decided_at, version, created_at, updated_at`

type AITriageReviewRepository struct{ pool *pgxpool.Pool }

func NewAITriageReviewRepository(pool *pgxpool.Pool) *AITriageReviewRepository {
	return &AITriageReviewRepository{pool: pool}
}

func (r *AITriageReviewRepository) UpsertPending(ctx context.Context, review aitriagereview.Review) error {
	tenant := shared.TenantOrDefault(review.TenantID).String()
	return WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ai_triage_reviews (
 id, tenant_id, engagement_id, project_id, finding_id, dedup_key, title, severity, cwe, owner,
 state, verdict, driver, confidence, suspected_fp, proposer_model, verifier_model, prompt_version, verified,
 verifier_verdict, verifier_driver, verifier_confidence, policy_version, policy_reason, shadow, would_gate_exempt, gate_exempt,
 review_required, evidence_ref, decided_by, decision_rationale, decided_at, version, created_at, updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)
 ON CONFLICT (tenant_id, engagement_id, dedup_key, policy_version, prompt_version, proposer_model, verifier_model) DO UPDATE SET
   project_id=EXCLUDED.project_id, finding_id=EXCLUDED.finding_id, title=EXCLUDED.title,
   severity=EXCLUDED.severity, cwe=EXCLUDED.cwe,
   verdict=EXCLUDED.verdict, driver=EXCLUDED.driver, confidence=EXCLUDED.confidence,
   suspected_fp=EXCLUDED.suspected_fp, proposer_model=EXCLUDED.proposer_model,
   verifier_model=EXCLUDED.verifier_model, prompt_version=EXCLUDED.prompt_version, verified=EXCLUDED.verified,
   verifier_verdict=EXCLUDED.verifier_verdict, verifier_driver=EXCLUDED.verifier_driver,
   verifier_confidence=EXCLUDED.verifier_confidence, policy_reason=EXCLUDED.policy_reason,
   shadow=EXCLUDED.shadow, would_gate_exempt=EXCLUDED.would_gate_exempt,
   evidence_ref=EXCLUDED.evidence_ref, updated_at=EXCLUDED.updated_at,
   version=ai_triage_reviews.version+1
 WHERE ai_triage_reviews.state='pending'`,
			review.ID.String(), tenant, review.EngagementID.String(), review.ProjectID.String(), review.FindingID.String(),
			review.DedupKey, review.Title, string(review.Severity), review.CWE, review.Owner, string(review.State),
			review.Verdict, review.Driver, review.Confidence, review.SuspectedFP, review.ProposerModel,
			review.VerifierModel, review.PromptVersion, review.Verified, review.VerifierVerdict, review.VerifierDriver,
			review.VerifierConfidence, review.PolicyVersion, review.PolicyReason, review.Shadow, review.WouldGateExempt,
			review.GateExempt, review.ReviewRequired, review.EvidenceRef.String(), review.DecidedBy, review.DecisionRationale,
			review.DecidedAt, review.Version, review.CreatedAt, review.UpdatedAt)
		if err != nil {
			return fmt.Errorf("upsert AI-triage review: %w", err)
		}
		return nil
	})
}

func (r *AITriageReviewRepository) Get(ctx context.Context, tenantID, id shared.ID) (aitriagereview.Review, error) {
	tenant := shared.TenantOrDefault(tenantID).String()
	var out aitriagereview.Review
	err := WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = scanAITriageReview(tx.QueryRow(ctx, `SELECT `+aiTriageReviewCols+` FROM ai_triage_reviews WHERE tenant_id=$1 AND id=$2`, tenant, id.String()))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return aitriagereview.Review{}, shared.ErrNotFound
	}
	if err != nil {
		return aitriagereview.Review{}, fmt.Errorf("get AI-triage review: %w", err)
	}
	return out, nil
}

func (r *AITriageReviewRepository) List(ctx context.Context, tenantID shared.ID, filter ports.AITriageReviewFilter) ([]aitriagereview.Review, error) {
	tenant := shared.TenantOrDefault(tenantID).String()
	out := make([]aitriagereview.Review, 0)
	err := WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+aiTriageReviewCols+` FROM ai_triage_reviews
 WHERE tenant_id=$1 AND ($2='' OR severity=$2) AND ($3='' OR upper(cwe)=upper($3))
   AND ($4='' OR project_id=$4) AND ($5='' OR state=$5)
 ORDER BY created_at DESC, id COLLATE "C" ASC LIMIT 1000`, tenant, string(filter.Severity), filter.CWE, filter.ProjectID.String(), string(filter.State))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			review, err := scanAITriageReview(rows)
			if err != nil {
				return err
			}
			out = append(out, review)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list AI-triage reviews: %w", err)
	}
	return out, nil
}

func (r *AITriageReviewRepository) SaveDecision(ctx context.Context, review aitriagereview.Review, expectedVersion int) error {
	tenant := shared.TenantOrDefault(review.TenantID).String()
	return WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ai_triage_reviews SET state=$1, decided_by=$2,
 decision_rationale=$3, decided_at=$4, version=$5, updated_at=$6
 WHERE tenant_id=$7 AND id=$8 AND state='pending' AND version=$9`, string(review.State), review.DecidedBy,
			review.DecisionRationale, review.DecidedAt, review.Version, review.UpdatedAt, tenant, review.ID.String(), expectedVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: AI-triage review changed", shared.ErrConflict)
		}
		return nil
	})
}

func (r *AITriageReviewRepository) SaveOwner(ctx context.Context, review aitriagereview.Review, expectedVersion int) error {
	tenant := shared.TenantOrDefault(review.TenantID).String()
	return WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ai_triage_reviews SET owner=$1, version=$2, updated_at=$3
 WHERE tenant_id=$4 AND id=$5 AND state='pending' AND version=$6`, review.Owner, review.Version,
			review.UpdatedAt, tenant, review.ID.String(), expectedVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: AI-triage review changed", shared.ErrConflict)
		}
		return nil
	})
}

func scanAITriageReview(row rowScanner) (aitriagereview.Review, error) {
	var r aitriagereview.Review
	var id, tenant, eng, project, findingID, severity, state, evidenceRef string
	var decidedAt *time.Time
	if err := row.Scan(&id, &tenant, &eng, &project, &findingID, &r.DedupKey, &r.Title, &severity, &r.CWE, &r.Owner,
		&state, &r.Verdict, &r.Driver, &r.Confidence, &r.SuspectedFP, &r.ProposerModel, &r.VerifierModel,
		&r.PromptVersion, &r.Verified, &r.VerifierVerdict, &r.VerifierDriver, &r.VerifierConfidence, &r.PolicyVersion,
		&r.PolicyReason, &r.Shadow, &r.WouldGateExempt, &r.GateExempt, &r.ReviewRequired, &evidenceRef, &r.DecidedBy,
		&r.DecisionRationale, &decidedAt, &r.Version, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return aitriagereview.Review{}, err
	}
	r.ID, r.TenantID, r.EngagementID, r.ProjectID = shared.ID(id), shared.ID(tenant), shared.ID(eng), shared.ID(project)
	r.FindingID, r.EvidenceRef = shared.ID(findingID), shared.ID(evidenceRef)
	r.Severity, r.State, r.DecidedAt = shared.Severity(severity), aitriagereview.State(state), decidedAt
	if !r.State.Valid() || !r.Severity.Valid() {
		return aitriagereview.Review{}, fmt.Errorf("%w: invalid stored AI-triage review", shared.ErrValidation)
	}
	return r, nil
}

var _ ports.AITriageReviewStore = (*AITriageReviewRepository)(nil)

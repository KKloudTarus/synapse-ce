package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentRepository struct{ pool *pgxpool.Pool }

func NewAssessmentRepository(pool *pgxpool.Pool) *AssessmentRepository {
	return &AssessmentRepository{pool: pool}
}

var _ ports.AssessmentRepository = (*AssessmentRepository)(nil)

func (r *AssessmentRepository) Create(ctx context.Context, a assessment.Assessment, children []*engagement.Engagement) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if len(children) == 0 {
		return fmt.Errorf("%w: assessment requires engagement", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID != a.TenantID {
		return fmt.Errorf("%w: assessment tenant context", shared.ErrValidation)
	}
	roes := make([][]byte, len(children))
	seen := make(map[shared.ID]struct{}, len(children))
	for i, e := range children {
		if e == nil || e.ID.IsZero() || e.TenantID != a.TenantID || e.AssessmentID != a.ID {
			return fmt.Errorf("%w: invalid assessment engagement", shared.ErrValidation)
		}
		if _, duplicate := seen[e.ID]; duplicate {
			return fmt.Errorf("assessment engagement: %w", shared.ErrConflict)
		}
		roe, err := json.Marshal(e.RoE)
		if err != nil {
			return err
		}
		seen[e.ID], roes[i] = struct{}{}, roe
	}
	policy, err := json.Marshal(a.Policy)
	if err != nil {
		return err
	}
	return WithTenantTx(ctx, r.pool, a.TenantID, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM appsec_business_services WHERE id=$1`, a.BusinessServiceID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("business service %s: %w", a.BusinessServiceID, shared.ErrNotFound)
		} else if err != nil {
			return fmt.Errorf("read assessment business service: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessments (id,tenant_id,business_service_id,name,objective,status,policy,created_at,updated_at,created_by,updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, a.ID, a.TenantID, a.BusinessServiceID, a.Name, a.Objective, a.Status, policy, a.Audit.CreatedAt, a.Audit.UpdatedAt, a.Audit.CreatedBy, a.Audit.UpdatedBy); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("assessment name: %w", shared.ErrConflict)
			}
			return fmt.Errorf("create assessment: %w", err)
		}
		for i, e := range children {
			if _, err := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,assessment_id,project_id,name,client,status,authorized_from,authorized_to,created_at,updated_at,timezone,roe,live_recon,created_by,updated_by) VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, e.ID, e.TenantID, a.ID, e.ProjectID, e.Name, e.Client, e.Status, e.AuthorizedFrom, e.AuthorizedTo, e.Audit.CreatedAt, e.Audit.UpdatedAt, e.Timezone, roes[i], e.LiveReconEnabled, e.Audit.CreatedBy, e.Audit.UpdatedBy); err != nil {
				return fmt.Errorf("create assessment engagement: %w", err)
			}
		}
		return nil
	})
}
func (r *AssessmentRepository) Get(ctx context.Context, id shared.ID) (assessment.Assessment, error) {
	var a assessment.Assessment
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var policy []byte
		err := tx.QueryRow(ctx, `SELECT id,tenant_id,business_service_id,name,objective,status,policy,created_at,updated_at,created_by,updated_by FROM assessments WHERE id=$1`, id).Scan(&a.ID, &a.TenantID, &a.BusinessServiceID, &a.Name, &a.Objective, &a.Status, &policy, &a.Audit.CreatedAt, &a.Audit.UpdatedAt, &a.Audit.CreatedBy, &a.Audit.UpdatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("assessment: %w", shared.ErrNotFound)
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(policy, &a.Policy)
	})
	return a, err
}
func (r *AssessmentRepository) ListByBusinessService(ctx context.Context, serviceID shared.ID) ([]assessment.Assessment, error) {
	out := []assessment.Assessment{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,tenant_id,business_service_id,name,objective,status,policy,created_at,updated_at,created_by,updated_by FROM assessments WHERE business_service_id=$1 ORDER BY created_at DESC,id`, serviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a assessment.Assessment
			var policy []byte
			if err := rows.Scan(&a.ID, &a.TenantID, &a.BusinessServiceID, &a.Name, &a.Objective, &a.Status, &policy, &a.Audit.CreatedAt, &a.Audit.UpdatedAt, &a.Audit.CreatedBy, &a.Audit.UpdatedBy); err != nil {
				return err
			}
			if err := json.Unmarshal(policy, &a.Policy); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

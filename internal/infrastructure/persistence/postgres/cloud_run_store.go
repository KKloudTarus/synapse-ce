package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CloudRunStore persists the tenant-scoped CSPM lifecycle under RLS.
type CloudRunStore struct{ pool *pgxpool.Pool }

var _ ports.CloudRunStore = (*CloudRunStore)(nil)
var _ ports.CloudRunEnqueuer = (*CloudRunStore)(nil)

func NewCloudRunStore(pool *pgxpool.Pool) *CloudRunStore { return &CloudRunStore{pool: pool} }

func (s *CloudRunStore) SaveCloudRun(ctx context.Context, run cloudposture.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	coverage, err := json.Marshal(run.CoverageIssues)
	if err != nil {
		return fmt.Errorf("marshal CSPM coverage: %w", err)
	}
	evidenceRefs, err := json.Marshal(run.EvidenceRefs)
	if err != nil {
		return fmt.Errorf("marshal CSPM evidence refs: %w", err)
	}
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cspm_runs
			(tenant_id,id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id,id) DO UPDATE SET status=EXCLUDED.status, complete=EXCLUDED.complete,
			assets=EXCLUDED.assets, findings=EXCLUDED.findings, coverage=EXCLUDED.coverage,
			error_code=EXCLUDED.error_code, evidence_refs=EXCLUDED.evidence_refs, finished_at=EXCLUDED.finished_at`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.Actor, string(run.Status), run.Complete,
			run.Assets, run.Findings, coverage, run.ErrorCode, evidenceRefs, run.StartedAt, run.FinishedAt)
		return err
	})
}

func (s *CloudRunStore) EnqueueCloudRun(ctx context.Context, run cloudposture.Run, kind string, payload []byte) error {
	if err := run.Validate(); err != nil {
		return err
	}
	coverage, err := json.Marshal(run.CoverageIssues)
	if err != nil {
		return err
	}
	evidenceRefs, err := json.Marshal(run.EvidenceRefs)
	if err != nil {
		return err
	}
	jobID := run.ID.String() + "-job"
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO cspm_runs
			(tenant_id,id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.Actor, string(run.Status), run.Complete, run.Assets, run.Findings, coverage, run.ErrorCode, evidenceRefs, run.StartedAt, run.FinishedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id,tenant_id,kind,payload,status,available_at) VALUES ($1,$2,$3,$4,'queued',now())`, jobID, run.TenantID.String(), kind, payload)
		return err
	})
}

func (s *CloudRunStore) GetCloudRun(ctx context.Context, tenantID, id shared.ID) (out cloudposture.Run, err error) {
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var status string
		var coverage, evidenceRefs []byte
		err := tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,started_at,finished_at
			FROM cspm_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String()).Scan(
			&out.ID, &out.TenantID, &out.EngagementID, &out.Actor, &status, &out.Complete, &out.Assets, &out.Findings,
			&coverage, &out.ErrorCode, &evidenceRefs, &out.StartedAt, &out.FinishedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				return fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
			}
			return err
		}
		out.Status = cloudposture.RunStatus(status)
		if err := json.Unmarshal(coverage, &out.CoverageIssues); err != nil {
			return err
		}
		return json.Unmarshal(evidenceRefs, &out.EvidenceRefs)
	})
	if err != nil {
		return cloudposture.Run{}, fmt.Errorf("get CSPM run: %w", err)
	}
	return out, nil
}

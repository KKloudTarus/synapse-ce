package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DASTRunStore persists the tenant-scoped DAST run lifecycle under RLS.
type DASTRunStore struct{ pool *pgxpool.Pool }

var _ ports.DASTRunStore = (*DASTRunStore)(nil)
var _ ports.DASTRunEnqueuer = (*DASTRunStore)(nil)

func NewDASTRunStore(pool *pgxpool.Pool) *DASTRunStore { return &DASTRunStore{pool: pool} }

// SaveDASTRun upserts the run, but NEVER moves a terminal row backward: the ON CONFLICT update is guarded
// so a stored 'succeeded' or 'failed' row is frozen. This is defense-in-depth against a stale worker whose
// lease was reclaimed (its claim context is cancelled, so its writes should already fail, but a write that
// slips through the cancellation window must not un-terminalize a recorded outcome). FinishRun is the CAS
// that records terminal outcomes; SaveDASTRun only advances a run toward one.
func (s *DASTRunStore) SaveDASTRun(ctx context.Context, run dastrun.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		var prior, storedEngagement string
		err := tx.QueryRow(ctx, `SELECT status,engagement_id FROM dast_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, run.TenantID.String(), run.ID.String()).Scan(&prior, &storedEngagement)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil && storedEngagement != run.EngagementID.String() {
			return fmt.Errorf("%w: DAST run engagement does not match stored run", shared.ErrValidation)
		}
		_, err = tx.Exec(ctx, `INSERT INTO dast_runs
			(tenant_id,id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id,id) DO UPDATE SET status=EXCLUDED.status, verdict=EXCLUDED.verdict,
			http_status=EXCLUDED.http_status, evidence_id=EXCLUDED.evidence_id, error_code=EXCLUDED.error_code,
			finished_at=EXCLUDED.finished_at
			WHERE dast_runs.status NOT IN ('succeeded','failed')`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.ActionID.String(), run.Actor,
			string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.StartedAt, run.FinishedAt)
		if err != nil {
			return err
		}
		if run.Status.Terminal() && prior != string(dastrun.RunSucceeded) && prior != string(dastrun.RunFailed) {
			return appendDASTRunNotification(ctx, tx, run)
		}
		return nil
	})
}

func (s *DASTRunStore) EnqueueDASTRun(ctx context.Context, run dastrun.Run, kind string, payload []byte) error {
	if err := run.Validate(); err != nil {
		return err
	}
	jobID := run.ID.String() + "-job"
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO dast_runs
			(tenant_id,id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.ActionID.String(), run.Actor,
			string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.StartedAt, run.FinishedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id,tenant_id,kind,payload,status,available_at) VALUES ($1,$2,$3,$4,'queued',now())`,
			jobID, run.TenantID.String(), kind, payload)
		return err
	})
}

// StartRun moves a run 'queued' -> 'running' only if the stored row is still 'queued' (compare-and-set),
// reporting whether it won. A redelivered or lease-overlapping worker that finds the run already running or
// terminal loses (won=false) and must not execute the probe.
func (s *DASTRunStore) StartRun(ctx context.Context, tenantID shared.ID, run dastrun.Run) (won bool, err error) {
	if run.Status != dastrun.RunRunning {
		return false, fmt.Errorf("%w: StartRun needs a running run, got %s", shared.ErrValidation, run.Status)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE dast_runs SET status='running' WHERE tenant_id=$1 AND id=$2 AND status='queued'`,
			tenantID.String(), run.ID.String())
		if e != nil {
			return e
		}
		won = tag.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("start DAST run: %w", err)
	}
	return won, nil
}

func appendDASTRunNotification(ctx context.Context, tx pgx.Tx, run dastrun.Run) error {
	return appendRunFinishedNotification(ctx, tx, run.TenantID, run.EngagementID, notification.EventDASTRunFinished,
		"dast_run", run.ID.String(), "dast", string(run.Status), []string{"dast"}, "", run.ErrorCode, -1, *run.FinishedAt)
}

// FinishRun writes the terminal run only if the stored row is still 'running' (compare-and-set), and
// reports whether the row was updated. A redelivered or lease-overlapping worker that lost the race
// changes nothing.
func (s *DASTRunStore) FinishRun(ctx context.Context, tenantID shared.ID, run dastrun.Run) (won bool, err error) {
	if err := run.Validate(); err != nil {
		return false, err
	}
	if !run.Status.Terminal() {
		return false, fmt.Errorf("%w: FinishRun needs a terminal run, got %s", shared.ErrValidation, run.Status)
	}
	if run.TenantID != tenantID {
		return false, fmt.Errorf("%w: DAST run tenant does not match transaction tenant", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE dast_runs SET status=$3, verdict=$4, http_status=$5, evidence_id=$6, error_code=$7, finished_at=$8
			WHERE tenant_id=$1 AND id=$2 AND status='running' AND engagement_id=$9`,
			tenantID.String(), run.ID.String(), string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.FinishedAt, run.EngagementID.String())
		if e != nil {
			return e
		}
		won = tag.RowsAffected() == 1
		if !won {
			return nil
		}
		return appendDASTRunNotification(ctx, tx, run)
	})
	if err != nil {
		return false, fmt.Errorf("finish DAST run: %w", err)
	}
	return won, nil
}

func (s *DASTRunStore) GetDASTRun(ctx context.Context, tenantID, id shared.ID) (out dastrun.Run, err error) {
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var status, evidenceID string
		e := tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at
			FROM dast_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String()).Scan(
			&out.ID, &out.TenantID, &out.EngagementID, &out.ActionID, &out.Actor, &status, &out.Verdict,
			&out.HTTPStatus, &evidenceID, &out.ErrorCode, &out.StartedAt, &out.FinishedAt)
		if e != nil {
			if e == pgx.ErrNoRows {
				return fmt.Errorf("%w: DAST run", shared.ErrNotFound)
			}
			return e
		}
		out.Status = dastrun.RunStatus(status)
		out.EvidenceID = shared.ID(evidenceID)
		return nil
	})
	if err != nil {
		return dastrun.Run{}, fmt.Errorf("get DAST run: %w", err)
	}
	return out, nil
}

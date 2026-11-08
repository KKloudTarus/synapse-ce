package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"time"

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
	if current, ok := shared.TenantFrom(ctx); ok && current != run.TenantID {
		return fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if run.Kind != dastrun.KindVerifier {
		return fmt.Errorf("%w: unfenced scan save", shared.ErrForbidden)
	}
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		var prior, engagement, action, actor, kind string
		err := tx.QueryRow(ctx, `SELECT status,engagement_id,action_id,actor,kind FROM dast_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, run.TenantID.String(), run.ID.String()).Scan(&prior, &engagement, &action, &actor, &kind)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil && (engagement != run.EngagementID.String() || action != run.ActionID.String() || actor != run.Actor || kind != string(run.Kind)) {
			return fmt.Errorf("%w: DAST run identity does not match stored run", shared.ErrValidation)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO dast_runs
			(tenant_id,id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (tenant_id,id) DO UPDATE SET status=EXCLUDED.status, verdict=EXCLUDED.verdict,
			http_status=EXCLUDED.http_status, evidence_id=EXCLUDED.evidence_id, error_code=EXCLUDED.error_code,
			finished_at=EXCLUDED.finished_at
			WHERE dast_runs.kind='verifier' AND dast_runs.engagement_id=EXCLUDED.engagement_id AND dast_runs.action_id=EXCLUDED.action_id AND dast_runs.actor=EXCLUDED.actor AND dast_runs.status NOT IN ('succeeded','incomplete','failed')`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.ActionID.String(), run.Actor,
			string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.StartedAt, run.FinishedAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 && prior == "" {
			return fmt.Errorf("%w: conflicting DAST run", shared.ErrConflict)
		}
		if tag.RowsAffected() == 1 && run.Status.Terminal() {
			return appendDASTRunNotification(ctx, tx, run)
		}
		return nil
	})
}

func (s *DASTRunStore) EnqueueDASTRun(ctx context.Context, run dastrun.Run, kind string, payload []byte) error {
	if err := run.Validate(); err != nil {
		return err
	}
	if current, ok := shared.TenantFrom(ctx); ok && current != run.TenantID {
		return fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if run.Status != dastrun.RunQueued {
		return fmt.Errorf("%w: DAST enqueue requires queued run", shared.ErrValidation)
	}
	switch run.Kind {
	case dastrun.KindVerifier:
		var job ports.DASTRunJob
		if kind != "dast_run" || decodeDASTJob(payload, &job) != nil || job.TenantID != run.TenantID || job.RunID != run.ID {
			return fmt.Errorf("%w: invalid verifier job", shared.ErrValidation)
		}
	case dastrun.KindAuthenticatedScan:
		var job ports.DASTScanJob
		if kind != "dast_scan" || decodeDASTJob(payload, &job) != nil || job.TenantID != run.TenantID || job.RunID != run.ID || !validDASTScanJob(job) {
			return fmt.Errorf("%w: invalid scan job", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: invalid run kind", shared.ErrValidation)
	}
	var payloadHash *string
	if run.Kind == dastrun.KindAuthenticatedScan {
		digest := fmt.Sprintf("%x", sha256.Sum256(payload))
		payloadHash = &digest
	}
	jobID := run.ID.String() + "-job"
	var scanJobID *string
	if run.Kind == dastrun.KindAuthenticatedScan {
		scanJobID = &jobID
	}
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO dast_runs
			(tenant_id,id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at,kind,scan_payload_sha256,scan_job_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.ActionID.String(), run.Actor,
			string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.StartedAt, run.FinishedAt, string(run.Kind), payloadHash, scanJobID); err != nil {
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
	if current, ok := shared.TenantFrom(ctx); ok && current != tenantID {
		return false, fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if run.Status != dastrun.RunRunning {
		return false, fmt.Errorf("%w: StartRun needs a running run, got %s", shared.ErrValidation, run.Status)
	}
	if run.TenantID != tenantID || run.Kind != dastrun.KindVerifier {
		return false, fmt.Errorf("%w: invalid verifier identity", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE dast_runs SET status='running' WHERE tenant_id=$1 AND id=$2 AND status='queued' AND kind='verifier' AND engagement_id=$3 AND action_id=$4 AND actor=$5`,
			tenantID.String(), run.ID.String(), run.EngagementID.String(), run.ActionID.String(), run.Actor)
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
	if current, ok := shared.TenantFrom(ctx); ok && current != tenantID {
		return false, fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if err := run.Validate(); err != nil {
		return false, err
	}
	if !run.Status.Terminal() {
		return false, fmt.Errorf("%w: FinishRun needs a terminal run, got %s", shared.ErrValidation, run.Status)
	}
	if run.TenantID != tenantID {
		return false, fmt.Errorf("%w: DAST run tenant does not match transaction tenant", shared.ErrValidation)
	}
	if run.Kind != dastrun.KindVerifier {
		return false, fmt.Errorf("%w: unfenced scan finish", shared.ErrForbidden)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE dast_runs SET status=$3, verdict=$4, http_status=$5, evidence_id=$6, error_code=$7, finished_at=$8
			WHERE tenant_id=$1 AND id=$2 AND status='running' AND kind='verifier' AND engagement_id=$9 AND action_id=$10 AND actor=$11`,
			tenantID.String(), run.ID.String(), string(run.Status), run.Verdict, run.HTTPStatus, run.EvidenceID.String(), run.ErrorCode, run.FinishedAt, run.EngagementID.String(), run.ActionID.String(), run.Actor)
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
	if current, ok := shared.TenantFrom(ctx); ok && current != tenantID {
		return out, fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var status, evidenceID string
		e := tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,action_id,actor,status,verdict,http_status,evidence_id,error_code,started_at,finished_at,kind
			FROM dast_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String()).Scan(
			&out.ID, &out.TenantID, &out.EngagementID, &out.ActionID, &out.Actor, &status, &out.Verdict,
			&out.HTTPStatus, &evidenceID, &out.ErrorCode, &out.StartedAt, &out.FinishedAt, &out.Kind)
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

func decodeDASTJob(payload []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("invalid trailing job payload")
	}
	return nil
}

func validDASTScanJob(job ports.DASTScanJob) bool {
	if !filepath.IsAbs(job.HelperPath) || len(job.HelperSHA256) != 64 || strings.ToLower(job.HelperSHA256) != job.HelperSHA256 {
		return false
	}
	if _, err := hex.DecodeString(job.HelperSHA256); err != nil {
		return false
	}
	if len(job.Config) == 0 || !json.Valid(job.Config) {
		return false
	}
	return job.ConfigSHA256 == fmt.Sprintf("%x", sha256.Sum256(job.Config))
}

// scanLocked takes locks in approval, run, job, engagement order. The queue
// lease is checked against the database wall clock, not transaction start.
func (s *DASTRunStore) scanLocked(ctx context.Context, tx pgx.Tx, e ports.DASTScanExecution, owner bool) (dastrun.Run, ports.DASTScanJob, time.Duration, error) {
	var run dastrun.Run
	var job ports.DASTScanJob
	if _, err := e.ExecutionID(); err != nil {
		return run, job, 0, err
	}
	var action string
	if err := tx.QueryRow(ctx, `SELECT action_id FROM dast_runs WHERE tenant_id=$1 AND id=$2`, e.TenantID.String(), e.RunID.String()).Scan(&action); err != nil {
		return run, job, 0, dastAuthorityError(err, "run")
	}
	var locked string
	if err := tx.QueryRow(ctx, `SELECT action_id FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE`, e.TenantID.String(), action).Scan(&locked); err != nil {
		return run, job, 0, dastAuthorityError(err, "approval")
	}
	var storedJob *string
	var storedFence *int64
	var payloadHash *string
	var status, evidenceID string
	err := tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,action_id,actor,kind,status,verdict,http_status,evidence_id,error_code,started_at,finished_at,scan_job_id,scan_fence,scan_payload_sha256 FROM dast_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, e.TenantID.String(), e.RunID.String()).Scan(&run.ID, &run.TenantID, &run.EngagementID, &run.ActionID, &run.Actor, &run.Kind, &status, &run.Verdict, &run.HTTPStatus, &evidenceID, &run.ErrorCode, &run.StartedAt, &run.FinishedAt, &storedJob, &storedFence, &payloadHash)
	if err != nil {
		return run, job, 0, dastAuthorityError(err, "run")
	}
	run.Status, run.EvidenceID = dastrun.RunStatus(status), shared.ID(evidenceID)
	if run.Kind != dastrun.KindAuthenticatedScan || run.ActionID.String() != action {
		return run, job, 0, fmt.Errorf("%w: invalid scan identity", shared.ErrForbidden)
	}
	if owner && (run.Status != dastrun.RunRunning || storedJob == nil || storedFence == nil || *storedJob != e.JobID || *storedFence != e.Fence) {
		return run, job, 0, fmt.Errorf("%w: scan owner changed", ports.ErrStaleLease)
	}
	var kind, state string
	var payload []byte
	var fence int64
	var remaining *float64
	err = tx.QueryRow(ctx, `SELECT kind,payload,status,claim_fence,extract(epoch FROM (claimed_until-clock_timestamp()))::double precision FROM jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, e.TenantID.String(), e.JobID).Scan(&kind, &payload, &state, &fence, &remaining)
	if err != nil {
		return run, job, 0, dastAuthorityError(err, "job")
	}
	if e.JobID != e.RunID.String()+"-job" || kind != "dast_scan" || state != "claimed" || fence != e.Fence || remaining == nil || *remaining <= 0 || decodeDASTJob(payload, &job) != nil || job.TenantID != e.TenantID || job.RunID != e.RunID {
		return run, job, 0, fmt.Errorf("%w: invalid or expired scan claim", ports.ErrStaleLease)
	}
	if payloadHash == nil || *payloadHash != fmt.Sprintf("%x", sha256.Sum256(payload)) {
		return run, job, 0, fmt.Errorf("%w: scan payload changed", shared.ErrForbidden)
	}
	if err = tx.QueryRow(ctx, `SELECT id FROM engagements WHERE tenant_id=$1 AND id=$2 FOR SHARE`, e.TenantID.String(), run.EngagementID.String()).Scan(&locked); err != nil {
		return run, job, 0, dastAuthorityError(err, "engagement")
	}
	err = tx.QueryRow(ctx, `SELECT extract(epoch FROM (claimed_until-clock_timestamp()))::double precision FROM jobs WHERE tenant_id=$1 AND id=$2 AND status='claimed' AND claim_fence=$3`, e.TenantID.String(), e.JobID, e.Fence).Scan(&remaining)
	if err != nil || remaining == nil || *remaining <= 0 {
		return run, job, 0, fmt.Errorf("%w: scan claim expired while locking", ports.ErrStaleLease)
	}
	return run, job, time.Duration(*remaining * float64(time.Second)), nil
}

func scanLeaseLive(ctx context.Context, tx pgx.Tx, e ports.DASTScanExecution) error {
	var live bool
	err := tx.QueryRow(ctx, `SELECT status='claimed' AND claim_fence=$3 AND claimed_until>clock_timestamp() FROM jobs WHERE tenant_id=$1 AND id=$2`, e.TenantID.String(), e.JobID, e.Fence).Scan(&live)
	if err != nil || !live {
		return fmt.Errorf("%w: scan claim expired", ports.ErrStaleLease)
	}
	return nil
}

func (s *DASTRunStore) scanTransaction(ctx context.Context, e ports.DASTScanExecution, owner bool, fn func(context.Context, pgx.Tx, dastrun.Run, ports.DASTScanJob) error) error {
	if current, ok := shared.TenantFrom(ctx); ok && current != e.TenantID {
		return fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction); ok && bound.tenantID != e.TenantID.String() {
		return fmt.Errorf("%w: transaction tenant mismatch", shared.ErrForbidden)
	}
	ctx = context.WithValue(ctx, tenantTransactionKey{}, nil)
	return requireTenant(ctx, s.pool, e.TenantID, func(tx pgx.Tx) error {
		run, job, remaining, err := s.scanLocked(ctx, tx, e, owner)
		if err != nil {
			return err
		}
		bounded, cancel := context.WithTimeout(bindTenantTransaction(ctx, e.TenantID, tx), remaining)
		defer cancel()
		if err = fn(bounded, tx, run, job); err != nil {
			return err
		}
		if err = bounded.Err(); err != nil {
			return err
		}
		return scanLeaseLive(bounded, tx, e)
	})
}

func (s *DASTRunStore) StartDASTScan(ctx context.Context, e ports.DASTScanExecution, expected ports.DASTScanJob) (won bool, err error) {
	err = s.scanTransaction(ctx, e, false, func(c context.Context, tx pgx.Tx, run dastrun.Run, job ports.DASTScanJob) error {
		if !reflect.DeepEqual(job, expected) {
			return fmt.Errorf("%w: scan payload changed", shared.ErrForbidden)
		}
		tag, err := tx.Exec(c, `UPDATE dast_runs SET status='running',scan_fence=$4 WHERE tenant_id=$1 AND id=$2 AND kind='authenticated_scan' AND status='queued' AND scan_job_id=$3 AND scan_fence IS NULL`, e.TenantID.String(), e.RunID.String(), e.JobID, e.Fence)
		won = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, err
	}
	return won, nil
}

func (s *DASTRunStore) WithDASTScanOwner(ctx context.Context, e ports.DASTScanExecution, fn func(context.Context) error) error {
	if fn == nil {
		return fmt.Errorf("%w: callback required", shared.ErrValidation)
	}
	return s.scanTransaction(ctx, e, true, func(c context.Context, _ pgx.Tx, _ dastrun.Run, _ ports.DASTScanJob) error { return fn(c) })
}

func (s *DASTRunStore) FinishDASTScan(ctx context.Context, e ports.DASTScanExecution, result dastrun.Run) (won bool, err error) {
	if err := result.Validate(); err != nil {
		return false, err
	}
	if result.Kind != dastrun.KindAuthenticatedScan || !result.Status.Terminal() || result.TenantID != e.TenantID || result.ID != e.RunID {
		return false, fmt.Errorf("%w: invalid scan result", shared.ErrValidation)
	}
	err = s.scanTransaction(ctx, e, true, func(c context.Context, tx pgx.Tx, run dastrun.Run, _ ports.DASTScanJob) error {
		if result.EngagementID != run.EngagementID || result.ActionID != run.ActionID || result.Actor != run.Actor || !result.StartedAt.Equal(run.StartedAt) {
			return fmt.Errorf("%w: scan identity changed", shared.ErrForbidden)
		}
		tag, err := tx.Exec(c, `UPDATE dast_runs SET status=$3,evidence_id=$4,error_code=$5,finished_at=$6 WHERE tenant_id=$1 AND id=$2 AND status='running'`, e.TenantID.String(), e.RunID.String(), string(result.Status), result.EvidenceID.String(), result.ErrorCode, result.FinishedAt)
		if err != nil {
			return err
		}
		won = tag.RowsAffected() == 1
		if won {
			return appendDASTRunNotification(c, tx, result)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return won, nil
}

func (s *DASTRunStore) InterruptDASTScan(ctx context.Context, e ports.DASTScanExecution, at time.Time) (won bool, err error) {
	if at.IsZero() {
		return false, fmt.Errorf("%w: interruption time required", shared.ErrValidation)
	}
	err = s.scanTransaction(ctx, e, false, func(c context.Context, tx pgx.Tx, run dastrun.Run, _ ports.DASTScanJob) error {
		if run.Status != dastrun.RunRunning {
			return nil
		}
		tag, err := tx.Exec(c, `UPDATE dast_runs SET status='failed',error_code='interrupted',finished_at=$5 WHERE tenant_id=$1 AND id=$2 AND status='running' AND scan_job_id IS NOT NULL AND (scan_job_id<>$3 OR scan_fence<>$4)`, e.TenantID.String(), e.RunID.String(), e.JobID, e.Fence, at)
		if err != nil {
			return err
		}
		won = tag.RowsAffected() == 1
		if won {
			run.Fail("interrupted", at)
			return appendDASTRunNotification(c, tx, run)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return won, nil
}

// FailDeadLetteredDASTScan resolves the run from the immutable stored job ID,
// never from a possibly malformed queue payload. A failed job has no lease.
func (s *DASTRunStore) FailDeadLetteredDASTScan(ctx context.Context, job ports.QueuedJob, code string, at time.Time) (won bool, err error) {
	if job.TenantID.IsZero() || job.ID == "" || job.Kind != "dast_scan" || job.Fence < 1 || code == "" || at.IsZero() {
		return false, fmt.Errorf("%w: invalid deadletter identity", shared.ErrValidation)
	}
	if tenant, ok := shared.TenantFrom(ctx); ok && tenant != job.TenantID {
		return false, fmt.Errorf("%w: tenant mismatch", shared.ErrForbidden)
	}
	if bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction); ok && bound.tenantID != job.TenantID.String() {
		return false, fmt.Errorf("%w: transaction tenant mismatch", shared.ErrForbidden)
	}
	ctx = context.WithValue(ctx, tenantTransactionKey{}, nil)
	err = requireTenant(ctx, s.pool, job.TenantID, func(tx pgx.Tx) error {
		var id, action string
		err := tx.QueryRow(ctx, `SELECT id,action_id FROM dast_runs WHERE tenant_id=$1 AND kind='authenticated_scan' AND scan_job_id=$2`, job.TenantID.String(), job.ID).Scan(&id, &action)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		var locked string
		if err = tx.QueryRow(ctx, `SELECT action_id FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2 FOR UPDATE`, job.TenantID.String(), action).Scan(&locked); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return dastAuthorityError(err, "approval")
		}
		var run dastrun.Run
		var status, evidenceID string
		err = tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,action_id,actor,kind,status,verdict,http_status,evidence_id,error_code,started_at,finished_at FROM dast_runs WHERE tenant_id=$1 AND id=$2 AND kind='authenticated_scan' AND scan_job_id=$3 FOR UPDATE`, job.TenantID.String(), id, job.ID).Scan(&run.ID, &run.TenantID, &run.EngagementID, &run.ActionID, &run.Actor, &run.Kind, &status, &run.Verdict, &run.HTTPStatus, &evidenceID, &run.ErrorCode, &run.StartedAt, &run.FinishedAt)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if run.ActionID.String() != action {
			return fmt.Errorf("%w: scan action changed", shared.ErrForbidden)
		}
		run.Status, run.EvidenceID = dastrun.RunStatus(status), shared.ID(evidenceID)
		if run.Status.Terminal() {
			return nil
		}
		var kind, state string
		var fence int64
		err = tx.QueryRow(ctx, `SELECT kind,status,claim_fence FROM jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, job.TenantID.String(), job.ID).Scan(&kind, &state, &fence)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if kind != "dast_scan" || state != "failed" || fence != job.Fence {
			return nil
		}
		run.Fail(code, at)
		tag, err := tx.Exec(ctx, `UPDATE dast_runs SET status='failed',error_code=$3,finished_at=$4 WHERE tenant_id=$1 AND id=$2 AND status IN ('queued','running')`, job.TenantID.String(), id, code, at)
		if err != nil {
			return err
		}
		won = tag.RowsAffected() == 1
		if won {
			return appendDASTRunNotification(ctx, tx, run)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return won, nil
}

// RecoverDeadLetteredDASTScans reconciles a bounded batch per tenant. Candidate
// discovery grants no authority: the finalizer rechecks the stored identity,
// queue state and fence in its own tenant transaction.
func (s *DASTRunStore) RecoverDeadLetteredDASTScans(ctx context.Context, at time.Time) (int, error) {
	if at.IsZero() {
		return 0, fmt.Errorf("%w: missing recovery time", shared.ErrValidation)
	}
	if _, ok := shared.TenantFrom(ctx); ok {
		return 0, fmt.Errorf("%w: global recovery requires an unbound context", shared.ErrForbidden)
	}
	tenants, err := listTenantIDs(ctx, s.pool, "DAST scan recovery")
	if err != nil {
		return 0, err
	}
	var recovered int
	var failures error
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			return recovered, errors.Join(failures, err)
		}
		var jobs []ports.QueuedJob
		err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT j.id,j.claim_fence
				FROM dast_runs r JOIN jobs j ON j.tenant_id=r.tenant_id AND j.id=r.scan_job_id
				WHERE r.tenant_id=$1 AND r.kind='authenticated_scan' AND r.status IN ('queued','running')
				  AND j.kind='dast_scan' AND j.status='failed' AND j.claim_fence > 0
				ORDER BY r.scan_job_id LIMIT 100`, tenant.String())
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				job := ports.QueuedJob{TenantID: tenant, Kind: "dast_scan"}
				if err := rows.Scan(&job.ID, &job.Fence); err != nil {
					return err
				}
				jobs = append(jobs, job)
			}
			return rows.Err()
		})
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("discover DAST recovery candidates: %w", err))
			continue
		}
		for _, job := range jobs {
			won, err := s.FailDeadLetteredDASTScan(shared.WithTenant(ctx, tenant), job, "queue_failed", at)
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("finalize DAST recovery candidate: %w", err))
			} else if won {
				recovered++
			}
		}
	}
	return recovered, failures
}

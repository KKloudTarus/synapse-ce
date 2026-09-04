package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const findingLineageBackfillRunColumns = `tenant_id,id,schema_version,dry_run,batch_size,producer_filters,snapshot_at,checkpoint_finding_id,state,lease_owner,lease_token,lease_expires_at,processed_count,observation_created_count,provisional_candidate_count,skipped_count,created_by,created_at,updated_at,completed_at`

type FindingLineageBackfillRepository struct{ pool *pgxpool.Pool }

func NewFindingLineageBackfillRepository(pool *pgxpool.Pool) *FindingLineageBackfillRepository {
	return &FindingLineageBackfillRepository{pool: pool}
}

var _ ports.FindingLineageBackfillSource = (*FindingLineageBackfillRepository)(nil)
var _ ports.FindingLineageBackfillStore = (*FindingLineageBackfillRepository)(nil)

func (repository *FindingLineageBackfillRepository) ListFindingLineageBackfillSources(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, producerFilters []string, limit int) ([]ports.FindingLineageBackfillSourceRow, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || snapshotAt.IsZero() || limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: finding lineage backfill source query is invalid", shared.ErrValidation)
	}
	var out []ports.FindingLineageBackfillSourceRow
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT f.tenant_id,f.engagement_id,f.id,COALESCE(NULLIF(f.kind,''),'sca'),COALESCE(f.rule_key,''),COALESCE(f.dedup_key,''),
			COALESCE(f.advisory_id,''),COALESCE(f.occurrence_id,''),COALESCE(f.component_fingerprint,''),
			f.severity,f.risk_score,COALESCE(f.reachability,''),f.updated_at,f.data_flow,
			COALESCE(m.cycle_id,''),COALESCE(m.membership_count,0)=1,COALESCE(s.id,''),COALESCE(s.content_hash,'')
		FROM findings f
		LEFT JOIN LATERAL (
			SELECT min(cycle_id) AS cycle_id,count(*) AS membership_count
			FROM assessment_cycle_members
			WHERE tenant_id=f.tenant_id AND assessment_id=f.engagement_id AND archived_at IS NULL
		) m ON TRUE
		LEFT JOIN LATERAL (
			SELECT snap.id,snap.content_hash
			FROM assessment_snapshots snap
			WHERE snap.tenant_id=f.tenant_id AND snap.assessment_id=f.engagement_id AND snap.cycle_id=m.cycle_id
			ORDER BY EXISTS (
				SELECT 1 FROM assessment_snapshot_defaults pointer
				WHERE pointer.tenant_id=snap.tenant_id AND pointer.assessment_id=snap.assessment_id AND pointer.snapshot_id=snap.id
			) DESC,(snap.provenance='native') DESC,snap.snapshot_number DESC
			LIMIT 1
		) s ON m.membership_count=1
		WHERE f.tenant_id=$1 AND f.id>$2 AND f.created_at<=$3 AND f.updated_at<=$3
			AND (cardinality($4::text[])=0 OR COALESCE(NULLIF(f.kind,''),'sca')=ANY($4::text[]))
		ORDER BY f.id COLLATE "C" LIMIT $5`, tenantID.String(), after.String(), snapshotAt.UTC(), producerFilters, limit)
		if err != nil {
			return fmt.Errorf("list finding lineage backfill sources: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				source         ports.FindingLineageBackfillSourceRow
				kind, severity string
				dataFlowJSON   []byte
			)
			if err := rows.Scan(&source.TenantID, &source.AssessmentID, &source.FindingID, &kind, &source.RuleKey, &source.DedupKey,
				&source.AdvisoryID, &source.OccurrenceID, &source.ComponentFingerprint,
				&severity, &source.RiskScore, &source.Reachability, &source.ObservedAt, &dataFlowJSON,
				&source.CycleID, &source.OwnershipValid, &source.SnapshotID, &source.SnapshotContentHash); err != nil {
				return fmt.Errorf("scan finding lineage backfill source: %w", err)
			}
			source.Kind, source.Severity = finding.Kind(kind), shared.Severity(severity)
			source.SourceLocation = backfillSourceLocation(dataFlowJSON)
			out = append(out, source)
		}
		return rows.Err()
	})
	return out, err
}

func (repository *FindingLineageBackfillRepository) AcquireFindingLineageBackfillRun(ctx context.Context, request ports.FindingLineageBackfillAcquireRequest) (run ports.FindingLineageBackfillRun, resumed bool, err error) {
	if request.Run.ProducerFilters == nil {
		request.Run.ProducerFilters = []string{}
	}
	if err := validatePostgresFindingLineageBackfillAcquire(request); err != nil {
		return ports.FindingLineageBackfillRun{}, false, err
	}
	err = WithTenant(ctx, repository.pool, request.Run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, request.Run.TenantID.String()); err != nil {
			return fmt.Errorf("lock finding lineage backfill tenant: %w", err)
		}
		existing, scanErr := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `SELECT `+findingLineageBackfillRunColumns+` FROM finding_lineage_backfill_runs WHERE tenant_id=$1 AND state='running' FOR UPDATE`, request.Run.TenantID.String()))
		if scanErr == nil {
			if existing.LeaseOwner != request.Run.LeaseOwner && existing.LeaseExpiresAt.After(request.Run.CreatedAt) {
				return fmt.Errorf("%w: finding lineage backfill already running for tenant", shared.ErrConflict)
			}
			if existing.SchemaVersion != request.Run.SchemaVersion || existing.DryRun != request.Run.DryRun || existing.BatchSize != request.Run.BatchSize || strings.Join(existing.ProducerFilters, "\x00") != strings.Join(request.Run.ProducerFilters, "\x00") {
				return fmt.Errorf("%w: resumed finding lineage backfill options changed", shared.ErrConflict)
			}
			updated, err := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `UPDATE finding_lineage_backfill_runs SET lease_owner=$3,lease_token=$4,lease_expires_at=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND state='running' RETURNING `+findingLineageBackfillRunColumns,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt))
			if err != nil {
				return fmt.Errorf("resume finding lineage backfill run: %w", err)
			}
			run, resumed = updated, true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return fmt.Errorf("find active finding lineage backfill run: %w", scanErr)
		}
		created, err := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `INSERT INTO finding_lineage_backfill_runs (`+findingLineageBackfillRunColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'running',$9,$10,$11,0,0,0,0,$12,$13,$13,NULL) RETURNING `+findingLineageBackfillRunColumns,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, request.Run.ProducerFilters,
			request.Run.SnapshotAt, request.InitialCheckpoint.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedBy, request.Run.CreatedAt))
		if err != nil {
			return fmt.Errorf("create finding lineage backfill run: %w", err)
		}
		run = created
		return nil
	})
	return run, resumed, err
}

func (repository *FindingLineageBackfillRepository) GetFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID) (run ports.FindingLineageBackfillRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		item, err := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `SELECT `+findingLineageBackfillRunColumns+` FROM finding_lineage_backfill_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), runID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get finding lineage backfill run: %w", err)
		}
		run = item
		return nil
	})
	return run, err
}

func (repository *FindingLineageBackfillRepository) GetFindingLineageBackfillItem(ctx context.Context, tenantID, runID, sourceFindingID shared.ID) (item ports.FindingLineageBackfillItem, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var cycleID, snapshotID pgtype.Text
		err := tx.QueryRow(ctx, `SELECT tenant_id,run_id,assessment_id,cycle_id,snapshot_id,source_finding_id,schema_version,matcher_version,idempotency_key,source_hash,outcome,reason_code,processed_at
			FROM finding_lineage_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND source_finding_id=$3`, tenantID.String(), runID.String(), sourceFindingID.String()).Scan(
			&item.TenantID, &item.RunID, &item.AssessmentID, &cycleID, &snapshotID, &item.SourceFindingID, &item.SchemaVersion, &item.MatcherVersion,
			&item.IdempotencyKey, &item.SourceHash, &item.Outcome, &item.ReasonCode, &item.ProcessedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get finding lineage backfill item: %w", err)
		}
		if cycleID.Valid {
			item.CycleID = shared.ID(cycleID.String)
		}
		if snapshotID.Valid {
			item.SnapshotID = shared.ID(snapshotID.String)
		}
		return nil
	})
	return item, err
}

func (repository *FindingLineageBackfillRepository) CommitFindingLineageBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (ports.FindingLineageBackfillItem, error)) (item ports.FindingLineageBackfillItem, created bool, err error) {
	tenantID, now = shared.TenantOrDefault(tenantID), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseToken.IsZero() || now.IsZero() || build == nil {
		return item, false, fmt.Errorf("%w: finding lineage backfill commit identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state='running' AND lease_token=$3 AND lease_expires_at>$4 FROM finding_lineage_backfill_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), runID.String(), leaseToken.String(), now).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock finding lineage backfill lease: %w", err)
		}
		if !active {
			return fmt.Errorf("%w: finding lineage backfill lease is stale", shared.ErrConflict)
		}
		var err error
		item, err = build(bindTenantTransaction(ctx, tenantID, tx))
		if err != nil {
			return err
		}
		if item.TenantID != tenantID || item.RunID != runID {
			return fmt.Errorf("%w: finding lineage backfill item ownership differs from lease", shared.ErrValidation)
		}
		if err := validatePostgresFindingLineageBackfillItem(item); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `INSERT INTO finding_lineage_backfill_items (tenant_id,run_id,assessment_id,cycle_id,snapshot_id,source_finding_id,schema_version,matcher_version,idempotency_key,source_hash,outcome,reason_code,processed_at)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13 FROM finding_lineage_backfill_runs run
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running'
			ON CONFLICT (tenant_id,run_id,source_finding_id) DO NOTHING`, item.TenantID.String(), item.RunID.String(), item.AssessmentID.String(), nullableFindingID(item.CycleID), nullableFindingID(item.SnapshotID), item.SourceFindingID.String(),
			item.SchemaVersion, item.MatcherVersion, item.IdempotencyKey, item.SourceHash, item.Outcome, item.ReasonCode, item.ProcessedAt.UTC())
		if err != nil {
			return fmt.Errorf("save finding lineage backfill item: %w", err)
		}
		created = command.RowsAffected() == 1
		return nil
	})
	return item, created, err
}

func (repository *FindingLineageBackfillRepository) AdvanceFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.FindingLineageBackfillRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if leaseToken.IsZero() || checkpoint.IsZero() || leaseDuration <= 0 {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: finding lineage backfill checkpoint is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		updated, err := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `UPDATE finding_lineage_backfill_runs AS run SET checkpoint_finding_id=$5,updated_at=$6,lease_expires_at=$7,
			processed_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			observation_created_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='observation_created'),
			provisional_candidate_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='provisional_candidate_created'),
			skipped_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 AND run.checkpoint_finding_id<=$5 RETURNING `+findingLineageBackfillRunColumns,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), checkpoint.String(), now, now.Add(leaseDuration)))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: finding lineage backfill checkpoint rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("advance finding lineage backfill run: %w", err)
		}
		run = updated
		return nil
	})
	return run, err
}

func (repository *FindingLineageBackfillRepository) FinishFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.FindingLineageBackfillState, now time.Time) (run ports.FindingLineageBackfillRun, err error) {
	if state != ports.FindingLineageBackfillCompleted && state != ports.FindingLineageBackfillCancelled && state != ports.FindingLineageBackfillFailed {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: invalid finding lineage backfill terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || now.IsZero() {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: finding lineage backfill completion identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		finished, err := scanFindingLineageBackfillRun(tx.QueryRow(ctx, `UPDATE finding_lineage_backfill_runs AS run SET state=$5,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=$6,completed_at=$6,
			processed_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			observation_created_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='observation_created'),
			provisional_candidate_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='provisional_candidate_created'),
			skipped_count=(SELECT count(*) FROM finding_lineage_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 RETURNING `+findingLineageBackfillRunColumns,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), string(state), now))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: finding lineage backfill completion rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("finish finding lineage backfill run: %w", err)
		}
		run = finished
		return nil
	})
	return run, err
}

func scanFindingLineageBackfillRun(row rowScanner) (ports.FindingLineageBackfillRun, error) {
	var (
		run                       ports.FindingLineageBackfillRun
		state                     string
		leaseExpires, completedAt pgtype.Timestamptz
	)
	if err := row.Scan(&run.TenantID, &run.ID, &run.SchemaVersion, &run.DryRun, &run.BatchSize, &run.ProducerFilters, &run.SnapshotAt, &run.CheckpointFinding, &state, &run.LeaseOwner, &run.LeaseToken, &leaseExpires,
		&run.ProcessedCount, &run.ObservationCreatedCount, &run.ProvisionalCandidateCount, &run.SkippedCount, &run.CreatedBy, &run.CreatedAt, &run.UpdatedAt, &completedAt); err != nil {
		return ports.FindingLineageBackfillRun{}, err
	}
	run.State = ports.FindingLineageBackfillState(state)
	if leaseExpires.Valid {
		run.LeaseExpiresAt = leaseExpires.Time
	}
	if completedAt.Valid {
		completed := completedAt.Time
		run.CompletedAt = &completed
	}
	return run, nil
}

func validatePostgresFindingLineageBackfillAcquire(request ports.FindingLineageBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.FindingLineageBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: finding lineage backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validatePostgresFindingLineageBackfillItem(item ports.FindingLineageBackfillItem) error {
	validOutcome := item.Outcome == "observation_created" || item.Outcome == "provisional_candidate_created" || item.Outcome == "skipped"
	_, hashErr := hex.DecodeString(item.SourceHash)
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SourceFindingID.IsZero() || item.SchemaVersion <= 0 || item.MatcherVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || len(item.SourceHash) != 64 || strings.ToLower(item.SourceHash) != item.SourceHash || hashErr != nil || !validOutcome || !validPostgresBackfillReason(item.ReasonCode) || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: finding lineage backfill item is invalid", shared.ErrValidation)
	}
	if item.Outcome != "skipped" && (item.CycleID.IsZero() || item.SnapshotID.IsZero()) {
		return fmt.Errorf("%w: created lineage backfill outcome requires Cycle and Snapshot", shared.ErrValidation)
	}
	return nil
}

func validPostgresBackfillReason(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func backfillSourceLocation(data []byte) *finding.SourceLocation {
	if len(data) == 0 {
		return nil
	}
	var trace finding.DataFlowTrace
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&trace) != nil || decoder.Decode(&struct{}{}) != io.EOF || trace.Validate() != nil {
		return nil
	}
	sink := trace.Sink
	return &sink
}

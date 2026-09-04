package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentSnapshotColumns = `tenant_id,id,cycle_id,assessment_id,snapshot_number,default_version,lifecycle,provenance,boundary_kind,
	COALESCE(business_asset_id,''),COALESCE(project_id,''),schema_version,content_hash,request_key,request_hash,
	created_at,created_by,finalized_at,finalized_by,superseded_at,superseded_by`

type AssessmentSnapshotRepository struct{ pool *pgxpool.Pool }

func NewAssessmentSnapshotRepository(pool *pgxpool.Pool) *AssessmentSnapshotRepository {
	return &AssessmentSnapshotRepository{pool: pool}
}

var _ ports.AssessmentSnapshotRepository = (*AssessmentSnapshotRepository)(nil)

func (repository *AssessmentSnapshotRepository) CreateFinalizedCAS(ctx context.Context, snapshot *assessmentsnapshot.Snapshot, expectedDefaultVersion int64) (*assessmentsnapshot.Snapshot, bool, error) {
	if snapshot == nil {
		return nil, false, fmt.Errorf("%w: assessment snapshot is required", shared.ErrValidation)
	}
	if err := snapshot.Validate(); err != nil {
		return nil, false, err
	}
	tenantID := shared.TenantOrDefault(snapshot.TenantID)
	var stored *assessmentsnapshot.Snapshot
	created := false
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_counters(tenant_id,assessment_id,next_snapshot_number)
			VALUES($1,$2,1) ON CONFLICT (tenant_id,assessment_id) DO NOTHING`, tenantID.String(), snapshot.AssessmentID.String()); err != nil {
			return fmt.Errorf("initialize assessment snapshot counter: %w", err)
		}
		var snapshotNumber int
		if err := tx.QueryRow(ctx, `SELECT next_snapshot_number FROM assessment_snapshot_counters
			WHERE tenant_id=$1 AND assessment_id=$2 FOR UPDATE`, tenantID.String(), snapshot.AssessmentID.String()).Scan(&snapshotNumber); err != nil {
			return fmt.Errorf("lock assessment snapshot counter: %w", err)
		}
		existing, err := loadAssessmentSnapshotByRequest(ctx, tx, tenantID, snapshot.AssessmentID, snapshot.RequestKey)
		if err == nil {
			if existing.RequestHash != snapshot.RequestHash {
				return fmt.Errorf("%w: snapshot request key was reused with different content", shared.ErrConflict)
			}
			stored = existing
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}

		var currentSnapshotID string
		var currentVersion int64
		err = tx.QueryRow(ctx, `SELECT snapshot_id,version FROM assessment_snapshot_defaults
			WHERE tenant_id=$1 AND assessment_id=$2 FOR UPDATE`, tenantID.String(), snapshot.AssessmentID.String()).Scan(&currentSnapshotID, &currentVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			if expectedDefaultVersion != 0 {
				return fmt.Errorf("%w: assessment snapshot default version mismatch", shared.ErrConflict)
			}
			currentSnapshotID, currentVersion = "", 0
		} else if err != nil {
			return fmt.Errorf("lock assessment snapshot default: %w", err)
		} else if currentVersion != expectedDefaultVersion {
			return fmt.Errorf("%w: assessment snapshot default version mismatch", shared.ErrConflict)
		}

		if _, err := tx.Exec(ctx, `UPDATE assessment_snapshot_counters SET next_snapshot_number=next_snapshot_number+1
			WHERE tenant_id=$1 AND assessment_id=$2`, tenantID.String(), snapshot.AssessmentID.String()); err != nil {
			return fmt.Errorf("allocate assessment snapshot number: %w", err)
		}

		defaultVersion := currentVersion + 1
		if err := insertAndFinalizeAssessmentSnapshot(ctx, tx, tenantID, snapshot, snapshotNumber, defaultVersion); err != nil {
			return err
		}
		var result pgconn.CommandTag
		if currentSnapshotID != "" {
			result, err = tx.Exec(ctx, `UPDATE assessment_snapshots SET lifecycle='superseded',superseded_at=$1,superseded_by=$2
				WHERE tenant_id=$3 AND id=$4 AND lifecycle='finalized'`, snapshot.FinalizedAt, snapshot.FinalizedBy, tenantID.String(), currentSnapshotID)
			if err != nil {
				return fmt.Errorf("supersede assessment snapshot: %w", err)
			}
			if result.RowsAffected() != 1 {
				return fmt.Errorf("%w: current assessment snapshot changed", shared.ErrConflict)
			}
		}
		if currentVersion == 0 {
			result, err = tx.Exec(ctx, `INSERT INTO assessment_snapshot_defaults(tenant_id,assessment_id,snapshot_id,version,updated_at,updated_by)
				VALUES($1,$2,$3,1,$4,$5)`, tenantID.String(), snapshot.AssessmentID.String(), snapshot.ID.String(), snapshot.FinalizedAt, snapshot.FinalizedBy)
		} else {
			result, err = tx.Exec(ctx, `UPDATE assessment_snapshot_defaults SET snapshot_id=$1,version=version+1,updated_at=$2,updated_by=$3
				WHERE tenant_id=$4 AND assessment_id=$5 AND version=$6`, snapshot.ID.String(), snapshot.FinalizedAt, snapshot.FinalizedBy,
				tenantID.String(), snapshot.AssessmentID.String(), expectedDefaultVersion)
		}
		if err != nil {
			return mapPostgresError(err, "update assessment snapshot default")
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("%w: assessment snapshot default changed", shared.ErrConflict)
		}
		stored = cloneFinalizedSnapshot(snapshot, snapshotNumber, defaultVersion)
		created = true
		return nil
	})
	return stored, created, err
}

func (repository *AssessmentSnapshotRepository) CreateLegacyProjection(ctx context.Context, snapshot *assessmentsnapshot.Snapshot) (*assessmentsnapshot.Snapshot, bool, error) {
	if snapshot == nil || snapshot.Provenance != assessmentsnapshot.ProvenanceLegacy {
		return nil, false, fmt.Errorf("%w: legacy assessment snapshot is required", shared.ErrValidation)
	}
	if err := snapshot.Validate(); err != nil {
		return nil, false, err
	}
	tenantID := shared.TenantOrDefault(snapshot.TenantID)
	var stored *assessmentsnapshot.Snapshot
	created := false
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_counters(tenant_id,assessment_id,next_snapshot_number)
			VALUES($1,$2,1) ON CONFLICT (tenant_id,assessment_id) DO NOTHING`, tenantID.String(), snapshot.AssessmentID.String()); err != nil {
			return fmt.Errorf("initialize assessment snapshot counter: %w", err)
		}
		var snapshotNumber int
		if err := tx.QueryRow(ctx, `SELECT next_snapshot_number FROM assessment_snapshot_counters
			WHERE tenant_id=$1 AND assessment_id=$2 FOR UPDATE`, tenantID.String(), snapshot.AssessmentID.String()).Scan(&snapshotNumber); err != nil {
			return fmt.Errorf("lock assessment snapshot counter: %w", err)
		}
		existing, err := loadAssessmentSnapshotByRequest(ctx, tx, tenantID, snapshot.AssessmentID, snapshot.RequestKey)
		if err == nil {
			if existing.RequestHash != snapshot.RequestHash {
				return fmt.Errorf("%w: snapshot request key was reused with different content", shared.ErrConflict)
			}
			stored = existing
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE assessment_snapshot_counters SET next_snapshot_number=next_snapshot_number+1
			WHERE tenant_id=$1 AND assessment_id=$2`, tenantID.String(), snapshot.AssessmentID.String()); err != nil {
			return fmt.Errorf("allocate assessment snapshot number: %w", err)
		}
		if err := insertAndFinalizeAssessmentSnapshot(ctx, tx, tenantID, snapshot, snapshotNumber, 0); err != nil {
			return err
		}
		stored, created = cloneFinalizedSnapshot(snapshot, snapshotNumber, 0), true
		return nil
	})
	return stored, created, err
}

func insertAndFinalizeAssessmentSnapshot(ctx context.Context, tx pgx.Tx, tenantID shared.ID, snapshot *assessmentsnapshot.Snapshot, snapshotNumber int, defaultVersion int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO assessment_snapshots(
		tenant_id,id,cycle_id,assessment_id,snapshot_number,default_version,lifecycle,provenance,boundary_kind,business_asset_id,project_id,
		schema_version,content_hash,request_key,request_hash,created_at,created_by)
		VALUES($1,$2,$3,$4,$5,$6,'building',$7,$8,NULLIF($9,''),NULLIF($10,''),$11,$12,$13,$14,$15,$16)`,
		tenantID.String(), snapshot.ID.String(), snapshot.CycleID.String(), snapshot.AssessmentID.String(), snapshotNumber, defaultVersion,
		string(snapshot.Provenance), string(snapshot.Boundary.Kind), snapshot.Boundary.BusinessAssetID.String(), snapshot.Boundary.ProjectID.String(),
		snapshot.SchemaVersion, snapshot.ContentHash, snapshot.RequestKey, snapshot.RequestHash, snapshot.CreatedAt, snapshot.CreatedBy)
	if err != nil {
		return mapPostgresError(err, "create assessment snapshot")
	}
	for runPosition, run := range snapshot.RunReferences {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_run_refs(tenant_id,snapshot_id,position,scan_run_id,manifest_hash)
			VALUES($1,$2,$3,$4,$5)`, tenantID.String(), snapshot.ID.String(), runPosition, run.RunID, run.ManifestHash); err != nil {
			return mapPostgresError(err, "create assessment snapshot run reference")
		}
		for _, lane := range run.LaneReferences {
			if _, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_lane_refs(tenant_id,snapshot_id,run_position,scan_run_id,lane_key,manifest_hash)
				VALUES($1,$2,$3,$4,$5,$6)`, tenantID.String(), snapshot.ID.String(), runPosition, run.RunID, lane.LaneKey, lane.ManifestHash); err != nil {
				return mapPostgresError(err, "create assessment snapshot lane reference")
			}
		}
	}
	for position, dimension := range snapshot.Dimensions {
		includedScope, err := json.Marshal(dimension.IncludedScope)
		if err != nil {
			return fmt.Errorf("marshal snapshot included scope: %w", err)
		}
		excludedScope, err := json.Marshal(dimension.ExcludedScope)
		if err != nil {
			return fmt.Errorf("marshal snapshot excluded scope: %w", err)
		}
		versions, err := json.Marshal(dimension.Versions)
		if err != nil {
			return fmt.Errorf("marshal snapshot versions: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_dimensions(
			tenant_id,snapshot_id,position,run_id,lane_key,lane_manifest_hash,producer,finding_kind,target_kind,target_schema_version,
			target_canonical,evaluated_revision,coverage_state,reason_code,included_scope,excluded_scope,versions)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			tenantID.String(), snapshot.ID.String(), position, dimension.RunID, dimension.LaneKey, dimension.LaneManifestHash,
			dimension.Producer, dimension.FindingKind, string(dimension.Target.Kind), dimension.Target.SchemaVersion,
			dimension.Target.Canonical, dimension.Target.EvaluatedRevision, string(dimension.State), dimension.ReasonCode,
			includedScope, excludedScope, versions); err != nil {
			return mapPostgresError(err, "create assessment snapshot dimension")
		}
	}
	result, err := tx.Exec(ctx, `UPDATE assessment_snapshots SET lifecycle='finalized',finalized_at=$1,finalized_by=$2
		WHERE tenant_id=$3 AND id=$4 AND lifecycle='building'`, snapshot.FinalizedAt, snapshot.FinalizedBy, tenantID.String(), snapshot.ID.String())
	if err != nil {
		return fmt.Errorf("finalize assessment snapshot: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: assessment snapshot finalization lost", shared.ErrConflict)
	}
	return nil
}

func (repository *AssessmentSnapshotRepository) Get(ctx context.Context, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var snapshot *assessmentsnapshot.Snapshot
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		snapshot, err = loadAssessmentSnapshot(ctx, tx, tenantID, snapshotID)
		return err
	})
	return snapshot, err
}

func (repository *AssessmentSnapshotRepository) GetByRequestKey(ctx context.Context, tenantID, assessmentID shared.ID, requestKey string) (*assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var snapshot *assessmentsnapshot.Snapshot
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		snapshot, err = loadAssessmentSnapshotByRequest(ctx, tx, tenantID, assessmentID, requestKey)
		return err
	})
	return snapshot, err
}

func (repository *AssessmentSnapshotRepository) GetDefault(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentsnapshot.Snapshot, ports.AssessmentSnapshotDefault, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var snapshot *assessmentsnapshot.Snapshot
	var pointer ports.AssessmentSnapshotDefault
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var snapshotID string
		if err := tx.QueryRow(ctx, `SELECT snapshot_id,version,updated_at,updated_by FROM assessment_snapshot_defaults
			WHERE tenant_id=$1 AND assessment_id=$2`, tenantID.String(), assessmentID.String()).Scan(&snapshotID, &pointer.Version, &pointer.UpdatedAt, &pointer.UpdatedBy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return fmt.Errorf("load default assessment snapshot: %w", err)
		}
		pointer.TenantID, pointer.AssessmentID, pointer.SnapshotID = tenantID, assessmentID, shared.ID(snapshotID)
		var err error
		snapshot, err = loadAssessmentSnapshot(ctx, tx, tenantID, pointer.SnapshotID)
		return err
	})
	return snapshot, pointer, err
}

func (repository *AssessmentSnapshotRepository) ListByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) ([]assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var out []assessmentsnapshot.Snapshot
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM assessment_snapshots WHERE tenant_id=$1 AND assessment_id=$2 ORDER BY snapshot_number`, tenantID.String(), assessmentID.String())
		if err != nil {
			return fmt.Errorf("list assessment snapshots: %w", err)
		}
		defer rows.Close()
		var ids []shared.ID
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, shared.ID(id))
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			snapshot, err := loadAssessmentSnapshot(ctx, tx, tenantID, id)
			if err != nil {
				return err
			}
			out = append(out, *snapshot)
		}
		return nil
	})
	return out, err
}

func loadAssessmentSnapshotByRequest(ctx context.Context, tx pgx.Tx, tenantID, assessmentID shared.ID, requestKey string) (*assessmentsnapshot.Snapshot, error) {
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM assessment_snapshots WHERE tenant_id=$1 AND assessment_id=$2 AND request_key=$3`,
		tenantID.String(), assessmentID.String(), requestKey).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("load assessment snapshot request: %w", err)
	}
	return loadAssessmentSnapshot(ctx, tx, tenantID, shared.ID(id))
}

func loadAssessmentSnapshot(ctx context.Context, tx pgx.Tx, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error) {
	row := tx.QueryRow(ctx, `SELECT `+assessmentSnapshotColumns+` FROM assessment_snapshots WHERE tenant_id=$1 AND id=$2`, tenantID.String(), snapshotID.String())
	snapshot, err := scanAssessmentSnapshot(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan assessment snapshot: %w", err)
	}
	runRows, err := tx.Query(ctx, `SELECT position,scan_run_id,manifest_hash FROM assessment_snapshot_run_refs
		WHERE tenant_id=$1 AND snapshot_id=$2 ORDER BY position`, tenantID.String(), snapshotID.String())
	if err != nil {
		return nil, err
	}
	type persistedRunReference struct {
		position  int
		reference assessmentsnapshot.RunReference
	}
	var persistedRuns []persistedRunReference
	for runRows.Next() {
		var position int
		var reference assessmentsnapshot.RunReference
		if err := runRows.Scan(&position, &reference.RunID, &reference.ManifestHash); err != nil {
			runRows.Close()
			return nil, err
		}
		persistedRuns = append(persistedRuns, persistedRunReference{position: position, reference: reference})
	}
	if err := runRows.Err(); err != nil {
		runRows.Close()
		return nil, err
	}
	runRows.Close()
	for _, persisted := range persistedRuns {
		reference := persisted.reference
		laneRows, err := tx.Query(ctx, `SELECT lane_key,manifest_hash FROM assessment_snapshot_lane_refs
			WHERE tenant_id=$1 AND snapshot_id=$2 AND run_position=$3 ORDER BY lane_key`, tenantID.String(), snapshotID.String(), persisted.position)
		if err != nil {
			return nil, err
		}
		for laneRows.Next() {
			var lane assessmentsnapshot.LaneReference
			if err := laneRows.Scan(&lane.LaneKey, &lane.ManifestHash); err != nil {
				laneRows.Close()
				return nil, err
			}
			reference.LaneReferences = append(reference.LaneReferences, lane)
		}
		if err := laneRows.Err(); err != nil {
			laneRows.Close()
			return nil, err
		}
		laneRows.Close()
		snapshot.RunReferences = append(snapshot.RunReferences, reference)
	}

	dimensionRows, err := tx.Query(ctx, `SELECT run_id,lane_key,lane_manifest_hash,producer,finding_kind,target_kind,target_schema_version,
		target_canonical,evaluated_revision,coverage_state,reason_code,included_scope,excluded_scope,versions
		FROM assessment_snapshot_dimensions WHERE tenant_id=$1 AND snapshot_id=$2 ORDER BY position`, tenantID.String(), snapshotID.String())
	if err != nil {
		return nil, err
	}
	defer dimensionRows.Close()
	for dimensionRows.Next() {
		var dimension assessmentsnapshot.Dimension
		var targetKind, coverageState string
		var includedScope, excludedScope, versions []byte
		if err := dimensionRows.Scan(&dimension.RunID, &dimension.LaneKey, &dimension.LaneManifestHash, &dimension.Producer, &dimension.FindingKind,
			&targetKind, &dimension.Target.SchemaVersion, &dimension.Target.Canonical, &dimension.Target.EvaluatedRevision,
			&coverageState, &dimension.ReasonCode, &includedScope, &excludedScope, &versions); err != nil {
			return nil, err
		}
		dimension.Target.Kind = scanrun.TargetKind(targetKind)
		dimension.State = assessmentsnapshot.CoverageState(coverageState)
		if err := json.Unmarshal(includedScope, &dimension.IncludedScope); err != nil {
			return nil, fmt.Errorf("decode snapshot included scope: %w", err)
		}
		if err := json.Unmarshal(excludedScope, &dimension.ExcludedScope); err != nil {
			return nil, fmt.Errorf("decode snapshot excluded scope: %w", err)
		}
		if err := json.Unmarshal(versions, &dimension.Versions); err != nil {
			return nil, fmt.Errorf("decode snapshot versions: %w", err)
		}
		snapshot.Dimensions = append(snapshot.Dimensions, dimension)
	}
	if err := dimensionRows.Err(); err != nil {
		return nil, err
	}
	if err := snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("validate persisted assessment snapshot: %w", err)
	}
	return snapshot, nil
}

func scanAssessmentSnapshot(row rowScanner) (*assessmentsnapshot.Snapshot, error) {
	var snapshot assessmentsnapshot.Snapshot
	var tenantID, id, cycleID, assessmentID, lifecycle, provenance, boundaryKind, businessAssetID, projectID string
	var finalizedAt, supersededAt *time.Time
	if err := row.Scan(&tenantID, &id, &cycleID, &assessmentID, &snapshot.SnapshotNumber, &snapshot.DefaultVersion, &lifecycle, &provenance, &boundaryKind,
		&businessAssetID, &projectID, &snapshot.SchemaVersion, &snapshot.ContentHash, &snapshot.RequestKey, &snapshot.RequestHash,
		&snapshot.CreatedAt, &snapshot.CreatedBy, &finalizedAt, &snapshot.FinalizedBy, &supersededAt, &snapshot.SupersededBy); err != nil {
		return nil, err
	}
	snapshot.TenantID, snapshot.ID, snapshot.CycleID, snapshot.AssessmentID = shared.ID(tenantID), shared.ID(id), shared.ID(cycleID), shared.ID(assessmentID)
	snapshot.Lifecycle, snapshot.Provenance = assessmentsnapshot.Lifecycle(lifecycle), assessmentsnapshot.Provenance(provenance)
	snapshot.Boundary = assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryKind(boundaryKind), BusinessAssetID: shared.ID(businessAssetID), ProjectID: shared.ID(projectID)}
	snapshot.FinalizedAt, snapshot.SupersededAt = finalizedAt, supersededAt
	return &snapshot, nil
}

func cloneFinalizedSnapshot(snapshot *assessmentsnapshot.Snapshot, snapshotNumber int, defaultVersion int64) *assessmentsnapshot.Snapshot {
	copySnapshot := *snapshot
	copySnapshot.SnapshotNumber = snapshotNumber
	copySnapshot.DefaultVersion = defaultVersion
	return &copySnapshot
}

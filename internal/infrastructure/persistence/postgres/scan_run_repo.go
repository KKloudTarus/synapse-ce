package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunStore persists tenant-owned scan-run headers and sealed provenance.
type ScanRunStore struct{ pool *pgxpool.Pool }

func NewScanRunStore(pool *pgxpool.Pool) *ScanRunStore { return &ScanRunStore{pool: pool} }

var _ ports.ScanRunStore = (*ScanRunStore)(nil)

func (store *ScanRunStore) Begin(ctx context.Context, run ports.ScanRun) error {
	if err := run.ValidateBegin(); err != nil {
		return err
	}
	manifest, err := json.Marshal(run.Manifest)
	if err != nil {
		return fmt.Errorf("marshal scan run manifest: %w", err)
	}
	keys, err := json.Marshal(run.FindingKeys)
	if err != nil {
		return fmt.Errorf("marshal scan run finding keys: %w", err)
	}
	return WithTenant(ctx, store.pool, run.TenantID, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `INSERT INTO scan_runs
			(id, tenant_id, engagement_id, created_at, manifest, finding_keys, provenance, terminal_status, manifest_schema_version, manifest_hash, sealed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,NULL,NULL)
			ON CONFLICT (id) DO NOTHING`,
			run.ID, run.TenantID, run.EngagementID, run.CreatedAt.UTC(), manifest, keys, run.Provenance, run.TerminalStatus)
		if err != nil {
			return fmt.Errorf("begin scan run: %w", err)
		}
		if result.RowsAffected() == 1 {
			return nil
		}
		var tenantID, engagementID, terminalStatus string
		var createdAt time.Time
		if err := tx.QueryRow(ctx, `SELECT tenant_id, engagement_id, terminal_status, created_at FROM scan_runs WHERE id=$1`, run.ID).Scan(&tenantID, &engagementID, &terminalStatus, &createdAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrConflict)
			}
			return fmt.Errorf("read existing scan run: %w", err)
		}
		if tenantID == run.TenantID && engagementID == run.EngagementID && terminalStatus == string(scanrun.StatusBuilding) && createdAt.Equal(run.CreatedAt.UTC()) {
			return nil
		}
		return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrConflict)
	})
}

func (store *ScanRunStore) Seal(ctx context.Context, run ports.ScanRun) error {
	if err := run.ValidateSealed(); err != nil {
		return err
	}
	manifest, err := json.Marshal(run.Manifest)
	if err != nil {
		return fmt.Errorf("marshal scan run manifest: %w", err)
	}
	keys, err := json.Marshal(run.FindingKeys)
	if err != nil {
		return fmt.Errorf("marshal scan run finding keys: %w", err)
	}
	return WithTenant(ctx, store.pool, run.TenantID, func(tx pgx.Tx) error {
		var engagementID, terminalStatus string
		var manifestHash *string
		var sealedAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT engagement_id, terminal_status, manifest_hash, sealed_at FROM scan_runs WHERE id=$1 FOR UPDATE`, run.ID).
			Scan(&engagementID, &terminalStatus, &manifestHash, &sealedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrNotFound)
			}
			return fmt.Errorf("lock scan run: %w", err)
		}
		if manifestHash != nil {
			if *manifestHash == run.ManifestHash {
				return nil
			}
			return fmt.Errorf("scan run %s terminal write: %w", run.ID, shared.ErrConflict)
		}
		if engagementID != run.EngagementID || terminalStatus != string(scanrun.StatusBuilding) || sealedAt != nil {
			return fmt.Errorf("scan run %s terminal state: %w", run.ID, shared.ErrConflict)
		}
		for _, lane := range run.Lanes {
			if err := insertScanRunLane(ctx, tx, run, lane); err != nil {
				return err
			}
		}
		result, err := tx.Exec(ctx, `UPDATE scan_runs
			SET manifest=$1, finding_keys=$2, terminal_status=$3, manifest_schema_version=$4, manifest_hash=$5, sealed_at=$6
			WHERE tenant_id=$7 AND id=$8 AND terminal_status='building' AND sealed_at IS NULL`,
			manifest, keys, run.TerminalStatus, run.ManifestSchemaVersion, run.ManifestHash, run.SealedAt, run.TenantID, run.ID)
		if err != nil {
			return fmt.Errorf("seal scan run header: %w", err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("scan run %s terminal write: %w", run.ID, shared.ErrConflict)
		}
		return nil
	})
}

func insertScanRunLane(ctx context.Context, tx pgx.Tx, run ports.ScanRun, lane scanrun.Lane) error {
	includedScope, err := json.Marshal(lane.IncludedScope)
	if err != nil {
		return fmt.Errorf("marshal included scope: %w", err)
	}
	excludedScope, err := json.Marshal(lane.ExcludedScope)
	if err != nil {
		return fmt.Errorf("marshal excluded scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO scan_run_lanes
		(tenant_id, engagement_id, scan_run_id, lane_key, producer, terminal_status,
		 target_kind, target_identity_schema_version, target_identity_canonical, evaluated_revision,
		 authoritative_finding_kinds, included_scope, excluded_scope, started_at, finished_at,
		 result_ref, evidence_ref, result_sha256, manifest_schema_version, manifest_hash, sealed_at)
		VALUES ($1,$2,$3,$4,$5,'building',$6,$7,$8,$9,$10,$11,$12,$13,NULL,$14,$15,$16,$17,$18,NULL)`,
		run.TenantID, run.EngagementID, run.ID, lane.Key, lane.Producer,
		lane.Target.Kind, lane.Target.SchemaVersion, lane.Target.Canonical, lane.Target.EvaluatedRevision,
		lane.AuthoritativeFindingKinds, includedScope, excludedScope, lane.StartedAt.UTC(),
		lane.ResultRef, lane.EvidenceRef, nullIfEmpty(lane.ResultSHA256), lane.ManifestSchemaVersion, lane.ManifestHash); err != nil {
		return fmt.Errorf("insert scan run lane: %w", err)
	}
	for _, version := range lane.Versions {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_run_lane_versions
			(tenant_id, scan_run_id, lane_key, version_kind, name, version, digest)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			run.TenantID, run.ID, lane.Key, version.Kind, version.Name, version.Version, version.Digest); err != nil {
			return fmt.Errorf("insert scan run lane version: %w", err)
		}
	}
	for _, stage := range lane.Stages {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_run_lane_stages
			(tenant_id, scan_run_id, lane_key, stage_key, status, reason_code, started_at, finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			run.TenantID, run.ID, lane.Key, stage.Key, stage.Status, stage.ReasonCode, stage.StartedAt, stage.FinishedAt); err != nil {
			return fmt.Errorf("insert scan run lane stage: %w", err)
		}
	}
	result, err := tx.Exec(ctx, `UPDATE scan_run_lanes
		SET terminal_status=$1, finished_at=$2, sealed_at=$3
		WHERE tenant_id=$4 AND scan_run_id=$5 AND lane_key=$6 AND terminal_status='building' AND sealed_at IS NULL`,
		lane.TerminalStatus, lane.FinishedAt, lane.SealedAt, run.TenantID, run.ID, lane.Key)
	if err != nil {
		return fmt.Errorf("seal scan run lane: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("scan run lane %s terminal write: %w", lane.Key, shared.ErrConflict)
	}
	return nil
}

func (store *ScanRunStore) List(ctx context.Context, tenantID, engagementID shared.ID) (out []ports.ScanRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, store.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, scanRunSelect+` WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY created_at DESC, id`, tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list scan runs: %w", err)
		}
		for rows.Next() {
			run, err := scanRunRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, run)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for index := range out {
			out[index].Lanes, err = loadScanRunLanes(ctx, tx, out[index].TenantID, out[index].ID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (store *ScanRunStore) Get(ctx context.Context, tenantID shared.ID, runID string) (out ports.ScanRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, store.pool, tenantID.String(), func(tx pgx.Tx) error {
		run, err := scanRunRow(tx.QueryRow(ctx, scanRunSelect+` WHERE tenant_id=$1 AND id=$2`, tenantID.String(), runID))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("get scan run: %w", err)
		}
		run.Lanes, err = loadScanRunLanes(ctx, tx, run.TenantID, run.ID)
		if err != nil {
			return err
		}
		out = run
		return nil
	})
	return out, err
}

const scanRunSelect = `SELECT tenant_id, id, engagement_id, created_at, manifest, finding_keys,
	provenance, terminal_status, manifest_schema_version, COALESCE(manifest_hash,''), sealed_at FROM scan_runs`

func scanRunRow(row rowScanner) (ports.ScanRun, error) {
	var run ports.ScanRun
	var manifest, keys []byte
	if err := row.Scan(&run.TenantID, &run.ID, &run.EngagementID, &run.CreatedAt, &manifest, &keys,
		&run.Provenance, &run.TerminalStatus, &run.ManifestSchemaVersion, &run.ManifestHash, &run.SealedAt); err != nil {
		return ports.ScanRun{}, err
	}
	if err := json.Unmarshal(manifest, &run.Manifest); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode scan run manifest: %w", err)
	}
	if err := json.Unmarshal(keys, &run.FindingKeys); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode scan run finding keys: %w", err)
	}
	return run, nil
}

func loadScanRunLanes(ctx context.Context, tx pgx.Tx, tenantID, runID string) ([]scanrun.Lane, error) {
	rows, err := tx.Query(ctx, `SELECT lane_key, producer, terminal_status, target_kind,
		target_identity_schema_version, target_identity_canonical, evaluated_revision,
		authoritative_finding_kinds, included_scope, excluded_scope, started_at, finished_at,
		result_ref, evidence_ref, COALESCE(result_sha256,''), manifest_schema_version, manifest_hash, sealed_at
		FROM scan_run_lanes WHERE tenant_id=$1 AND scan_run_id=$2 ORDER BY lane_key`, tenantID, runID)
	if err != nil {
		return nil, fmt.Errorf("list scan run lanes: %w", err)
	}
	var lanes []scanrun.Lane
	for rows.Next() {
		var lane scanrun.Lane
		var includedScope, excludedScope []byte
		if err := rows.Scan(&lane.Key, &lane.Producer, &lane.TerminalStatus, &lane.Target.Kind,
			&lane.Target.SchemaVersion, &lane.Target.Canonical, &lane.Target.EvaluatedRevision,
			&lane.AuthoritativeFindingKinds, &includedScope, &excludedScope, &lane.StartedAt, &lane.FinishedAt,
			&lane.ResultRef, &lane.EvidenceRef, &lane.ResultSHA256, &lane.ManifestSchemaVersion, &lane.ManifestHash, &lane.SealedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(includedScope, &lane.IncludedScope); err != nil {
			rows.Close()
			return nil, fmt.Errorf("decode included scope: %w", err)
		}
		if err := json.Unmarshal(excludedScope, &lane.ExcludedScope); err != nil {
			rows.Close()
			return nil, fmt.Errorf("decode excluded scope: %w", err)
		}
		lanes = append(lanes, lane)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range lanes {
		lanes[index].Versions, err = loadScanRunLaneVersions(ctx, tx, tenantID, runID, lanes[index].Key)
		if err != nil {
			return nil, err
		}
		lanes[index].Stages, err = loadScanRunLaneStages(ctx, tx, tenantID, runID, lanes[index].Key)
		if err != nil {
			return nil, err
		}
	}
	return lanes, nil
}

func loadScanRunLaneVersions(ctx context.Context, tx pgx.Tx, tenantID, runID, laneKey string) ([]scanrun.Version, error) {
	rows, err := tx.Query(ctx, `SELECT version_kind, name, version, digest FROM scan_run_lane_versions
		WHERE tenant_id=$1 AND scan_run_id=$2 AND lane_key=$3 ORDER BY version_kind, name`, tenantID, runID, laneKey)
	if err != nil {
		return nil, fmt.Errorf("list scan run lane versions: %w", err)
	}
	defer rows.Close()
	var versions []scanrun.Version
	for rows.Next() {
		var version scanrun.Version
		if err := rows.Scan(&version.Kind, &version.Name, &version.Version, &version.Digest); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func loadScanRunLaneStages(ctx context.Context, tx pgx.Tx, tenantID, runID, laneKey string) ([]scanrun.Stage, error) {
	rows, err := tx.Query(ctx, `SELECT stage_key, status, reason_code, started_at, finished_at FROM scan_run_lane_stages
		WHERE tenant_id=$1 AND scan_run_id=$2 AND lane_key=$3 ORDER BY stage_key`, tenantID, runID, laneKey)
	if err != nil {
		return nil, fmt.Errorf("list scan run lane stages: %w", err)
	}
	defer rows.Close()
	var stages []scanrun.Stage
	for rows.Next() {
		var stage scanrun.Stage
		if err := rows.Scan(&stage.Key, &stage.Status, &stage.ReasonCode, &stage.StartedAt, &stage.FinishedAt); err != nil {
			return nil, err
		}
		stages = append(stages, stage)
	}
	return stages, rows.Err()
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

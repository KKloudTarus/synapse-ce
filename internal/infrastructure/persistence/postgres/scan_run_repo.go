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

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunStore persists scan-run manifests, finding keys, and tenant-scoped sealed provenance.
type ScanRunStore struct {
	pool *pgxpool.Pool
}

// NewScanRunStore returns a store backed by the given pool.
func NewScanRunStore(pool *pgxpool.Pool) *ScanRunStore {
	return &ScanRunStore{pool: pool}
}

var _ ports.ScanRunStore = (*ScanRunStore)(nil)

// Save records a legacy scan run for backwards compatibility.
func (r *ScanRunStore) Save(ctx context.Context, run ports.ScanRun) error {
	manifest, err := json.Marshal(run.Manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	keys, err := json.Marshal(run.FindingKeys)
	if err != nil {
		return fmt.Errorf("marshal finding keys: %w", err)
	}

	tenantID, _ := shared.TenantFrom(ctx)
	if tenantID.IsZero() {
		tenantID = shared.DefaultTenant
	}

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO scan_runs (
				tenant_id, id, engagement_id, provenance, terminal_status,
				manifest_schema_version, manifest_hash, created_at, updated_at,
				manifest, finding_keys
			) VALUES ($1, $2, $3, 'legacy', 'unknown', 1, '', $4, $4, $5, $6)
			ON CONFLICT (tenant_id, id) DO NOTHING
		`, tenantID.String(), run.ID, run.EngagementID, run.CreatedAt, manifest, keys)
		if err != nil {
			return mapScanRunSQLError(err)
		}
		return nil
	})
}

// List returns legacy scan runs for an engagement.
func (r *ScanRunStore) List(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		tenantID = shared.DefaultTenant
	}

	var out []ports.ScanRun
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, engagement_id, created_at, manifest, finding_keys
			FROM scan_runs
			WHERE tenant_id = $1 AND engagement_id = $2
			ORDER BY created_at DESC, id ASC
		`, tenantID.String(), engagementID.String())
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			run, err := scanLegacyRunRow(rows)
			if err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, mapScanRunSQLError(err)
	}
	return out, nil
}

// Get returns a legacy scan run by ID.
func (r *ScanRunStore) Get(ctx context.Context, runID string) (ports.ScanRun, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		tenantID = shared.DefaultTenant
	}

	var run ports.ScanRun
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, engagement_id, created_at, manifest, finding_keys
			FROM scan_runs
			WHERE tenant_id = $1 AND id = $2
		`, tenantID.String(), runID)
		var err error
		run, err = scanLegacyRunRow(row)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanRun{}, mapScanRunSQLError(err)
	}
	return run, nil
}

// SaveScanRun persists a tenant-owned native or legacy scan run.
func (r *ScanRunStore) SaveScanRun(ctx context.Context, run scanrun.ScanRun) error {
	if err := run.Validate(); err != nil {
		return err
	}

	return WithTenant(ctx, r.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		manifestBytes := run.LegacyManifest
		if len(manifestBytes) == 0 {
			manifestBytes = []byte("{}")
		}
		findingKeysBytes, err := json.Marshal(run.LegacyFindingKeys)
		if err != nil {
			return fmt.Errorf("marshal finding keys: %w", err)
		}

		res, err := tx.Exec(ctx, `
			INSERT INTO scan_runs (
				tenant_id, id, engagement_id, provenance, terminal_status,
				manifest_schema_version, manifest_hash, sealed_at, created_at, updated_at,
				manifest, finding_keys
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (tenant_id, id) DO UPDATE SET
				terminal_status = EXCLUDED.terminal_status,
				manifest_schema_version = EXCLUDED.manifest_schema_version,
				manifest_hash = EXCLUDED.manifest_hash,
				sealed_at = EXCLUDED.sealed_at,
				updated_at = EXCLUDED.updated_at
			WHERE scan_runs.sealed_at IS NULL
		`, run.TenantID.String(), run.ID, run.EngagementID.String(),
			string(run.Provenance), string(run.TerminalStatus),
			run.ManifestSchemaVersion, run.ManifestHash, run.SealedAt,
			run.CreatedAt, run.UpdatedAt, manifestBytes, findingKeysBytes)
		if err != nil {
			return mapScanRunSQLError(err)
		}
		if res.RowsAffected() == 0 {
			// Row exists and was sealed
			return fmt.Errorf("%w: cannot update sealed scan run %s", shared.ErrConflict, run.ID)
		}
		return nil
	})
}

// GetScanRun retrieves a full scan run aggregate including lanes, versions, and stages.
func (r *ScanRunStore) GetScanRun(ctx context.Context, tenantID shared.ID, runID string) (scanrun.ScanRun, error) {
	if tenantID.IsZero() || runID == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: tenant ID and scan run ID are required", shared.ErrValidation)
	}

	var run scanrun.ScanRun
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var (
			tenantStr, engStr, idStr, provStr, termStr, manifestHash string
			manifestSchemaVer                                        int
			sealedAt                                                 *time.Time
			createdAt, updatedAt                                     time.Time
			legacyManifest, legacyFindingKeys                        []byte
		)

		err := tx.QueryRow(ctx, `
			SELECT tenant_id, engagement_id, id, provenance, terminal_status,
			       manifest_schema_version, manifest_hash, sealed_at, created_at, updated_at,
			       manifest, finding_keys
			FROM scan_runs
			WHERE tenant_id = $1 AND id = $2
		`, tenantID.String(), runID).Scan(
			&tenantStr, &engStr, &idStr, &provStr, &termStr,
			&manifestSchemaVer, &manifestHash, &sealedAt, &createdAt, &updatedAt,
			&legacyManifest, &legacyFindingKeys,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
		}
		if err != nil {
			return err
		}

		var findingKeys []string
		if len(legacyFindingKeys) > 0 {
			_ = json.Unmarshal(legacyFindingKeys, &findingKeys)
		}

		run = scanrun.ScanRun{
			TenantID:              shared.ID(tenantStr),
			EngagementID:          shared.ID(engStr),
			ID:                    idStr,
			Provenance:            scanrun.ProvenanceKind(provStr),
			TerminalStatus:        scanrun.TerminalStatus(termStr),
			ManifestSchemaVersion: manifestSchemaVer,
			ManifestHash:          manifestHash,
			SealedAt:              sealedAt,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
			LegacyManifest:        legacyManifest,
			LegacyFindingKeys:     findingKeys,
		}

		lanes, err := r.loadLanesForRun(ctx, tx, tenantID.String(), runID)
		if err != nil {
			return err
		}
		run.Lanes = lanes
		return nil
	})
	if err != nil {
		return scanrun.ScanRun{}, mapScanRunSQLError(err)
	}
	return run, nil
}

// ListScanRuns returns all scan runs for an engagement, ordered newest first.
func (r *ScanRunStore) ListScanRuns(ctx context.Context, tenantID, engagementID shared.ID) ([]scanrun.ScanRun, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: tenant ID and engagement ID are required", shared.ErrValidation)
	}

	var out []scanrun.ScanRun
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, engagement_id, id, provenance, terminal_status,
			       manifest_schema_version, manifest_hash, sealed_at, created_at, updated_at,
			       manifest, finding_keys
			FROM scan_runs
			WHERE tenant_id = $1 AND engagement_id = $2
			ORDER BY created_at DESC, id ASC
		`, tenantID.String(), engagementID.String())
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				tenantStr, engStr, idStr, provStr, termStr, manifestHash string
				manifestSchemaVer                                        int
				sealedAt                                                 *time.Time
				createdAt, updatedAt                                     time.Time
				legacyManifest, legacyFindingKeys                        []byte
			)
			if err := rows.Scan(
				&tenantStr, &engStr, &idStr, &provStr, &termStr,
				&manifestSchemaVer, &manifestHash, &sealedAt, &createdAt, &updatedAt,
				&legacyManifest, &legacyFindingKeys,
			); err != nil {
				return err
			}

			var findingKeys []string
			if len(legacyFindingKeys) > 0 {
				_ = json.Unmarshal(legacyFindingKeys, &findingKeys)
			}

			out = append(out, scanrun.ScanRun{
				TenantID:              shared.ID(tenantStr),
				EngagementID:          shared.ID(engStr),
				ID:                    idStr,
				Provenance:            scanrun.ProvenanceKind(provStr),
				TerminalStatus:        scanrun.TerminalStatus(termStr),
				ManifestSchemaVersion: manifestSchemaVer,
				ManifestHash:          manifestHash,
				SealedAt:              sealedAt,
				CreatedAt:             createdAt,
				UpdatedAt:             updatedAt,
				LegacyManifest:        legacyManifest,
				LegacyFindingKeys:     findingKeys,
			})
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for i := range out {
			lanes, err := r.loadLanesForRun(ctx, tx, tenantID.String(), out[i].ID)
			if err != nil {
				return err
			}
			out[i].Lanes = lanes
		}
		return nil
	})
	if err != nil {
		return nil, mapScanRunSQLError(err)
	}
	return out, nil
}

// SealScanRun atomically acquires a row lock on scan_runs, validates seal state, and inserts lanes/versions/stages.
func (r *ScanRunStore) SealScanRun(ctx context.Context, tenantID shared.ID, runID string, terminalStatus scanrun.TerminalStatus, lanes []scanrun.Lane, manifestSchemaVersion int, manifestHash string, sealedAt time.Time) error {
	if tenantID.IsZero() || runID == "" {
		return fmt.Errorf("%w: tenant ID and scan run ID are required", shared.ErrValidation)
	}

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var (
			existingStatus, existingHash string
			existingSealedAt             *time.Time
			engID                        string
		)

		err := tx.QueryRow(ctx, `
			SELECT engagement_id, terminal_status, manifest_hash, sealed_at
			FROM scan_runs
			WHERE tenant_id = $1 AND id = $2
			FOR UPDATE
		`, tenantID.String(), runID).Scan(&engID, &existingStatus, &existingHash, &existingSealedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
		}
		if err != nil {
			return err
		}

		// Idempotent seal check
		if existingSealedAt != nil {
			if existingStatus == string(terminalStatus) && existingHash == manifestHash {
				return nil
			}
			return fmt.Errorf("%w: scan run %s is already sealed with different state", shared.ErrConflict, runID)
		}

		// Insert lanes
		for _, lane := range lanes {
			authoritativeJSON := []byte("[]")
			if len(lane.AuthoritativeFindingKinds) > 0 {
				var err error
				authoritativeJSON, err = json.Marshal(lane.AuthoritativeFindingKinds)
				if err != nil {
					return fmt.Errorf("marshal authoritative finding kinds: %w", err)
				}
			}

			incScopeJSON := []byte("[]")
			if len(lane.IncludedScope) > 0 {
				var err error
				incScopeJSON, err = json.Marshal(lane.IncludedScope)
				if err != nil {
					return fmt.Errorf("marshal included scope: %w", err)
				}
			}

			excScopeJSON := []byte("[]")
			if len(lane.ExcludedScope) > 0 {
				var err error
				excScopeJSON, err = json.Marshal(lane.ExcludedScope)
				if err != nil {
					return fmt.Errorf("marshal excluded scope: %w", err)
				}
			}

			_, err = tx.Exec(ctx, `
				INSERT INTO scan_run_lanes (
					tenant_id, engagement_id, scan_run_id, lane_key, producer,
					terminal_status, target_kind, target_identity_schema_version,
					target_identity_canonical, evaluated_revision,
					authoritative_finding_kinds, included_scope, excluded_scope,
					started_at, finished_at, result_ref, evidence_ref,
					result_sha256, manifest_schema_version, manifest_hash,
					sealed_at, created_at
				) VALUES (
					$1, $2, $3, $4, $5,
					$6, $7, $8,
					$9, $10,
					$11, $12, $13,
					$14, $15, $16, $17,
					$18, $19, $20,
					$21, $21
				)
			`, tenantID.String(), engID, runID, lane.LaneKey, lane.Producer,
				string(lane.TerminalStatus), string(lane.Target.TargetKind), lane.Target.TargetIdentitySchemaVersion,
				lane.Target.TargetIdentityCanonical, lane.Target.EvaluatedRevision,
				authoritativeJSON, incScopeJSON, excScopeJSON,
				lane.StartedAt, lane.FinishedAt, lane.ResultRef, lane.EvidenceRef,
				lane.ResultSHA256, lane.ManifestSchemaVersion, lane.ManifestHash,
				sealedAt)
			if err != nil {
				return mapScanRunSQLError(err)
			}

			// Insert versions
			for _, v := range lane.Versions {
				_, err = tx.Exec(ctx, `
					INSERT INTO scan_run_lane_versions (
						tenant_id, scan_run_id, lane_key, version_kind, name, version, digest
					) VALUES ($1, $2, $3, $4, $5, $6, $7)
				`, tenantID.String(), runID, lane.LaneKey, string(v.VersionKind), v.Name, v.Version, v.Digest)
				if err != nil {
					return mapScanRunSQLError(err)
				}
			}

			// Insert stages
			for _, st := range lane.Stages {
				_, err = tx.Exec(ctx, `
					INSERT INTO scan_run_lane_stages (
						tenant_id, scan_run_id, lane_key, stage_key, status, reason_code, started_at, finished_at
					) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				`, tenantID.String(), runID, lane.LaneKey, st.StageKey, string(st.Status), st.ReasonCode, st.StartedAt, st.FinishedAt)
				if err != nil {
					return mapScanRunSQLError(err)
				}
			}
		}

		// Update scan_runs header to sealed
		_, err = tx.Exec(ctx, `
			UPDATE scan_runs
			SET terminal_status = $3,
			    manifest_schema_version = $4,
			    manifest_hash = $5,
			    sealed_at = $6,
			    updated_at = $6
			WHERE tenant_id = $1 AND id = $2 AND sealed_at IS NULL
		`, tenantID.String(), runID, string(terminalStatus), manifestSchemaVersion, manifestHash, sealedAt)
		if err != nil {
			return mapScanRunSQLError(err)
		}

		return nil
	})
}

func (r *ScanRunStore) loadLanesForRun(ctx context.Context, tx pgx.Tx, tenantID, runID string) ([]scanrun.Lane, error) {
	rows, err := tx.Query(ctx, `
		SELECT tenant_id, engagement_id, scan_run_id, lane_key, producer,
		       terminal_status, target_kind, target_identity_schema_version,
		       target_identity_canonical, evaluated_revision,
		       authoritative_finding_kinds, included_scope, excluded_scope,
		       started_at, finished_at, result_ref, evidence_ref,
		       result_sha256, manifest_schema_version, manifest_hash, sealed_at
		FROM scan_run_lanes
		WHERE tenant_id = $1 AND scan_run_id = $2
		ORDER BY lane_key ASC
	`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var lanes []scanrun.Lane
	for rows.Next() {
		var (
			tenantStr, engStr, runIDStr, laneKey, producer string
			termStatus, targetKind                         string
			targetSchemaVer                                int
			targetCanonical, evalRev                       string
			authKindsJSON, incScopeJSON, excScopeJSON      []byte
			startedAt                                      time.Time
			finishedAt, sealedAt                           *time.Time
			resultRef, evidenceRef, resultSHA256           string
			manifestSchemaVer                              int
			manifestHash                                   string
		)

		if err := rows.Scan(
			&tenantStr, &engStr, &runIDStr, &laneKey, &producer,
			&termStatus, &targetKind, &targetSchemaVer,
			&targetCanonical, &evalRev,
			&authKindsJSON, &incScopeJSON, &excScopeJSON,
			&startedAt, &finishedAt, &resultRef, &evidenceRef,
			&resultSHA256, &manifestSchemaVer, &manifestHash, &sealedAt,
		); err != nil {
			return nil, err
		}

		var authKinds, incScope, excScope []string
		_ = json.Unmarshal(authKindsJSON, &authKinds)
		_ = json.Unmarshal(incScopeJSON, &incScope)
		_ = json.Unmarshal(excScopeJSON, &excScope)

		lanes = append(lanes, scanrun.Lane{
			TenantID:       shared.ID(tenantStr),
			EngagementID:   shared.ID(engStr),
			ScanRunID:      runIDStr,
			LaneKey:        laneKey,
			Producer:       producer,
			TerminalStatus: scanrun.TerminalStatus(termStatus),
			Target: scanrun.TargetIdentity{
				TargetKind:                  scanrun.TargetKind(targetKind),
				TargetIdentitySchemaVersion: targetSchemaVer,
				TargetIdentityCanonical:     targetCanonical,
				EvaluatedRevision:           evalRev,
			},
			AuthoritativeFindingKinds: authKinds,
			IncludedScope:             incScope,
			ExcludedScope:             excScope,
			StartedAt:                 startedAt,
			FinishedAt:                finishedAt,
			ResultRef:                 resultRef,
			EvidenceRef:               evidenceRef,
			ResultSHA256:              resultSHA256,
			ManifestSchemaVersion:     manifestSchemaVer,
			ManifestHash:              manifestHash,
			SealedAt:                  sealedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load versions and stages for each lane
	for i := range lanes {
		versions, err := r.loadVersionsForLane(ctx, tx, tenantID, runID, lanes[i].LaneKey)
		if err != nil {
			return nil, err
		}
		lanes[i].Versions = versions

		stages, err := r.loadStagesForLane(ctx, tx, tenantID, runID, lanes[i].LaneKey)
		if err != nil {
			return nil, err
		}
		lanes[i].Stages = stages
	}

	return lanes, nil
}

func (r *ScanRunStore) loadVersionsForLane(ctx context.Context, tx pgx.Tx, tenantID, runID, laneKey string) ([]scanrun.LaneVersion, error) {
	rows, err := tx.Query(ctx, `
		SELECT version_kind, name, version, digest
		FROM scan_run_lane_versions
		WHERE tenant_id = $1 AND scan_run_id = $2 AND lane_key = $3
		ORDER BY version_kind ASC, name ASC
	`, tenantID, runID, laneKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []scanrun.LaneVersion
	for rows.Next() {
		var vKind, name, ver, digest string
		if err := rows.Scan(&vKind, &name, &ver, &digest); err != nil {
			return nil, err
		}
		versions = append(versions, scanrun.LaneVersion{
			VersionKind: scanrun.VersionKind(vKind),
			Name:        name,
			Version:     ver,
			Digest:      digest,
		})
	}
	return versions, rows.Err()
}

func (r *ScanRunStore) loadStagesForLane(ctx context.Context, tx pgx.Tx, tenantID, runID, laneKey string) ([]scanrun.LaneStage, error) {
	rows, err := tx.Query(ctx, `
		SELECT stage_key, status, reason_code, started_at, finished_at
		FROM scan_run_lane_stages
		WHERE tenant_id = $1 AND scan_run_id = $2 AND lane_key = $3
		ORDER BY stage_key ASC
	`, tenantID, runID, laneKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stages []scanrun.LaneStage
	for rows.Next() {
		var (
			stageKey, status, reasonCode string
			startedAt                    time.Time
			finishedAt                   *time.Time
		)
		if err := rows.Scan(&stageKey, &status, &reasonCode, &startedAt, &finishedAt); err != nil {
			return nil, err
		}
		stages = append(stages, scanrun.LaneStage{
			StageKey:   stageKey,
			Status:     scanrun.StageStatus(status),
			ReasonCode: reasonCode,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
		})
	}
	return stages, rows.Err()
}

func scanLegacyRunRow(row rowScanner) (ports.ScanRun, error) {
	var (
		run            ports.ScanRun
		manifest, keys []byte
	)
	if err := row.Scan(&run.ID, &run.EngagementID, &run.CreatedAt, &manifest, &keys); err != nil {
		return ports.ScanRun{}, err
	}
	if len(manifest) > 0 {
		if err := json.Unmarshal(manifest, &run.Manifest); err != nil {
			return ports.ScanRun{}, fmt.Errorf("decode manifest: %w", err)
		}
	}
	if len(keys) > 0 {
		if err := json.Unmarshal(keys, &run.FindingKeys); err != nil {
			return ports.ScanRun{}, fmt.Errorf("decode finding keys: %w", err)
		}
	}
	return run, nil
}

func mapScanRunSQLError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s", shared.ErrConflict, pgErr.Message)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s", shared.ErrNotFound, pgErr.Message)
		case "23514": // check_violation
			return fmt.Errorf("%w: %s", shared.ErrValidation, pgErr.Message)
		}
	}
	return err
}

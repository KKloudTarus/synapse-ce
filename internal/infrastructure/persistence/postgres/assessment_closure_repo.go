package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentClosureManifestCols = `tenant_id, cycle_id, id, manifest_version, lifecycle, cycle_version,
	root_assessment_id, final_assessment_id, initial_snapshot_id, final_snapshot_id, comparison_id,
	initial_snapshot_hash, final_snapshot_hash, comparison_hash, canonical_input_hash, content_hash,
	policy_version, algorithm_version, fingerprint_version, risk_version, renderer_contract_version,
	coverage_decisions, scope_profile_changes, override_blocker_ids, non_final_branches,
	reason, override_reason, as_of_at, created_at, created_by, sealed_at, sealed_by, superseded_at, superseded_by_manifest_id`

var _ ports.AssessmentClosureRepository = (*AssessmentCycleRepository)(nil)

func (r *AssessmentCycleRepository) NextManifestVersion(ctx context.Context, tenantID, cycleID shared.ID) (int64, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return 0, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	var version int64
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_cycles WHERE tenant_id=$1 AND id=$2)`, tenantID.String(), cycleID.String()).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
		}
		return tx.QueryRow(ctx, `SELECT COALESCE(MAX(manifest_version),0)+1 FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2`, tenantID.String(), cycleID.String()).Scan(&version)
	})
	return version, err
}

func (r *AssessmentCycleRepository) CommitClosure(ctx context.Context, commit ports.AssessmentClosureCommit) error {
	if commit.Manifest == nil || commit.Cycle == nil || commit.ExpectedCycleVersion < 1 {
		return fmt.Errorf("%w: closure manifest, cycle, and expected version are required", shared.ErrValidation)
	}
	if err := commit.Manifest.Validate(); err != nil {
		return err
	}
	if err := commit.Cycle.Validate(); err != nil {
		return err
	}
	tenantID := shared.TenantOrDefault(commit.Cycle.TenantID)
	if commit.Manifest.TenantID != tenantID || commit.Manifest.CycleID != commit.Cycle.ID || commit.Manifest.Lifecycle != assessmentclosure.LifecycleActive ||
		commit.Cycle.Status != assessmentcycle.StatusCompleted || commit.Cycle.ActiveClosureManifestID != commit.Manifest.ID ||
		commit.Manifest.CycleVersion != commit.Cycle.Version || commit.Cycle.Version != commit.ExpectedCycleVersion+1 {
		return fmt.Errorf("%w: closure manifest and completed cycle do not match", shared.ErrValidation)
	}

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		stored, err := lockAssessmentCycleTx(ctx, tx, tenantID, commit.Cycle.ID)
		if err != nil {
			return err
		}
		if stored.Version != commit.ExpectedCycleVersion || stored.Status != assessmentcycle.StatusOpen || !stored.ActiveClosureManifestID.IsZero() ||
			stored.RootAssessmentID != commit.Manifest.RootAssessmentID || stored.SelectedHeadAssessmentID != commit.Manifest.FinalAssessmentID {
			return fmt.Errorf("%w: assessment cycle version or closure state changed", shared.ErrConflict)
		}
		var nextVersion int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(manifest_version),0)+1 FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2`, tenantID.String(), commit.Cycle.ID.String()).Scan(&nextVersion); err != nil {
			return err
		}
		if nextVersion != commit.Manifest.ManifestVersion {
			return fmt.Errorf("%w: closure manifest version changed", shared.ErrConflict)
		}
		if err := insertClosureManifestTx(ctx, tx, commit.Manifest); err != nil {
			return err
		}
		if err := updateClosedCycleTx(ctx, tx, commit.Cycle, commit.ExpectedCycleVersion); err != nil {
			return err
		}
		return nil
	})
}

func (r *AssessmentCycleRepository) ReopenClosure(ctx context.Context, reopen ports.AssessmentClosureReopen) error {
	if reopen.Manifest == nil || reopen.Cycle == nil || reopen.ExpectedCycleVersion < 1 {
		return fmt.Errorf("%w: superseded manifest, cycle, and expected version are required", shared.ErrValidation)
	}
	if err := reopen.Manifest.Validate(); err != nil {
		return err
	}
	if err := reopen.Cycle.Validate(); err != nil {
		return err
	}
	tenantID := shared.TenantOrDefault(reopen.Cycle.TenantID)
	if reopen.Manifest.TenantID != tenantID || reopen.Manifest.CycleID != reopen.Cycle.ID || reopen.Manifest.Lifecycle != assessmentclosure.LifecycleSuperseded ||
		reopen.Cycle.Status != assessmentcycle.StatusOpen || !reopen.Cycle.ActiveClosureManifestID.IsZero() || reopen.Cycle.Version != reopen.ExpectedCycleVersion+1 {
		return fmt.Errorf("%w: superseded manifest and reopened cycle do not match", shared.ErrValidation)
	}

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		storedCycle, err := lockAssessmentCycleTx(ctx, tx, tenantID, reopen.Cycle.ID)
		if err != nil {
			return err
		}
		if storedCycle.Version != reopen.ExpectedCycleVersion || storedCycle.Status != assessmentcycle.StatusCompleted || storedCycle.ActiveClosureManifestID != reopen.Manifest.ID {
			return fmt.Errorf("%w: assessment cycle version or active manifest changed", shared.ErrConflict)
		}
		storedManifest, err := loadClosureManifestTx(ctx, tx, tenantID, reopen.Cycle.ID, reopen.Manifest.ID)
		if err != nil {
			return err
		}
		if storedManifest.Lifecycle != assessmentclosure.LifecycleActive || storedManifest.ContentHash != reopen.Manifest.ContentHash || storedManifest.CanonicalInputHash != reopen.Manifest.CanonicalInputHash {
			return fmt.Errorf("%w: active closure manifest changed", shared.ErrConflict)
		}
		if err := updateReopenedCycleTx(ctx, tx, reopen.Cycle, reopen.Manifest.ID, reopen.ExpectedCycleVersion); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE assessment_cycle_closure_manifests
			SET lifecycle='superseded', superseded_at=$4, superseded_by_manifest_id=NULLIF($5,'')
			WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3 AND lifecycle='active'`,
			tenantID.String(), reopen.Cycle.ID.String(), reopen.Manifest.ID.String(), reopen.Manifest.SupersededAt, reopen.Manifest.SupersededByManifestID.String())
		if err != nil {
			return mapPostgresError(err, "supersede assessment closure manifest")
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: active closure manifest changed", shared.ErrConflict)
		}
		return nil
	})
}

func (r *AssessmentCycleRepository) GetClosureManifest(ctx context.Context, tenantID, cycleID, manifestID shared.ID) (*assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() || manifestID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and manifest ids are required", shared.ErrValidation)
	}
	var manifest *assessmentclosure.Manifest
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		loaded, err := loadClosureManifestTx(ctx, tx, tenantID, cycleID, manifestID)
		if err != nil {
			return err
		}
		manifest = loaded
		return nil
	})
	return manifest, err
}

func (r *AssessmentCycleRepository) GetActiveClosureManifest(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	var manifest *assessmentclosure.Manifest
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2 AND lifecycle='active'`, tenantID.String(), cycleID.String()).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: active closure manifest not found", shared.ErrNotFound)
			}
			return err
		}
		loaded, err := loadClosureManifestTx(ctx, tx, tenantID, cycleID, shared.ID(id))
		if err != nil {
			return err
		}
		manifest = loaded
		return nil
	})
	return manifest, err
}

func (r *AssessmentCycleRepository) ListClosureManifests(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	var manifests []assessmentclosure.Manifest
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2 ORDER BY manifest_version DESC`, tenantID.String(), cycleID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		var ids []shared.ID
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for _, id := range ids {
			manifest, err := loadClosureManifestTx(ctx, tx, tenantID, cycleID, id)
			if err != nil {
				return err
			}
			manifests = append(manifests, *manifest)
		}
		if len(ids) == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_cycles WHERE tenant_id=$1 AND id=$2)`, tenantID.String(), cycleID.String()).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
			}
		}
		return nil
	})
	return manifests, err
}

func lockAssessmentCycleTx(ctx context.Context, tx pgx.Tx, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	cycle, err := scanAssessmentCycle(tx.QueryRow(ctx, `SELECT `+assessmentCycleCols+` FROM assessment_cycles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), cycleID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
	}
	return cycle, err
}

func insertClosureManifestTx(ctx context.Context, tx pgx.Tx, manifest *assessmentclosure.Manifest) error {
	coverage, err := json.Marshal(manifest.CoverageDecisions)
	if err != nil {
		return fmt.Errorf("marshal closure coverage decisions: %w", err)
	}
	scopeChanges, err := json.Marshal(manifest.ScopeProfileChanges)
	if err != nil {
		return fmt.Errorf("marshal closure scope changes: %w", err)
	}
	overrides, err := json.Marshal(manifest.OverrideBlockerIDs)
	if err != nil {
		return fmt.Errorf("marshal closure overrides: %w", err)
	}
	branches, err := json.Marshal(manifest.NonFinalBranches)
	if err != nil {
		return fmt.Errorf("marshal closure branches: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_manifests (`+assessmentClosureManifestCols+`) VALUES (
		$1,$2,$3,$4,'building',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'',$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,NULL,'',NULL,NULL)`,
		manifest.TenantID.String(), manifest.CycleID.String(), manifest.ID.String(), manifest.ManifestVersion, manifest.CycleVersion,
		manifest.RootAssessmentID.String(), manifest.FinalAssessmentID.String(), manifest.InitialSnapshotID.String(), manifest.FinalSnapshotID.String(), manifest.ComparisonID.String(),
		manifest.InitialSnapshotHash, manifest.FinalSnapshotHash, manifest.ComparisonHash, manifest.CanonicalInputHash,
		manifest.PolicyVersion, manifest.AlgorithmVersion, manifest.FingerprintVersion, manifest.RiskVersion, manifest.RendererContractVersion,
		coverage, scopeChanges, overrides, branches, manifest.Reason, manifest.OverrideReason, manifest.AsOfAt, manifest.CreatedAt, manifest.CreatedBy)
	if err != nil {
		return mapPostgresError(err, "create assessment closure manifest")
	}
	for _, member := range manifest.Path {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_path_members
			(tenant_id,cycle_id,manifest_id,path_position,assessment_id,assessment_type,retest_number,relationship_version,snapshot_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''))`,
			manifest.TenantID.String(), manifest.CycleID.String(), manifest.ID.String(), member.PathPosition, member.AssessmentID.String(), string(member.AssessmentType), member.RetestNumber, member.RelationshipVersion, member.SnapshotID.String()); err != nil {
			return mapPostgresError(err, "create assessment closure path")
		}
	}
	for _, reference := range manifest.References {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_references
			(tenant_id,cycle_id,manifest_id,reference_kind,reference_id,reference_version,content_hash,expires_at,metadata)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			manifest.TenantID.String(), manifest.CycleID.String(), manifest.ID.String(), reference.Kind, reference.ID.String(), reference.Version, reference.ContentHash, reference.ExpiresAt, reference.Metadata); err != nil {
			return mapPostgresError(err, "create assessment closure reference")
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE assessment_cycle_closure_manifests SET lifecycle='active',content_hash=$4,sealed_at=$5,sealed_by=$6
		WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3 AND lifecycle='building'`,
		manifest.TenantID.String(), manifest.CycleID.String(), manifest.ID.String(), manifest.ContentHash, manifest.SealedAt, manifest.SealedBy)
	if err != nil {
		return mapPostgresError(err, "seal assessment closure manifest")
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: closure manifest could not be sealed", shared.ErrConflict)
	}
	return nil
}

func updateClosedCycleTx(ctx context.Context, tx pgx.Tx, cycle *assessmentcycle.AssessmentCycle, expectedVersion int64) error {
	tag, err := tx.Exec(ctx, `UPDATE assessment_cycles SET status='completed',selected_head_assessment_id=$3,version=$4,updated_at=$5,updated_by=$6,
		active_closure_manifest_id=$7,active_closure_cycle_version=$8
		WHERE tenant_id=$1 AND id=$2 AND version=$9 AND status='open' AND active_closure_manifest_id IS NULL`,
		cycle.TenantID.String(), cycle.ID.String(), cycle.SelectedHeadAssessmentID.String(), cycle.Version, cycle.UpdatedAt, cycle.UpdatedBy,
		cycle.ActiveClosureManifestID.String(), cycle.ActiveClosureCycleVersion, expectedVersion)
	if err != nil {
		return mapPostgresError(err, "complete assessment cycle")
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: assessment cycle version or closure state changed", shared.ErrConflict)
	}
	return nil
}

func updateReopenedCycleTx(ctx context.Context, tx pgx.Tx, cycle *assessmentcycle.AssessmentCycle, manifestID shared.ID, expectedVersion int64) error {
	tag, err := tx.Exec(ctx, `UPDATE assessment_cycles SET status='open',selected_head_assessment_id=$3,version=$4,updated_at=$5,updated_by=$6,
		active_closure_manifest_id=NULL,active_closure_cycle_version=NULL
		WHERE tenant_id=$1 AND id=$2 AND version=$7 AND status='completed' AND active_closure_manifest_id=$8`,
		cycle.TenantID.String(), cycle.ID.String(), cycle.SelectedHeadAssessmentID.String(), cycle.Version, cycle.UpdatedAt, cycle.UpdatedBy,
		expectedVersion, manifestID.String())
	if err != nil {
		return mapPostgresError(err, "reopen assessment cycle")
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: assessment cycle version or active manifest changed", shared.ErrConflict)
	}
	return nil
}

func loadClosureManifestTx(ctx context.Context, tx pgx.Tx, tenantID, cycleID, manifestID shared.ID) (*assessmentclosure.Manifest, error) {
	manifest, err := scanClosureManifest(tx.QueryRow(ctx, `SELECT `+assessmentClosureManifestCols+` FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantID.String(), cycleID.String(), manifestID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: closure manifest %q not found", shared.ErrNotFound, manifestID)
	}
	if err != nil {
		return nil, err
	}
	pathRows, err := tx.Query(ctx, `SELECT path_position,assessment_id,assessment_type,retest_number,relationship_version,COALESCE(snapshot_id,'')
		FROM assessment_cycle_closure_path_members WHERE tenant_id=$1 AND cycle_id=$2 AND manifest_id=$3 ORDER BY path_position`, tenantID.String(), cycleID.String(), manifestID.String())
	if err != nil {
		return nil, err
	}
	for pathRows.Next() {
		var member assessmentclosure.PathMember
		var assessmentType string
		if err := pathRows.Scan(&member.PathPosition, &member.AssessmentID, &assessmentType, &member.RetestNumber, &member.RelationshipVersion, &member.SnapshotID); err != nil {
			pathRows.Close()
			return nil, err
		}
		member.AssessmentType = assessmentcycle.AssessmentType(assessmentType)
		manifest.Path = append(manifest.Path, member)
	}
	if err := pathRows.Err(); err != nil {
		pathRows.Close()
		return nil, err
	}
	pathRows.Close()

	referenceRows, err := tx.Query(ctx, `SELECT reference_kind,reference_id,reference_version,content_hash,expires_at,metadata
		FROM assessment_cycle_closure_references WHERE tenant_id=$1 AND cycle_id=$2 AND manifest_id=$3 ORDER BY reference_kind,reference_id`, tenantID.String(), cycleID.String(), manifestID.String())
	if err != nil {
		return nil, err
	}
	for referenceRows.Next() {
		var reference assessmentclosure.Reference
		var expiresAt pgtype.Timestamptz
		var metadata []byte
		if err := referenceRows.Scan(&reference.Kind, &reference.ID, &reference.Version, &reference.ContentHash, &expiresAt, &metadata); err != nil {
			referenceRows.Close()
			return nil, err
		}
		if expiresAt.Valid {
			expires := expiresAt.Time.UTC().Truncate(time.Microsecond)
			reference.ExpiresAt = &expires
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, metadata); err != nil {
			referenceRows.Close()
			return nil, fmt.Errorf("compact closure reference metadata: %w", err)
		}
		reference.Metadata = compact.Bytes()
		manifest.References = append(manifest.References, reference)
	}
	if err := referenceRows.Err(); err != nil {
		referenceRows.Close()
		return nil, err
	}
	referenceRows.Close()
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate persisted closure manifest: %w", err)
	}
	return manifest, nil
}

func scanClosureManifest(row rowScanner) (*assessmentclosure.Manifest, error) {
	var manifest assessmentclosure.Manifest
	var lifecycle string
	var coverage, scopeChanges, overrides, branches []byte
	var sealedAt, supersededAt pgtype.Timestamptz
	var supersededBy pgtype.Text
	if err := row.Scan(
		&manifest.TenantID, &manifest.CycleID, &manifest.ID, &manifest.ManifestVersion, &lifecycle, &manifest.CycleVersion,
		&manifest.RootAssessmentID, &manifest.FinalAssessmentID, &manifest.InitialSnapshotID, &manifest.FinalSnapshotID, &manifest.ComparisonID,
		&manifest.InitialSnapshotHash, &manifest.FinalSnapshotHash, &manifest.ComparisonHash, &manifest.CanonicalInputHash, &manifest.ContentHash,
		&manifest.PolicyVersion, &manifest.AlgorithmVersion, &manifest.FingerprintVersion, &manifest.RiskVersion, &manifest.RendererContractVersion,
		&coverage, &scopeChanges, &overrides, &branches, &manifest.Reason, &manifest.OverrideReason, &manifest.AsOfAt, &manifest.CreatedAt, &manifest.CreatedBy,
		&sealedAt, &manifest.SealedBy, &supersededAt, &supersededBy,
	); err != nil {
		return nil, err
	}
	manifest.Lifecycle = assessmentclosure.Lifecycle(lifecycle)
	manifest.AsOfAt = manifest.AsOfAt.UTC().Truncate(time.Microsecond)
	manifest.CreatedAt = manifest.CreatedAt.UTC().Truncate(time.Microsecond)
	if sealedAt.Valid {
		value := sealedAt.Time.UTC().Truncate(time.Microsecond)
		manifest.SealedAt = &value
	}
	if supersededAt.Valid {
		value := supersededAt.Time.UTC().Truncate(time.Microsecond)
		manifest.SupersededAt = &value
	}
	if supersededBy.Valid {
		manifest.SupersededByManifestID = shared.ID(supersededBy.String)
	}
	if err := json.Unmarshal(coverage, &manifest.CoverageDecisions); err != nil {
		return nil, fmt.Errorf("decode closure coverage decisions: %w", err)
	}
	if err := json.Unmarshal(scopeChanges, &manifest.ScopeProfileChanges); err != nil {
		return nil, fmt.Errorf("decode closure scope changes: %w", err)
	}
	if err := json.Unmarshal(overrides, &manifest.OverrideBlockerIDs); err != nil {
		return nil, fmt.Errorf("decode closure overrides: %w", err)
	}
	if err := json.Unmarshal(branches, &manifest.NonFinalBranches); err != nil {
		return nil, fmt.Errorf("decode closure branches: %w", err)
	}
	return &manifest, nil
}

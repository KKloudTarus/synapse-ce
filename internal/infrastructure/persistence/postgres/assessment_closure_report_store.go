package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.AssessmentClosureReportStore = (*AssessmentCycleRepository)(nil)

func (r *AssessmentCycleRepository) SaveClosureReport(ctx context.Context, report ports.AssessmentClosureReportArtifact) (ports.AssessmentClosureReportArtifact, bool, error) {
	report.TenantID = shared.TenantOrDefault(report.TenantID)
	report.GeneratedAt = report.GeneratedAt.UTC().Truncate(time.Microsecond)
	if err := validatePostgresClosureReport(report); err != nil {
		return ports.AssessmentClosureReportArtifact{}, false, err
	}
	var stored ports.AssessmentClosureReportArtifact
	var created bool
	err := WithTenant(ctx, r.pool, report.TenantID.String(), func(tx pgx.Tx) error {
		var rendererVersion string
		if err := tx.QueryRow(ctx, `SELECT renderer_contract_version FROM assessment_cycle_closure_manifests WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, report.TenantID.String(), report.CycleID.String(), report.ManifestID.String()).Scan(&rendererVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: closure manifest %q not found", shared.ErrNotFound, report.ManifestID)
			}
			return err
		}
		if rendererVersion != report.RendererContractVersion {
			return fmt.Errorf("%w: report renderer does not match closure manifest", shared.ErrValidation)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_reports
			(tenant_id,cycle_id,manifest_id,renderer_contract_version,content_hash,content,generated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			report.TenantID.String(), report.CycleID.String(), report.ManifestID.String(), report.RendererContractVersion, report.ContentHash, report.Content, report.GeneratedAt)
		if err != nil {
			return mapPostgresError(err, "save assessment closure report")
		}
		created = tag.RowsAffected() == 1
		stored, err = getClosureReportTx(ctx, tx, report.TenantID, report.CycleID, report.ManifestID, report.RendererContractVersion)
		if err != nil {
			return err
		}
		if stored.ContentHash != report.ContentHash || !bytes.Equal(stored.Content, report.Content) || !stored.GeneratedAt.Equal(report.GeneratedAt) {
			return fmt.Errorf("%w: closure report key was reused with different content", shared.ErrConflict)
		}
		return nil
	})
	return stored, created, err
}

func (r *AssessmentCycleRepository) GetClosureReport(ctx context.Context, tenantID, cycleID, manifestID shared.ID, rendererVersion string) (ports.AssessmentClosureReportArtifact, error) {
	tenantID, rendererVersion = shared.TenantOrDefault(tenantID), strings.TrimSpace(rendererVersion)
	if tenantID.IsZero() || cycleID.IsZero() || manifestID.IsZero() || rendererVersion == "" {
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("%w: closure report identity is required", shared.ErrValidation)
	}
	var report ports.AssessmentClosureReportArtifact
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		report, err = getClosureReportTx(ctx, tx, tenantID, cycleID, manifestID, rendererVersion)
		return err
	})
	return report, err
}

func getClosureReportTx(ctx context.Context, tx pgx.Tx, tenantID, cycleID, manifestID shared.ID, rendererVersion string) (ports.AssessmentClosureReportArtifact, error) {
	var report ports.AssessmentClosureReportArtifact
	err := tx.QueryRow(ctx, `SELECT tenant_id,cycle_id,manifest_id,renderer_contract_version,content_hash,content,generated_at
		FROM assessment_cycle_closure_reports WHERE tenant_id=$1 AND cycle_id=$2 AND manifest_id=$3 AND renderer_contract_version=$4`,
		tenantID.String(), cycleID.String(), manifestID.String(), rendererVersion).Scan(
		&report.TenantID, &report.CycleID, &report.ManifestID, &report.RendererContractVersion, &report.ContentHash, &report.Content, &report.GeneratedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("%w: closure report not found", shared.ErrNotFound)
	}
	if err != nil {
		return ports.AssessmentClosureReportArtifact{}, err
	}
	report.GeneratedAt = report.GeneratedAt.UTC().Truncate(time.Microsecond)
	if err := validatePostgresClosureReport(report); err != nil {
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("validate persisted closure report: %w", err)
	}
	return report, nil
}

func validatePostgresClosureReport(report ports.AssessmentClosureReportArtifact) error {
	if report.TenantID.IsZero() || report.CycleID.IsZero() || report.ManifestID.IsZero() || report.GeneratedAt.IsZero() ||
		report.RendererContractVersion == "" || report.RendererContractVersion != strings.TrimSpace(report.RendererContractVersion) || len(report.RendererContractVersion) > 128 ||
		len(report.Content) < 2 || len(report.Content) > 16*1024*1024 || len(report.ContentHash) != sha256.Size*2 {
		return fmt.Errorf("%w: closure report artifact is invalid", shared.ErrValidation)
	}
	digest := sha256.Sum256(report.Content)
	if hex.EncodeToString(digest[:]) != report.ContentHash {
		return fmt.Errorf("%w: closure report content hash mismatch", shared.ErrValidation)
	}
	return nil
}

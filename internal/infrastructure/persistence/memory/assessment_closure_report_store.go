package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (r *AssessmentCycleRepository) SaveClosureReport(_ context.Context, report ports.AssessmentClosureReportArtifact) (ports.AssessmentClosureReportArtifact, bool, error) {
	report.TenantID = shared.TenantOrDefault(report.TenantID)
	if err := validateClosureReportArtifact(report); err != nil {
		return ports.AssessmentClosureReportArtifact{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	manifest := r.closureManifests[report.TenantID][report.CycleID][report.ManifestID]
	if manifest == nil {
		return ports.AssessmentClosureReportArtifact{}, false, fmt.Errorf("%w: closure manifest %q not found", shared.ErrNotFound, report.ManifestID)
	}
	if manifest.RendererContractVersion != report.RendererContractVersion {
		return ports.AssessmentClosureReportArtifact{}, false, fmt.Errorf("%w: report renderer does not match closure manifest", shared.ErrValidation)
	}
	if r.closureReports[report.TenantID] == nil {
		r.closureReports[report.TenantID] = map[shared.ID]map[shared.ID]map[string]ports.AssessmentClosureReportArtifact{}
	}
	if r.closureReports[report.TenantID][report.CycleID] == nil {
		r.closureReports[report.TenantID][report.CycleID] = map[shared.ID]map[string]ports.AssessmentClosureReportArtifact{}
	}
	if r.closureReports[report.TenantID][report.CycleID][report.ManifestID] == nil {
		r.closureReports[report.TenantID][report.CycleID][report.ManifestID] = map[string]ports.AssessmentClosureReportArtifact{}
	}
	existing, exists := r.closureReports[report.TenantID][report.CycleID][report.ManifestID][report.RendererContractVersion]
	if exists {
		if existing.ContentHash != report.ContentHash || !bytes.Equal(existing.Content, report.Content) || !existing.GeneratedAt.Equal(report.GeneratedAt) {
			return ports.AssessmentClosureReportArtifact{}, false, fmt.Errorf("%w: closure report key was reused with different content", shared.ErrConflict)
		}
		return cloneClosureReport(existing), false, nil
	}
	stored := cloneClosureReport(report)
	r.closureReports[report.TenantID][report.CycleID][report.ManifestID][report.RendererContractVersion] = stored
	return cloneClosureReport(stored), true, nil
}

func (r *AssessmentCycleRepository) GetClosureReport(_ context.Context, tenantID, cycleID, manifestID shared.ID, rendererVersion string) (ports.AssessmentClosureReportArtifact, error) {
	tenantID, rendererVersion = shared.TenantOrDefault(tenantID), strings.TrimSpace(rendererVersion)
	if tenantID.IsZero() || cycleID.IsZero() || manifestID.IsZero() || rendererVersion == "" {
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("%w: closure report identity is required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	report, exists := r.closureReports[tenantID][cycleID][manifestID][rendererVersion]
	if !exists {
		return ports.AssessmentClosureReportArtifact{}, fmt.Errorf("%w: closure report not found", shared.ErrNotFound)
	}
	return cloneClosureReport(report), nil
}

func validateClosureReportArtifact(report ports.AssessmentClosureReportArtifact) error {
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

func cloneClosureReport(report ports.AssessmentClosureReportArtifact) ports.AssessmentClosureReportArtifact {
	report.Content = append([]byte(nil), report.Content...)
	return report
}

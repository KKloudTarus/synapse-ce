package sca

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SetProjectSourceProjects enables validation of server-owned Project source
// selections. The composition root supplies the tenant-scoped Project store.
func (s *Service) SetProjectSourceProjects(projects ports.ProjectRepository) {
	s.projects = projects
}

func (s *Service) validateProjectSourceScan(ctx context.Context, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) error {
	selection := req.ProjectSource
	if selection == nil {
		return nil
	}
	if s.projects == nil || selection.ProjectID.IsZero() || req.Kind != ports.TargetLocal || opts.ProjectAnalysis || opts.CodeQuality || opts.Mode != ScanModeVulnerabilities {
		return fmt.Errorf("%w: invalid project source scan", shared.ErrValidation)
	}
	if strings.TrimSpace(selection.Root) == "" || strings.ContainsRune(selection.Root, '\x00') || !filepath.IsAbs(selection.Root) || filepath.Clean(selection.Root) != selection.Root {
		return fmt.Errorf("%w: invalid project source root", shared.ErrValidation)
	}
	if strings.ContainsRune(selection.Subdirectory, '\x00') || strings.Contains(selection.Subdirectory, `\`) || strings.TrimSpace(selection.Subdirectory) != selection.Subdirectory {
		return fmt.Errorf("%w: invalid project source subdirectory", shared.ErrValidation)
	}
	child := path.Clean(selection.Subdirectory)
	if selection.Subdirectory == "" || child == "." || child != selection.Subdirectory || strings.HasPrefix(child, "/") || strings.HasPrefix(child, "../") || child == ".." {
		return fmt.Errorf("%w: project source subdirectory must be a canonical relative child", shared.ErrValidation)
	}
	if req.Value != filepath.Join(selection.Root, filepath.FromSlash(child)) {
		return fmt.Errorf("%w: project source target does not match selection", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fmt.Errorf("%w: tenant context is required for project source scan", shared.ErrValidation)
	}
	p, err := s.projects.GetByID(ctx, tenantID, selection.ProjectID)
	if err != nil {
		return fmt.Errorf("load project source binding: %w", err)
	}
	if p == nil || p.SourceBinding.Kind != project.SourceLocal || p.SourceBinding.Value != selection.Root {
		return fmt.Errorf("%w: project source binding changed", shared.ErrForbidden)
	}
	// Internal Project contexts are intentionally excluded from public
	// engagement reads. Resolve by the server-owned Project ID and then bind the
	// queued engagement ID exactly; this preserves the visibility boundary.
	hidden, err := s.engagements.GetByProjectID(ctx, tenantID, selection.ProjectID)
	if err != nil {
		return fmt.Errorf("load project source context: %w", err)
	}
	if hidden == nil || hidden.ID != engagementID || hidden.ProjectID != selection.ProjectID {
		return fmt.Errorf("%w: project source context does not match project", shared.ErrForbidden)
	}
	return nil
}

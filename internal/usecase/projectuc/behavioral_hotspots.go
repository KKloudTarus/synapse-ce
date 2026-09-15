package projectuc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// GetBehavioralHotspots returns a bounded ranking from one immutable analysis. It never reads the
// working tree or invokes Git, so historical analyses cannot change underneath callers.
func (s *Service) GetBehavioralHotspots(ctx context.Context, tenantID shared.ID, projectKey, analysisID, path string, limit int) (BehavioralHotspotsResponse, error) {
	if s.analyses == nil || strings.TrimSpace(analysisID) == "" {
		return BehavioralHotspotsResponse{}, shared.ErrNotFound
	}
	if limit < 1 || limit > 100 {
		return BehavioralHotspotsResponse{}, fmt.Errorf("%w: limit must be between 1 and 100", shared.ErrValidation)
	}
	canonical, err := measure.CanonicalPath(path)
	if err != nil || canonical != path {
		return BehavioralHotspotsResponse{}, fmt.Errorf("%w: invalid canonical path", shared.ErrValidation)
	}

	p, err := s.repo.GetByKey(ctx, tenantID, strings.TrimSpace(projectKey))
	if err != nil {
		return BehavioralHotspotsResponse{}, err
	}
	analysis, err := s.analyses.Get(ctx, p.TenantID, p.ID, shared.ID(analysisID))
	if err != nil {
		return BehavioralHotspotsResponse{}, err
	}
	if err := analysis.Snapshot.Validate(); err != nil {
		return BehavioralHotspotsResponse{}, err
	}

	pathExists := canonical == ""
	for i := range analysis.Snapshot.Nodes {
		if analysis.Snapshot.Nodes[i].Path == canonical {
			pathExists = true
			break
		}
	}
	if !pathExists {
		return BehavioralHotspotsResponse{}, shared.ErrNotFound
	}

	res := BehavioralHotspotsResponse{
		Project:  ProjectNodeInfo{Key: p.Key, Name: p.Name},
		Analysis: AnalysisMetadata{ID: analysis.ID, CreatedAt: analysis.CreatedAt, SourceRef: analysis.SourceRef, SourceCommit: analysis.SourceCommit},
		Path:     canonical, Availability: measure.BehavioralUnavailable,
		FormulaVersion: measure.BehavioralHotspotsSchemaVersion,
		Items:          []BehavioralHotspotItem{},
	}
	if analysis.BehavioralHotspots == nil {
		reason := "legacy_analysis"
		res.Reason = &reason
		return res, nil
	}
	report := analysis.BehavioralHotspots
	if err := report.Validate(); err != nil {
		return BehavioralHotspotsResponse{}, err
	}
	res.Availability = report.Availability
	res.FormulaVersion = report.Version
	res.RequestedCommits = report.RequestedCommits
	res.EvaluatedCommits = report.EvaluatedCommits
	res.ReachedRoot = report.ReachedRoot
	if report.Reason != "" {
		reason := report.Reason
		res.Reason = &reason
	}

	items, totalMeasured, shown, omitted := report.RankedFiles(canonical, limit)
	res.TotalMeasured, res.Shown, res.Omitted = totalMeasured, shown, omitted
	for _, item := range items {
		res.Items = append(res.Items, BehavioralHotspotItem{
			Path: item.Path, Language: item.Language, Cyclomatic: item.Cyclomatic,
			ChangeCount: item.ChangeCount, Score: item.Score,
		})
	}
	prefix := ""
	if canonical != "" {
		prefix = canonical + "/"
	}
	for _, item := range report.Files {
		if canonical == "" || item.Path == canonical || strings.HasPrefix(item.Path, prefix) {
			res.TotalEligible++
		}
	}
	for _, gap := range report.Gaps {
		if canonical == "" || gap.Path == canonical || strings.HasPrefix(gap.Path, prefix) {
			res.TotalEligible++
			res.TotalExcluded++
		}
	}
	return res, nil
}

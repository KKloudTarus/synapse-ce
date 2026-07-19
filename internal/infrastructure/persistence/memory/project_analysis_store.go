package memory

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ProjectAnalysisStore is an append-only in-memory Project analysis store.
type storedProjectAnalysis struct {
	analysis projectanalysis.Analysis
	result   []byte
}

type analysisHotspot struct {
	AnalysisID shared.ID
	HotspotID  shared.ID
	IsNew      bool
	Status     hotspot.Status
	Version    int
}

type ProjectAnalysisStore struct {
	mu               sync.RWMutex
	data             []storedProjectAnalysis
	hotspots         []hotspot.Hotspot
	reviewEvents     []hotspot.ReviewEvent
	analysisHotspots []analysisHotspot
}

func NewProjectAnalysisStore() *ProjectAnalysisStore { return &ProjectAnalysisStore{} }

var _ ports.ProjectAnalysisStore = (*ProjectAnalysisStore)(nil)

func (s *ProjectAnalysisStore) Save(ctx context.Context, analysis projectanalysis.Analysis) error {
	return s.SaveWithResult(ctx, analysis, nil)
}

func (s *ProjectAnalysisStore) SaveWithResult(_ context.Context, analysis projectanalysis.Analysis, result []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveWithResultLocked(analysis, result)
}

func (s *ProjectAnalysisStore) SaveWithResultAndHotspots(_ context.Context, analysis projectanalysis.Analysis, result []byte, candidates []hotspot.Candidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateCandidates(analysis, candidates); err != nil {
		return err
	}
	if err := s.saveWithResultLocked(analysis, result); err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := s.upsertHotspotLocked(analysis, candidate); err != nil {
			return err
		}
	}
	return nil
}

func (s *ProjectAnalysisStore) saveWithResultLocked(analysis projectanalysis.Analysis, result []byte) error {
	for _, current := range s.data {
		if current.analysis.ID == analysis.ID {
			return nil
		}
	}
	s.data = append(s.data, storedProjectAnalysis{analysis: cloneProjectAnalysis(analysis), result: slices.Clone(result)})
	return nil
}

func (s *ProjectAnalysisStore) LatestForProjects(_ context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]projectanalysis.Analysis, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wanted := map[shared.ID]bool{}
	for _, id := range projectIDs {
		wanted[id] = true
	}
	out := map[shared.ID]projectanalysis.Analysis{}
	for _, stored := range s.data {
		analysis := stored.analysis
		id := shared.ID(analysis.ProjectID)
		if !wanted[id] || (!tenantID.IsZero() && analysis.TenantID != tenantID.String()) {
			continue
		}
		if current, ok := out[id]; !ok || analysis.CreatedAt.After(current.CreatedAt) || (analysis.CreatedAt.Equal(current.CreatedAt) && analysis.ID > current.ID) {
			out[id] = cloneProjectAnalysis(analysis)
		}
	}
	return out, nil
}

func (s *ProjectAnalysisStore) LatestWithResult(_ context.Context, tenantID, projectID shared.ID) (projectanalysis.Analysis, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *storedProjectAnalysis
	for i := range s.data {
		current := &s.data[i]
		if current.analysis.ProjectID != projectID.String() || (!tenantID.IsZero() && current.analysis.TenantID != tenantID.String()) || len(current.result) == 0 {
			continue
		}
		if latest == nil || current.analysis.CreatedAt.After(latest.analysis.CreatedAt) || (current.analysis.CreatedAt.Equal(latest.analysis.CreatedAt) && current.analysis.ID > latest.analysis.ID) {
			latest = current
		}
	}
	if latest == nil || len(latest.result) == 0 {
		return projectanalysis.Analysis{}, nil, shared.ErrNotFound
	}
	return cloneProjectAnalysis(latest.analysis), slices.Clone(latest.result), nil
}

func (s *ProjectAnalysisStore) List(_ context.Context, tenantID, projectID shared.ID, limit int, beforeCreatedAt time.Time, beforeID shared.ID) ([]projectanalysis.Analysis, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]projectanalysis.Analysis, 0)
	for _, stored := range s.data {
		analysis := stored.analysis
		if analysis.ProjectID != projectID.String() || (!tenantID.IsZero() && analysis.TenantID != tenantID.String()) {
			continue
		}
		if !beforeCreatedAt.IsZero() && (analysis.CreatedAt.After(beforeCreatedAt) || (analysis.CreatedAt.Equal(beforeCreatedAt) && analysis.ID >= beforeID.String())) {
			continue
		}
		out = append(out, cloneProjectAnalysis(analysis))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func cloneProjectAnalysis(in projectanalysis.Analysis) projectanalysis.Analysis {
	out := in
	out.Measures = maps.Clone(in.Measures)
	out.Gate.Results = slices.Clone(in.Gate.Results)
	out.InternalIssues = slices.Clone(in.InternalIssues)
	out.Issues = cloneCounts(in.Issues)
	out.NewCode.Counts = cloneCounts(in.NewCode.Counts)
	if in.Delta != nil {
		delta := *in.Delta
		delta.Issues = cloneCounts(in.Delta.Issues)
		delta.Measures = maps.Clone(in.Delta.Measures)
		delta.Ratings = maps.Clone(in.Delta.Ratings)
		out.Delta = &delta
	}
	if in.Coverage != nil {
		coverage := *in.Coverage
		coverage.Files = slices.Clone(in.Coverage.Files)
		out.Coverage = &coverage
	}
	out.Duplication = cloneDuplication(in.Duplication)
	return out
}

func validateCandidates(analysis projectanalysis.Analysis, candidates []hotspot.Candidate) error {
	for _, candidate := range candidates {
		_, err := hotspot.Project(shared.ID(analysis.TenantID), shared.ID(analysis.ProjectID), analysis.ID, analysis.CreatedAt, candidate)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ProjectAnalysisStore) upsertHotspotLocked(analysis projectanalysis.Analysis, candidate hotspot.Candidate) error {
	var itemID shared.ID
	var isNew bool
	var finalStatus hotspot.Status
	var finalVersion int
	var reopened bool

	found := false
	for i := range s.hotspots {
		current := &s.hotspots[i]
		if current.TenantID != shared.ID(analysis.TenantID) || current.ProjectID != shared.ID(analysis.ProjectID) || current.Key != candidate.Key {
			continue
		}
		found = true
		itemID = current.ID

		if current.Status == hotspot.StatusFixed && analysis.CreatedAt.After(current.LastSeenAt) {
			eID := hotspot.DeterministicID(shared.ID(analysis.ID), current.ID, "reopen")
			newVersion := current.Version + 1
			newStatus := hotspot.StatusToReview

			s.reviewEvents = append(s.reviewEvents, hotspot.ReviewEvent{
				ID:              eID,
				TenantID:        current.TenantID,
				ProjectID:       current.ProjectID,
				HotspotID:       current.ID,
				From:            current.Status,
				To:              newStatus,
				Actor:           "system:project-analysis",
				Rationale:       "Automatically reopened: hotspot detected in later analysis.",
				PreviousVersion: current.Version,
				Version:         newVersion,
				CreatedAt:       analysis.CreatedAt,
			})

			current.Status = newStatus
			current.Version = newVersion
			reopened = true
		}

		if analysis.CreatedAt.Before(current.FirstSeenAt) || (analysis.CreatedAt.Equal(current.FirstSeenAt) && analysis.ID < current.FirstSeenAnalysisID) {
			current.FirstSeenAnalysisID, current.FirstSeenAt = analysis.ID, analysis.CreatedAt
			current.Audit.CreatedAt = analysis.CreatedAt
		}
		if analysis.CreatedAt.After(current.LastSeenAt) || (analysis.CreatedAt.Equal(current.LastSeenAt) && analysis.ID > current.LastSeenAnalysisID) {
			current.FindingIdentity = candidate.FindingIdentity
			current.RuleKey, current.Title, current.Description = candidate.RuleKey, candidate.Title, candidate.Description
			current.Severity, current.Kind, current.CWE, current.Location = candidate.Severity, candidate.Kind, candidate.CWE, candidate.Location
			current.LastSeenAnalysisID, current.LastSeenAt = analysis.ID, analysis.CreatedAt
			current.Audit.UpdatedAt = analysis.CreatedAt
		}

		isNew = reopened || (current.FirstSeenAnalysisID == analysis.ID && current.LastSeenAnalysisID == analysis.ID)
		finalStatus = current.Status
		finalVersion = current.Version
		break
	}

	if !found {
		item, err := hotspot.Project(
			shared.ID(analysis.TenantID),
			shared.ID(analysis.ProjectID),
			analysis.ID,
			analysis.CreatedAt,
			candidate,
		)
		if err != nil {
			return err
		}

		itemID = item.ID
		s.hotspots = append(s.hotspots, item)
		isNew = true
		finalStatus = item.Status
		finalVersion = item.Version
	}

	// Avoid duplicates in analysisHotspots if called multiple times somehow
	for _, ah := range s.analysisHotspots {
		if ah.AnalysisID.String() == analysis.ID && ah.HotspotID == itemID {
			return nil
		}
	}
	s.analysisHotspots = append(s.analysisHotspots, analysisHotspot{
		AnalysisID: shared.ID(analysis.ID),
		HotspotID:  itemID,
		IsNew:      isNew,
		Status:     finalStatus,
		Version:    finalVersion,
	})

	return nil
}

func cloneCounts(in projectanalysis.Counts) projectanalysis.Counts {
	out := in
	out.ByKind = maps.Clone(in.ByKind)
	out.BySeverity = maps.Clone(in.BySeverity)
	out.ByStatus = maps.Clone(in.ByStatus)
	return out
}

func cloneDuplication(in measure.DuplicationReport) measure.DuplicationReport {
	out := in
	out.Blocks = slices.Clone(in.Blocks)
	for i := range out.Blocks {
		out.Blocks[i].Occurrences = slices.Clone(in.Blocks[i].Occurrences)
	}
	return out
}

func (s *ProjectAnalysisStore) Get(_ context.Context, tenantID, projectID, analysisID shared.ID) (projectanalysis.Analysis, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, stored := range s.data {
		analysis := stored.analysis
		if analysis.ID == analysisID.String() && analysis.ProjectID == projectID.String() && (tenantID.IsZero() || analysis.TenantID == tenantID.String()) {
			return cloneProjectAnalysis(analysis), nil
		}
	}
	return projectanalysis.Analysis{}, shared.ErrNotFound
}

package memory

import (
	"context"
	"errors"
	"sort"
	"strings"

	cmp "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssessmentCycleReaders supplies the same read projections joined by PostgreSQL.
// Omit readers only for domain/repository fixtures which do not exercise reads.
type AssessmentCycleReaders struct {
	Engagements ports.EngagementRepository
	Snapshots   ports.AssessmentSnapshotRepository
	Comparisons ports.AssessmentComparisonRepository
	Runs        ports.ScanRunProvenanceStore
}

// Called while the Cycle repository mutex is held. Readers never call back into
// this repository, keeping a single lock ordering for the process-local adapter.
func (r *AssessmentCycleRepository) projectCycleRecord(ctx context.Context, record *ports.AssessmentCycleListRecord, query ports.AssessmentCycleListQuery) (bool, error) {
	cycle := record.Cycle
	record.MemberStatuses = make(map[shared.ID]engagement.Status, len(record.Members))
	if r.readers.Engagements != nil {
		head, err := r.readers.Engagements.GetByIDInTenant(ctx, cycle.TenantID, cycle.SelectedHeadAssessmentID)
		if err != nil {
			return false, err
		}
		if query.AssessmentStatus != "" && head.Status != query.AssessmentStatus {
			return false, nil
		}
		for _, member := range record.Members {
			assessment, err := r.readers.Engagements.GetByIDInTenant(ctx, cycle.TenantID, member.AssessmentID)
			if err != nil {
				return false, err
			}
			record.MemberStatuses[member.AssessmentID] = assessment.Status
		}
	} else if query.AssessmentStatus != "" {
		return false, shared.ErrValidation
	}
	record.ActiveManifestID = cycle.ActiveClosureManifestID
	manifest := r.closureManifests[cycle.TenantID][cycle.ID][cycle.ActiveClosureManifestID]
	if cycle.Status == assessmentcycle.StatusCompleted {
		if manifest != nil {
			record.RootSnapshotID, record.CurrentSnapshotID = manifest.InitialSnapshotID, manifest.FinalSnapshotID
		}
	} else if r.readers.Snapshots != nil {
		for _, ref := range []struct {
			assessmentID shared.ID
			dest         *shared.ID
		}{
			{cycle.RootAssessmentID, &record.RootSnapshotID}, {cycle.SelectedHeadAssessmentID, &record.CurrentSnapshotID},
		} {
			assessmentID, dest := ref.assessmentID, ref.dest
			snapshot, _, err := r.readers.Snapshots.GetDefault(ctx, cycle.TenantID, assessmentID)
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			if err != nil {
				return false, err
			}
			*dest = snapshot.ID
		}
	}
	if r.readers.Comparisons != nil {
		values, err := r.readers.Comparisons.ListMetadataByCycle(ctx, cycle.TenantID, cycle.ID)
		if err != nil {
			return false, err
		}
		var selected *cmp.Comparison
		for index := range values {
			value := &values[index]
			if value.Mode != cmp.ModeLifecycle || value.BaselineSnapshotID != record.RootSnapshotID || value.CurrentSnapshotID != record.CurrentSnapshotID {
				continue
			}
			if cycle.Status == assessmentcycle.StatusCompleted {
				if manifest == nil || value.ID != manifest.ComparisonID || value.Status != cmp.StatusComplete && value.Status != cmp.StatusSuperseded {
					continue
				}
			} else if value.Status != cmp.StatusComplete && value.Status != cmp.StatusNeedsReview {
				continue
			}
			if value.CompletedAt == nil {
				continue
			}
			if selected == nil || value.CompletedAt.After(*selected.CompletedAt) || value.CompletedAt.Equal(*selected.CompletedAt) && value.ID > selected.ID {
				selected = value
			}
		}
		if selected != nil {
			record.ComparisonID, record.ComparisonStatus, record.ComparisonSummary = selected.ID, selected.Status, selected.Summary
		}
	}
	if query.ProducerKind != "" || query.FindingKind != "" || query.ReviewState != "" || query.ChangePresence != "" || query.ChangeSeverity != "" {
		if r.readers.Comparisons == nil {
			return false, shared.ErrValidation
		}
		if record.ComparisonID.IsZero() {
			return false, nil
		}
		page, err := r.readers.Comparisons.ListItems(ctx, cycle.TenantID, record.ComparisonID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 1, ProducerKind: query.ProducerKind, FindingKind: query.FindingKind, ReviewState: query.ReviewState, Presence: string(query.ChangePresence), Severity: query.ChangeSeverity})
		if err != nil {
			return false, err
		}
		if len(page.Items) == 0 {
			return false, nil
		}
	}
	record.ScanStaleness = "missing"
	if r.readers.Runs != nil {
		runs, err := r.readers.Runs.ListScanRuns(ctx, cycle.TenantID, cycle.SelectedHeadAssessmentID)
		if err != nil {
			return false, err
		}
		for _, run := range runs {
			if run.Provenance != scanrun.ProvenanceNative || run.SealedAt == nil || run.TerminalStatus != scanrun.StatusSucceeded && run.TerminalStatus != scanrun.StatusPartial {
				continue
			}
			if record.SelectedHeadScanAt == nil || run.SealedAt.After(*record.SelectedHeadScanAt) {
				at := *run.SealedAt
				record.SelectedHeadScanAt = &at
			}
		}
	}
	if record.SelectedHeadScanAt != nil {
		record.ScanStaleness = "stale"
		if !record.SelectedHeadScanAt.Before(query.ScanStaleBefore) {
			record.ScanStaleness = "fresh"
		}
	}
	return query.ScanStaleness == "" || query.ScanStaleness == record.ScanStaleness, nil
}

func (r *AssessmentCycleRepository) ListMigrationPendingAssessments(ctx context.Context, query ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleMigrationPendingRecord, int, error) {
	if query.Limit < 1 || query.Limit > 100 {
		return nil, 0, shared.ErrValidation
	}
	if r.readers.Engagements == nil {
		return nil, 0, nil
	}
	tenantID := shared.TenantOrDefault(query.TenantID)
	assessments, err := r.readers.Engagements.List(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]ports.AssessmentCycleMigrationPendingRecord, 0)
	total := 0
	for _, assessment := range assessments {
		if assessment.Internal() || assessment.TenantID != tenantID || !r.assessmentToCycle[tenantID][assessment.ID].IsZero() {
			continue
		}
		total++
		if query.Status != "" || !query.SelectedHeadID.IsZero() || query.AssessmentType != "" || query.ProducerKind != "" || query.FindingKind != "" || query.ReviewState != "" || query.ChangePresence != "" || query.ChangeSeverity != "" || query.ScanStaleness != "" {
			continue
		}
		kind := assessmentcycle.BoundaryFor(assessment.BusinessAssetID, assessment.AssessmentProjectID)
		if query.AssessmentStatus != "" && assessment.Status != query.AssessmentStatus || query.BoundaryKind != "" && query.BoundaryKind != kind {
			continue
		}
		needle := strings.ToLower(query.Search)
		if needle != "" && !strings.Contains(strings.ToLower(assessment.Name), needle) && !strings.Contains(strings.ToLower(assessment.ID.String()), needle) {
			continue
		}
		items = append(items, ports.AssessmentCycleMigrationPendingRecord{AssessmentID: assessment.ID, Name: assessment.Name, Status: string(assessment.Status), BoundaryKind: kind, BusinessAssetID: assessment.BusinessAssetID, UpdatedAt: assessment.Audit.UpdatedAt})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].AssessmentID > items[j].AssessmentID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items[:min(len(items), query.Limit)], total, nil
}

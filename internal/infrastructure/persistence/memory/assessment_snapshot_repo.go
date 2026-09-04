package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentSnapshotRepository struct {
	mu       sync.RWMutex
	byID     map[shared.ID]map[shared.ID]*assessmentsnapshot.Snapshot
	requests map[shared.ID]map[shared.ID]map[string]shared.ID
	defaults map[shared.ID]map[shared.ID]ports.AssessmentSnapshotDefault
	counters map[shared.ID]map[shared.ID]int
}

func NewAssessmentSnapshotRepository() *AssessmentSnapshotRepository {
	return &AssessmentSnapshotRepository{
		byID:     map[shared.ID]map[shared.ID]*assessmentsnapshot.Snapshot{},
		requests: map[shared.ID]map[shared.ID]map[string]shared.ID{},
		defaults: map[shared.ID]map[shared.ID]ports.AssessmentSnapshotDefault{},
		counters: map[shared.ID]map[shared.ID]int{},
	}
}

var _ ports.AssessmentSnapshotRepository = (*AssessmentSnapshotRepository)(nil)

func (repository *AssessmentSnapshotRepository) CreateFinalizedCAS(_ context.Context, snapshot *assessmentsnapshot.Snapshot, expectedDefaultVersion int64) (*assessmentsnapshot.Snapshot, bool, error) {
	if snapshot == nil {
		return nil, false, fmt.Errorf("%w: assessment snapshot is required", shared.ErrValidation)
	}
	if err := snapshot.Validate(); err != nil {
		return nil, false, err
	}
	tenantID := shared.TenantOrDefault(snapshot.TenantID)
	repository.mu.Lock()
	defer repository.mu.Unlock()

	if tenantRequests := repository.requests[tenantID]; tenantRequests != nil {
		if assessmentRequests := tenantRequests[snapshot.AssessmentID]; assessmentRequests != nil {
			if existingID, ok := assessmentRequests[snapshot.RequestKey]; ok {
				existing := repository.byID[tenantID][existingID]
				if existing.RequestHash != snapshot.RequestHash {
					return nil, false, fmt.Errorf("%w: snapshot request key was reused with different content", shared.ErrConflict)
				}
				return cloneAssessmentSnapshot(existing), false, nil
			}
		}
	}

	current, hasDefault := repository.defaults[tenantID][snapshot.AssessmentID]
	if (!hasDefault && expectedDefaultVersion != 0) || (hasDefault && current.Version != expectedDefaultVersion) {
		return nil, false, fmt.Errorf("%w: assessment snapshot default version mismatch", shared.ErrConflict)
	}
	if repository.byID[tenantID] != nil {
		if _, exists := repository.byID[tenantID][snapshot.ID]; exists {
			return nil, false, fmt.Errorf("%w: assessment snapshot %q already exists", shared.ErrConflict, snapshot.ID)
		}
	}

	if repository.counters[tenantID] == nil {
		repository.counters[tenantID] = map[shared.ID]int{}
	}
	next := repository.counters[tenantID][snapshot.AssessmentID] + 1
	repository.counters[tenantID][snapshot.AssessmentID] = next
	stored := cloneAssessmentSnapshot(snapshot)
	stored.SnapshotNumber = next

	if repository.byID[tenantID] == nil {
		repository.byID[tenantID] = map[shared.ID]*assessmentsnapshot.Snapshot{}
	}
	if hasDefault {
		previous := repository.byID[tenantID][current.SnapshotID]
		if previous == nil {
			return nil, false, fmt.Errorf("%w: current default snapshot is missing", shared.ErrConflict)
		}
		if err := previous.Supersede(stored.FinalizedBy, *stored.FinalizedAt); err != nil {
			return nil, false, err
		}
	}
	repository.byID[tenantID][stored.ID] = stored
	if repository.requests[tenantID] == nil {
		repository.requests[tenantID] = map[shared.ID]map[string]shared.ID{}
	}
	if repository.requests[tenantID][stored.AssessmentID] == nil {
		repository.requests[tenantID][stored.AssessmentID] = map[string]shared.ID{}
	}
	repository.requests[tenantID][stored.AssessmentID][stored.RequestKey] = stored.ID
	if repository.defaults[tenantID] == nil {
		repository.defaults[tenantID] = map[shared.ID]ports.AssessmentSnapshotDefault{}
	}
	pointer := ports.AssessmentSnapshotDefault{
		TenantID: tenantID, AssessmentID: stored.AssessmentID, SnapshotID: stored.ID,
		Version: current.Version + 1, UpdatedAt: *stored.FinalizedAt, UpdatedBy: stored.FinalizedBy,
	}
	stored.DefaultVersion = pointer.Version
	repository.defaults[tenantID][stored.AssessmentID] = pointer
	return cloneAssessmentSnapshot(stored), true, nil
}

func (repository *AssessmentSnapshotRepository) CreateLegacyProjection(_ context.Context, snapshot *assessmentsnapshot.Snapshot) (*assessmentsnapshot.Snapshot, bool, error) {
	if snapshot == nil || snapshot.Provenance != assessmentsnapshot.ProvenanceLegacy {
		return nil, false, fmt.Errorf("%w: legacy assessment snapshot is required", shared.ErrValidation)
	}
	if err := snapshot.Validate(); err != nil {
		return nil, false, err
	}
	tenantID := shared.TenantOrDefault(snapshot.TenantID)
	repository.mu.Lock()
	defer repository.mu.Unlock()

	if tenantRequests := repository.requests[tenantID]; tenantRequests != nil {
		if assessmentRequests := tenantRequests[snapshot.AssessmentID]; assessmentRequests != nil {
			if existingID, ok := assessmentRequests[snapshot.RequestKey]; ok {
				existing := repository.byID[tenantID][existingID]
				if existing.RequestHash != snapshot.RequestHash {
					return nil, false, fmt.Errorf("%w: snapshot request key was reused with different content", shared.ErrConflict)
				}
				return cloneAssessmentSnapshot(existing), false, nil
			}
		}
	}
	if repository.byID[tenantID] != nil {
		if _, exists := repository.byID[tenantID][snapshot.ID]; exists {
			return nil, false, fmt.Errorf("%w: assessment snapshot %q already exists", shared.ErrConflict, snapshot.ID)
		}
	}
	if repository.counters[tenantID] == nil {
		repository.counters[tenantID] = map[shared.ID]int{}
	}
	next := repository.counters[tenantID][snapshot.AssessmentID] + 1
	repository.counters[tenantID][snapshot.AssessmentID] = next
	stored := cloneAssessmentSnapshot(snapshot)
	stored.SnapshotNumber = next
	if repository.byID[tenantID] == nil {
		repository.byID[tenantID] = map[shared.ID]*assessmentsnapshot.Snapshot{}
	}
	repository.byID[tenantID][stored.ID] = stored
	if repository.requests[tenantID] == nil {
		repository.requests[tenantID] = map[shared.ID]map[string]shared.ID{}
	}
	if repository.requests[tenantID][stored.AssessmentID] == nil {
		repository.requests[tenantID][stored.AssessmentID] = map[string]shared.ID{}
	}
	repository.requests[tenantID][stored.AssessmentID][stored.RequestKey] = stored.ID
	return cloneAssessmentSnapshot(stored), true, nil
}

func (repository *AssessmentSnapshotRepository) Get(_ context.Context, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	snapshot := repository.byID[tenantID][snapshotID]
	if snapshot == nil {
		return nil, fmt.Errorf("assessment snapshot %s: %w", snapshotID, shared.ErrNotFound)
	}
	return cloneAssessmentSnapshot(snapshot), nil
}

func (repository *AssessmentSnapshotRepository) GetByRequestKey(_ context.Context, tenantID, assessmentID shared.ID, requestKey string) (*assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	id, ok := repository.requests[tenantID][assessmentID][strings.TrimSpace(requestKey)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return cloneAssessmentSnapshot(repository.byID[tenantID][id]), nil
}

func (repository *AssessmentSnapshotRepository) GetDefault(_ context.Context, tenantID, assessmentID shared.ID) (*assessmentsnapshot.Snapshot, ports.AssessmentSnapshotDefault, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	pointer, ok := repository.defaults[tenantID][assessmentID]
	if !ok {
		return nil, ports.AssessmentSnapshotDefault{}, shared.ErrNotFound
	}
	snapshot := repository.byID[tenantID][pointer.SnapshotID]
	if snapshot == nil {
		return nil, ports.AssessmentSnapshotDefault{}, fmt.Errorf("default assessment snapshot: %w", shared.ErrNotFound)
	}
	return cloneAssessmentSnapshot(snapshot), pointer, nil
}

func (repository *AssessmentSnapshotRepository) ListByAssessment(_ context.Context, tenantID, assessmentID shared.ID) ([]assessmentsnapshot.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	var out []assessmentsnapshot.Snapshot
	for _, snapshot := range repository.byID[tenantID] {
		if snapshot.AssessmentID == assessmentID {
			out = append(out, *cloneAssessmentSnapshot(snapshot))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SnapshotNumber < out[j].SnapshotNumber })
	return out, nil
}

func cloneAssessmentSnapshot(snapshot *assessmentsnapshot.Snapshot) *assessmentsnapshot.Snapshot {
	if snapshot == nil {
		return nil
	}
	copySnapshot := *snapshot
	copySnapshot.RunReferences = append([]assessmentsnapshot.RunReference(nil), snapshot.RunReferences...)
	for index := range copySnapshot.RunReferences {
		copySnapshot.RunReferences[index].LaneReferences = append([]assessmentsnapshot.LaneReference(nil), snapshot.RunReferences[index].LaneReferences...)
	}
	copySnapshot.Dimensions = append([]assessmentsnapshot.Dimension(nil), snapshot.Dimensions...)
	for index := range copySnapshot.Dimensions {
		copySnapshot.Dimensions[index].IncludedScope = append([]string(nil), snapshot.Dimensions[index].IncludedScope...)
		copySnapshot.Dimensions[index].ExcludedScope = append([]string(nil), snapshot.Dimensions[index].ExcludedScope...)
		copySnapshot.Dimensions[index].Versions = append([]assessmentsnapshot.Version(nil), snapshot.Dimensions[index].Versions...)
	}
	if snapshot.FinalizedAt != nil {
		value := *snapshot.FinalizedAt
		copySnapshot.FinalizedAt = &value
	}
	if snapshot.SupersededAt != nil {
		value := *snapshot.SupersededAt
		copySnapshot.SupersededAt = &value
	}
	return &copySnapshot
}

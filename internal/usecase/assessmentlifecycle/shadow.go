package assessmentlifecycle

import (
	"context"
	"errors"
	"fmt"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ShadowCoordinator turns a sealed native scan run into a Snapshot and queues
// the directed lifecycle comparison, without exposing lifecycle reads. Tenant
// rollout is checked on every callback so wiring it does not broaden rollout.
type ShadowCoordinator struct {
	cycles      ports.AssessmentCycleRepository
	snapshots   ports.AssessmentSnapshotRepository
	finalizer   *snapshotuc.Service
	comparisons *comparisonuc.Service
	enabled     func(string) bool
}

func NewShadowCoordinator(cycles ports.AssessmentCycleRepository, snapshots ports.AssessmentSnapshotRepository, finalizer *snapshotuc.Service, comparisons *comparisonuc.Service, enabled func(string) bool) (*ShadowCoordinator, error) {
	if cycles == nil || snapshots == nil || finalizer == nil || comparisons == nil || enabled == nil {
		return nil, fmt.Errorf("%w: assessment lifecycle shadow dependencies are required", shared.ErrValidation)
	}
	return &ShadowCoordinator{cycles: cycles, snapshots: snapshots, finalizer: finalizer, comparisons: comparisons, enabled: enabled}, nil
}

func (coordinator *ShadowCoordinator) AssessmentScanRunSealed(ctx context.Context, tenantID, assessmentID, runID shared.ID) error {
	tenantID = shared.TenantOrDefault(tenantID)
	if !coordinator.enabled(tenantID.String()) {
		return nil
	}
	cycle, err := coordinator.cycles.GetCycleByAssessment(ctx, tenantID, assessmentID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	baseline, pointer, err := coordinator.snapshots.GetDefault(ctx, tenantID, assessmentID)
	if errors.Is(err, shared.ErrNotFound) {
		baseline, pointer, err = nil, ports.AssessmentSnapshotDefault{}, nil
	}
	if err != nil {
		return err
	}
	var current *assessmentsnapshot.Snapshot
	created := false
	for attempt := 0; attempt < 3; attempt++ {
		current, created, err = coordinator.finalizer.Finalize(ctx, snapshotuc.FinalizeInput{
			TenantID: tenantID, CycleID: cycle.ID, AssessmentID: assessmentID,
			SelectedRunIDs: []string{runID.String()}, RequestKey: "shadow:scan:" + runID.String(),
			ExpectedDefaultVersion: pointer.Version, Actor: "system:assessment-lifecycle-shadow",
		})
		if err == nil || !errors.Is(err, shared.ErrConflict) {
			break
		}
		baseline, pointer, err = coordinator.snapshots.GetDefault(ctx, tenantID, assessmentID)
		if err != nil {
			return err
		}
	}
	if err != nil || current == nil {
		return err
	}
	if !created && baseline != nil && baseline.ID == current.ID {
		baseline = nil
		items, listErr := coordinator.snapshots.ListByAssessment(ctx, tenantID, assessmentID)
		if listErr != nil {
			return listErr
		}
		for index := range items {
			candidate := &items[index]
			if candidate.SnapshotNumber < current.SnapshotNumber && (baseline == nil || candidate.SnapshotNumber > baseline.SnapshotNumber) {
				baseline = candidate
			}
		}
	}
	if baseline == nil {
		member, memberErr := coordinator.cycles.GetMember(ctx, tenantID, cycle.ID, assessmentID)
		if memberErr != nil {
			return memberErr
		}
		if member.PredecessorAssessmentID.IsZero() {
			return nil
		}
		baseline, _, err = coordinator.snapshots.GetDefault(ctx, tenantID, member.PredecessorAssessmentID)
		if errors.Is(err, shared.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	_, _, _, err = coordinator.comparisons.Queue(ctx, comparisonuc.QueueInput{
		TenantID: tenantID, BaselineSnapshotID: baseline.ID, CurrentSnapshotID: current.ID,
		Mode: cmpdom.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: comparisonuc.RiskModelVersionV1,
		Actor: "system:assessment-lifecycle-shadow",
	})
	return err
}

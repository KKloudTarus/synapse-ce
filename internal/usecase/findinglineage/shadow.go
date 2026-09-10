package findinglineage

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ShadowProjector freezes manual/offensive observations at Snapshot finalization.
// Findings created later belong to the next Snapshot, never an existing default.
type ShadowProjector struct {
	nativeEvidence ports.ScanRunEvidenceStore
	nativeRuns     ports.AssessmentSnapshotRunReader
	lineage        *Service
	cycles         ports.AssessmentCycleRepository
	snapshots      ports.AssessmentSnapshotRepository
	findings       ports.FindingRepository
	enabled        func(string) bool
}

func NewShadowProjector(lineage *Service, cycles ports.AssessmentCycleRepository, snapshots ports.AssessmentSnapshotRepository, findings ports.FindingRepository, enabled func(string) bool) (*ShadowProjector, error) {
	if lineage == nil || cycles == nil || snapshots == nil || findings == nil || enabled == nil {
		return nil, fmt.Errorf("%w: finding lineage shadow dependencies are required", shared.ErrValidation)
	}
	return &ShadowProjector{lineage: lineage, cycles: cycles, snapshots: snapshots, findings: findings, enabled: enabled}, nil
}

// ProjectCreatedFinding intentionally defers projection until the next Snapshot.
// Retaining this hook keeps the Finding workflow independent during cutover.
func (projector *ShadowProjector) ProjectCreatedFinding(context.Context, shared.ID, finding.Finding, string) error {
	return nil
}

func (projector *ShadowProjector) AssessmentSnapshotFinalized(ctx context.Context, snapshot *assessmentsnapshot.Snapshot, actor string) error {
	if snapshot == nil || !projector.enabled(snapshot.TenantID.String()) {
		return nil
	}
	if err := projector.projectNativeEvidence(ctx, snapshot, actor); err != nil {
		return err
	}
	items, err := projector.findings.ListByEngagement(ctx, snapshot.AssessmentID)
	if err != nil {
		return err
	}
	for _, item := range items {
		// Scanner Findings are mutable projections and are not authoritative for a
		// finalized Snapshot. They are projected only by the backfill/native producer
		// path that can prove the selected immutable run and lane. Finalization merely
		// closes the gap for native human/offensive findings created before a Snapshot.
		if !manualOrOffensive(item.Kind) || item.EngagementID != snapshot.AssessmentID {
			continue
		}
		if err := projector.project(ctx, snapshot.TenantID, snapshot.CycleID, snapshot, item, actor); err != nil {
			// One malformed legacy manual Finding must not roll back an otherwise valid
			// finalized Snapshot. Infrastructure/audit failures remain fatal and preserve
			// the shared transaction's all-or-nothing guarantee.
			if nonRetryableProjectionError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func (projector *ShadowProjector) project(ctx context.Context, tenantID, cycleID shared.ID, snapshot *assessmentsnapshot.Snapshot, item finding.Finding, actor string) error {
	if snapshot == nil || snapshot.TenantID != tenantID || snapshot.CycleID != cycleID || snapshot.AssessmentID != item.EngagementID {
		return fmt.Errorf("%w: shadow Finding/Snapshot ownership mismatch", shared.ErrValidation)
	}
	source := ports.FindingLineageBackfillSourceRow{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshot.ID, SnapshotContentHash: snapshot.ContentHash,
		AssessmentID: item.EngagementID, OwnershipValid: true, FindingID: item.ID, Kind: item.Kind,
		RuleKey: item.RuleKey, DedupKey: item.DedupKey, AdvisoryID: item.AdvisoryID,
		ComponentFingerprint: item.ComponentFingerprint, Severity: item.Severity, RiskScore: item.RiskScore,
		Reachability: item.Reachability, SourceLocation: item.SourceLocation, ObservedAt: item.Audit.CreatedAt,
	}
	producer, findingKind := legacyProducer(item.Kind)
	target := selectBackfillTarget(*snapshot, producer, findingKind, item.EngagementID)
	observation, err := backfillObservation(source, target)
	if err != nil {
		return err
	}
	class := ManualFindingNative
	if item.Kind != finding.KindManual {
		class = ManualFindingOffensive
	}
	_, err = projector.lineage.CorrelateNativeManual(ctx, NativeManualInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshot.ID, AssessmentID: item.EngagementID,
		IdentityID: legacyManualIdentityID(item.ID), FindingClass: class, Actor: actor, Observation: observation,
	})
	return err
}

func nonRetryableProjectionError(err error) bool {
	return errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrConflict) ||
		errors.Is(err, ErrSecretMaterialRejected)
}

func manualOrOffensive(kind finding.Kind) bool {
	return kind == finding.KindManual || kind == finding.KindRecon || kind == finding.KindExploitation
}

var _ interface {
	AssessmentSnapshotFinalized(context.Context, *assessmentsnapshot.Snapshot, string) error
} = (*ShadowProjector)(nil)

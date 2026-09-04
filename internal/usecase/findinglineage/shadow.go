package findinglineage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ShadowProjector writes native manual/offensive observations for allowlisted
// tenants. It is used both at Finding creation and at Snapshot finalization:
// the former gives immediate projection when a default Snapshot exists, while
// the latter closes the gap for Findings created before their first Snapshot.
type ShadowProjector struct {
	lineage   *Service
	cycles    ports.AssessmentCycleRepository
	snapshots ports.AssessmentSnapshotRepository
	findings  ports.FindingRepository
	enabled   func(string) bool
	sca       SCAMatcherV1
	sast      SASTMatcherV1
	quality   QualityMatcherV1
	secret    SecretMatcherV1
	iac       IaCMatcherV1
}

func NewShadowProjector(lineage *Service, cycles ports.AssessmentCycleRepository, snapshots ports.AssessmentSnapshotRepository, findings ports.FindingRepository, enabled func(string) bool) (*ShadowProjector, error) {
	if lineage == nil || cycles == nil || snapshots == nil || findings == nil || enabled == nil {
		return nil, fmt.Errorf("%w: finding lineage shadow dependencies are required", shared.ErrValidation)
	}
	sca, err := NewSCAMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	sast, err := NewSASTMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	quality, err := NewQualityMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	secret, err := NewSecretMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	iac, err := NewIaCMatcherV1(nil)
	if err != nil {
		return nil, err
	}
	return &ShadowProjector{lineage: lineage, cycles: cycles, snapshots: snapshots, findings: findings, enabled: enabled, sca: sca, sast: sast, quality: quality, secret: secret, iac: iac}, nil
}

func (projector *ShadowProjector) ProjectCreatedFinding(ctx context.Context, tenantID shared.ID, item finding.Finding, actor string) error {
	tenantID = shared.TenantOrDefault(tenantID)
	if !projector.enabled(tenantID.String()) || !manualOrOffensive(item.Kind) {
		return nil
	}
	cycle, err := projector.cycles.GetCycleByAssessment(ctx, tenantID, item.EngagementID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	snapshot, _, err := projector.snapshots.GetDefault(ctx, tenantID, item.EngagementID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return projector.project(ctx, tenantID, cycle.ID, snapshot, item, actor)
}

func (projector *ShadowProjector) AssessmentSnapshotFinalized(ctx context.Context, snapshot *assessmentsnapshot.Snapshot, actor string) error {
	if snapshot == nil || !projector.enabled(snapshot.TenantID.String()) {
		return nil
	}
	items, err := projector.findings.ListByEngagement(ctx, snapshot.AssessmentID)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := projector.project(ctx, snapshot.TenantID, snapshot.CycleID, snapshot, item, actor); err != nil {
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
	base := CorrelateInput{
		TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshot.ID, InputTrusted: true,
		OwnershipValidated: true, RedactionComplete: true, Observation: observation, Actor: strings.TrimSpace(actor),
	}
	if manualOrOffensive(item.Kind) {
		class := ManualFindingNative
		if item.Kind != finding.KindManual {
			class = ManualFindingOffensive
		}
		_, err = projector.lineage.CorrelateNativeManual(ctx, NativeManualInput{
			TenantID: tenantID, CycleID: cycleID, SnapshotID: snapshot.ID, AssessmentID: item.EngagementID,
			IdentityID: legacyManualIdentityID(item.ID), FindingClass: class, Actor: strings.TrimSpace(actor), Observation: observation,
		})
		return err
	}
	var correlate CorrelateInput
	switch item.Kind {
	case "", finding.KindSCA:
		plan, buildErr := projector.sca.Build(SCAFingerprintInputV1{TargetIdentityCanonical: target.canonical, AdvisoryID: item.AdvisoryID, DependencyInstanceID: item.ComponentFingerprint, LegacyDedupKey: item.DedupKey})
		if buildErr != nil {
			return buildErr
		}
		correlate = plan.Apply(base)
	case finding.KindSAST:
		plan, buildErr := projector.sast.Build(SASTFingerprintInputV1{TargetIdentityCanonical: target.canonical, RepoPath: sourcePath(source), RuleKey: item.RuleKey, LegacyDedupKey: item.DedupKey, LegacySourceValidated: true, LegacyOwnershipValid: true})
		if buildErr != nil {
			return buildErr
		}
		correlate = plan.Apply(base)
	case finding.KindQuality, finding.KindReliability:
		plan, buildErr := projector.quality.Build(QualityFingerprintInputV1{TargetIdentityCanonical: target.canonical, FindingClass: string(item.Kind), RepoPath: sourcePath(source), RuleKey: item.RuleKey, LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		if buildErr != nil {
			return buildErr
		}
		correlate = plan.Apply(base)
	case finding.KindSecret:
		if unsafeLegacySecretKey(item.DedupKey) {
			return ErrSecretMaterialRejected
		}
		redacted, redactErr := RedactSecretProducerInputV1(SecretProducerInputV1{TargetIdentityCanonical: target.canonical, DetectorKey: item.RuleKey, RepoPath: sourcePath(source), LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		if redactErr != nil {
			return redactErr
		}
		plan, buildErr := projector.secret.Build(redacted)
		if buildErr != nil {
			return buildErr
		}
		correlate = plan.Apply(base)
	case finding.KindMisconfig:
		plan, buildErr := projector.iac.Build(IaCFingerprintInputV1{TargetIdentityCanonical: target.canonical, RuleKey: item.RuleKey, RepoPath: sourcePath(source), LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		if buildErr != nil {
			return buildErr
		}
		correlate = plan.Apply(base)
	default:
		correlate = base
		correlate.ProducerKind, correlate.FindingKind, correlate.FingerprintSchemaVersion = producer, findingKind, 1
		correlate.TrustedProducerID = true
		correlate.FingerprintInput = lineagedom.FingerprintCanonicalInputV1{
			CanonicalizationVersion: lineagedom.CanonicalizationVersionV1, ProducerKind: producer,
			TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: target.canonical,
			IdentityFields: map[string]lineagedom.CanonicalValue{"source_finding_id": lineagedom.Text(item.ID.String())},
		}
	}
	if target.reasonCode != "" && !correlate.ReviewReason.Valid() {
		correlate.ProvisionalIdentity, correlate.ReviewReason, correlate.ReviewDetailCode = true, lineagedom.ReasonInsufficientAnchor, target.reasonCode
	}
	_, err = projector.lineage.Correlate(ctx, correlate)
	return err
}

func manualOrOffensive(kind finding.Kind) bool {
	return kind == finding.KindManual || kind == finding.KindRecon || kind == finding.KindExploitation
}

var _ interface {
	AssessmentSnapshotFinalized(context.Context, *assessmentsnapshot.Snapshot, string) error
} = (*ShadowProjector)(nil)

package findinglineage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const NativeEvidenceVersion = 1
const MaxNativeObservations = 100000

// NativeEvidence contains only redacted matcher inputs and observed attributes.
// No workflow status, raw finding description, source excerpt, or secret enters
// this retained contract. Ownership is assigned from the selected sealed run.
type NativeEvidence struct {
	Version int
	Records []CorrelateInput
}

func NativeNamespace(kind finding.Kind) (string, string) { return legacyProducer(kind) }

func BuildNativeEvidenceRecord(item finding.Finding, target string, current *vulnerability.Vulnerability) (CorrelateInput, error) {
	source := ports.FindingLineageBackfillSourceRow{
		FindingID: item.ID, Kind: item.Kind, RuleKey: item.RuleKey, DedupKey: item.DedupKey,
		Severity: item.Severity, RiskScore: item.RiskScore, Reachability: item.Reachability,
		SourceLocation: item.SourceLocation, ObservedAt: item.Audit.CreatedAt,
	}
	observation, err := backfillObservation(source, backfillTarget{canonical: target})
	if err != nil {
		return CorrelateInput{}, err
	}
	base := CorrelateInput{InputTrusted: true, OwnershipValidated: true, RedactionComplete: true, Observation: observation}
	switch item.Kind {
	case "", finding.KindSCA:
		matcher, _ := NewSCAMatcherV1(nil)
		input := SCAFingerprintInputV1{TargetIdentityCanonical: target, AdvisoryID: item.AdvisoryID, LegacyDedupKey: item.DedupKey}
		if current != nil {
			input = SCAFingerprintInputFromVulnerabilityV1(target, *current, nil, item.DedupKey, "")
			base.Observation.ComponentVersion = current.Version
		}
		plan, err := matcher.Build(input)
		return plan.Apply(base), err
	case finding.KindSAST:
		matcher, _ := NewSASTMatcherV1(nil)
		plan, err := matcher.Build(SASTFingerprintInputV1{TargetIdentityCanonical: target, RepoPath: sourcePath(source), RuleKey: item.RuleKey, LegacyDedupKey: item.DedupKey, LegacySourceValidated: true, LegacyOwnershipValid: true})
		return plan.Apply(base), err
	case finding.KindQuality, finding.KindReliability:
		matcher, _ := NewQualityMatcherV1(nil)
		plan, err := matcher.Build(QualityFingerprintInputV1{TargetIdentityCanonical: target, FindingClass: string(item.Kind), RepoPath: sourcePath(source), RuleKey: item.RuleKey, LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		return plan.Apply(base), err
	case finding.KindSecret:
		redacted, err := RedactSecretProducerInputV1(SecretProducerInputV1{TargetIdentityCanonical: target, DetectorKey: item.RuleKey, RepoPath: sourcePath(source), LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		if err != nil {
			return CorrelateInput{}, err
		}
		matcher, _ := NewSecretMatcherV1(nil)
		plan, err := matcher.Build(redacted)
		return plan.Apply(base), err
	case finding.KindMisconfig:
		matcher, _ := NewIaCMatcherV1(nil)
		plan, err := matcher.Build(IaCFingerprintInputV1{TargetIdentityCanonical: target, RepoPath: sourcePath(source), RuleKey: item.RuleKey, LegacyDedupKey: item.DedupKey, LegacySourceValidated: true})
		return plan.Apply(base), err
	default:
		return CorrelateInput{}, fmt.Errorf("%w: unsupported native finding kind", shared.ErrValidation)
	}
}

func (projector *ShadowProjector) SetNativeEvidence(store ports.ScanRunEvidenceStore, runs ports.AssessmentSnapshotRunReader) {
	projector.nativeEvidence, projector.nativeRuns = store, runs
}

func (projector *ShadowProjector) projectNativeEvidence(ctx context.Context, snapshot *assessmentsnapshot.Snapshot, actor string) error {
	if projector.nativeEvidence == nil || snapshot.Provenance != assessmentsnapshot.ProvenanceNative {
		return nil
	}
	runs := make(map[string][]assessmentsnapshot.Dimension)
	for _, dimension := range snapshot.Dimensions {
		runs[dimension.RunID] = append(runs[dimension.RunID], dimension)
	}
	runIDs := make([]string, 0, len(runs))
	for runID := range runs {
		runIDs = append(runIDs, runID)
	}
	sort.Strings(runIDs)
	total := 0
	for _, runID := range runIDs {
		dimensions := runs[runID]
		evidence, err := projector.nativeEvidence.GetScanRunEvidence(ctx, snapshot.TenantID, runID)
		if err != nil {
			return fmt.Errorf("load immutable selected-run evidence: %w", err)
		}
		if err := evidence.Validate(); err != nil {
			return err
		}
		if projector.nativeRuns == nil {
			return fmt.Errorf("%w: native run verification is unavailable", shared.ErrValidation)
		}
		run, err := projector.nativeRuns.GetScanRun(ctx, snapshot.TenantID, runID)
		if err != nil {
			return err
		}
		if !run.IsSealed() || run.EngagementID != snapshot.AssessmentID {
			return fmt.Errorf("%w: selected run evidence ownership mismatch", shared.ErrValidation)
		}
		for _, dimension := range dimensions {
			bound := false
			for _, lane := range run.Lanes {
				if lane.LaneKey == dimension.LaneKey && lane.ManifestHash == dimension.LaneManifestHash && lane.ResultSHA256 == evidence.ContentHash {
					bound = true
					break
				}
			}
			if !bound {
				return fmt.Errorf("%w: evidence is not bound to the selected sealed lane", shared.ErrValidation)
			}
		}
		var input NativeEvidence
		if err := json.Unmarshal(evidence.Payload, &input); err != nil {
			return fmt.Errorf("%w: invalid native evidence schema", shared.ErrValidation)
		}
		total += len(input.Records)
		if input.Version != NativeEvidenceVersion || total > MaxNativeObservations {
			return fmt.Errorf("%w: unsupported native evidence version or cardinality", shared.ErrValidation)
		}
		for _, record := range input.Records {
			var selected *assessmentsnapshot.Dimension
			for index := range dimensions {
				dimension := &dimensions[index]
				if dimension.Producer == record.ProducerKind && dimension.FindingKind == record.FindingKind && dimension.Target.Canonical == record.FingerprintInput.TargetIdentityCanonical {
					selected = dimension
					break
				}
			}
			if selected == nil {
				continue
			} // A user may select only a subset of run lanes.
			record.TenantID, record.CycleID, record.SnapshotID = snapshot.TenantID, snapshot.CycleID, snapshot.ID
			record.Actor = actor
			record.IdentityID, record.Observation.ID = "", ""
			record.Observation.EvidenceDigest = evidence.ContentHash
			record.Observation.ScannerProvenance = domain.ScannerProvenance{ScanRunID: runID, LaneKey: selected.LaneKey, ToolName: record.ProducerKind}
			if _, err := projector.lineage.Correlate(ctx, record); err != nil {
				return err
			}
		}
	}
	return nil
}

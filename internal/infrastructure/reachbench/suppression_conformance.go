package reachbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

const suppressionConformanceSchemaVersion = "synapse-reachability-suppression-projection-conformance-v1"

var errSuppressionConformance = errors.New("candidate suppression projection conformance failed")

type suppressionConformanceSpec struct {
	caseID   string
	cohortID string
	modeID   string
	tier     judgment.ReachabilityTier
	proposer string
	verifier string
}

type suppressionCoordinatorFactory func(staticAnalyzer, captureLifecycle) (*reachproof.Coordinator, error)

// SuppressionProjectionConformance is candidate-only evidence that the actual normalized analyzer output and
// subjects project through an isolated normal production coordinator to the public present_unreached label.
// It is deliberately separate from MeasuredObservation.Suppression and does not claim any downstream effect.
type SuppressionProjectionConformance struct {
	SchemaVersion string                                    `json:"schema_version"`
	Repetition    int                                       `json:"repetition"`
	Passed        bool                                      `json:"passed"`
	Controls      []SuppressionProjectionConformanceControl `json:"controls"`
}

// SuppressionProjectionConformanceControl contains only bounded, sanitized projection evidence. Analyzer output
// and subject payloads are digest-bound; the persisted judgment is reduced to the fields needed to replay the
// public reachability projection.
type SuppressionProjectionConformanceControl struct {
	CaseID              string                         `json:"case_id"`
	BindingID           string                         `json:"binding_id"`
	CohortID            string                         `json:"cohort_id"`
	ModeID              string                         `json:"mode_id"`
	SubjectID           string                         `json:"subject_id"`
	AnalyzerDigest      string                         `json:"analyzer_digest,omitempty"`
	SubjectsDigest      string                         `json:"subjects_digest,omitempty"`
	ExpectedTier        judgment.ReachabilityTier      `json:"expected_tier"`
	ExpectedProposer    string                         `json:"expected_proposer"`
	ExpectedVerifier    string                         `json:"expected_verifier"`
	CoordinatorRecorded bool                           `json:"coordinator_recorded"`
	JudgmentCount       int                            `json:"judgment_count"`
	Judgment            *SuppressionProjectionJudgment `json:"judgment,omitempty"`
	Evidence            *exportuc.ReachabilityEvidence `json:"evidence,omitempty"`
	Passed              bool                           `json:"passed"`
	FailureCode         string                         `json:"failure_code,omitempty"`
}

// SuppressionProjectionJudgment is the sanitized persisted-judgment projection needed by
// export.DeriveReachabilityEvidence. It carries no raw evidence, runtime path, or arbitrary rationale.
type SuppressionProjectionJudgment struct {
	FindingID     string                     `json:"finding_id"`
	Claim         judgment.ReachabilityClaim `json:"claim"`
	State         judgment.State             `json:"state"`
	EvidenceScore int                        `json:"evidence_score"`
	ProposedBy    string                     `json:"proposed_by"`
	VerifiedBy    string                     `json:"verified_by"`
}

// SuppressionConformanceRepeat binds the two candidate-only conformance reports into semantic repeat evidence.
type SuppressionConformanceRepeat struct {
	SemanticallyEqual bool   `json:"semantically_equal"`
	ReportDigest      string `json:"report_digest"`
	Passed            bool   `json:"passed"`
}

func suppressionConformanceSpecs() ([]suppressionConformanceSpec, error) {
	registry, err := judgment.NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		return nil, fmt.Errorf("load suppression authority registry: %w", err)
	}
	base := []suppressionConformanceSpec{
		{caseID: "dotnet-build-aware-import-control-unreachable", cohortID: "dotnet", modeID: "build_aware_import", tier: judgment.Tier1},
		{caseID: "go-source-tier2-control-unreachable", cohortID: "go", modeID: "source_tier2", tier: judgment.Tier2},
		{caseID: "python-import-control-unreachable", cohortID: "python", modeID: "import", tier: judgment.Tier1},
		{caseID: "python-semantic-control-unreachable", cohortID: "python", modeID: "semantic", tier: judgment.Tier2},
	}
	eligible := make(map[string]judgment.ReachabilityAuthorityPolicy)
	for _, policy := range registry.Policies() {
		if policy.Disposition() == judgment.SuppressionEligible {
			eligible[policy.Key().String()] = policy
		}
	}
	if len(eligible) != len(base) {
		return nil, fmt.Errorf("suppression conformance requires exactly %d eligible authority policies, got %d", len(base), len(eligible))
	}
	for index := range base {
		key := base[index].cohortID + "/" + base[index].modeID
		policy, ok := eligible[key]
		if !ok {
			return nil, fmt.Errorf("suppression conformance lacks eligible authority policy %q", key)
		}
		approval, ok := policy.Approval()
		if !ok {
			return nil, fmt.Errorf("suppression conformance policy %q lacks approval", key)
		}
		base[index].proposer = approval.Proposer()
		base[index].verifier = approval.Verifier()
	}
	sort.Slice(base, func(left, right int) bool { return base[left].caseID < base[right].caseID })
	return base, nil
}

func suppressionConformancePlan(cells []ExecutionCell) (map[string]struct{}, error) {
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		return nil, err
	}
	byCase := make(map[string]suppressionConformanceSpec, len(specs))
	counts := make(map[string]int, len(specs))
	selected := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		byCase[spec.caseID] = spec
	}
	for _, cell := range cells {
		spec, ok := byCase[cell.CaseID]
		if !ok {
			continue
		}
		if cell.CohortID != spec.cohortID || cell.ModeID != spec.modeID {
			return nil, fmt.Errorf("suppression conformance control %q has unexpected cohort/mode %s/%s", cell.CaseID, cell.CohortID, cell.ModeID)
		}
		counts[cell.CaseID]++
		selected[opaqueCellKey(cell)] = struct{}{}
	}
	for _, spec := range specs {
		if counts[spec.caseID] != 1 {
			return nil, fmt.Errorf("suppression conformance requires exactly one enabled cell for %q, got %d", spec.caseID, counts[spec.caseID])
		}
	}
	return selected, nil
}

func suppressionConformanceSpecForCell(cell ExecutionCell) (suppressionConformanceSpec, error) {
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		return suppressionConformanceSpec{}, err
	}
	for _, spec := range specs {
		if spec.caseID != cell.CaseID {
			continue
		}
		if spec.cohortID != cell.CohortID || spec.modeID != cell.ModeID {
			return suppressionConformanceSpec{}, fmt.Errorf("suppression conformance control %q does not match %s/%s", cell.CaseID, cell.CohortID, cell.ModeID)
		}
		return spec, nil
	}
	return suppressionConformanceSpec{}, fmt.Errorf("cell %q is not a suppression conformance control", cell.CaseID)
}

func newGoSuppressionCoordinator(analyzer staticAnalyzer, lifecycle captureLifecycle) (*reachproof.Coordinator, error) {
	return reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
}

func newPythonImportSuppressionCoordinator(analyzer staticAnalyzer, lifecycle captureLifecycle) (*reachproof.Coordinator, error) {
	return reachproof.NewCoordinatorForTier(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1)
}

func newPythonSemanticSuppressionCoordinator(analyzer staticAnalyzer, lifecycle captureLifecycle) (*reachproof.Coordinator, error) {
	return reachproof.NewCoordinatorForLanguage(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier2, reachproof.LanguagePython)
}

func newDotNetSuppressionCoordinator(analyzer staticAnalyzer, lifecycle captureLifecycle) (*reachproof.Coordinator, error) {
	coordinator, err := reachproof.NewCoordinatorForLanguage(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1, reachproof.LanguageDotNet)
	if err != nil {
		return nil, err
	}
	return coordinator.WithSkipUnresolvedSubjects(), nil
}

type conformanceReplayAnalyzer struct {
	analysis *reachability.Analysis
	symbols  []string
}

func (analyzer conformanceReplayAnalyzer) Analyze(ctx context.Context, _ string, symbols []string) (*reachability.Analysis, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !slices.Equal(symbols, analyzer.symbols) {
		return nil, errors.New("suppression conformance subjects differ from the production analyzer request")
	}
	if analyzer.analysis == nil {
		return nil, errNilAnalyzerResult
	}
	encoded, err := json.Marshal(analyzer.analysis)
	if err != nil {
		return nil, fmt.Errorf("clone suppression conformance analysis: %w", err)
	}
	var cloned reachability.Analysis
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return nil, fmt.Errorf("clone suppression conformance analysis: %w", err)
	}
	return &cloned, nil
}

func captureSuppressionConformance(ctx context.Context, request CaptureRequest, executed execution) (SuppressionProjectionConformanceControl, error) {
	spec, err := suppressionConformanceSpecForCell(request.Cell)
	if err != nil {
		return SuppressionProjectionConformanceControl{}, err
	}
	control := SuppressionProjectionConformanceControl{
		CaseID: request.Cell.CaseID, BindingID: request.Cell.BindingID, CohortID: request.Cell.CohortID,
		ModeID: request.Cell.ModeID, SubjectID: request.Cell.SubjectID, ExpectedTier: spec.tier,
		ExpectedProposer: spec.proposer, ExpectedVerifier: spec.verifier,
	}
	if executed.analyzer != nil && executed.analyzer.result != nil {
		encoded, encodeErr := benchmark.CanonicalJSON(executed.analyzer.result)
		if encodeErr != nil {
			return SuppressionProjectionConformanceControl{}, fmt.Errorf("digest suppression conformance analysis: %w", encodeErr)
		}
		control.AnalyzerDigest = benchmark.SHA256Digest(encoded)
	}
	if len(executed.subjects) > 0 {
		encoded, encodeErr := benchmark.CanonicalJSON(executed.subjects)
		if encodeErr != nil {
			return SuppressionProjectionConformanceControl{}, fmt.Errorf("digest suppression conformance subjects: %w", encodeErr)
		}
		control.SubjectsDigest = benchmark.SHA256Digest(encoded)
	}
	if err := ctx.Err(); err != nil {
		return SuppressionProjectionConformanceControl{}, err
	}
	if executed.conformanceCoordinator != nil && executed.analyzer != nil && executed.analyzer.result != nil && len(executed.subjects) > 0 {
		lifecycle, lifecycleErr := newCaptureLifecycle()
		if lifecycleErr != nil {
			return SuppressionProjectionConformanceControl{}, lifecycleErr
		}
		replay := conformanceReplayAnalyzer{analysis: executed.analyzer.result, symbols: append([]string(nil), executed.analyzer.symbols...)}
		coordinator, coordinatorErr := executed.conformanceCoordinator(replay, lifecycle)
		if coordinatorErr == nil {
			_, coordinatorErr = coordinator.Record(ctx, productionCaptureEngagementID, "fixture://root", cloneReachabilitySubjects(executed.subjects))
		}
		if coordinatorErr == nil {
			control.CoordinatorRecorded = true
			items, listErr := lifecycle.judgments.List(ctx, productionCaptureEngagementID)
			if listErr != nil {
				return SuppressionProjectionConformanceControl{}, fmt.Errorf("list suppression conformance judgments: %w", listErr)
			}
			for _, item := range items {
				if item.Capability != judgment.CapReachability || item.SubjectKind != judgment.SubjectFinding || item.SubjectID.String() != request.Cell.SubjectID {
					continue
				}
				control.JudgmentCount++
				if control.Judgment == nil {
					claim, _ := item.Claim.(judgment.ReachabilityClaim)
					control.Judgment = &SuppressionProjectionJudgment{
						FindingID: item.SubjectID.String(), Claim: claim, State: item.State, EvidenceScore: item.EvidenceScore,
						ProposedBy: item.ProposedBy, VerifiedBy: item.VerifiedBy,
					}
				}
			}
			control.Evidence = exportuc.DeriveReachabilityEvidence(items, request.Cell.SubjectID)
		}
	}
	control.FailureCode = suppressionConformanceFailure(control, spec)
	control.Passed = control.FailureCode == ""
	return control, nil
}

func suppressionConformanceFailure(control SuppressionProjectionConformanceControl, spec suppressionConformanceSpec) string {
	if control.CaseID != spec.caseID || control.CohortID != spec.cohortID || control.ModeID != spec.modeID ||
		strings.TrimSpace(control.BindingID) == "" || control.SubjectID == "" || control.ExpectedTier != spec.tier ||
		control.ExpectedProposer != spec.proposer || control.ExpectedVerifier != spec.verifier {
		return "control_identity_mismatch"
	}
	if !validDigest(control.AnalyzerDigest) {
		return "analysis_unavailable"
	}
	if !validDigest(control.SubjectsDigest) {
		return "subjects_unavailable"
	}
	if !control.CoordinatorRecorded {
		return "coordinator_replay_failed"
	}
	if control.JudgmentCount != 1 || control.Judgment == nil {
		return "judgment_count_mismatch"
	}
	item := control.Judgment.domain()
	if item.ProposedBy != spec.proposer || item.VerifiedBy != spec.verifier || item.SubjectID.String() != control.SubjectID || item.Claim.(judgment.ReachabilityClaim).Tier != spec.tier {
		return "judgment_authority_mismatch"
	}
	if !item.Publishable() {
		return "judgment_not_publishable"
	}
	claim := item.Claim.(judgment.ReachabilityClaim)
	if !claim.SuppressesFinding() {
		return "claim_not_suppressing"
	}
	derived := exportuc.DeriveReachabilityEvidence([]judgment.Judgment{item}, control.SubjectID)
	if control.Evidence == nil || !reflect.DeepEqual(*derived, *control.Evidence) {
		return "projection_mismatch"
	}
	if derived.Source != "reachability" || derived.Label != exportuc.LabelPresentUnreached || derived.Tier != spec.tier || len(derived.Path) != 0 {
		return "unexpected_projection"
	}
	return ""
}

func (item SuppressionProjectionJudgment) domain() judgment.Judgment {
	return judgment.Judgment{
		ID: shared.ID("reachbench-suppression-conformance"), EngagementID: productionCaptureEngagementID,
		Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(item.FindingID),
		Claim: item.Claim, State: item.State, EvidenceScore: item.EvidenceScore,
		ProposedBy: item.ProposedBy, VerifiedBy: item.VerifiedBy, Version: 1,
	}
}

func validateSuppressionConformanceControl(control SuppressionProjectionConformanceControl, cell ExecutionCell) error {
	spec, err := suppressionConformanceSpecForCell(cell)
	if err != nil {
		return err
	}
	failure := suppressionConformanceFailure(control, spec)
	if control.FailureCode != failure || control.Passed != (failure == "") {
		return fmt.Errorf("suppression conformance control %q has inconsistent pass state", control.CaseID)
	}
	return nil
}

func validateSuppressionConformance(report SuppressionProjectionConformance) error {
	if report.SchemaVersion != suppressionConformanceSchemaVersion || report.Repetition < 1 || report.Repetition > fixedRepetitions {
		return errors.New("invalid suppression conformance report identity")
	}
	specs, err := suppressionConformanceSpecs()
	if err != nil {
		return err
	}
	if len(report.Controls) != len(specs) {
		return fmt.Errorf("suppression conformance report requires %d controls", len(specs))
	}
	passed := true
	previous := ""
	for index, control := range report.Controls {
		key := control.CaseID + "\x00" + control.BindingID
		if previous != "" && key <= previous {
			return errors.New("suppression conformance controls are not uniquely sorted")
		}
		previous = key
		failure := suppressionConformanceFailure(control, specs[index])
		if control.FailureCode != failure || control.Passed != (failure == "") {
			return fmt.Errorf("suppression conformance control %q has inconsistent pass state", control.CaseID)
		}
		passed = passed && control.Passed
	}
	if report.Passed != passed {
		return errors.New("suppression conformance report has inconsistent aggregate state")
	}
	return nil
}

func suppressionConformanceProjectionDigest(report SuppressionProjectionConformance) (string, error) {
	projection := struct {
		Passed   bool                                      `json:"passed"`
		Controls []SuppressionProjectionConformanceControl `json:"controls"`
	}{Passed: report.Passed, Controls: report.Controls}
	encoded, err := benchmark.CanonicalJSON(projection)
	if err != nil {
		return "", fmt.Errorf("encode suppression conformance projection: %w", err)
	}
	return benchmark.SHA256Digest(encoded), nil
}

func buildSuppressionConformanceReport(repetition int, controls []SuppressionProjectionConformanceControl) (SuppressionProjectionConformance, error) {
	sorted := append([]SuppressionProjectionConformanceControl(nil), controls...)
	sort.Slice(sorted, func(left, right int) bool {
		leftKey := sorted[left].CaseID + "\x00" + sorted[left].BindingID
		rightKey := sorted[right].CaseID + "\x00" + sorted[right].BindingID
		return leftKey < rightKey
	})
	report := SuppressionProjectionConformance{SchemaVersion: suppressionConformanceSchemaVersion, Repetition: repetition, Passed: true, Controls: sorted}
	for _, control := range sorted {
		report.Passed = report.Passed && control.Passed
	}
	if err := validateSuppressionConformance(report); err != nil {
		return SuppressionProjectionConformance{}, err
	}
	return report, nil
}

func replaySuppressionConformance(ctx context.Context, stage string, manifest LifecycleManifest, repeat SemanticRepeatResult) error {
	required := manifest.Route != RouteProtectedBaseline
	if !required {
		if len(manifest.SuppressionConformance) != 0 || repeat.SuppressionConformance != nil {
			return errors.New("protected baseline replay contains suppression conformance evidence")
		}
		return nil
	}
	if len(manifest.SuppressionConformance) != fixedRepetitions || repeat.SuppressionConformance == nil {
		return errors.New("candidate replay lacks suppression conformance bindings")
	}
	reports := make([]SuppressionProjectionConformance, fixedRepetitions)
	projectionDigests := make([]string, fixedRepetitions)
	passed := true
	for index := 0; index < fixedRepetitions; index++ {
		if err := contextError(ctx); err != nil {
			return err
		}
		expectedPath := fmt.Sprintf("repetition-%d/suppression-projection-conformance.json", index+1)
		entry := manifest.SuppressionConformance[index]
		if entry.Path != expectedPath || !validDigest(entry.Digest) {
			return fmt.Errorf("suppression conformance lifecycle binding %d is invalid", index+1)
		}
		artifactPath := filepath.Join(stage, filepath.FromSlash(expectedPath))
		raw, err := readRegularFileContext(ctx, artifactPath)
		if err != nil {
			return fmt.Errorf("reopen repetition %d suppression conformance: %w", index+1, err)
		}
		if _, err := readCanonicalJSONContext(ctx, artifactPath, &reports[index]); err != nil {
			return fmt.Errorf("replay repetition %d suppression conformance: %w", index+1, err)
		}
		if benchmark.SHA256Digest(raw) != entry.Digest {
			return fmt.Errorf("replayed repetition %d suppression conformance digest differs from lifecycle binding", index+1)
		}
		if reports[index].Repetition != index+1 {
			return fmt.Errorf("replayed suppression conformance repetition %d has wrong identity", index+1)
		}
		if err := validateSuppressionConformance(reports[index]); err != nil {
			return fmt.Errorf("validate replayed repetition %d suppression conformance: %w", index+1, err)
		}
		projectionDigests[index], err = suppressionConformanceProjectionDigest(reports[index])
		if err != nil {
			return err
		}
		passed = passed && reports[index].Passed
	}
	binding := repeat.SuppressionConformance
	if !binding.SemanticallyEqual || projectionDigests[0] != projectionDigests[1] || binding.ReportDigest != projectionDigests[0] {
		return errors.New("suppression conformance semantic-repeat binding is inconsistent")
	}
	if binding.Passed != passed {
		return errors.New("suppression conformance semantic-repeat pass state is inconsistent")
	}
	return nil
}

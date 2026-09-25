package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const (
	fixedRepetitions           = 2
	reachabilityCleanupTimeout = 2 * time.Minute
)

var errCandidateRejected = errors.New("candidate reachability benchmark rejected")

// Run rejects every argument, derives all lifecycle identity internally, and publishes only after cleanup succeeds.
func (runner *Runner) Run(ctx context.Context, args []string) (result Result, runErr error) {
	if len(args) != 0 {
		return Result{}, errors.New("synapse-reachability-cycle accepts no flags or positional arguments")
	}
	facts, err := runner.deriveRuntime(ctx)
	if err != nil {
		return Result{}, err
	}
	_, controllerProvided := runner.dependencies.Environment(ControllerEnvelopeEnvironment)
	var envelope RunEnvelope
	var bundle TrustedBundle
	var bundleRef measurement.ArtifactReference
	var bundleRoot string
	authoritative := false
	if controllerProvided {
		if err := runner.requirePristineAuthoritativeCheckout(ctx); err != nil {
			return Result{}, err
		}
		envelope, err = runner.loadControllerEnvelope(facts)
		if err != nil {
			return Result{}, err
		}
		bundleRoot, err = controllerBundleRoot(facts)
		if err != nil {
			return Result{}, err
		}
		bundle, bundleRef, err = runner.loadBundle(bundleRoot, envelope.Route)
		if err != nil {
			return Result{}, err
		}
		if err := runner.authenticateAuthoritativeController(ctx, facts, envelope, bundleRef); err != nil {
			return Result{}, err
		}
		if err := runner.validateAuthoritativeEnvelope(ctx, envelope, facts, bundleRef); err != nil {
			return Result{}, err
		}
		authoritative = envelope.Route.authoritative()
	} else {
		bundleRoot, err = checkoutBundleRoot(facts)
		if err != nil {
			return Result{}, err
		}
		bundle, bundleRef, err = runner.loadBundle(bundleRoot, RouteLocalDiagnostic)
		if err != nil {
			return Result{}, err
		}
		candidateTemplate, inputErr := runner.loadInputTemplate(bundleRoot, *bundle.CandidateInput, measurement.CandidateAcceptance)
		if inputErr != nil {
			return Result{}, inputErr
		}
		envelope = localEnvelope(facts, bundleRef, candidateTemplate.ActiveSnapshot)
		if err := validateLocalEnvelope(envelope, facts, bundleRef); err != nil {
			return Result{}, err
		}
	}

	asset, err := bundle.selected(envelope.Route)
	if err != nil {
		return Result{}, err
	}
	template, err := runner.loadInputTemplate(bundleRoot, asset, envelope.Purpose)
	if err != nil {
		return Result{}, err
	}
	if err := validateEnvelopeMeasurement(envelope, template, bundleRef); err != nil {
		return Result{}, err
	}
	profile, err := measurement.ResolveReachabilityProfile(template)
	if err != nil {
		return Result{}, fmt.Errorf("resolve reachability benchmark profile: %w", err)
	}
	if err := requireProfileAuthority(profile, authoritative); err != nil {
		return Result{}, err
	}
	var allowlistResult *BaselineAllowlistResult
	if envelope.Route == RouteProtectedBaseline {
		result, resultErr := runner.verifyBaselineAllowlist(ctx, bundleRoot, bundle.BaselineAllowlist, facts, envelope.Analyzer)
		if resultErr != nil {
			return Result{}, resultErr
		}
		allowlistResult = &result
	}
	cells, err := enumerateCellsForProfile(template, profile)
	if err != nil {
		return Result{}, err
	}
	if err := validatePublicationCapacity(len(cells)); err != nil {
		return Result{}, err
	}
	conformanceCells := map[string]struct{}{}
	if envelope.Route != RouteProtectedBaseline {
		conformanceCells, err = suppressionConformancePlan(cells)
		if err != nil {
			return Result{}, err
		}
	}

	workspace, err := benchcycle.PrepareWorkspace(facts.rawRoot, facts.runKey)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(workspace.RawRunRoot(), 0o700); err != nil {
		return Result{}, runner.cleanupWorkspaceAfterFailure(workspace, fmt.Errorf("create private reachability evidence root: %w", err))
	}
	evidence, err := benchcycle.NewEvidenceStore(workspace.RawRunRoot(), reachabilityEvidenceLimits())
	if err != nil {
		return Result{}, runner.cleanupWorkspaceAfterFailure(workspace, fmt.Errorf("create private reachability evidence store: %w", err))
	}

	var manifest LifecycleManifest
	var repeat SemanticRepeatResult
	publication, err := benchcycle.BeginPublication(facts.output, reachabilityPublicationLimits(), func(cleanupCtx context.Context) error {
		return workspace.Cleanup(cleanupCtx, runner.dependencies.RuntimeCleanup)
	}, func(verifyCtx context.Context, stage string, _ []benchcycle.FileIdentity) error {
		return replaySanitizedBundle(verifyCtx, stage, manifest, repeat, facts)
	})
	if err != nil {
		return Result{}, runner.cleanupWorkspaceAfterFailure(workspace, fmt.Errorf("begin reachability publication: %w", err))
	}
	publicationTerminal := false
	defer func() {
		if publicationTerminal {
			return
		}
		if cleanupErr := publication.Abort(); cleanupErr != nil {
			runErr = errors.Join(runErr, cleanupErr)
		}
	}()

	plan := benchcycle.TwoPassPlan[ExecutionCell]{Cells: make([]benchcycle.PlanCell[ExecutionCell], len(cells))}
	for index, cell := range cells {
		plan.Cells[index] = benchcycle.PlanCell[ExecutionCell]{Key: opaqueCellKey(cell), Cell: cell}
	}
	comparisons := make([]CellRepeatDigest, 0, len(plan.Cells))
	pairs, err := benchcycle.ExecuteTwoPass(ctx, plan,
		func(captureCtx context.Context, attempt benchcycle.Attempt[ExecutionCell]) (benchcycle.AttemptOutcome[CaptureResult], error) {
			_, projectionConformanceControl := conformanceCells[attempt.Address.CellKey]
			captured, captureErr := runner.capture.Capture(captureCtx, CaptureRequest{
				Repetition:                   attempt.Address.Repetition,
				Cell:                         attempt.Cell,
				Analyzer:                     envelope.Analyzer,
				Snapshot:                     template.ActiveSnapshot,
				WorkRoot:                     workspace.WorkRoot(),
				profile:                      profile,
				attempt:                      attempt.Address,
				evidence:                     evidence,
				projectionConformanceControl: projectionConformanceControl,
			})
			if captureErr != nil {
				return benchcycle.AttemptOutcome[CaptureResult]{}, fmt.Errorf("capture repetition %d %s/%s: %w", attempt.Address.Repetition, attempt.Cell.CaseID, attempt.Cell.BindingID, captureErr)
			}
			if err := captureCtx.Err(); err != nil {
				return benchcycle.AttemptOutcome[CaptureResult]{}, err
			}
			if err := validateCapturedCell(attempt.Cell, captured.Observation); err != nil {
				return benchcycle.AttemptOutcome[CaptureResult]{}, fmt.Errorf("capture repetition %d: %w", attempt.Address.Repetition, err)
			}
			if err := validateEvidenceReceipts(captured.EvidenceReceipts); err != nil {
				return benchcycle.AttemptOutcome[CaptureResult]{}, fmt.Errorf("capture repetition %d evidence: %w", attempt.Address.Repetition, err)
			}
			if projectionConformanceControl != (captured.SuppressionConformance != nil) {
				return benchcycle.AttemptOutcome[CaptureResult]{}, fmt.Errorf("capture repetition %d %s/%s has inconsistent suppression conformance output", attempt.Address.Repetition, attempt.Cell.CaseID, attempt.Cell.BindingID)
			}
			if captured.SuppressionConformance != nil {
				if err := validateSuppressionConformanceControl(*captured.SuppressionConformance, attempt.Cell); err != nil {
					return benchcycle.AttemptOutcome[CaptureResult]{}, fmt.Errorf("capture repetition %d suppression conformance: %w", attempt.Address.Repetition, err)
				}
			}
			return benchcycle.AttemptOutcome[CaptureResult]{Address: attempt.Address, Outcome: captured}, nil
		},
		func(compareCtx context.Context, pair benchcycle.PairOutcome[ExecutionCell, CaptureResult]) error {
			if err := compareCtx.Err(); err != nil {
				return err
			}
			left, err := canonicalProjection(pair.Outcomes[0].Outcome.Observation)
			if err != nil {
				return err
			}
			right, err := canonicalProjection(pair.Outcomes[1].Outcome.Observation)
			if err != nil {
				return err
			}
			if !bytes.Equal(left, right) {
				return fmt.Errorf("semantic repeat mismatch for %s/%s", pair.Cell.Cell.CaseID, pair.Cell.Cell.BindingID)
			}
			if (pair.Outcomes[0].Outcome.SuppressionConformance != nil) != (pair.Outcomes[1].Outcome.SuppressionConformance != nil) {
				return fmt.Errorf("suppression conformance repeat presence mismatch for %s/%s", pair.Cell.Cell.CaseID, pair.Cell.Cell.BindingID)
			}
			if pair.Outcomes[0].Outcome.SuppressionConformance != nil && !sameCanonical(*pair.Outcomes[0].Outcome.SuppressionConformance, *pair.Outcomes[1].Outcome.SuppressionConformance) {
				return fmt.Errorf("suppression conformance repeat mismatch for %s/%s", pair.Cell.Cell.CaseID, pair.Cell.Cell.BindingID)
			}
			comparisons = append(comparisons, CellRepeatDigest{
				CaseID: pair.Cell.Cell.CaseID, BindingID: pair.Cell.Cell.BindingID, ProjectionDigest: benchmark.SHA256Digest(left),
			})
			return nil
		},
	)
	if err != nil {
		return Result{}, err
	}

	captures := make([][]CaptureResult, fixedRepetitions)
	for repetition := range captures {
		captures[repetition] = make([]CaptureResult, len(pairs))
		for index, pair := range pairs {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			captures[repetition][index] = pair.Outcomes[repetition].Outcome
		}
	}
	inputs := make([]measurement.MeasurementInput, fixedRepetitions)
	reports := make([]measurement.MeasurementReport, fixedRepetitions)
	encodedReports := make([][]byte, fixedRepetitions)
	conformanceReports := make([]SuppressionProjectionConformance, 0, fixedRepetitions)
	for repetition := range captures {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		input, inputErr := materializeInput(template, cells, captures[repetition])
		if inputErr != nil {
			return Result{}, fmt.Errorf("materialize repetition %d input: %w", repetition+1, inputErr)
		}
		report, evaluateErr := measurement.EvaluateMeasurement(input)
		if evaluateErr != nil {
			return Result{}, fmt.Errorf("evaluate repetition %d: %w", repetition+1, evaluateErr)
		}
		encoded, encodeErr := encodeReport(report)
		if encodeErr != nil {
			return Result{}, fmt.Errorf("encode repetition %d report: %w", repetition+1, encodeErr)
		}
		inputs[repetition], reports[repetition], encodedReports[repetition] = input, report, encoded
		if envelope.Route != RouteProtectedBaseline {
			controls := make([]SuppressionProjectionConformanceControl, 0, len(conformanceCells))
			for _, captured := range captures[repetition] {
				if captured.SuppressionConformance != nil {
					controls = append(controls, *captured.SuppressionConformance)
				}
			}
			conformanceReport, conformanceErr := buildSuppressionConformanceReport(repetition+1, controls)
			if conformanceErr != nil {
				return Result{}, fmt.Errorf("build repetition %d suppression conformance: %w", repetition+1, conformanceErr)
			}
			conformanceReports = append(conformanceReports, conformanceReport)
		}
	}
	if !bytes.Equal(encodedReports[0], encodedReports[1]) {
		return Result{}, errors.New("canonical reachability reports differ between repetitions")
	}

	sort.Slice(comparisons, func(left, right int) bool {
		leftKey := comparisons[left].CaseID + "\x00" + comparisons[left].BindingID
		rightKey := comparisons[right].CaseID + "\x00" + comparisons[right].BindingID
		return leftKey < rightKey
	})
	manifest = LifecycleManifest{
		SchemaVersion:     LifecycleSchemaVersion,
		Route:             envelope.Route,
		Purpose:           envelope.Purpose,
		FinalMode:         envelope.FinalMode,
		Authoritative:     authoritative,
		Harness:           facts.harness,
		Analyzer:          envelope.Analyzer,
		Authority:         envelope.Authority,
		Snapshot:          template.ActiveSnapshot,
		Bundle:            bundleRef,
		BaselineAllowlist: allowlistResult,
		RunKey:            facts.runKey,
		Repetitions:       fixedRepetitions,
		Cells:             cells,
		ReportIDs:         []string{reports[0].ID, reports[1].ID},
	}
	repeat = SemanticRepeatResult{
		SchemaVersion:     RepeatSchemaVersion,
		Repetitions:       fixedRepetitions,
		SemanticallyEqual: true,
		ReportIDs:         []string{reports[0].ID, reports[1].ID},
		Cells:             comparisons,
	}
	if err := writeSanitizedBundle(ctx, publication, &manifest, &repeat, inputs, reports, conformanceReports); err != nil {
		return Result{}, err
	}
	publicationTerminal = true
	if err := publication.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("publish reachability lifecycle: %w", err)
	}
	result = Result{RunKey: facts.runKey, Authoritative: authoritative, Output: facts.output, Manifest: manifest}
	var decisionErr error
	if envelope.Purpose == measurement.CandidateAcceptance && !reports[0].Candidate.Accepted {
		decisionErr = errors.Join(decisionErr, errCandidateRejected)
	}
	for _, conformance := range conformanceReports {
		if !conformance.Passed {
			decisionErr = errors.Join(decisionErr, errSuppressionConformance)
			break
		}
	}
	return result, decisionErr
}

func reachabilityEvidenceLimits() benchcycle.EvidenceLimits {
	return benchcycle.EvidenceLimits{
		MaxArtifactBytes: maxRawEvidenceArtifactBytes,
		MaxTotalBytes:    maxRawEvidenceTotalBytes,
		MaxFiles:         maxRawEvidenceFiles,
	}
}

func reachabilityPublicationLimits() benchcycle.PublicationLimits {
	return benchcycle.PublicationLimits{
		MaxFileBytes:   benchmark.MaxJSONBytes,
		MaxTotalBytes:  int64(maxArtifactFiles) * benchmark.MaxJSONBytes,
		MaxFiles:       maxArtifactFiles,
		CleanupTimeout: reachabilityCleanupTimeout,
	}
}

func (runner *Runner) cleanupWorkspaceAfterFailure(workspace benchcycle.Workspace, failure error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), reachabilityCleanupTimeout)
	defer cancel()
	if cleanupErr := workspace.Cleanup(cleanupCtx, runner.dependencies.RuntimeCleanup); cleanupErr != nil {
		return errors.Join(failure, fmt.Errorf("cleanup private reachability workspace: %w", cleanupErr))
	}
	return failure
}

func validateEvidenceReceipts(receipts []benchcycle.EvidenceReceipt) error {
	if len(receipts) > 1 {
		return errors.New("capture retained more than one raw evidence receipt")
	}
	for _, receipt := range receipts {
		if receipt.Reference == "" || receipt.Size < 0 || receipt.Size > maxRawEvidenceArtifactBytes || !validEvidenceDigest(receipt.Digest) {
			return errors.New("capture retained an invalid raw evidence receipt")
		}
	}
	return nil
}

func validEvidenceDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (bundle TrustedBundle) selected(route Route) (BundleAsset, error) {
	if err := bundle.ValidateRoute(route); err != nil {
		return BundleAsset{}, err
	}
	if route == RouteProtectedBaseline {
		return bundle.BaselineInput, nil
	}
	return *bundle.CandidateInput, nil
}

func (runner *Runner) validateAuthoritativeEnvelope(ctx context.Context, envelope RunEnvelope, facts runtimeFacts, bundle measurement.ArtifactReference) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if envelope.Harness != facts.harness || envelope.Authority.ReviewedHarnessID != facts.harness.ID {
		return errors.New("controller envelope harness identity does not match independently derived runtime facts")
	}
	if envelope.Route == RouteCandidate && (envelope.Analyzer.Commit != facts.harness.Commit || envelope.Analyzer.Tree != facts.harness.Tree) {
		return errors.New("controller candidate analyzer revision does not match the independently derived runtime harness")
	}
	if envelope.Route == RouteProtectedBaseline {
		analyzer, err := runner.deriveTrustedBaselineAnalyzer(ctx)
		if err != nil {
			return err
		}
		if envelope.Analyzer != analyzer {
			return errors.New("controller envelope baseline analyzer identity does not match the fixed trusted base")
		}
	}
	if envelope.Bundle != bundle {
		return errors.New("controller envelope does not bind the loaded controller-owned trusted bundle")
	}
	return nil
}

func validateLocalEnvelope(envelope RunEnvelope, facts runtimeFacts, bundle measurement.ArtifactReference) error {
	if envelope.Route != RouteLocalDiagnostic || envelope.Purpose != measurement.CandidateAcceptance || envelope.FinalMode != FinalDiagnostic {
		return errors.New("local run is not an explicit non-authoritative diagnostic route")
	}
	if envelope.Harness != facts.harness || envelope.Analyzer != (RevisionIdentity{ID: AnalyzerSubjectID, Commit: facts.harness.Commit, Tree: facts.harness.Tree}) || envelope.Bundle != bundle {
		return errors.New("generated local envelope does not match runtime facts")
	}
	if envelope.Authority != (ProceduralAuthority{}) {
		return errors.New("local diagnostic run cannot carry procedural authority")
	}
	return nil
}

func validateEnvelopeMeasurement(envelope RunEnvelope, input measurement.MeasurementInput, bundle measurement.ArtifactReference) error {
	if input.Purpose != envelope.Purpose || input.ActiveSnapshot != envelope.Snapshot || envelope.Bundle != bundle {
		return errors.New("run envelope does not agree with the measurement contract input")
	}
	if envelope.Route == RouteCandidate || envelope.Route == RouteLocalDiagnostic {
		if input.Baseline == nil || input.Checkpoint == nil || input.Ratchet == nil {
			return errors.New("candidate route requires trusted baseline report, checkpoint, and ratchet")
		}
	}
	if envelope.Route == RouteProtectedBaseline && (input.Baseline != nil || input.Checkpoint != nil || input.Ratchet != nil) {
		return errors.New("protected baseline input cannot carry candidate lifecycle artifacts")
	}
	return nil
}

func (runner *Runner) loadInputTemplate(root string, asset BundleAsset, purpose measurement.RunPurpose) (measurement.MeasurementInput, error) {
	path, err := benchcycle.BelowRoot(root, asset.Path)
	if err != nil {
		return measurement.MeasurementInput{}, fmt.Errorf("resolve trusted measurement input: %w", err)
	}
	var input measurement.MeasurementInput
	encoded, err := readCanonicalJSON(path, &input)
	if err != nil {
		return measurement.MeasurementInput{}, fmt.Errorf("read trusted measurement input: %w", err)
	}
	if benchmark.SHA256Digest(encoded) != asset.Digest {
		return measurement.MeasurementInput{}, errors.New("trusted measurement input digest does not match bundle")
	}
	if err := input.Validate(); err != nil {
		return measurement.MeasurementInput{}, fmt.Errorf("validate trusted measurement input: %w", err)
	}
	if err := validateFrozenTemplateStaticContract(input); err != nil {
		return measurement.MeasurementInput{}, err
	}
	if input.Purpose != purpose {
		return measurement.MeasurementInput{}, errors.New("trusted bundle selected an input for the wrong lifecycle purpose")
	}
	if len(input.Observations) != 0 {
		return measurement.MeasurementInput{}, errors.New("trusted measurement input must not pre-populate captured observations")
	}
	return input, nil
}

func enumerateCells(input measurement.MeasurementInput) ([]ExecutionCell, error) {
	profile, err := measurement.ResolveReachabilityProfile(input)
	if err != nil {
		return nil, err
	}
	return enumerateCellsForProfile(input, profile)
}

func requireProfileAuthority(profile measurement.ReachabilityProfile, authoritative bool) error {
	if authoritative && !profile.Authoritative {
		return errors.New("reachability benchmark profile is pending independent review")
	}
	return nil
}

func enumerateCellsForProfile(input measurement.MeasurementInput, profile measurement.ReachabilityProfile) ([]ExecutionCell, error) {
	fixtures := profile.Fixtures
	cohorts := make(map[string]measurement.ProductionCohort, len(input.Inventory.Cohorts))
	for _, cohort := range input.Inventory.Cohorts {
		cohorts[cohort.ID+"\x00"+cohort.Mode] = cohort
	}
	cells := make([]ExecutionCell, 0)
	seen := map[string]struct{}{}
	for _, item := range input.Corpus.Cases {
		cohort, ok := cohorts[item.CohortID+"\x00"+item.ModeID]
		if !ok {
			return nil, fmt.Errorf("corpus case %q has no production cohort", item.ID)
		}
		if !cohort.BenchmarkRequired {
			continue
		}
		if item.Fixture == nil {
			return nil, fmt.Errorf("corpus case %q has no fixture", item.ID)
		}
		resolved, err := fixtures.ResolveFixtureSubject(*item.Fixture, item.SubjectID)
		if err != nil {
			return nil, fmt.Errorf("resolve fixture subject for corpus case %q: %w", item.ID, err)
		}
		if resolved.Subject.ID != item.SubjectID {
			return nil, fmt.Errorf("fixture subject identity mismatch for corpus case %q", item.ID)
		}
		for _, binding := range cohort.Bindings {
			if binding.State != measurement.BindingEnabled {
				continue
			}
			cell := ExecutionCell{
				CaseID:        item.ID,
				CohortID:      item.CohortID,
				ModeID:        item.ModeID,
				BindingID:     binding.ID,
				AnalyzerID:    cohort.AnalyzerID,
				Configuration: binding.Configuration,
				SubjectID:     resolved.Subject.ID,
				Fixture:       *item.Fixture,
				BoundaryID:    binding.BoundaryID,
			}
			key := cell.CaseID + "\x00" + cell.BindingID
			if _, exists := seen[key]; exists {
				return nil, fmt.Errorf("duplicate required reachability cell %q", key)
			}
			seen[key] = struct{}{}
			cells = append(cells, cell)
			if len(cells) > maxCells {
				return nil, fmt.Errorf("reachability lifecycle exceeds %d execution cells", maxCells)
			}
		}
	}
	if len(cells) == 0 {
		return nil, errors.New("reachability lifecycle has no required execution cells")
	}
	sort.Slice(cells, func(left, right int) bool {
		return cellKey(cells[left]) < cellKey(cells[right])
	})
	return cells, nil
}

func validatePublicationCapacity(cellCount int) error {
	if cellCount <= 0 {
		return errors.New("reachability lifecycle has no publishable execution cells")
	}
	required := publicationDocumentReserve + int64(cellCount)*maxPublishedCellBytes
	if required > benchmark.MaxJSONBytes {
		return fmt.Errorf("reachability lifecycle publication budget for %d cells exceeds %d bytes", cellCount, benchmark.MaxJSONBytes)
	}
	return nil
}

func materializeInput(template measurement.MeasurementInput, cells []ExecutionCell, captures []CaptureResult) (measurement.MeasurementInput, error) {
	if len(cells) != len(captures) {
		return measurement.MeasurementInput{}, errors.New("missing reachability capture cell")
	}
	planned := make(map[string]ExecutionCell, len(cells))
	for _, cell := range cells {
		key := observationKey(cell.CaseID, cell.BindingID)
		if _, exists := planned[key]; exists {
			return measurement.MeasurementInput{}, fmt.Errorf("duplicate reachability plan observation %q", key)
		}
		planned[key] = cell
	}
	captured := make(map[string]measurement.MeasuredObservation, len(captures))
	for _, capture := range captures {
		key := observationKey(capture.Observation.CaseID, capture.Observation.BindingID)
		cell, expected := planned[key]
		if !expected {
			return measurement.MeasurementInput{}, fmt.Errorf("unexpected reachability capture cell %q", key)
		}
		if err := validateCapturedCell(cell, capture.Observation); err != nil {
			return measurement.MeasurementInput{}, err
		}
		if _, exists := captured[key]; exists {
			return measurement.MeasurementInput{}, fmt.Errorf("duplicate reachability capture cell %q", key)
		}
		captured[key] = capture.Observation
	}
	input := template
	input.Observations = make([]measurement.MeasuredObservation, 0, len(cells))
	for _, cell := range cells {
		key := observationKey(cell.CaseID, cell.BindingID)
		observation, found := captured[key]
		if !found {
			return measurement.MeasurementInput{}, fmt.Errorf("missing reachability capture cell %q", key)
		}
		input.Observations = append(input.Observations, observation)
	}
	if err := input.Validate(); err != nil {
		return measurement.MeasurementInput{}, err
	}
	return input, nil
}

func observationKey(caseID, bindingID string) string {
	return caseID + "\x00" + bindingID
}

func validateCapturedCell(cell ExecutionCell, observation measurement.MeasuredObservation) error {
	if observation.CaseID != cell.CaseID || observation.BindingID != cell.BindingID {
		return fmt.Errorf("capture cell identity %q/%q does not match required %q/%q", observation.CaseID, observation.BindingID, cell.CaseID, cell.BindingID)
	}
	if observation.Analyzer.ID != cell.AnalyzerID || observation.Configuration != cell.Configuration {
		return errors.New("capture analyzer or configuration does not match production binding")
	}
	return nil
}

func opaqueCellKey(cell ExecutionCell) string {
	return benchmark.SHA256Digest([]byte(cellKey(cell)))
}

func cellKey(cell ExecutionCell) string {
	return strings.Join([]string{
		cell.CohortID,
		cell.ModeID,
		cell.BindingID,
		cell.CaseID,
		cell.SubjectID,
		cell.Fixture.ID,
		cell.Fixture.Digest,
		cell.BoundaryID,
	}, "\x00")
}

type semanticProjection struct {
	CaseID        string                         `json:"case_id"`
	BindingID     string                         `json:"binding_id"`
	Invoked       bool                           `json:"invoked"`
	Outcome       measurement.Outcome            `json:"outcome"`
	Coverage      measurement.ObservedCoverage   `json:"coverage"`
	OutputCapture measurement.CaptureStatus      `json:"output_capture"`
	Analyzer      measurement.ArtifactReference  `json:"analyzer"`
	Configuration measurement.ArtifactReference  `json:"configuration"`
	Suppression   measurement.SuppressionCapture `json:"suppression"`
	Positive      *measurement.PositiveEvidence  `json:"positive_evidence,omitempty"`
}

func canonicalProjection(observation measurement.MeasuredObservation) ([]byte, error) {
	return benchmark.CanonicalJSON(semanticProjection{
		CaseID: observation.CaseID, BindingID: observation.BindingID, Invoked: observation.Invoked,
		Outcome: observation.Outcome, Coverage: observation.Coverage, OutputCapture: observation.OutputCapture,
		Analyzer: observation.Analyzer, Configuration: observation.Configuration, Suppression: observation.Suppression,
		Positive: observation.Positive,
	})
}

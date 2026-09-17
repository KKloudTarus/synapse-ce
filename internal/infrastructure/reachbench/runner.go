package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

const fixedRepetitions = 2

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
		envelope, err = runner.loadControllerEnvelope(facts)
		if err != nil {
			return Result{}, err
		}
		bundleRoot, err = controllerBundleRoot(facts)
		if err != nil {
			return Result{}, err
		}
		bundle, bundleRef, err = runner.loadBundle(bundleRoot)
		if err != nil {
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
		bundle, bundleRef, err = runner.loadBundle(bundleRoot)
		if err != nil {
			return Result{}, err
		}
		candidateTemplate, inputErr := runner.loadInputTemplate(bundleRoot, bundle.CandidateInput, measurement.CandidateAcceptance)
		if inputErr != nil {
			return Result{}, inputErr
		}
		envelope = localEnvelope(facts, bundleRef, candidateTemplate.ActiveSnapshot)
		if err := validateLocalEnvelope(envelope, facts, bundleRef); err != nil {
			return Result{}, err
		}
	}

	template, err := runner.loadInputTemplate(bundleRoot, bundle.selected(envelope.Route), envelope.Purpose)
	if err != nil {
		return Result{}, err
	}
	if err := validateEnvelopeMeasurement(envelope, template, bundleRef); err != nil {
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
	cells, err := enumerateCells(template)
	if err != nil {
		return Result{}, err
	}

	workspace, err := benchcycle.PrepareWorkspace(facts.rawRoot, facts.runKey)
	if err != nil {
		return Result{}, err
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = workspace.Cleanup(context.Background(), runner.dependencies.RuntimeCleanup)
		}
	}()

	comparisons := make([]CellRepeatDigest, 0, len(cells))
	captures, err := benchcycle.ExecuteRepeated(ctx, fixedRepetitions, cells,
		func(captureCtx context.Context, repetition int, cell ExecutionCell) (CaptureResult, error) {
			captured, captureErr := runner.capture.Capture(captureCtx, CaptureRequest{
				Repetition: repetition,
				Cell:       cell,
				Analyzer:   envelope.Analyzer,
				Snapshot:   template.ActiveSnapshot,
				WorkRoot:   workspace.WorkRoot(),
			})
			if captureErr != nil {
				return CaptureResult{}, fmt.Errorf("capture repetition %d %s/%s: %w", repetition, cell.CaseID, cell.BindingID, captureErr)
			}
			if err := validateCapturedCell(cell, captured.Observation); err != nil {
				return CaptureResult{}, fmt.Errorf("capture repetition %d: %w", repetition, err)
			}
			if len(captured.RawEvidence) > maxRawEvidenceBytes {
				return CaptureResult{}, fmt.Errorf("capture repetition %d has raw evidence over %d bytes", repetition, maxRawEvidenceBytes)
			}
			if len(captured.RawEvidence) != 0 {
				path := rawEvidencePath(workspace.RawRunRoot(), repetition, cell)
				if err := benchcycle.WriteNewFile(path, captured.RawEvidence, 0o600); err != nil {
					return CaptureResult{}, fmt.Errorf("write private raw evidence: %w", err)
				}
			}
			return captured, nil
		},
		func(_ context.Context, cell ExecutionCell, repetitions []CaptureResult) error {
			if len(repetitions) != fixedRepetitions {
				return errors.New("reachability repeat comparison did not receive two captures")
			}
			left, err := canonicalProjection(repetitions[0].Observation)
			if err != nil {
				return err
			}
			right, err := canonicalProjection(repetitions[1].Observation)
			if err != nil {
				return err
			}
			if !bytes.Equal(left, right) {
				return fmt.Errorf("semantic repeat mismatch for %s/%s", cell.CaseID, cell.BindingID)
			}
			comparisons = append(comparisons, CellRepeatDigest{
				CaseID: cell.CaseID, BindingID: cell.BindingID, ProjectionDigest: benchmark.SHA256Digest(left),
			})
			return nil
		},
	)
	if err != nil {
		return Result{}, err
	}

	inputs := make([]measurement.MeasurementInput, fixedRepetitions)
	reports := make([]measurement.MeasurementReport, fixedRepetitions)
	encodedReports := make([][]byte, fixedRepetitions)
	for repetition := range captures {
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
	}
	if !bytes.Equal(encodedReports[0], encodedReports[1]) {
		return Result{}, errors.New("canonical reachability reports differ between repetitions")
	}

	// Raw evidence and the private workspace must be gone before any public artifact is staged.
	if err := workspace.Cleanup(ctx, runner.dependencies.RuntimeCleanup); err != nil {
		return Result{}, fmt.Errorf("cleanup reachability lifecycle before publication: %w", err)
	}
	cleaned = true

	stage, err := os.MkdirTemp(facts.outputRoot, ".stage-")
	if err != nil {
		return Result{}, fmt.Errorf("create sanitized publication stage: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	sort.Slice(comparisons, func(left, right int) bool {
		leftKey := comparisons[left].CaseID + "\x00" + comparisons[left].BindingID
		rightKey := comparisons[right].CaseID + "\x00" + comparisons[right].BindingID
		return leftKey < rightKey
	})
	manifest := LifecycleManifest{
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
	repeat := SemanticRepeatResult{
		SchemaVersion:     RepeatSchemaVersion,
		Repetitions:       fixedRepetitions,
		SemanticallyEqual: true,
		ReportIDs:         []string{reports[0].ID, reports[1].ID},
		Cells:             comparisons,
	}
	if err := writeSanitizedBundle(stage, manifest, repeat, inputs, reports); err != nil {
		return Result{}, err
	}
	if err := replaySanitizedBundle(stage, manifest, repeat, facts); err != nil {
		return Result{}, err
	}
	if err := benchcycle.PublishDirectory(stage, facts.output); err != nil {
		return Result{}, fmt.Errorf("publish reachability lifecycle: %w", err)
	}
	published = true
	return Result{RunKey: facts.runKey, Authoritative: authoritative, Output: facts.output, Manifest: manifest}, nil
}

func (bundle TrustedBundle) selected(route Route) BundleAsset {
	if route == RouteProtectedBaseline {
		return bundle.BaselineInput
	}
	return bundle.CandidateInput
}

func (runner *Runner) validateAuthoritativeEnvelope(ctx context.Context, envelope RunEnvelope, facts runtimeFacts, bundle measurement.ArtifactReference) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if envelope.Harness != facts.harness || envelope.Authority.ReviewedHarnessID != facts.harness.ID {
		return errors.New("controller envelope harness identity does not match independently derived runtime facts")
	}
	if envelope.Route == RouteCandidate && (envelope.Analyzer.Commit == facts.harness.Commit || envelope.Analyzer.Tree == facts.harness.Tree) {
		return errors.New("controller candidate analyzer identity must be distinct from the runtime harness")
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
	if input.Purpose != purpose {
		return measurement.MeasurementInput{}, errors.New("trusted bundle selected an input for the wrong lifecycle purpose")
	}
	if len(input.Observations) != 0 {
		return measurement.MeasurementInput{}, errors.New("trusted measurement input must not pre-populate captured observations")
	}
	return input, nil
}

func enumerateCells(input measurement.MeasurementInput) ([]ExecutionCell, error) {
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
		for _, binding := range cohort.Bindings {
			if binding.State != measurement.BindingEnabled {
				continue
			}
			cell := ExecutionCell{
				CaseID: item.ID, CohortID: item.CohortID, ModeID: item.ModeID, BindingID: binding.ID,
				AnalyzerID: cohort.AnalyzerID, Configuration: binding.Configuration,
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

func materializeInput(template measurement.MeasurementInput, cells []ExecutionCell, captures []CaptureResult) (measurement.MeasurementInput, error) {
	if len(cells) != len(captures) {
		return measurement.MeasurementInput{}, errors.New("missing reachability capture cell")
	}
	input := template
	input.Observations = make([]measurement.MeasuredObservation, 0, len(captures))
	seen := map[string]struct{}{}
	for index, capture := range captures {
		cell := cells[index]
		if err := validateCapturedCell(cell, capture.Observation); err != nil {
			return measurement.MeasurementInput{}, err
		}
		key := cellKey(cell)
		if _, exists := seen[key]; exists {
			return measurement.MeasurementInput{}, fmt.Errorf("duplicate reachability capture cell %q", key)
		}
		seen[key] = struct{}{}
		input.Observations = append(input.Observations, capture.Observation)
	}
	if len(seen) != len(cells) {
		return measurement.MeasurementInput{}, errors.New("missing reachability capture cell")
	}
	if err := input.Validate(); err != nil {
		return measurement.MeasurementInput{}, err
	}
	return input, nil
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

func rawEvidencePath(root string, repetition int, cell ExecutionCell) string {
	key := benchmark.SHA256Digest([]byte(cellKey(cell)))
	return filepath.Join(root, fmt.Sprintf("repetition-%d", repetition), key[len("sha256:"):]+".raw")
}

func cellKey(cell ExecutionCell) string {
	return strings.Join([]string{cell.CohortID, cell.ModeID, cell.BindingID, cell.CaseID}, "\x00")
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

package scabench

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// CycleCellCapture is one validated existing capture bundle associated with a
// planned slot. Native-comparison identities are added to the ledger only after
// the target-native phase has completed.
type CycleCellCapture struct {
	Repetition        int                            `json:"repetition"`
	TargetID          string                         `json:"target_id"`
	Engine            bench.Engine                   `json:"engine"`
	Outcome           bench.CycleAttemptOutcome      `json:"outcome"`
	ObservationState  bench.ObservationState         `json:"observation_state"`
	ScannerDispatches int                            `json:"scanner_dispatches"`
	Bundle            bench.ProtectedBundleReference `json:"protected_bundle"`
	Identity          BundleIdentity                 `json:"bundle_identity"`
	EvidenceIdentity  *bench.BundleEvidenceIdentity  `json:"evidence_identity,omitempty"`
	NativeEvidence    bench.NativeTargetEvidence     `json:"native_evidence"`
}

// CycleCellInput keeps all path-bearing input as data. It composes the existing
// Prepare, CapturePrepared/CaptureCapabilityPrepared, WriteBundle, and
// ValidateBundle primitives rather than adding a scanner engine.
type CycleCellInput struct {
	RepositoryRoot    string
	SourceFreeze      bench.SourceFreeze
	OracleCandidate   bench.OracleCandidate
	CrossCheck        bench.AutomatedCrossCheck
	Adjudication      bench.AdjudicationRecord
	AccountableReview bench.AccountableReview
	FinalOracleFreeze bench.FinalOracleFreeze
	Plan              bench.CyclePlan
	Repetition        int
	Catalog           bench.Catalog
	Manifest          CaptureManifest
	Output            string
	Retention         bench.ProtectedBundleDestination
	NativeEvidence    bench.NativeTargetEvidence
	Runner            ports.ToolRunner
}

func CaptureCycleCell(ctx context.Context, input CycleCellInput) (CycleCellCapture, error) {
	if err := ValidateCycleInputsAtRepository(input.RepositoryRoot, input.Plan, input.SourceFreeze, input.OracleCandidate, input.CrossCheck, input.Adjudication, input.AccountableReview, input.FinalOracleFreeze); err != nil {
		return CycleCellCapture{}, fmt.Errorf("validate frozen cycle inputs before capture: %w", err)
	}
	if err := input.Plan.Validate(); err != nil {
		return CycleCellCapture{}, err
	}
	if input.Repetition < 1 || input.Repetition > input.Plan.Repetitions {
		return CycleCellCapture{}, fmt.Errorf("cycle repetition is outside the plan")
	}
	cell, ok := plannedCycleCell(input.Plan, input.Manifest.TargetID, input.Manifest.Engine)
	if !ok {
		return CycleCellCapture{}, fmt.Errorf("capture manifest target and engine are not a planned cycle cell")
	}
	if err := input.Retention.Validate(); err != nil {
		return CycleCellCapture{}, err
	}
	if err := input.NativeEvidence.Validate(); err != nil {
		return CycleCellCapture{}, fmt.Errorf("validate target-native evidence: %w", err)
	}
	if input.NativeEvidence.TargetID != input.Manifest.TargetID {
		return CycleCellCapture{}, fmt.Errorf("target-native evidence does not bind the capture target")
	}
	prepared, err := Prepare(input.Catalog, input.Manifest)
	if err != nil {
		return CycleCellCapture{}, fmt.Errorf("prepare planned capture: %w", err)
	}
	defer func() { _ = prepared.Close() }()
	var result CaptureResult
	if input.Manifest.Capability != nil {
		result, err = CaptureCapabilityPrepared(prepared)
	} else {
		if input.Runner == nil {
			return CycleCellCapture{}, fmt.Errorf("planned scanner cell requires a runner")
		}
		result, err = NewCapturer(input.Runner).CapturePrepared(ctx, prepared)
	}
	if err != nil {
		return CycleCellCapture{}, fmt.Errorf("capture planned cell: %w", err)
	}
	if err := WriteBundle(input.Output, result); err != nil {
		return CycleCellCapture{}, fmt.Errorf("write planned bundle: %w", err)
	}
	if err := ValidateBundle(input.Output); err != nil {
		return CycleCellCapture{}, fmt.Errorf("validate published planned bundle: %w", err)
	}
	identity, err := BundleIdentityFromPath(input.Output)
	if err != nil {
		return CycleCellCapture{}, fmt.Errorf("identify planned bundle: %w", err)
	}
	protectedBundle, err := input.Retention.BindRootDigest(identity.RootDigest)
	if err != nil {
		return CycleCellCapture{}, fmt.Errorf("bind protected raw bundle to full evidence root: %w", err)
	}
	capture := CycleCellCapture{
		Repetition: input.Repetition, TargetID: input.Manifest.TargetID, Engine: input.Manifest.Engine,
		ObservationState: result.Observation().State, ScannerDispatches: cell.ScannerDispatches,
		Bundle: protectedBundle, Identity: identity, NativeEvidence: input.NativeEvidence,
	}
	if capture.ObservationState == cell.ExpectedState {
		evidenceIdentity, evidenceErr := CycleEvidenceIdentityFromBundle(identity, input.NativeEvidence)
		if evidenceErr != nil {
			return CycleCellCapture{}, fmt.Errorf("bind target-native evidence to bundle identity: %w", evidenceErr)
		}
		capture.Outcome = bench.CycleAttemptAccepted
		capture.EvidenceIdentity = &evidenceIdentity
		return capture, nil
	}
	if capture.ObservationState == bench.ObservationIncomplete || capture.ObservationState == bench.ObservationUnknown {
		// The bundle is valid evidence of an unsuccessful dispatch and must remain
		// retained for an explicit later retry rather than being discarded.
		capture.Outcome = bench.CycleAttemptFailed
		return capture, nil
	}
	return CycleCellCapture{}, fmt.Errorf("planned capture state %q does not match expected state %q", capture.ObservationState, cell.ExpectedState)
}

// ValidateCycleInputsAtRepository performs the pre-capture source, locator,
// digest, and symlink checks for a fresh cycle.
func ValidateCycleInputsAtRepository(repositoryRoot string, plan bench.CyclePlan, freeze bench.SourceFreeze, candidate bench.OracleCandidate, crossCheck bench.AutomatedCrossCheck, adjudication bench.AdjudicationRecord, review bench.AccountableReview, finalOracle bench.FinalOracleFreeze) error {
	if err := bench.ValidateCycleInputs(plan, freeze, candidate, crossCheck, adjudication, review, finalOracle); err != nil {
		return err
	}
	if err := VerifyFreshCycleAssets(repositoryRoot, freeze, candidate); err != nil {
		return err
	}
	if err := VerifyAccountableReviewCapture(repositoryRoot, review); err != nil {
		return fmt.Errorf("verify immutable accountable review capture: %w", err)
	}
	return nil
}

// BuildCycleLedger creates one accepted retained attempt per machine-readable
// captured slot. The caller cannot omit, duplicate, or substitute plan cells.
func BuildCycleLedger(plan bench.CyclePlan, captures []CycleCellCapture) (bench.CycleLedger, error) {
	if err := plan.Validate(); err != nil {
		return bench.CycleLedger{}, err
	}
	expected := make(map[string]bench.CycleCell, len(plan.Cells)*plan.Repetitions)
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		for _, cell := range plan.Cells {
			expected[fmt.Sprintf("%d\x00%s\x00%s", repetition, cell.TargetID, cell.Engine)] = cell
		}
	}
	groups := make(map[string][]CycleCellCapture, len(expected))
	seenRoots := make(map[string]struct{}, len(captures))
	for _, capture := range captures {
		key := fmt.Sprintf("%d\x00%s\x00%s", capture.Repetition, capture.TargetID, capture.Engine)
		cell, exists := expected[key]
		if !exists {
			return bench.CycleLedger{}, fmt.Errorf("captured slot is not in the plan")
		}
		if capture.ScannerDispatches != cell.ScannerDispatches || capture.Identity.TargetID != capture.TargetID || capture.Identity.Engine != capture.Engine || capture.Identity.RootDigest != capture.Bundle.Digest {
			return bench.CycleLedger{}, fmt.Errorf("captured slot does not bind its plan identity and retained bundle")
		}
		if err := capture.Bundle.Validate(); err != nil {
			return bench.CycleLedger{}, err
		}
		if err := capture.NativeEvidence.Validate(); err != nil || capture.NativeEvidence.TargetID != capture.TargetID {
			return bench.CycleLedger{}, fmt.Errorf("captured slot has invalid target-native evidence")
		}
		rootKey := key + "\x00" + capture.Bundle.Digest
		if _, duplicate := seenRoots[rootKey]; duplicate {
			return bench.CycleLedger{}, fmt.Errorf("captured attempt is duplicated")
		}
		seenRoots[rootKey] = struct{}{}
		if capture.Outcome == bench.CycleAttemptAccepted {
			if capture.ObservationState != cell.ExpectedState || capture.EvidenceIdentity == nil {
				return bench.CycleLedger{}, fmt.Errorf("accepted captured slot does not match the plan or evidence identity")
			}
			if err := capture.EvidenceIdentity.Validate(); err != nil || capture.EvidenceIdentity.TargetID != capture.TargetID || capture.EvidenceIdentity.Engine != capture.Engine {
				return bench.CycleLedger{}, fmt.Errorf("accepted captured slot has invalid evidence identity")
			}
			nativeDigest, err := bench.DigestNativeTargetEvidence(capture.NativeEvidence)
			if err != nil || capture.EvidenceIdentity.NativeComparisonDigest != nativeDigest {
				return bench.CycleLedger{}, fmt.Errorf("accepted captured slot has unbound target-native evidence")
			}
		} else if capture.Outcome != bench.CycleAttemptFailed && capture.Outcome != bench.CycleAttemptRetry || capture.EvidenceIdentity != nil {
			return bench.CycleLedger{}, fmt.Errorf("non-accepted captured slot has an invalid outcome or publication identity")
		}
		groups[key] = append(groups[key], capture)
	}
	planDigest, err := bench.DigestCyclePlan(plan)
	if err != nil {
		return bench.CycleLedger{}, err
	}
	ledger := bench.CycleLedger{SchemaVersion: bench.CycleLedgerSchemaVersion, CycleID: plan.CycleID, CyclePlanDigest: planDigest, Slots: make([]bench.CycleSlot, 0, len(expected))}
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		for _, cell := range plan.Cells {
			key := fmt.Sprintf("%d\x00%s\x00%s", repetition, cell.TargetID, cell.Engine)
			group := groups[key]
			if len(group) == 0 {
				return bench.CycleLedger{}, fmt.Errorf("captured slot is missing")
			}
			attempts := make([]bench.CycleAttempt, 0, len(group))
			for index, capture := range group {
				attemptID := bench.SHA256Digest([]byte(fmt.Sprintf("%s\n%s\n%d", key, capture.Bundle.Digest, index+1)))
				var evidence *bench.BundleEvidenceIdentity
				if capture.EvidenceIdentity != nil {
					copyIdentity := *capture.EvidenceIdentity
					evidence = &copyIdentity
				}
				attempts = append(attempts, bench.CycleAttempt{AttemptID: attemptID, Sequence: index + 1, Outcome: capture.Outcome, ObservationState: capture.ObservationState, ScannerDispatches: capture.ScannerDispatches, ProtectedBundle: capture.Bundle, EvidenceIdentity: evidence})
			}
			ledger.Slots = append(ledger.Slots, bench.CycleSlot{Repetition: repetition, TargetID: cell.TargetID, Engine: cell.Engine, ExpectedState: cell.ExpectedState, ScannerDispatches: cell.ScannerDispatches, Attempts: attempts})
		}
	}
	if err := ledger.ValidateAgainstPlan(plan); err != nil {
		return bench.CycleLedger{}, err
	}
	return ledger, nil
}

// FinalizeCycle reduces every planned repetition independently, applies the
// ratchet to each, and rejects drift. It never chooses a preferred repetition.
type CycleFinalizationInput struct {
	Plan          bench.CyclePlan
	Ledger        bench.CycleLedger
	Catalog       bench.Catalog
	Oracle        bench.Oracle
	Ratchet       bench.Ratchet
	Repetitions   [][]bench.Observation
	Comparisons   []SemanticBundleComparison
	FalsifierSpec bench.FalsifierSpec
	Falsifiers    []FalsifierResult
}

type CycleFinalization struct {
	Result      bench.Result
	ResultBytes []byte
	Rendered    []byte
}

func FinalizeCycle(input CycleFinalizationInput) (CycleFinalization, error) {
	if err := input.Plan.Validate(); err != nil {
		return CycleFinalization{}, err
	}
	if err := input.Ledger.ValidateAgainstPlan(input.Plan); err != nil {
		return CycleFinalization{}, err
	}
	oracleDigest, err := bench.DigestOracle(input.Oracle)
	if err != nil {
		return CycleFinalization{}, fmt.Errorf("digest final oracle: %w", err)
	}
	if oracleDigest != input.Plan.FinalOracleDigest {
		return CycleFinalization{}, fmt.Errorf("finalization oracle does not match the frozen final oracle digest")
	}
	if err := validateFinalizationComparisons(input.Plan, input.Comparisons); err != nil {
		return CycleFinalization{}, err
	}
	if err := validateFinalizationFalsifiers(input.FalsifierSpec, input.Falsifiers); err != nil {
		return CycleFinalization{}, err
	}
	if len(input.Repetitions) != input.Plan.Repetitions {
		return CycleFinalization{}, fmt.Errorf("finalization requires every planned repetition")
	}
	var expectedResult []byte
	var expectedRendered []byte
	var finalResult bench.Result
	for index, observations := range input.Repetitions {
		result, err := bench.Reduce(input.Catalog, input.Oracle, observations)
		if err != nil {
			return CycleFinalization{}, fmt.Errorf("reduce repetition %d: %w", index+1, err)
		}
		result, err = bench.ApplyRatchet(result, input.Ratchet)
		if err != nil {
			return CycleFinalization{}, fmt.Errorf("apply ratchet to repetition %d: %w", index+1, err)
		}
		var encoded bytes.Buffer
		if err := bench.EncodeResult(&encoded, result); err != nil {
			return CycleFinalization{}, fmt.Errorf("encode repetition %d result: %w", index+1, err)
		}
		var rendered bytes.Buffer
		if err := bench.RenderResult(&rendered, result); err != nil {
			return CycleFinalization{}, fmt.Errorf("render repetition %d: %w", index+1, err)
		}
		if index == 0 {
			expectedResult = encoded.Bytes()
			expectedRendered = rendered.Bytes()
			finalResult = result
			continue
		}
		if !bytes.Equal(expectedResult, encoded.Bytes()) || !bytes.Equal(expectedRendered, rendered.Bytes()) {
			return CycleFinalization{}, fmt.Errorf("repetition %d reduction differs from the complete cycle", index+1)
		}
	}
	return CycleFinalization{Result: finalResult, ResultBytes: append([]byte(nil), expectedResult...), Rendered: append([]byte(nil), expectedRendered...)}, nil
}

func validateFinalizationComparisons(plan bench.CyclePlan, comparisons []SemanticBundleComparison) error {
	if len(comparisons) != len(plan.Cells) {
		return fmt.Errorf("finalization requires one validated comparison for every planned cell")
	}
	allowed := make(map[bench.Engine]int, len(plan.Cells))
	for _, cell := range plan.Cells {
		allowed[cell.Engine]++
	}
	seen := make(map[bench.Engine]int, len(comparisons))
	for _, comparison := range comparisons {
		if comparison.SchemaVersion != semanticBundleComparisonSchema || comparison.Engine == "" || !comparison.SemanticEqual || len(comparison.UnclassifiedDifferences) != 0 {
			return fmt.Errorf("finalization comparison is not a validated semantic equality")
		}
		if comparison.Left.RootDigest == "" || comparison.Right.RootDigest == "" || comparison.Left.RootDigest == comparison.Right.RootDigest {
			return fmt.Errorf("finalization comparison does not retain distinct raw roots")
		}
		seen[comparison.Engine]++
	}
	for engine, count := range allowed {
		if seen[engine] != count {
			return fmt.Errorf("finalization comparisons do not cover planned engine %q", engine)
		}
	}
	return nil
}

func validateFinalizationFalsifiers(spec bench.FalsifierSpec, results []FalsifierResult) error {
	if err := validateExecutableFalsifierSpec(spec); err != nil {
		return err
	}
	if len(results) != len(spec.Entries) {
		return fmt.Errorf("finalization requires every executable falsifier result")
	}
	byID := make(map[string]FalsifierResult, len(results))
	for _, result := range results {
		if result.ID == "" || result.BaselineDigest == "" || result.MutationDigest == "" || result.BaselineDigest == result.MutationDigest || result.ReasonCode == "" {
			return fmt.Errorf("finalization falsifier result is incomplete")
		}
		if _, exists := byID[result.ID]; exists {
			return fmt.Errorf("finalization falsifier result %q is duplicated", result.ID)
		}
		byID[result.ID] = result
	}
	for _, entry := range spec.Entries {
		result, exists := byID[entry.ID]
		if !exists || result.Capability != entry.Capability || result.Engine != entry.Engine || result.Baseline != entry.Baseline || result.Mutation != entry.Mutation || result.Operation != entry.Operation || result.ExpectedOutcome != entry.ExpectedOutcome || result.ObservedOutcome != entry.ExpectedOutcome {
			return fmt.Errorf("finalization falsifier %q does not match its executable specification", entry.ID)
		}
		if result.ObservedOutcome == "rejected" && result.Reason == "" {
			return fmt.Errorf("finalization rejected falsifier %q lacks a reason", entry.ID)
		}
	}
	return nil
}

// WriteSourceFreezeRecord creates an immutable freeze record. Existing paths
// are refused rather than amended.
func WriteSourceFreezeRecord(path string, freeze bench.SourceFreeze) error {
	if err := freeze.Validate(); err != nil {
		return err
	}
	return writeCycleRecord(path, freeze)
}

// WritePublicationManifestRecord creates an immutable publication manifest.
func WritePublicationManifestRecord(path string, plan bench.CyclePlan, manifest bench.PublicationManifest) error {
	if err := manifest.ValidateAgainstPlan(plan); err != nil {
		return err
	}
	return writeCycleRecord(path, manifest)
}

func writeCycleRecord(path string, value any) error {
	if filepath.Clean(path) == "." || path == "" {
		return fmt.Errorf("cycle record path is required")
	}
	body, err := bench.CanonicalJSON(value)
	if err != nil {
		return fmt.Errorf("encode cycle record: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("cycle record already exists")
		}
		return fmt.Errorf("create cycle record: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(append(body, '\n')); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write cycle record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("sync cycle record: %w", err)
	}
	return nil
}

func plannedCycleCell(plan bench.CyclePlan, targetID string, engine bench.Engine) (bench.CycleCell, bool) {
	for _, cell := range plan.Cells {
		if cell.TargetID == targetID && cell.Engine == engine {
			return cell, true
		}
	}
	return bench.CycleCell{}, false
}

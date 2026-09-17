package reachbench

import (
	"bytes"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestStrictDecodeAndCanonicalDigests(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"synapse-reachability-measurement-input-v2","schema_version":"other"}`,
		`{"schema_version":"synapse-reachability-measurement-input-v2"} {}`,
		`{"schema_version":"synapse-reachability-measurement-input-v2","unknown":true}`,
	} {
		if _, err := DecodeMeasurementInput(strings.NewReader(raw)); err == nil {
			t.Fatalf("DecodeMeasurementInput accepted %q", raw)
		}
	}

	input := fixtureInput(t)
	left := input.Corpus
	right := input.Corpus
	right.Cases[0], right.Cases[len(right.Cases)-1] = right.Cases[len(right.Cases)-1], right.Cases[0]
	leftDigest, err := DigestContractCorpus(left)
	if err != nil {
		t.Fatalf("DigestContractCorpus(left): %v", err)
	}
	rightDigest, err := DigestContractCorpus(right)
	if err != nil {
		t.Fatalf("DigestContractCorpus(right): %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("canonical corpus digest drifted: %s != %s", leftDigest, rightDigest)
	}
}

func TestInventoryHasEveryProductionCohortAndHonestBindings(t *testing.T) {
	inventory := DefaultProductionInventory()
	if err := inventory.Validate(); err != nil {
		t.Fatalf("DefaultProductionInventory: %v", err)
	}
	if len(inventory.Cohorts) != len(requiredProductionCohorts) {
		t.Fatalf("production cohort count = %d, want %d", len(inventory.Cohorts), len(requiredProductionCohorts))
	}
	for _, cohort := range inventory.Cohorts {
		for _, binding := range cohort.Bindings {
			if binding.State != BindingEnabled && binding.Reason == "" {
				t.Fatalf("%s/%s %s has no non-enabled reason", cohort.ID, cohort.Mode, binding.ID)
			}
		}
	}
}

func TestRejectsDuplicateIDsReferencesAndConflictingRawObservations(t *testing.T) {
	input := fixtureInput(t)
	duplicateCase := input.Corpus.Cases[0]
	input.Corpus.Cases = append(input.Corpus.Cases, duplicateCase)
	if err := input.Corpus.Validate(); err == nil {
		t.Fatal("duplicate corpus case was accepted")
	}

	input = fixtureInput(t)
	input.Observations = append(input.Observations, input.Observations[0])
	if _, err := EvaluateMeasurement(input); err == nil || !strings.Contains(err.Error(), "duplicate raw") {
		t.Fatalf("duplicate raw observation error = %v", err)
	}

	input = fixtureInput(t)
	input.Policy.Rules = append(input.Policy.Rules, input.Policy.Rules[0])
	if err := input.Policy.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate policy rule error = %v", err)
	}

	input = fixtureInput(t)
	input.Policy.Rules = append(input.Policy.Rules, SuppressionPolicyRule{CohortID: "not-inventory", ModeID: "mode", Disposition: SuppressionRaiseOnly})
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "non-inventory") {
		t.Fatalf("extra policy cohort rule error = %v", err)
	}
}

func TestPreservesExecutionDenominatorsAndDoesNotTreatMissingAsNoAnalysis(t *testing.T) {
	input := fixtureInput(t)
	input.Observations = input.Observations[:3]
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement: %v", err)
	}
	if report.RequiredExecutions != 4 || report.ObservedExecutions != 3 || report.UnobservedExecutions != 1 {
		t.Fatalf("execution denominator = required=%d observed=%d missing=%d", report.RequiredExecutions, report.ObservedExecutions, report.UnobservedExecutions)
	}
	goSummary := cohortSummary(t, report, "go", "source_tier2")
	if goSummary.Assessment != NotAssessed {
		t.Fatalf("missing execution assessment = %q", goSummary.Assessment)
	}
	if report.NoAnalysis != 0 {
		t.Fatalf("unobserved execution became no_analysis: %d", report.NoAnalysis)
	}
}

func TestPresentUnreachedDoesNotImplySuppression(t *testing.T) {
	report, err := EvaluateMeasurement(fixtureInput(t))
	if err != nil {
		t.Fatalf("EvaluateMeasurement: %v", err)
	}
	if report.Suppressions.Eligible != 1 || report.Suppressions.Produced != 0 || report.Suppressions.Valid != 0 {
		t.Fatalf("suppression metrics = %+v", report.Suppressions)
	}
	if report.Suppressions.Status != RatioAvailable || !report.Safety.Pass {
		t.Fatalf("unproduced, complete capture must be safe but non-passing recall: %+v safety=%+v", report.Suppressions, report.Safety)
	}
}

func TestIncompleteCaptureIsNeverZeroSuppressionAuthority(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-unreached" {
			input.Observations[i].Suppression.Status = CaptureIncomplete
		}
	}
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement: %v", err)
	}
	if report.Suppressions.Status != RatioUnavailable || report.Safety.Pass {
		t.Fatalf("incomplete capture must remove suppression authority: metrics=%+v safety=%+v", report.Suppressions, report.Safety)
	}
}

func TestBaselineRecordsUnsafeEvidenceAndCandidateRejectsIt(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID != "go-unreached" {
			continue
		}
		input.Observations[i].Suppression = SuppressionCapture{
			Claim: SuppressionProduced, Status: CaptureComplete,
			Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: fixtureProof(input, "go-unreached", "api", false)}},
		}
	}
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("baseline must preserve unsafe historical evidence, got %v", err)
	}
	if baseline.Suppressions.Invalid != 1 || baseline.Safety.Pass {
		t.Fatalf("baseline unsafe evidence = suppressions=%+v safety=%+v", baseline.Suppressions, baseline.Safety)
	}

	candidate := candidateInput(t, input, baseline)
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("candidate evaluation must report rejection rather than erase evidence: %v", err)
	}
	if report.Candidate.Accepted || !contains(report.Candidate.Reasons, "candidate produced false or invalid suppressions") {
		t.Fatalf("candidate did not reject invalid suppression: %+v", report.Candidate)
	}
}

func TestFalseSuppressionRemainsDiagnosticInBaselineAndFailsCandidate(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-reachable" {
			input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: fixtureProof(input, "go-reachable", "api", true)}}}
		}
	}
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("baseline false suppression: %v", err)
	}
	if baseline.Suppressions.False != 1 || baseline.Safety.Pass {
		t.Fatalf("baseline did not retain false suppression: %+v %+v", baseline.Suppressions, baseline.Safety)
	}
	candidate := candidateInput(t, input, baseline)
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("candidate false suppression: %v", err)
	}
	if report.Candidate.Accepted || !contains(report.Candidate.Reasons, "candidate produced false or invalid suppressions") {
		t.Fatalf("candidate accepted false suppression: %+v", report.Candidate)
	}
}

func TestPolicyValidatesInitialSuppressionPermissions(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Policy.Rules {
		rule := &input.Policy.Rules[i]
		if rule.CohortID == "javascript" && rule.ModeID == "lexical" {
			rule.Disposition = SuppressionEligible
			rule.CompletenessContract = refPointer(fixtureReference("js-contract"))
			rule.ApprovedProposer = "proposer"
			rule.ApprovedVerifier = "verifier"
		}
	}
	if err := input.Policy.Validate(); err == nil || !strings.Contains(err.Error(), "runtime/deployment") {
		t.Fatalf("javascript default raise-only policy was weakened: %v", err)
	}
}

func TestRejectsStaleProofAndMismatchedAnalyzerConfiguration(t *testing.T) {
	for _, mutate := range []func(*SuppressionProof){
		func(proof *SuppressionProof) { proof.Snapshot.Source = fixtureReference("stale-source") },
		func(proof *SuppressionProof) { proof.Analyzer = fixtureReference("other-analyzer") },
	} {
		input := fixtureInput(t)
		for i := range input.Observations {
			if input.Observations[i].CaseID == "go-unreached" {
				proof := fixtureProof(input, "go-unreached", "api", true)
				mutate(&proof)
				input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: proof}}}
			}
		}
		report, err := EvaluateMeasurement(input)
		if err != nil {
			t.Fatalf("baseline measurement rejected diagnostic invalid proof: %v", err)
		}
		if report.Suppressions.Invalid != 1 || report.Safety.Pass {
			t.Fatalf("stale or mismatched proof was accepted: %+v %+v", report.Suppressions, report.Safety)
		}
	}
}

func TestDuplicateRootsDoNotInflateC2Credit(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Inventory.Cohorts {
		if input.Inventory.Cohorts[i].ID == "go" && input.Inventory.Cohorts[i].Mode == "source_tier2" {
			input.Inventory.Cohorts[i].Bindings = append(input.Inventory.Cohorts[i].Bindings, CompositionBinding{ID: "api-duplicate", Root: "synapse-api", BoundaryID: "sca/reachability/go-source-tier2/api-duplicate", Configuration: fixtureReference("go-source-tier2-api-duplicate-config"), State: BindingEnabled})
		}
	}
	for _, observation := range append([]MeasuredObservation(nil), input.Observations...) {
		observation.BindingID = "api-duplicate"
		observation.Configuration = fixtureReference("go-source-tier2-api-duplicate-config")
		input.Observations = append(input.Observations, observation)
	}
	refreshPolicyReferences(t, &input)
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("EvaluateMeasurement: %v", err)
	}
	if report.C2.ProductionBreadth != 1 || report.C2.CorrectPositiveCases != 2 {
		t.Fatalf("duplicate root inflated semantic C2: %+v", report.C2)
	}
}

func TestStrictC2AndMandatoryGuards(t *testing.T) {
	baseline := C2Vector{ProductionBreadth: 1, CorrectPositiveCases: 2, MacroReachableRecall: ratioFromCounts(1, 2)}
	if strictlyGreaterC2(baseline, baseline) {
		t.Fatal("equal C2 vector passed")
	}
	if !strictlyGreaterC2(C2Vector{ProductionBreadth: 1, CorrectPositiveCases: 3, MacroReachableRecall: ratioFromCounts(1, 2)}, baseline) {
		t.Fatal("strict positive improvement did not pass")
	}

	candidate := MeasurementReport{Purpose: CandidateAcceptance, RatchetDigest: "sha256:" + strings.Repeat("a", 64), C2: C2Vector{ProductionBreadth: 2, CorrectPositiveCases: 5, MacroReachableRecall: ratioFromCounts(1, 1)}, Reachability: ReachabilityMetrics{Precision: ratioFromCounts(1, 2)}, Suppressions: SuppressionMetrics{}, Safety: SafetyDisposition{Pass: true}, Cohorts: []CohortSummary{{CohortID: "go", ModeID: "source_tier2", BenchmarkRequired: true, Assessment: Assessed, Reachability: ReachabilityMetrics{Recall: ratioFromCounts(1, 2)}}}, Languages: []LanguageSummary{{Language: "go", Reachability: ReachabilityMetrics{Recall: ratioFromCounts(1, 2)}}}}
	ratchet := CandidateRatchet{ID: candidate.RatchetDigest, C2: baseline, Reachability: ReachabilityMetrics{Precision: ratioFromCounts(1, 1)}, Cohorts: []RatchetCohort{{CohortID: "go", ModeID: "source_tier2", Recall: ratioFromCounts(1, 1)}}, Languages: []RatchetLanguage{{Language: "go", Recall: ratioFromCounts(1, 1)}}}
	reasons := CheckCandidateAcceptance(candidate, ratchet, ExceptionManifest{SchemaVersion: ExceptionManifestSchemaVersion, ID: "none"})
	if !contains(reasons, "reachable precision regressed") || !contains(reasons, "cohort go/source_tier2 reachable recall regressed") || !contains(reasons, "language go reachable recall regressed") {
		t.Fatalf("higher C2 offset a mandatory guard: %v", reasons)
	}
}

func TestLegacyConversionPreservesBytesLabelsAndCannotEnterAcceptance(t *testing.T) {
	raw := []byte(`{"schema_version":"synapse-reachability-input-v1","corpus":{"schema_version":"synapse-reachability-corpus-v1","cases":[{"name":"go-hit","language":"go","fixture":"fixture","symbol":"fixture.hit","expected":"reachable"}]},"observations":[{"case":"go-hit","label":"reachable"}]}`)
	legacy, err := ImportLegacyInput(raw)
	if err != nil {
		t.Fatalf("ImportLegacyInput: %v", err)
	}
	if !bytes.Equal(legacy.OriginalBytes, raw) || legacy.OriginalDigest != benchmark.SHA256Digest(raw) || len(legacy.Labels) != 1 || legacy.Labels[0].Label != Reachable {
		t.Fatalf("legacy conversion lost evidence: %+v", legacy)
	}
	if legacy.Coverage != LegacyUnavailable || legacy.SuppressionCapture != LegacyUnavailable || legacy.Authority != LegacyUnavailable {
		t.Fatalf("legacy limitations were not explicit: %+v", legacy)
	}

	v1, err := DecodeInput(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("DecodeInput: %v", err)
	}
	corpus, oracle, err := ImportLegacyCorpus(v1.Corpus)
	if err != nil {
		t.Fatalf("ImportLegacyCorpus: %v", err)
	}
	if oracle.Cases[0].Expected != OutcomeReachable || corpus.Cases[0].LegacyOrigin == nil || corpus.Cases[0].CohortID != "legacy" || corpus.Cases[0].ModeID != "v1" || oracle.Cases[0].Category != OracleNoCoverage {
		t.Fatalf("v1 label was reinterpreted as modern production evidence: %+v %+v", corpus, oracle)
	}
	input := fixtureInput(t)
	input.Corpus = corpus
	input.Oracle = oracle
	input.Observations = nil
	refreshPolicyReferences(t, &input)
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "legacy v1") {
		t.Fatalf("legacy migration entered a contract acceptance input: %v", err)
	}
}

func TestProceduralCheckpointAndAcyclicRatchet(t *testing.T) {
	input := fixtureInput(t)
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	checkpoint := fixtureCheckpoint(t, input.Policy, baseline)
	if err := checkpoint.Validate(input.Policy, baseline); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	bad := checkpoint
	bad.Reviewer = bad.Producer
	if err := bad.Validate(input.Policy, baseline); err == nil {
		t.Fatal("checkpoint accepted same producer and reviewer")
	}
	bad = checkpoint
	bad.OriginAuthenticated = true
	if err := bad.Validate(input.Policy, baseline); err == nil {
		t.Fatal("procedural checkpoint claimed external origin authentication")
	}
	bad = checkpoint
	bad.BaselineResult = fixtureReference("unbound-result")
	if err := bad.Validate(input.Policy, baseline); err == nil {
		t.Fatal("checkpoint accepted unbound baseline reference")
	}
	ratchet, err := DeriveCandidateRatchet(input.Policy, baseline, checkpoint, input.Exceptions)
	if err != nil {
		t.Fatalf("DeriveCandidateRatchet: %v", err)
	}
	if baseline.RatchetDigest != "" || ratchet.BaselineResult.Digest != baseline.ID || ratchet.Policy.Digest != baseline.Policy.Digest {
		t.Fatalf("acyclic baseline/ratchet binding = baseline=%+v ratchet=%+v", baseline, ratchet)
	}
}

func TestAssessmentDoesNotChangePolicyIdentity(t *testing.T) {
	input := fixtureInput(t)
	before, err := DigestMeasurementPolicy(input.Policy)
	if err != nil {
		t.Fatal(err)
	}
	full, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Observations = input.Observations[:3]
	partial, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if cohortSummary(t, full, "go", "source_tier2").Assessment != Assessed || cohortSummary(t, partial, "go", "source_tier2").Assessment != NotAssessed {
		t.Fatal("assessment was not derived from each report")
	}
	after, err := DigestMeasurementPolicy(input.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("derived assessment changed measurement policy identity: %s != %s", before, after)
	}
}

func TestC2BreadthUsesOracleCategoriesRatherThanPublicLabels(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Oracle.Cases {
		if input.Oracle.Cases[i].CaseID == "go-conditional" {
			input.Oracle.Cases[i].Expected = OutcomeReachable
		}
	}
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-conditional" {
			input.Observations[i].Outcome = OutcomeReachable
		}
	}
	refreshPolicyReferences(t, &input)
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.C2.ProductionBreadth != 1 {
		t.Fatalf("semantic categories with a missing public label lost C2 breadth: %+v", report.C2)
	}

	input = fixtureInput(t)
	for i := range input.Oracle.Cases {
		if input.Oracle.Cases[i].CaseID == "go-conditional" {
			input.Oracle.Cases[i].Category = OracleReachable
		}
	}
	refreshPolicyReferences(t, &input)
	report, err = EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.C2.ProductionBreadth != 0 {
		t.Fatalf("public labels substituted for required oracle categories: %+v", report.C2)
	}

	input = fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-conditional" {
			input.Observations[i].Outcome = OutcomeReachable
		}
	}
	report, err = EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.C2.CorrectPositiveCases != 1 || !sameRatio(report.C2.MacroReachableRecall, ratioFromCounts(1, 1)) {
		t.Fatalf("C2 macro recall used exact-label positives rather than positive-family recall: %+v", report.C2)
	}
}

func TestRejectsForgedSuppressionProofSubjectAndBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*SuppressionProof){
		"subject":  func(proof *SuppressionProof) { proof.SubjectID = "forged-subject" },
		"boundary": func(proof *SuppressionProof) { proof.BoundaryID = "forged-boundary" },
	} {
		t.Run(name, func(t *testing.T) {
			input := fixtureInput(t)
			for i := range input.Observations {
				if input.Observations[i].CaseID == "go-unreached" {
					proof := fixtureProof(input, "go-unreached", "api", true)
					mutate(&proof)
					input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: proof}}}
				}
			}
			report, err := EvaluateMeasurement(input)
			if err != nil {
				t.Fatal(err)
			}
			if report.Suppressions.Invalid != 1 || report.Safety.Pass {
				t.Fatalf("forged %s proof was accepted: %+v %+v", name, report.Suppressions, report.Safety)
			}
		})
	}
}

func TestIncompletePositiveGetsNoMetricOrC2Credit(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-reachable" {
			input.Observations[i].OutputCapture = CaptureIncomplete
		}
	}
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	cohort := cohortSummary(t, report, "go", "source_tier2")
	if cohort.Reachability.Found != 1 || cohort.CorrectPositiveCases != 1 || cohort.Assessment != NotAssessed || report.C2.ProductionBreadth != 0 {
		t.Fatalf("incomplete positive output received credit: cohort=%+v c2=%+v", cohort, report.C2)
	}
}

func TestCountsProducedSuppressionWhenAnotherBindingProducesNone(t *testing.T) {
	input := fixtureInput(t)
	for i := range input.Inventory.Cohorts {
		if input.Inventory.Cohorts[i].ID == "go" && input.Inventory.Cohorts[i].Mode == "source_tier2" {
			input.Inventory.Cohorts[i].Bindings = append(input.Inventory.Cohorts[i].Bindings, CompositionBinding{ID: "api-shadow", Root: "synapse-api", BoundaryID: "sca/reachability/go-source-tier2/api-shadow", Configuration: fixtureReference("go-source-tier2-api-shadow-config"), State: BindingEnabled})
		}
	}
	for _, observation := range append([]MeasuredObservation(nil), input.Observations...) {
		observation.BindingID = "api-shadow"
		observation.Configuration = fixtureReference("go-source-tier2-api-shadow-config")
		input.Observations = append(input.Observations, observation)
	}
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-unreached" && input.Observations[i].BindingID == "api" {
			input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: fixtureProof(input, "go-unreached", "api", true)}}}
		}
	}
	refreshPolicyReferences(t, &input)
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Suppressions.Produced != 1 || report.Suppressions.Valid != 1 || report.Suppressions.False != 0 || report.Suppressions.Invalid != 0 {
		t.Fatalf("one produced binding was hidden by another none binding: %+v", report.Suppressions)
	}
}

func TestRatchetRejectsCopiedIDAndBindingRecallRegression(t *testing.T) {
	input := fixtureInput(t)
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateInput(t, input, baseline)
	tampered := *candidate.Ratchet
	tampered.Cohorts[0].Recall = ratioFromCounts(0, 1)
	candidate.Ratchet = &tampered
	if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "candidate ratchet") {
		t.Fatalf("ratchet with copied ID was accepted: %v", err)
	}

	candidate = candidateInput(t, input, baseline)
	tampered = *candidate.Ratchet
	tampered.Cohorts[0].Recall = ratioFromCounts(0, 1)
	tampered.ID, err = DigestCandidateRatchet(tampered)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Ratchet = &tampered
	if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "deterministic derivative") {
		t.Fatalf("self-digested but non-derived ratchet was accepted: %v", err)
	}

	candidate = candidateInput(t, input, baseline)
	for i := range candidate.Observations {
		if candidate.Observations[i].CaseID == "go-reachable" {
			candidate.Observations[i].Outcome = OutcomePresentUnreached
		}
	}
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(report.Candidate.Reasons, "binding go/source_tier2/api reachable recall regressed") {
		t.Fatalf("binding recall regression was not guarded: %+v", report.Candidate)
	}
}

func TestRatioStatusOrderingAndReplayRetention(t *testing.T) {
	if compareRatios(Ratio{Status: RatioAvailable, Numerator: "0", Denominator: "1"}, notApplicableRatio()) <= 0 || compareRatios(notApplicableRatio(), unavailableRatio()) <= 0 || compareRatios(notApplicableRatio(), Ratio{Status: RatioAvailable, Numerator: "0", Denominator: "1"}) >= 0 {
		t.Fatal("ratio availability status ordering is not antisymmetric")
	}
	if err := (Ratio{Status: RatioAvailable, Numerator: "-1", Denominator: "1"}).Validate(); err == nil {
		t.Fatal("negative exact ratio numerator was accepted")
	}

	input := fixtureInput(t)
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Observations) != len(input.Observations) {
		t.Fatalf("baseline did not retain normalized observations: %d", len(baseline.Observations))
	}
	duplicateSummary := baseline
	duplicateSummary.Cohorts = append(duplicateSummary.Cohorts, duplicateSummary.Cohorts[0])
	duplicateSummary.ID, err = DigestMeasurementReport(duplicateSummary)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicateSummary.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate cohort") {
		t.Fatalf("report accepted duplicate structural summary: %v", err)
	}
	tampered := baseline
	tampered.Observations[0].Outcome = OutcomeNoAnalysis
	id, err := DigestMeasurementReport(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tampered.ID = id
	if err := tampered.Validate(); err != nil {
		t.Fatalf("structurally valid tampered replay fixture: %v", err)
	}
	candidate := candidateInput(t, input, tampered)
	if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), "reducer replay") {
		t.Fatalf("candidate trusted stored baseline metrics without replay: %v", err)
	}
}

func TestInitialPermissionsAndInventoryBindingsAreExact(t *testing.T) {
	inventory := DefaultProductionInventory()
	for _, target := range []struct {
		cohort, mode string
	}{
		{"rust", "symbols_tier2"},
		{"php", "symbols_tier2"},
		{"ruby", "symbols_tier2"},
		{"dotnet", "symbols_tier2"},
	} {
		cohort, ok := inventory.cohort(cohortKey(target.cohort, target.mode))
		if !ok || !cohort.DefaultEnabled {
			t.Fatalf("%s/%s is not default enabled: %+v", target.cohort, target.mode, cohort)
		}
	}
	coarse, ok := inventory.cohort("jvm/coarse")
	if !ok || bindingState(coarse, "worker") != BindingEnabled || bindingState(coarse, "cli") != BindingEnabled {
		t.Fatalf("JVM coarse bindings do not match composition facts: %+v", coarse)
	}
	tier2, ok := inventory.cohort("jvm/tier2")
	if !ok || bindingState(tier2, "worker") != BindingEnabled || bindingState(tier2, "cli") != BindingNotWired {
		t.Fatalf("JVM tier2 bindings do not match composition facts: %+v", tier2)
	}

	for _, target := range []struct {
		cohort, mode string
		expectError  string
	}{
		{"rust", "import", "suppression_prohibited"},
		{"ruby", "import", "suppression_prohibited"},
		{"rust", "symbols_tier2", "raise_only"},
		{"ruby", "symbols_tier2", "raise_only"},
		{"php", "symbols_tier2", "raise_only"},
		{"dotnet", "symbols_tier2", "raise_only"},
	} {
		input := fixtureInput(t)
		for i := range input.Policy.Rules {
			rule := &input.Policy.Rules[i]
			if rule.CohortID == target.cohort && rule.ModeID == target.mode {
				rule.Disposition = SuppressionEligible
				rule.CompletenessContract = refPointer(fixtureReference("test-contract"))
				rule.ApprovedProposer, rule.ApprovedVerifier = "proposer", "verifier"
			}
		}
		if err := input.Policy.Validate(); err == nil || !strings.Contains(err.Error(), target.expectError) {
			t.Fatalf("%s/%s eligibility error = %v", target.cohort, target.mode, err)
		}
	}

	input := fixtureInput(t)
	for i := range input.Policy.Rules {
		rule := &input.Policy.Rules[i]
		if rule.CohortID == "php" && rule.ModeID == "import" {
			rule.Disposition = SuppressionEligible
			rule.CompletenessContract = refPointer(fixtureReference("php-contract"))
			rule.ApprovedProposer, rule.ApprovedVerifier = "proposer", "verifier"
		}
	}
	if err := input.Policy.Validate(); err == nil || !strings.Contains(err.Error(), "Composer") {
		t.Fatalf("PHP import eligibility skipped Composer completeness: %v", err)
	}
	for i := range input.Policy.Rules {
		if input.Policy.Rules[i].CohortID == "php" && input.Policy.Rules[i].ModeID == "import" {
			input.Policy.Rules[i].ComposerBootstrapComplete = true
		}
	}
	if err := input.Policy.Validate(); err != nil {
		t.Fatalf("PHP import with Composer completeness was not potentially eligible: %v", err)
	}

	input = fixtureInput(t)
	for i := range input.Policy.Rules {
		rule := &input.Policy.Rules[i]
		if rule.CohortID == "dotnet" && rule.ModeID == "build_aware_import" {
			rule.Disposition = SuppressionEligible
			rule.CompletenessContract = refPointer(fixtureReference("dotnet-contract"))
			rule.ApprovedProposer, rule.ApprovedVerifier = "proposer", "verifier"
		}
	}
	if err := input.Policy.Validate(); err != nil {
		t.Fatalf(".NET build-aware import was not potentially eligible: %v", err)
	}
}

func TestCandidateAllowsDistinctSnapshotsAndReplaysBaseline(t *testing.T) {
	input := fixtureInput(t)
	baseline, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	candidate := candidateInput(t, input, baseline)
	candidate.ActiveSnapshot = SnapshotIdentity{
		Source: fixtureReference("candidate-source"),
		SBOM:   fixtureReference("candidate-sbom"),
		Run:    fixtureReference("candidate-run"),
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("candidate with a distinct snapshot was rejected: %v", err)
	}
	report, err := EvaluateMeasurement(candidate)
	if err != nil {
		t.Fatalf("candidate with a distinct snapshot: %v", err)
	}
	if !sameSnapshot(report.ActiveSnapshot, candidate.ActiveSnapshot) || sameSnapshot(baseline.ActiveSnapshot, candidate.ActiveSnapshot) {
		t.Fatalf("baseline and candidate snapshots were not kept distinct: baseline=%+v candidate=%+v report=%+v", baseline.ActiveSnapshot, candidate.ActiveSnapshot, report.ActiveSnapshot)
	}
}

func TestSubjectIDsPermitPackageAndSymbolPunctuation(t *testing.T) {
	accepted := "pkg:golang/example.com/acme/lib@v1.2.3?arch=amd64#Example.(*Type).Method%2A"
	if !validSubjectID(accepted) || validID(accepted) {
		t.Fatalf("subject validator did not distinguish package/symbol identity from strict IDs: %q", accepted)
	}

	input := fixtureInput(t)
	for i := range input.Corpus.Cases {
		if input.Corpus.Cases[i].ID == "go-unreached" {
			input.Corpus.Cases[i].SubjectID = accepted
		}
	}
	refreshPolicyReferences(t, &input)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-unreached" {
			input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: fixtureProof(input, "go-unreached", "api", true)}}}
		}
	}
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatalf("punctuated subject was rejected: %v", err)
	}
	if report.Suppressions.Valid != 1 {
		t.Fatalf("proof did not preserve punctuated subject identity: %+v", report.Suppressions)
	}

	for name, subject := range map[string]string{
		"empty":          "",
		"leading-space":  " subject",
		"trailing-space": "subject ",
		"control":        "subject\x00id",
		"invalid-utf8":   string([]byte{'s', 0xff}),
		"oversized":      strings.Repeat("a", maxSubjectIDBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixtureInput(t).Corpus
			candidate.Cases[0].SubjectID = subject
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid subject %q was accepted", subject)
			}
		})
	}
}

func TestRejectsInconsistentSuppressionApplicableOracle(t *testing.T) {
	for name, mutate := range map[string]func(*OracleCase){
		"wrong-category":                 func(item *OracleCase) { item.Category = OracleOpaque },
		"wrong-outcome":                  func(item *OracleCase) { item.Expected = OutcomeNoAnalysis },
		"incomplete-coverage":            func(item *OracleCase) { item.CoverageExpectation = CoveragePartial },
		"missing-contract":               func(item *OracleCase) { item.CompletenessContract = nil },
		"contract-without-applicability": func(item *OracleCase) { item.SuppressionApplicable = false },
	} {
		t.Run(name, func(t *testing.T) {
			oracle := fixtureInput(t).Oracle
			for i := range oracle.Cases {
				if oracle.Cases[i].CaseID == "go-unreached" {
					mutate(&oracle.Cases[i])
				}
			}
			if err := oracle.Validate(); err == nil {
				t.Fatal("inconsistent suppression applicability was accepted")
			}
		})
	}
}

func TestPinsBindingConfigurationAndCohortSpecificBoundary(t *testing.T) {
	input := fixtureInput(t)
	input.Observations[0].Configuration = fixtureReference("wrong-binding-configuration")
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "configuration does not match production binding") {
		t.Fatalf("observation configuration mismatch was accepted: %v", err)
	}

	inventory := DefaultProductionInventory()
	cohort, ok := inventory.cohort("go/source_tier2")
	if !ok {
		t.Fatal("inventory lacks go/source_tier2")
	}
	for i := range inventory.Cohorts {
		if inventory.Cohorts[i].ID != cohort.ID || inventory.Cohorts[i].Mode != cohort.Mode {
			continue
		}
		for j := range inventory.Cohorts[i].Bindings {
			if inventory.Cohorts[i].Bindings[j].ID == "api" {
				inventory.Cohorts[i].Bindings[j].BoundaryID = "sca/default-scan/api"
			}
		}
	}
	if err := inventory.Validate(); err == nil || !strings.Contains(err.Error(), "cohort-specific boundary") {
		t.Fatalf("generic root boundary was accepted: %v", err)
	}

	input = fixtureInput(t)
	for i := range input.Observations {
		if input.Observations[i].CaseID == "go-unreached" {
			proof := fixtureProof(input, "go-unreached", "api", true)
			proof.BoundaryID = "sca/default-scan/api"
			input.Observations[i].Suppression = SuppressionCapture{Claim: SuppressionProduced, Status: CaptureComplete, Effects: []SuppressionEffect{{Kind: EffectSuppressingJudgment, Proof: proof}}}
		}
	}
	report, err := EvaluateMeasurement(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Suppressions.Invalid != 1 || report.Safety.Pass {
		t.Fatalf("proof against generic root boundary was accepted: %+v %+v", report.Suppressions, report.Safety)
	}
}

func bindingState(cohort ProductionCohort, id string) BindingState {
	binding, _ := findBinding(cohort, id)
	return binding.State
}

func fixtureInput(t *testing.T) MeasurementInput {
	t.Helper()
	inventory := DefaultProductionInventory()
	corpus := ContractCorpus{SchemaVersion: ContractCorpusSchemaVersion, ID: "fixture-corpus", Cases: []ContractCase{
		{ID: "go-reachable", SubjectID: "subject-go-reachable", CohortID: "go", ModeID: "source_tier2", Fixture: refPointer(fixtureReference("fixture-reachable"))},
		{ID: "go-conditional", SubjectID: "subject-go-conditional", CohortID: "go", ModeID: "source_tier2", Fixture: refPointer(fixtureReference("fixture-conditional"))},
		{ID: "go-unreached", SubjectID: "subject-go-unreached", CohortID: "go", ModeID: "source_tier2", Fixture: refPointer(fixtureReference("fixture-unreached"))},
		{ID: "go-no-analysis", SubjectID: "subject-go-no-analysis", CohortID: "go", ModeID: "source_tier2", Fixture: refPointer(fixtureReference("fixture-no-analysis"))},
	}}
	completeness := fixtureReference("go-source-completeness")
	oracle := ReachabilityOracle{SchemaVersion: OracleSchemaVersion, ID: "fixture-oracle", Cases: []OracleCase{
		{CaseID: "go-reachable", Expected: OutcomeReachable, Category: OracleReachable, CoverageExpectation: CoverageComplete},
		{CaseID: "go-conditional", Expected: OutcomeConditionallyReachable, Category: OracleOpaque, CoverageExpectation: CoverageComplete},
		{CaseID: "go-unreached", Expected: OutcomePresentUnreached, Category: OracleTrulyUnreachable, CoverageExpectation: CoverageComplete, SuppressionApplicable: true, CompletenessContract: refPointer(completeness)},
		{CaseID: "go-no-analysis", Expected: OutcomeNoAnalysis, Category: OracleNoCoverage, CoverageExpectation: CoverageComplete},
	}}
	exceptions := ExceptionManifest{SchemaVersion: ExceptionManifestSchemaVersion, ID: "no-exceptions"}
	input := MeasurementInput{SchemaVersion: MeasurementInputSchemaVersion, Purpose: BaselineMeasurement, Inventory: inventory, Corpus: corpus, Oracle: oracle, Exceptions: exceptions, ActiveSnapshot: fixtureSnapshot()}
	input.Policy = fixturePolicy(t, inventory, corpus, oracle, exceptions)
	cohort, ok := inventory.cohort("go/source_tier2")
	if !ok {
		t.Fatal("fixture inventory lacks go/source_tier2")
	}
	binding, ok := findBinding(cohort, "api")
	if !ok {
		t.Fatal("fixture inventory lacks go/source_tier2 api binding")
	}
	for _, item := range oracle.Cases {
		input.Observations = append(input.Observations, MeasuredObservation{CaseID: item.CaseID, BindingID: "api", Invoked: true, Outcome: item.Expected, Coverage: completeCoverage(), OutputCapture: CaptureComplete, Analyzer: fixtureReference(cohort.AnalyzerID), Configuration: binding.Configuration, Suppression: SuppressionCapture{Claim: SuppressionNone, Status: CaptureComplete}})
	}
	if err := input.Validate(); err != nil {
		t.Fatalf("fixture input is invalid: %v", err)
	}
	return input
}

func fixturePolicy(t *testing.T, inventory ProductionInventory, corpus ContractCorpus, oracle ReachabilityOracle, exceptions ExceptionManifest) MeasurementPolicy {
	t.Helper()
	inventoryDigest, err := DigestProductionInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	corpusDigest, err := DigestContractCorpus(corpus)
	if err != nil {
		t.Fatal(err)
	}
	oracleDigest, err := DigestReachabilityOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	exceptionDigest, err := DigestExceptionManifest(exceptions)
	if err != nil {
		t.Fatal(err)
	}
	contract := fixtureReference("go-source-completeness")
	rules := make([]SuppressionPolicyRule, 0, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		rule := SuppressionPolicyRule{CohortID: cohort.ID, ModeID: cohort.Mode, Disposition: SuppressionRaiseOnly}
		if (cohort.ID == "rust" || cohort.ID == "ruby") && cohort.Mode == "import" {
			rule.Disposition = SuppressionProhibited
		}
		if cohort.ID == "go" && cohort.Mode == "source_tier2" {
			rule.Disposition = SuppressionEligible
			rule.CompletenessContract = refPointer(contract)
			rule.ApprovedProposer = "proposer"
			rule.ApprovedVerifier = "verifier"
		}
		rules = append(rules, rule)
	}
	return MeasurementPolicy{SchemaVersion: PolicySchemaVersion, ID: "fixture-policy", Inventory: artifactRef(inventory.ID, inventoryDigest), Corpus: artifactRef(corpus.ID, corpusDigest), Oracle: artifactRef(oracle.ID, oracleDigest), ExceptionManifest: artifactRef(exceptions.ID, exceptionDigest), SchemaDefinition: fixtureReference("contract-schema-definition"), RunPurposeRules: fixtureReference("contract-run-purpose-rules"), RatchetConstructionRule: fixtureReference("contract-ratchet-construction"), Evaluator: fixtureReference("contract-evaluator"), MetricDefinition: fixtureReference("contract-metrics"), Adapters: []ArtifactReference{fixtureReference("production-adapter")}, Rules: rules}
}

func refreshPolicyReferences(t *testing.T, input *MeasurementInput) {
	t.Helper()
	input.Policy = fixturePolicy(t, input.Inventory, input.Corpus, input.Oracle, input.Exceptions)
}

func candidateInput(t *testing.T, input MeasurementInput, baseline MeasurementReport) MeasurementInput {
	t.Helper()
	checkpoint := fixtureCheckpoint(t, input.Policy, baseline)
	ratchet, err := DeriveCandidateRatchet(input.Policy, baseline, checkpoint, input.Exceptions)
	if err != nil {
		t.Fatal(err)
	}
	input.Purpose = CandidateAcceptance
	input.Baseline = &baseline
	input.Checkpoint = &checkpoint
	input.Ratchet = &ratchet
	return input
}

func fixtureCheckpoint(t *testing.T, policy MeasurementPolicy, baseline MeasurementReport) ProceduralBaselineCheckpoint {
	t.Helper()
	policyDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := ProceduralBaselineCheckpoint{SchemaVersion: BaselineCheckpointSchemaVersion, AuthorityClass: "procedural", StartingRevision: TrustedBaselineRevision, Policy: artifactRef(policy.ID, policyDigest), BaselineResult: artifactRef(baseline.ID, baseline.ID), HarnessContract: fixtureReference("harness-contract"), AllowlistEvidence: fixtureReference("allowlist"), ReviewEvidence: fixtureReference("review"), DispositionEvidence: fixtureReference("disposition"), Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer"}
	id, err := DigestProceduralBaselineCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.ID = id
	return checkpoint
}

func fixtureProof(input MeasurementInput, caseID, bindingID string, complete bool) SuppressionProof {
	item := corpusCase(input.Corpus, caseID)
	cohort, _ := input.Inventory.cohort(cohortKey(item.CohortID, item.ModeID))
	binding, _ := findBinding(cohort, bindingID)
	proof := SuppressionProof{Judgment: fixtureReference("judgment"), SubjectID: item.SubjectID, BoundaryID: binding.BoundaryID, Proposer: "proposer", Verifier: "verifier", CompletenessContract: fixtureReference("go-source-completeness"), Snapshot: input.ActiveSnapshot, Analyzer: fixtureReference(cohort.AnalyzerID), Configuration: binding.Configuration, Evidence: fixtureReference("evidence")}
	if !complete {
		proof.Judgment = ArtifactReference{}
	}
	return proof
}

func fixtureSnapshot() SnapshotIdentity {
	return SnapshotIdentity{Source: fixtureReference("source"), SBOM: fixtureReference("sbom"), Run: fixtureReference("run")}
}
func fixtureReference(id string) ArtifactReference {
	return ArtifactReference{ID: id, Digest: benchmark.SHA256Digest([]byte(id))}
}
func refPointer(ref ArtifactReference) *ArtifactReference { return &ref }
func completeCoverage() ObservedCoverage {
	return ObservedCoverage{Status: CoverageComplete, Obligations: []CoverageObligation{{ID: "entrypoints", Status: CoverageComplete}}}
}

func cohortSummary(t *testing.T, report MeasurementReport, cohortID, modeID string) CohortSummary {
	t.Helper()
	for _, summary := range report.Cohorts {
		if summary.CohortID == cohortID && summary.ModeID == modeID {
			return summary
		}
	}
	t.Fatalf("missing cohort %s/%s", cohortID, modeID)
	return CohortSummary{}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

package reachbench

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestDefaultMeasurementContractMatchesFrozenProductionAuthority(t *testing.T) {
	input, err := DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(input.Corpus.Cases); got != 83 {
		t.Fatalf("default corpus cases = %d, want 83", got)
	}
	if got := len(input.Inventory.Cohorts); got != 19 {
		t.Fatalf("default inventory cohorts = %d, want 19", got)
	}
	if got := defaultEnabledCellCount(input); got != 95 {
		t.Fatalf("default enabled measurement cells = %d, want 95", got)
	}
	if len(input.Observations) != 0 || input.Baseline != nil || input.Checkpoint != nil || input.Ratchet != nil {
		t.Fatalf("default baseline template contains lifecycle state: %+v", input)
	}
	exceptions := DefaultExceptionManifest()
	if input.Exceptions.SchemaVersion != exceptions.SchemaVersion || input.Exceptions.ID != exceptions.ID || len(input.Exceptions.Entries) != 0 {
		t.Fatalf("baseline template exceptions = %+v, want deterministic no-exception default", input.Exceptions)
	}

	registry, err := judgment.NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Policy.Rules) != len(registry.Policies()) {
		t.Fatalf("default policy rule count = %d, domain authority count = %d", len(input.Policy.Rules), len(registry.Policies()))
	}
	for _, rule := range input.Policy.Rules {
		authority, err := registry.Lookup(rule.CohortID, rule.ModeID)
		if err != nil {
			t.Fatalf("default policy rule %s/%s is absent from domain authority: %v", rule.CohortID, rule.ModeID, err)
		}
		if rule.Disposition != suppressionDisposition(authority.Disposition()) {
			t.Fatalf("default policy disposition %s/%s = %q, domain authority = %q", rule.CohortID, rule.ModeID, rule.Disposition, authority.Disposition())
		}
		approval, eligible := authority.Approval()
		if !eligible {
			if rule.CompletenessContract != nil || rule.ApprovedProposer != "" || rule.ApprovedVerifier != "" {
				t.Fatalf("non-eligible policy rule %s/%s carries approval metadata", rule.CohortID, rule.ModeID)
			}
			continue
		}
		want := artifactRef(approval.Contract().ID(), approval.Contract().Digest())
		if rule.CompletenessContract == nil || *rule.CompletenessContract != want || rule.ApprovedProposer != approval.Proposer() || rule.ApprovedVerifier != approval.Verifier() {
			t.Fatalf("eligible policy rule %s/%s does not match frozen authority approval", rule.CohortID, rule.ModeID)
		}
	}
}

func TestDefaultBuildersAreDeterministicAndRejectStaticMutation(t *testing.T) {
	firstPolicy, err := DefaultMeasurementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	secondPolicy, err := DefaultMeasurementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := benchmark.CanonicalJSON(firstPolicy)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := benchmark.CanonicalJSON(secondPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("default measurement policy is not deterministic")
	}
	firstInput, err := DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	secondInput, err := DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err = benchmark.CanonicalJSON(firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err = benchmark.CanonicalJSON(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("default baseline input is not deterministic")
	}
	if got := DefaultExceptionManifest(); got.ID != defaultExceptionManifestID || len(got.Entries) != 0 {
		t.Fatalf("default exception manifest = %+v, want no exceptions", got)
	}

	mutated := firstInput
	mutated.Policy.Inventory = artifactRef("substituted-inventory", benchmark.SHA256Digest([]byte("substituted-inventory")))
	if err := mutated.Validate(); err == nil {
		t.Fatal("baseline input accepted a policy mutation that breaks its static contract binding")
	}
}

func TestDefaultPolicyDescriptorsBindFrozenSemantics(t *testing.T) {
	policy, err := DefaultMeasurementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string]struct {
		descriptor any
		reference  ArtifactReference
	}{
		"schema":      {defaultMeasurementSchemaDescriptor(), policy.SchemaDefinition},
		"run purpose": {defaultRunPurposeRulesDescriptor(), policy.RunPurposeRules},
		"ratchet":     {defaultRatchetConstructionDescriptor(), policy.RatchetConstructionRule},
		"evaluator":   {defaultEvaluatorDescriptor(), policy.Evaluator},
		"metrics":     {defaultMetricDefinitionDescriptor(), policy.MetricDefinition},
	} {
		expected, err := descriptorReference(pair.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if pair.reference != expected {
			t.Fatalf("default %s descriptor reference = %+v, want %+v", name, pair.reference, expected)
		}
	}
	metrics := defaultMetricDefinitionDescriptor()
	if metrics.C2Comparison != "strict_lexicographic" || len(metrics.C2Dimensions) != 3 || !metrics.RequiresZeroFalseSuppressions || !metrics.RequiresZeroInvalidSuppressions || !metrics.GuardsBindingReachableRecall || !metrics.GuardsCoverageExceptApprovedManifestEntries {
		t.Fatalf("metric descriptor does not enumerate candidate acceptance semantics: %+v", metrics)
	}
	mutatedMetrics := metrics
	mutatedMetrics.RequiresZeroInvalidSuppressions = false
	mutatedReference, err := descriptorReference(mutatedMetrics)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedReference == policy.MetricDefinition {
		t.Fatal("metric semantic mutation did not change the descriptor reference")
	}
	mutatedPolicy := policy
	mutatedPolicy.MetricDefinition = mutatedReference
	originalDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	mutatedDigest, err := DigestMeasurementPolicy(mutatedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if originalDigest == mutatedDigest {
		t.Fatal("metric semantic mutation did not change the measurement policy digest")
	}
}

func defaultEnabledCellCount(input MeasurementInput) int {
	cohorts := make(map[string]ProductionCohort, len(input.Inventory.Cohorts))
	for _, cohort := range input.Inventory.Cohorts {
		cohorts[cohortKey(cohort.ID, cohort.Mode)] = cohort
	}
	count := 0
	for _, item := range input.Corpus.Cases {
		cohort := cohorts[cohortKey(item.CohortID, item.ModeID)]
		if !cohort.BenchmarkRequired {
			continue
		}
		for _, binding := range cohort.Bindings {
			if binding.State == BindingEnabled {
				count++
			}
		}
	}
	return count
}

package reachbench

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

const (
	defaultExceptionManifestID = "synapse-reachability-no-exceptions-v2"
	defaultMeasurementPolicyID = "synapse-reachability-default-measurement-policy-v2"

	defaultDescriptorSchemaVersion = "synapse-reachability-measurement-descriptor-v1"
	defaultSnapshotRunID           = "synapse-reachability-frozen-contract-run-v2"
)

// measurementSchemaDescriptor records the closed schemas and primary value
// vocabularies that identify a frozen measurement contract. It deliberately
// records no source location or asserted external origin.
type measurementSchemaDescriptor struct {
	SchemaVersion     string                   `json:"schema_version"`
	ID                string                   `json:"id"`
	InventorySchema   string                   `json:"inventory_schema"`
	CorpusSchema      string                   `json:"corpus_schema"`
	OracleSchema      string                   `json:"oracle_schema"`
	PolicySchema      string                   `json:"policy_schema"`
	ExceptionSchema   string                   `json:"exception_schema"`
	InputSchema       string                   `json:"input_schema"`
	ReportSchema      string                   `json:"report_schema"`
	CheckpointSchema  string                   `json:"checkpoint_schema"`
	RatchetSchema     string                   `json:"ratchet_schema"`
	Outcomes          []Outcome                `json:"outcomes"`
	OracleCategories  []OracleCategory         `json:"oracle_categories"`
	CoverageStatuses  []CoverageStatus         `json:"coverage_statuses"`
	SuppressionStates []SuppressionDisposition `json:"suppression_states"`
}

type runPurposeRulesDescriptor struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Baseline      purposeRuleSet `json:"baseline"`
	Candidate     purposeRuleSet `json:"candidate"`
}

type purposeRuleSet struct {
	Purpose                 RunPurpose `json:"purpose"`
	RequiresBaseline        bool       `json:"requires_baseline"`
	RequiresCheckpoint      bool       `json:"requires_checkpoint"`
	RequiresRatchet         bool       `json:"requires_ratchet"`
	RequiresAcyclicBaseline bool       `json:"requires_acyclic_baseline"`
}

type ratchetConstructionDescriptor struct {
	SchemaVersion             string   `json:"schema_version"`
	ID                        string   `json:"id"`
	Inputs                    []string `json:"inputs"`
	BaselineMustBeAcyclic     bool     `json:"baseline_must_be_acyclic"`
	CandidateMustReplay       bool     `json:"candidate_must_replay"`
	CapturedDimensions        []string `json:"captured_dimensions"`
	BindsExceptionManifest    bool     `json:"binds_exception_manifest"`
	BindsProceduralCheckpoint bool     `json:"binds_procedural_checkpoint"`
}

type evaluatorDescriptor struct {
	SchemaVersion                             string `json:"schema_version"`
	ID                                        string `json:"id"`
	ValidatesInputBeforeReduction             bool   `json:"validates_input_before_reduction"`
	RejectsDuplicateCorpusCases               bool   `json:"rejects_duplicate_corpus_cases"`
	RejectsUnknownObservations                bool   `json:"rejects_unknown_observations"`
	RejectsDuplicateObservations              bool   `json:"rejects_duplicate_observations"`
	IncompleteCapturePreventsSuppressionClaim bool   `json:"incomplete_capture_prevents_suppression_claim"`
	EvaluatesCandidateAgainstRatchet          bool   `json:"evaluates_candidate_against_ratchet"`
}

type metricDefinitionDescriptor struct {
	SchemaVersion                               string   `json:"schema_version"`
	ID                                          string   `json:"id"`
	C2Comparison                                string   `json:"c2_comparison"`
	C2Dimensions                                []string `json:"c2_dimensions"`
	RequiresAssessedRequiredCohorts             bool     `json:"requires_assessed_required_cohorts"`
	GuardsBindingReachableRecall                bool     `json:"guards_binding_reachable_recall"`
	GuardsCohortReachableRecall                 bool     `json:"guards_cohort_reachable_recall"`
	GuardsCohortSuppressionMetrics              bool     `json:"guards_cohort_suppression_metrics"`
	GuardsLanguageReachableRecall               bool     `json:"guards_language_reachable_recall"`
	GuardsOverallReachablePrecision             bool     `json:"guards_overall_reachable_precision"`
	RequiresZeroFalseSuppressions               bool     `json:"requires_zero_false_suppressions"`
	RequiresZeroInvalidSuppressions             bool     `json:"requires_zero_invalid_suppressions"`
	RequiresSafeSuppressionCapture              bool     `json:"requires_safe_suppression_capture"`
	GuardsCoverageExceptApprovedManifestEntries bool     `json:"guards_coverage_except_approved_manifest_entries"`
}

// workloadAdapterDescriptor is a package-owned description of one closed
// production adapter/binding pair. Its digest changes only when the frozen
// inventory binding it describes changes.
type workloadAdapterDescriptor struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	CohortID      string            `json:"cohort_id"`
	ModeID        string            `json:"mode_id"`
	AnalyzerID    string            `json:"analyzer_id"`
	BindingID     string            `json:"binding_id"`
	BoundaryID    string            `json:"boundary_id"`
	Configuration ArtifactReference `json:"configuration"`
}

// frozenContractRunDescriptor binds the three concrete static artifacts used by
// the default input's active snapshot. It is a static template identity, not a
// claim that a baseline observation has happened.
type frozenContractRunDescriptor struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Fixtures      ArtifactReference `json:"fixtures"`
	Inventory     ArtifactReference `json:"inventory"`
	Policy        ArtifactReference `json:"policy"`
}

// DefaultExceptionManifest returns the closed default with no approved coverage
// exceptions. It does not invent an exception for an uncaptured baseline.
func DefaultExceptionManifest() ExceptionManifest {
	return ExceptionManifest{
		SchemaVersion: ExceptionManifestSchemaVersion,
		ID:            defaultExceptionManifestID,
		Entries:       []CoverageException{},
	}
}

// DefaultMeasurementPolicy constructs the closed production policy from the
// embedded inventory and benchmark contract plus the inward reachability
// authority registry. It contains only static authority; it never includes a
// baseline, review, checkpoint, or candidate ratchet.
func DefaultMeasurementPolicy() (MeasurementPolicy, error) {
	inventory := DefaultProductionInventory()
	contract := DefaultReachabilityBenchmark()
	exceptions := DefaultExceptionManifest()

	inventoryDigest, err := DigestProductionInventory(inventory)
	if err != nil {
		return MeasurementPolicy{}, fmt.Errorf("digest default production inventory: %w", err)
	}
	corpusDigest, err := DigestContractCorpus(contract.Corpus)
	if err != nil {
		return MeasurementPolicy{}, fmt.Errorf("digest default reachability corpus: %w", err)
	}
	oracleDigest, err := DigestReachabilityOracle(contract.Oracle)
	if err != nil {
		return MeasurementPolicy{}, fmt.Errorf("digest default reachability oracle: %w", err)
	}
	exceptionsDigest, err := DigestExceptionManifest(exceptions)
	if err != nil {
		return MeasurementPolicy{}, fmt.Errorf("digest default exception manifest: %w", err)
	}
	registry, err := judgment.NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		return MeasurementPolicy{}, fmt.Errorf("create default reachability authority registry: %w", err)
	}

	rules, err := defaultSuppressionRules(inventory, registry)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	adapters, err := defaultAdapterDescriptors(inventory)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	descriptors, err := defaultPolicyDescriptors()
	if err != nil {
		return MeasurementPolicy{}, err
	}
	policy := MeasurementPolicy{
		SchemaVersion:           PolicySchemaVersion,
		ID:                      defaultMeasurementPolicyID,
		Inventory:               artifactRef(inventory.ID, inventoryDigest),
		Corpus:                  artifactRef(contract.Corpus.ID, corpusDigest),
		Oracle:                  artifactRef(contract.Oracle.ID, oracleDigest),
		ExceptionManifest:       artifactRef(exceptions.ID, exceptionsDigest),
		SchemaDefinition:        descriptors.schema,
		RunPurposeRules:         descriptors.runPurpose,
		RatchetConstructionRule: descriptors.ratchet,
		Evaluator:               descriptors.evaluator,
		MetricDefinition:        descriptors.metrics,
		Adapters:                adapters,
		Rules:                   rules,
	}
	if err := policy.Validate(); err != nil {
		return MeasurementPolicy{}, fmt.Errorf("validate default measurement policy: %w", err)
	}
	return canonicalPolicy(policy), nil
}

type policyDescriptors struct {
	schema     ArtifactReference
	runPurpose ArtifactReference
	ratchet    ArtifactReference
	evaluator  ArtifactReference
	metrics    ArtifactReference
}

func defaultPolicyDescriptors() (policyDescriptors, error) {
	schema, err := descriptorReference(defaultMeasurementSchemaDescriptor())
	if err != nil {
		return policyDescriptors{}, fmt.Errorf("build default measurement schema descriptor: %w", err)
	}
	runPurpose, err := descriptorReference(defaultRunPurposeRulesDescriptor())
	if err != nil {
		return policyDescriptors{}, fmt.Errorf("build default run-purpose descriptor: %w", err)
	}
	ratchet, err := descriptorReference(defaultRatchetConstructionDescriptor())
	if err != nil {
		return policyDescriptors{}, fmt.Errorf("build default ratchet descriptor: %w", err)
	}
	evaluator, err := descriptorReference(defaultEvaluatorDescriptor())
	if err != nil {
		return policyDescriptors{}, fmt.Errorf("build default evaluator descriptor: %w", err)
	}
	metrics, err := descriptorReference(defaultMetricDefinitionDescriptor())
	if err != nil {
		return policyDescriptors{}, fmt.Errorf("build default metric definition descriptor: %w", err)
	}
	return policyDescriptors{schema: schema, runPurpose: runPurpose, ratchet: ratchet, evaluator: evaluator, metrics: metrics}, nil
}

func defaultMeasurementSchemaDescriptor() measurementSchemaDescriptor {
	return measurementSchemaDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion, ID: "synapse-reachability-measurement-schema-v2",
		InventorySchema: ProductionInventorySchemaVersion, CorpusSchema: ContractCorpusSchemaVersion, OracleSchema: OracleSchemaVersion,
		PolicySchema: PolicySchemaVersion, ExceptionSchema: ExceptionManifestSchemaVersion, InputSchema: MeasurementInputSchemaVersion,
		ReportSchema: MeasurementReportSchemaVersion, CheckpointSchema: BaselineCheckpointSchemaVersion, RatchetSchema: CandidateRatchetSchemaVersion,
		Outcomes:          []Outcome{OutcomeReachable, OutcomeConditionallyReachable, OutcomePresentUnreached, OutcomeNoAnalysis},
		OracleCategories:  []OracleCategory{OracleReachable, OracleTrulyUnreachable, OracleOpaque, OracleNoCoverage},
		CoverageStatuses:  []CoverageStatus{CoverageComplete, CoveragePartial, CoverageUnavailable, CoverageNotApplicable},
		SuppressionStates: []SuppressionDisposition{SuppressionEligible, SuppressionRaiseOnly, SuppressionProhibited},
	}
}

func defaultRunPurposeRulesDescriptor() runPurposeRulesDescriptor {
	return runPurposeRulesDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion, ID: "synapse-reachability-run-purpose-rules-v2",
		Baseline: purposeRuleSet{Purpose: BaselineMeasurement},
		Candidate: purposeRuleSet{
			Purpose: CandidateAcceptance, RequiresBaseline: true, RequiresCheckpoint: true, RequiresRatchet: true, RequiresAcyclicBaseline: true,
		},
	}
}

func defaultRatchetConstructionDescriptor() ratchetConstructionDescriptor {
	return ratchetConstructionDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion, ID: "synapse-reachability-ratchet-construction-v2",
		Inputs:                []string{"policy", "baseline_report", "procedural_checkpoint", "exception_manifest"},
		BaselineMustBeAcyclic: true, CandidateMustReplay: true,
		CapturedDimensions:     []string{"c2", "reachability", "bindings", "cohorts", "languages", "execution_coverage"},
		BindsExceptionManifest: true, BindsProceduralCheckpoint: true,
	}
}

func defaultEvaluatorDescriptor() evaluatorDescriptor {
	return evaluatorDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion, ID: "synapse-reachability-evaluator-v2",
		ValidatesInputBeforeReduction: true, RejectsDuplicateCorpusCases: true, RejectsUnknownObservations: true,
		RejectsDuplicateObservations: true, IncompleteCapturePreventsSuppressionClaim: true, EvaluatesCandidateAgainstRatchet: true,
	}
}

func defaultMetricDefinitionDescriptor() metricDefinitionDescriptor {
	return metricDefinitionDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion, ID: "synapse-reachability-metric-definition-v2",
		C2Comparison:                    "strict_lexicographic",
		C2Dimensions:                    []string{"production_breadth", "correct_positive_cases", "macro_reachable_recall"},
		RequiresAssessedRequiredCohorts: true, GuardsBindingReachableRecall: true, GuardsCohortReachableRecall: true,
		GuardsCohortSuppressionMetrics: true, GuardsLanguageReachableRecall: true, GuardsOverallReachablePrecision: true,
		RequiresZeroFalseSuppressions: true, RequiresZeroInvalidSuppressions: true, RequiresSafeSuppressionCapture: true,
		GuardsCoverageExceptApprovedManifestEntries: true,
	}
}

func defaultSuppressionRules(inventory ProductionInventory, registry judgment.ReachabilityAuthorityRegistry) ([]SuppressionPolicyRule, error) {
	rules := make([]SuppressionPolicyRule, 0, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		authority, err := registry.Lookup(cohort.ID, cohort.Mode)
		if err != nil {
			return nil, fmt.Errorf("find default authority for %s: %w", cohortKey(cohort.ID, cohort.Mode), err)
		}
		rule := SuppressionPolicyRule{
			CohortID:    cohort.ID,
			ModeID:      cohort.Mode,
			Disposition: suppressionDisposition(authority.Disposition()),
		}
		if approval, eligible := authority.Approval(); eligible {
			completeness := approval.Contract()
			reference := artifactRef(completeness.ID(), completeness.Digest())
			rule.CompletenessContract = &reference
			rule.ApprovedProposer = approval.Proposer()
			rule.ApprovedVerifier = approval.Verifier()
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(left, right int) bool {
		return cohortKey(rules[left].CohortID, rules[left].ModeID) < cohortKey(rules[right].CohortID, rules[right].ModeID)
	})
	if len(rules) != len(registry.Policies()) {
		return nil, fmt.Errorf("default authority registry and production inventory differ")
	}
	return rules, nil
}

func suppressionDisposition(value judgment.SuppressionDisposition) SuppressionDisposition {
	switch value {
	case judgment.SuppressionEligible:
		return SuppressionEligible
	case judgment.SuppressionRaiseOnly:
		return SuppressionRaiseOnly
	case judgment.SuppressionProhibited:
		return SuppressionProhibited
	default:
		return ""
	}
}

func defaultAdapterDescriptors(inventory ProductionInventory) ([]ArtifactReference, error) {
	adapters := make([]ArtifactReference, 0)
	for _, cohort := range inventory.Cohorts {
		for _, binding := range cohort.Bindings {
			id := "synapse-reachability-workload-adapter-v2/" + cohort.ID + "-" + cohort.Mode + "-" + binding.ID
			reference, err := descriptorReference(workloadAdapterDescriptor{
				SchemaVersion: defaultDescriptorSchemaVersion,
				ID:            id,
				CohortID:      cohort.ID,
				ModeID:        cohort.Mode,
				AnalyzerID:    cohort.AnalyzerID,
				BindingID:     binding.ID,
				BoundaryID:    binding.BoundaryID,
				Configuration: binding.Configuration,
			})
			if err != nil {
				return nil, fmt.Errorf("build default adapter descriptor %q: %w", id, err)
			}
			adapters = append(adapters, reference)
		}
	}
	sort.Slice(adapters, func(left, right int) bool { return adapters[left].ID < adapters[right].ID })
	return adapters, nil
}

func descriptorReference(value any) (ArtifactReference, error) {
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return ArtifactReference{}, err
	}
	var id string
	switch descriptor := value.(type) {
	case measurementSchemaDescriptor:
		id = descriptor.ID
	case runPurposeRulesDescriptor:
		id = descriptor.ID
	case ratchetConstructionDescriptor:
		id = descriptor.ID
	case evaluatorDescriptor:
		id = descriptor.ID
	case metricDefinitionDescriptor:
		id = descriptor.ID
	case workloadAdapterDescriptor:
		id = descriptor.ID
	case frozenContractRunDescriptor:
		id = descriptor.ID
	default:
		return ArtifactReference{}, fmt.Errorf("unknown measurement descriptor")
	}
	return artifactRef(id, benchmark.SHA256Digest(encoded)), nil
}

// DefaultBaselineMeasurementInput returns the frozen static baseline template.
// It holds no measured observations and no candidate lifecycle artifacts; a real
// baseline report must be captured and independently checkpointed later.
func DefaultBaselineMeasurementInput() (MeasurementInput, error) {
	inventory := DefaultProductionInventory()
	contract := DefaultReachabilityBenchmark()
	exceptions := DefaultExceptionManifest()
	policy, err := DefaultMeasurementPolicy()
	if err != nil {
		return MeasurementInput{}, err
	}
	snapshot, err := defaultActiveSnapshot(contract.Fixtures, inventory, policy)
	if err != nil {
		return MeasurementInput{}, err
	}
	input := MeasurementInput{
		SchemaVersion:  MeasurementInputSchemaVersion,
		Purpose:        BaselineMeasurement,
		Inventory:      inventory,
		Corpus:         contract.Corpus,
		Oracle:         contract.Oracle,
		Policy:         policy,
		Exceptions:     exceptions,
		ActiveSnapshot: snapshot,
		Observations:   []MeasuredObservation{},
	}
	if err := input.Validate(); err != nil {
		return MeasurementInput{}, fmt.Errorf("validate default baseline measurement input: %w", err)
	}
	return input, nil
}

func defaultActiveSnapshot(fixtures FixtureManifest, inventory ProductionInventory, policy MeasurementPolicy) (SnapshotIdentity, error) {
	fixtureDigest, err := DigestFixtureManifest(fixtures)
	if err != nil {
		return SnapshotIdentity{}, fmt.Errorf("digest frozen fixture manifest: %w", err)
	}
	inventoryDigest, err := DigestProductionInventory(inventory)
	if err != nil {
		return SnapshotIdentity{}, fmt.Errorf("digest frozen production inventory: %w", err)
	}
	policyDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		return SnapshotIdentity{}, fmt.Errorf("digest frozen measurement policy: %w", err)
	}
	fixturesReference := artifactRef(fixtures.ID, fixtureDigest)
	inventoryReference := artifactRef(inventory.ID, inventoryDigest)
	policyReference := artifactRef(policy.ID, policyDigest)
	run, err := descriptorReference(frozenContractRunDescriptor{
		SchemaVersion: defaultDescriptorSchemaVersion,
		ID:            defaultSnapshotRunID,
		Fixtures:      fixturesReference,
		Inventory:     inventoryReference,
		Policy:        policyReference,
	})
	if err != nil {
		return SnapshotIdentity{}, fmt.Errorf("build frozen contract run descriptor: %w", err)
	}
	return SnapshotIdentity{Source: fixturesReference, SBOM: inventoryReference, Run: run}, nil
}

// BuildCandidateMeasurementInput constructs the complete candidate template from
// a captured baseline and independently supplied checkpoint. It cannot create a
// baseline observation, checkpoint, or ratchet on its own.
func BuildCandidateMeasurementInput(baselineReport MeasurementReport, checkpoint ProceduralBaselineCheckpoint) (MeasurementInput, error) {
	input, err := DefaultBaselineMeasurementInput()
	if err != nil {
		return MeasurementInput{}, err
	}
	if err := baselineReport.Validate(); err != nil {
		return MeasurementInput{}, fmt.Errorf("validate candidate baseline report: %w", err)
	}
	if !sameSnapshot(baselineReport.ActiveSnapshot, input.ActiveSnapshot) {
		return MeasurementInput{}, fmt.Errorf("candidate baseline report does not bind the default active snapshot")
	}
	ratchet, err := DeriveCandidateRatchet(input.Policy, baselineReport, checkpoint, input.Exceptions)
	if err != nil {
		return MeasurementInput{}, fmt.Errorf("derive candidate ratchet: %w", err)
	}
	input.Purpose = CandidateAcceptance
	input.Baseline = &baselineReport
	input.Checkpoint = &checkpoint
	input.Ratchet = &ratchet
	if err := input.Validate(); err != nil {
		return MeasurementInput{}, fmt.Errorf("validate candidate measurement input: %w", err)
	}
	return input, nil
}

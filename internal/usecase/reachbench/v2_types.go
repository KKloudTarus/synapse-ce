package reachbench

const (
	ProductionInventorySchemaVersion = "synapse-reachability-production-inventory-v2"
	ContractCorpusSchemaVersion      = "synapse-reachability-contract-corpus-v2"
	OracleSchemaVersionV2            = "synapse-reachability-oracle-v2"
	PolicySchemaVersion              = "synapse-reachability-measurement-policy-v2"
	ExceptionManifestSchemaVersion   = "synapse-reachability-exception-manifest-v2"
	MeasurementInputSchemaVersion    = "synapse-reachability-measurement-input-v2"
	MeasurementReportSchemaVersion   = "synapse-reachability-measurement-report-v2"
	BaselineCheckpointSchemaVersion  = "synapse-reachability-baseline-checkpoint-v2"
	CandidateRatchetSchemaVersion    = "synapse-reachability-candidate-ratchet-v2"

	TrustedBaselineRevision = "50d205260be412dc2f57736f71d1448a8f58177a"
)

// Outcome is the closed public reachability result vocabulary. Suppression is represented separately.
type Outcome string

const (
	OutcomeReachable              Outcome = "reachable"
	OutcomeConditionallyReachable Outcome = "conditionally_reachable"
	OutcomePresentUnreached       Outcome = "present_unreached"
	OutcomeNoAnalysis             Outcome = "no_analysis"
)

func (value Outcome) valid() bool {
	switch value {
	case OutcomeReachable, OutcomeConditionallyReachable, OutcomePresentUnreached, OutcomeNoAnalysis:
		return true
	default:
		return false
	}
}

func positiveOutcome(value Outcome) bool {
	return value == OutcomeReachable || value == OutcomeConditionallyReachable
}

// OracleCategory is the semantic truth category used for C2 breadth. It deliberately does not
// reuse the public outcome vocabulary: a conditional public result can still be an opaque oracle case.
type OracleCategory string

const (
	OracleReachable        OracleCategory = "reachable"
	OracleTrulyUnreachable OracleCategory = "truly_unreachable"
	OracleOpaque           OracleCategory = "opaque"
	OracleNoCoverage       OracleCategory = "no_coverage"
)

func (value OracleCategory) valid() bool {
	switch value {
	case OracleReachable, OracleTrulyUnreachable, OracleOpaque, OracleNoCoverage:
		return true
	default:
		return false
	}
}

// AssessmentState reports whether a boundary was actually exercised and fully captured.
type AssessmentState string

const (
	Assessed    AssessmentState = "assessed"
	NotAssessed AssessmentState = "not_assessed"
)

func (value AssessmentState) valid() bool { return value == Assessed || value == NotAssessed }

// BindingState reports whether a production composition root is reachable by the measurement contract.
type BindingState string

const (
	BindingEnabled  BindingState = "enabled"
	BindingDisabled BindingState = "disabled"
	BindingNotWired BindingState = "not_wired"
)

func (value BindingState) valid() bool {
	return value == BindingEnabled || value == BindingDisabled || value == BindingNotWired
}

// CoverageStatus is deliberately independent of public outcomes and assessment state.
type CoverageStatus string

const (
	CoverageComplete      CoverageStatus = "complete"
	CoveragePartial       CoverageStatus = "partial"
	CoverageUnavailable   CoverageStatus = "unavailable"
	CoverageNotApplicable CoverageStatus = "not_applicable"
)

func (value CoverageStatus) valid() bool {
	switch value {
	case CoverageComplete, CoveragePartial, CoverageUnavailable, CoverageNotApplicable:
		return true
	default:
		return false
	}
}

// CoverageReasonCode retains bounded evidence about why a coverage obligation was not complete.
type CoverageReasonCode string

const (
	CoverageReasonUnknown     CoverageReasonCode = "unknown"
	CoverageReasonStale       CoverageReasonCode = "stale"
	CoverageReasonFailed      CoverageReasonCode = "failed"
	CoverageReasonSkipped     CoverageReasonCode = "skipped"
	CoverageReasonUnsupported CoverageReasonCode = "unsupported"
	CoverageReasonOpaque      CoverageReasonCode = "opaque"
)

func (value CoverageReasonCode) valid() bool {
	switch value {
	case CoverageReasonUnknown, CoverageReasonStale, CoverageReasonFailed, CoverageReasonSkipped, CoverageReasonUnsupported, CoverageReasonOpaque:
		return true
	default:
		return false
	}
}

// CaptureStatus describes whether production output was completely captured. It is not an outcome.
type CaptureStatus string

const (
	CaptureComplete   CaptureStatus = "complete"
	CaptureIncomplete CaptureStatus = "incomplete"
	CaptureFailed     CaptureStatus = "failed"
)

func (value CaptureStatus) valid() bool {
	return value == CaptureComplete || value == CaptureIncomplete || value == CaptureFailed
}

// SuppressionClaim states only whether the measured boundary produced a suppression effect.
type SuppressionClaim string

const (
	SuppressionNone     SuppressionClaim = "none"
	SuppressionProduced SuppressionClaim = "produced"
)

func (value SuppressionClaim) valid() bool {
	return value == SuppressionNone || value == SuppressionProduced
}

// SuppressionEffectKind is constrained to concrete effects currently represented by Synapse evidence.
type SuppressionEffectKind string

const (
	EffectSuppressingJudgment SuppressionEffectKind = "suppressing_judgment"
	EffectOpenVEX             SuppressionEffectKind = "openvex"
)

func (value SuppressionEffectKind) valid() bool {
	return value == EffectSuppressingJudgment || value == EffectOpenVEX
}

// SuppressionDisposition is static corpus/policy authorization, never an observation property.
type SuppressionDisposition string

const (
	SuppressionRaiseOnly  SuppressionDisposition = "raise_only"
	SuppressionEligible   SuppressionDisposition = "suppression_eligible"
	SuppressionProhibited SuppressionDisposition = "suppression_prohibited"
)

func (value SuppressionDisposition) valid() bool {
	switch value {
	case SuppressionRaiseOnly, SuppressionEligible, SuppressionProhibited:
		return true
	default:
		return false
	}
}

// RunPurpose separates diagnostic baseline measurement from candidate acceptance.
type RunPurpose string

const (
	BaselineMeasurement RunPurpose = "baseline_measurement"
	CandidateAcceptance RunPurpose = "candidate_acceptance"
)

func (value RunPurpose) valid() bool {
	return value == BaselineMeasurement || value == CandidateAcceptance
}

// RatioStatus prevents absent denominators from being serialized as 1.0.
type RatioStatus string

const (
	RatioAvailable     RatioStatus = "available"
	RatioNotApplicable RatioStatus = "not_applicable"
	RatioUnavailable   RatioStatus = "unavailable"
)

func (value RatioStatus) valid() bool {
	return value == RatioAvailable || value == RatioNotApplicable || value == RatioUnavailable
}

// Ratio represents an exact non-negative rational number. Numerator and denominator are decimal integers so
// macro recall can remain exact even when its unweighted cohort denominators have no small common multiple.
type Ratio struct {
	Status      RatioStatus `json:"status"`
	Numerator   string      `json:"numerator,omitempty"`
	Denominator string      `json:"denominator,omitempty"`
}

// ArtifactReference binds a named immutable artifact to a SHA-256 digest.
type ArtifactReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// CompositionBinding identifies one actual application root and its stable production boundary. Multiple
// bindings may name the same root; they remain separate execution obligations but collapse to one semantic
// cohort for C2 credit.
type CompositionBinding struct {
	ID            string            `json:"id"`
	Root          string            `json:"root"`
	BoundaryID    string            `json:"boundary_id"`
	Configuration ArtifactReference `json:"configuration"`
	State         BindingState      `json:"state"`
	Reason        string            `json:"reason,omitempty"`
}

// ProductionCohort is one analyzer/language mode in the closed production inventory. DefaultEnabled describes
// the deployed configuration default; BenchmarkRequired is the independent C2 obligation. Assessment belongs
// only to a measurement report and is never static policy identity.
type ProductionCohort struct {
	ID                string               `json:"id"`
	Language          string               `json:"language"`
	Mode              string               `json:"mode"`
	AnalyzerID        string               `json:"analyzer_id"`
	BoundaryID        string               `json:"boundary_id"`
	DefaultEnabled    bool                 `json:"default_enabled"`
	BenchmarkRequired bool                 `json:"benchmark_required"`
	Bindings          []CompositionBinding `json:"bindings"`
}

// ProductionInventory is the closed production reachability inventory used by the v2 contract.
type ProductionInventory struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Cohorts       []ProductionCohort `json:"cohorts"`
}

// ContractCase describes immutable fixture identity and the semantic cohort assignment. LegacyOrigin is an
// explicit migration marker; such a case cannot be used for a v2 baseline or candidate acceptance input.
type ContractCase struct {
	ID           string               `json:"id"`
	SubjectID    string               `json:"subject_id"`
	CohortID     string               `json:"cohort_id"`
	ModeID       string               `json:"mode_id"`
	Fixture      *ArtifactReference   `json:"fixture,omitempty"`
	LegacyOrigin *LegacyCaseReference `json:"legacy_origin,omitempty"`
}

// ContractCorpus holds fixture cases separately from oracle decisions.
type ContractCorpus struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Cases         []ContractCase `json:"cases"`
}

// OracleCase owns the static truth and authorization metadata for one contract case.
type OracleCase struct {
	CaseID                string             `json:"case_id"`
	Expected              Outcome            `json:"expected"`
	Category              OracleCategory     `json:"category"`
	CoverageExpectation   CoverageStatus     `json:"coverage_expectation"`
	SuppressionApplicable bool               `json:"suppression_applicable"`
	CompletenessContract  *ArtifactReference `json:"completeness_contract,omitempty"`
}

// ReachabilityOracle holds exactly one oracle entry per corpus case.
type ReachabilityOracle struct {
	SchemaVersion string       `json:"schema_version"`
	ID            string       `json:"id"`
	Cases         []OracleCase `json:"cases"`
}

// SuppressionPolicyRule carries reviewed static authorization. It is intentionally absent from observations.
type SuppressionPolicyRule struct {
	CohortID                  string                 `json:"cohort_id"`
	ModeID                    string                 `json:"mode_id"`
	Disposition               SuppressionDisposition `json:"disposition"`
	CompletenessContract      *ArtifactReference     `json:"completeness_contract,omitempty"`
	ApprovedProposer          string                 `json:"approved_proposer,omitempty"`
	ApprovedVerifier          string                 `json:"approved_verifier,omitempty"`
	RuntimeDeploymentComplete bool                   `json:"runtime_deployment_complete,omitempty"`
	ComposerBootstrapComplete bool                   `json:"composer_bootstrap_complete,omitempty"`
}

// MeasurementPolicy binds the static inventory, corpus, oracle, approvals, and exception manifest. It must
// never contain a baseline result, checkpoint, threshold, or ratchet reference; that preserves acyclic identity.
type MeasurementPolicy struct {
	SchemaVersion           string                  `json:"schema_version"`
	ID                      string                  `json:"id"`
	Inventory               ArtifactReference       `json:"inventory"`
	Corpus                  ArtifactReference       `json:"corpus"`
	Oracle                  ArtifactReference       `json:"oracle"`
	ExceptionManifest       ArtifactReference       `json:"exception_manifest"`
	SchemaDefinition        ArtifactReference       `json:"schema_definition"`
	RunPurposeRules         ArtifactReference       `json:"run_purpose_rules"`
	RatchetConstructionRule ArtifactReference       `json:"ratchet_construction_rule"`
	Evaluator               ArtifactReference       `json:"evaluator"`
	MetricDefinition        ArtifactReference       `json:"metric_definition"`
	Adapters                []ArtifactReference     `json:"adapters"`
	Rules                   []SuppressionPolicyRule `json:"rules"`
}

// CoverageObligation records a bounded coverage fact rather than inferring a negative from a clean output.
type CoverageObligation struct {
	ID     string         `json:"id"`
	Status CoverageStatus `json:"status"`
}

// CoverageReason explains incomplete coverage using a closed reason vocabulary.
type CoverageReason struct {
	Code   CoverageReasonCode `json:"code"`
	Detail string             `json:"detail,omitempty"`
}

// ObservedCoverage is measured production coverage, separate from public reachability outcomes.
type ObservedCoverage struct {
	Status      CoverageStatus       `json:"status"`
	Obligations []CoverageObligation `json:"obligations"`
	Reasons     []CoverageReason     `json:"reasons,omitempty"`
}

// SnapshotIdentity binds the active source, SBOM, and run identities used to interpret an observation.
type SnapshotIdentity struct {
	Source ArtifactReference `json:"source"`
	SBOM   ArtifactReference `json:"sbom"`
	Run    ArtifactReference `json:"run"`
}

// SuppressionProof preserves the immutable production evidence needed to validate a suppressing effect.
type SuppressionProof struct {
	Judgment             ArtifactReference `json:"judgment"`
	SubjectID            string            `json:"subject_id"`
	BoundaryID           string            `json:"boundary_id"`
	Proposer             string            `json:"proposer"`
	Verifier             string            `json:"verifier"`
	CompletenessContract ArtifactReference `json:"completeness_contract"`
	Snapshot             SnapshotIdentity  `json:"snapshot"`
	Analyzer             ArtifactReference `json:"analyzer"`
	Configuration        ArtifactReference `json:"configuration"`
	Evidence             ArtifactReference `json:"evidence"`
	MissingProvenance    []string          `json:"missing_provenance,omitempty"`
}

// SuppressionEffect is one produced effect witnessed by the production boundary.
type SuppressionEffect struct {
	Kind  SuppressionEffectKind `json:"kind"`
	Proof SuppressionProof      `json:"proof"`
}

// SuppressionCapture reports the observed output capture; incomplete is never interpreted as zero effects.
type SuppressionCapture struct {
	Claim   SuppressionClaim    `json:"claim"`
	Status  CaptureStatus       `json:"status"`
	Effects []SuppressionEffect `json:"effects,omitempty"`
}

// PositiveEvidence optionally binds a positive path/evidence projection to the active snapshot.
type PositiveEvidence struct {
	Snapshot SnapshotIdentity  `json:"snapshot"`
	Evidence ArtifactReference `json:"evidence"`
}

// MeasuredObservation contains production output only. Policy authorization is resolved by the reducer.
type MeasuredObservation struct {
	CaseID        string             `json:"case_id"`
	BindingID     string             `json:"binding_id"`
	Invoked       bool               `json:"invoked"`
	Outcome       Outcome            `json:"outcome"`
	Coverage      ObservedCoverage   `json:"coverage"`
	OutputCapture CaptureStatus      `json:"output_capture"`
	Analyzer      ArtifactReference  `json:"analyzer"`
	Configuration ArtifactReference  `json:"configuration"`
	Suppression   SuppressionCapture `json:"suppression"`
	Positive      *PositiveEvidence  `json:"positive_evidence,omitempty"`
}

// CoverageException is the only allowable coverage regression exception. It cannot waive a suppression proof.
type CoverageException struct {
	ID        string `json:"id"`
	CohortID  string `json:"cohort_id"`
	ModeID    string `json:"mode_id"`
	BindingID string `json:"binding_id"`
	CaseID    string `json:"case_id"`
	Reason    string `json:"reason"`
}

// ExceptionManifest is frozen into the policy and candidate ratchet by digest.
type ExceptionManifest struct {
	SchemaVersion string              `json:"schema_version"`
	ID            string              `json:"id"`
	Entries       []CoverageException `json:"entries"`
}

// MeasurementInput is the v2 observation/input envelope.
type MeasurementInput struct {
	SchemaVersion  string                        `json:"schema_version"`
	Purpose        RunPurpose                    `json:"purpose"`
	Inventory      ProductionInventory           `json:"inventory"`
	Corpus         ContractCorpus                `json:"corpus"`
	Oracle         ReachabilityOracle            `json:"oracle"`
	Policy         MeasurementPolicy             `json:"policy"`
	Exceptions     ExceptionManifest             `json:"exceptions"`
	ActiveSnapshot SnapshotIdentity              `json:"active_snapshot"`
	Observations   []MeasuredObservation         `json:"observations"`
	Baseline       *MeasurementReport            `json:"baseline,omitempty"`
	Checkpoint     *ProceduralBaselineCheckpoint `json:"checkpoint,omitempty"`
	Ratchet        *CandidateRatchet             `json:"ratchet,omitempty"`
}

// OutcomeConfusion is one exact expected/observed public-outcome cell.
type OutcomeConfusion struct {
	Expected Outcome `json:"expected"`
	Observed Outcome `json:"observed"`
	Count    int64   `json:"count"`
}

// CoverageCount is an observed coverage-status count. Unobserved execution remains separate.
type CoverageCount struct {
	Status CoverageStatus `json:"status"`
	Count  int64          `json:"count"`
}

// ReachabilityMetrics uses integer counts and exact ratios. Found is a validated positive-set true positive.
type ReachabilityMetrics struct {
	Expected  int64 `json:"expected"`
	Found     int64 `json:"found"`
	Produced  int64 `json:"produced"`
	Precision Ratio `json:"precision"`
	Recall    Ratio `json:"recall"`
}

// SuppressionMetrics distinguishes raw produced claims from proof-valid suppressions.
type SuppressionMetrics struct {
	Status    RatioStatus `json:"status"`
	Eligible  int64       `json:"eligible"`
	Found     int64       `json:"found"`
	Produced  int64       `json:"produced"`
	Valid     int64       `json:"valid"`
	False     int64       `json:"false"`
	Invalid   int64       `json:"invalid"`
	Precision Ratio       `json:"precision"`
	Recall    Ratio       `json:"recall"`
}

// ExecutionCoverage makes every required binding/case unit visible to denominator and regression checks.
type ExecutionCoverage struct {
	CohortID  string          `json:"cohort_id"`
	ModeID    string          `json:"mode_id"`
	BindingID string          `json:"binding_id"`
	CaseID    string          `json:"case_id"`
	Observed  bool            `json:"observed"`
	Assessed  bool            `json:"assessed"`
	Coverage  *CoverageStatus `json:"coverage,omitempty"`
}

// BindingSummary is scored per actual root binding.
type BindingSummary struct {
	CohortID           string              `json:"cohort_id"`
	ModeID             string              `json:"mode_id"`
	BindingID          string              `json:"binding_id"`
	RequiredExecutions int64               `json:"required_executions"`
	ObservedExecutions int64               `json:"observed_executions"`
	Assessment         AssessmentState     `json:"assessment"`
	Reachability       ReachabilityMetrics `json:"reachability"`
	Suppressions       SuppressionMetrics  `json:"suppressions"`
	Coverage           []CoverageCount     `json:"coverage"`
	CoverageRate       Ratio               `json:"coverage_rate"`
	NoAnalysis         int64               `json:"no_analysis"`
	NoAnalysisRate     Ratio               `json:"no_analysis_rate"`
}

// CohortSummary is the semantic (cohort_id, mode_id) scoring unit. Its positive credit is collapsed across
// all benchmark-required bindings, so duplicate roots cannot inflate C2 breadth or positive results.
type CohortSummary struct {
	CohortID             string                `json:"cohort_id"`
	ModeID               string                `json:"mode_id"`
	Language             string                `json:"language"`
	BenchmarkRequired    bool                  `json:"benchmark_required"`
	Assessment           AssessmentState       `json:"assessment"`
	Cases                int64                 `json:"cases"`
	RequiredExecutions   int64                 `json:"required_executions"`
	ObservedExecutions   int64                 `json:"observed_executions"`
	OutcomeCounts        []OutcomeCount        `json:"outcome_counts"`
	CategoryCounts       []OracleCategoryCount `json:"category_counts"`
	Reachability         ReachabilityMetrics   `json:"reachability"`
	Suppressions         SuppressionMetrics    `json:"suppressions"`
	Coverage             []CoverageCount       `json:"coverage"`
	CoverageRate         Ratio                 `json:"coverage_rate"`
	NoAnalysis           int64                 `json:"no_analysis"`
	NoAnalysisRate       Ratio                 `json:"no_analysis_rate"`
	CorrectPositiveCases int64                 `json:"correct_positive_cases"`
}

// OutcomeCount is an oracle outcome denominator count.
type OutcomeCount struct {
	Outcome Outcome `json:"outcome"`
	Count   int64   `json:"count"`
}

// OracleCategoryCount is a semantic-category denominator count for C2 breadth.
type OracleCategoryCount struct {
	Category OracleCategory `json:"category"`
	Count    int64          `json:"count"`
}

// LanguageSummary applies the same conservative semantic-case aggregation across language cohorts.
type LanguageSummary struct {
	Language       string              `json:"language"`
	Cohorts        int64               `json:"cohorts"`
	Reachability   ReachabilityMetrics `json:"reachability"`
	Suppressions   SuppressionMetrics  `json:"suppressions"`
	Coverage       []CoverageCount     `json:"coverage"`
	CoverageRate   Ratio               `json:"coverage_rate"`
	NoAnalysis     int64               `json:"no_analysis"`
	NoAnalysisRate Ratio               `json:"no_analysis_rate"`
}

// C2Vector is the strictly compared, lexicographic candidate-improvement vector.
type C2Vector struct {
	ProductionBreadth    int64 `json:"production_breadth"`
	CorrectPositiveCases int64 `json:"correct_positive_cases"`
	MacroReachableRecall Ratio `json:"macro_reachable_recall"`
}

// SafetyFinding records unsafe historical evidence rather than erasing it from a baseline measurement.
type SafetyFinding struct {
	Kind      string `json:"kind"`
	CohortID  string `json:"cohort_id"`
	ModeID    string `json:"mode_id"`
	BindingID string `json:"binding_id"`
	CaseID    string `json:"case_id"`
	Reason    string `json:"reason"`
}

// SafetyDisposition is diagnostic for baseline measurement and mandatory for candidate acceptance.
type SafetyDisposition struct {
	Pass     bool            `json:"pass"`
	Findings []SafetyFinding `json:"findings"`
}

// CandidateDisposition reports acceptance independently of the baseline's diagnostic safety state.
type CandidateDisposition struct {
	Evaluated bool     `json:"evaluated"`
	Accepted  bool     `json:"accepted"`
	Reasons   []string `json:"reasons,omitempty"`
}

// MeasurementReport is a digest-bound scorecard. RatchetDigest is intentionally empty for baseline reports.
type MeasurementReport struct {
	SchemaVersion             string                `json:"schema_version"`
	ID                        string                `json:"id"`
	Purpose                   RunPurpose            `json:"purpose"`
	Policy                    ArtifactReference     `json:"policy"`
	Inventory                 ArtifactReference     `json:"inventory"`
	Corpus                    ArtifactReference     `json:"corpus"`
	Oracle                    ArtifactReference     `json:"oracle"`
	ExceptionManifest         ArtifactReference     `json:"exception_manifest"`
	ActiveSnapshot            SnapshotIdentity      `json:"active_snapshot"`
	RatchetDigest             string                `json:"ratchet_digest,omitempty"`
	RequiredExecutions        int64                 `json:"required_executions"`
	ObservedExecutions        int64                 `json:"observed_executions"`
	UnobservedExecutions      int64                 `json:"unobserved_executions"`
	OutcomeConfusion          []OutcomeConfusion    `json:"outcome_confusion"`
	Reachability              ReachabilityMetrics   `json:"reachability"`
	Suppressions              SuppressionMetrics    `json:"suppressions"`
	Coverage                  []CoverageCount       `json:"coverage"`
	CoverageRate              Ratio                 `json:"coverage_rate"`
	NoAnalysis                int64                 `json:"no_analysis"`
	NoAnalysisRate            Ratio                 `json:"no_analysis_rate"`
	EnabledCohorts            int64                 `json:"enabled_cohorts"`
	AssessedEnabledCohorts    int64                 `json:"assessed_enabled_cohorts"`
	ProductionPositiveCohorts int64                 `json:"production_positive_cohorts"`
	Bindings                  []BindingSummary      `json:"bindings"`
	Cohorts                   []CohortSummary       `json:"cohorts"`
	Languages                 []LanguageSummary     `json:"languages"`
	ExecutionCoverage         []ExecutionCoverage   `json:"execution_coverage"`
	Observations              []MeasuredObservation `json:"observations"`
	C2                        C2Vector              `json:"c2"`
	Safety                    SafetyDisposition     `json:"safety"`
	Candidate                 CandidateDisposition  `json:"candidate"`
}

// ProceduralBaselineCheckpoint binds a reviewed baseline without claiming external cryptographic identity.
type ProceduralBaselineCheckpoint struct {
	SchemaVersion       string            `json:"schema_version"`
	ID                  string            `json:"id"`
	AuthorityClass      string            `json:"authority_class"`
	OriginAuthenticated bool              `json:"origin_authenticated"`
	StartingRevision    string            `json:"starting_revision"`
	Policy              ArtifactReference `json:"policy"`
	BaselineResult      ArtifactReference `json:"baseline_result"`
	HarnessContract     ArtifactReference `json:"harness_contract"`
	AllowlistEvidence   ArtifactReference `json:"allowlist_evidence"`
	ReviewEvidence      ArtifactReference `json:"review_evidence"`
	DispositionEvidence ArtifactReference `json:"disposition_evidence"`
	Producer            string            `json:"producer"`
	Reviewer            string            `json:"reviewer"`
	Maintainer          string            `json:"maintainer"`
}

// RatchetCohort holds mandatory per-cohort guards derived from the attested baseline.
type RatchetCohort struct {
	CohortID     string             `json:"cohort_id"`
	ModeID       string             `json:"mode_id"`
	Recall       Ratio              `json:"recall"`
	Suppressions SuppressionMetrics `json:"suppressions"`
}

// RatchetLanguage holds mandatory per-language recall guards derived from the baseline.
type RatchetLanguage struct {
	Language string `json:"language"`
	Recall   Ratio  `json:"recall"`
}

// RatchetBinding holds the non-offsettable recall floor for one actual production boundary.
type RatchetBinding struct {
	CohortID  string `json:"cohort_id"`
	ModeID    string `json:"mode_id"`
	BindingID string `json:"binding_id"`
	Recall    Ratio  `json:"recall"`
}

// CandidateRatchet is created only after a procedural baseline checkpoint. It contains baseline-derived
// thresholds and guards, while MeasurementPolicy deliberately does not.
type CandidateRatchet struct {
	SchemaVersion      string              `json:"schema_version"`
	ID                 string              `json:"id"`
	Policy             ArtifactReference   `json:"policy"`
	BaselineResult     ArtifactReference   `json:"baseline_result"`
	BaselineCheckpoint ArtifactReference   `json:"baseline_checkpoint"`
	ExceptionManifest  ArtifactReference   `json:"exception_manifest"`
	C2                 C2Vector            `json:"c2"`
	Reachability       ReachabilityMetrics `json:"reachability"`
	Bindings           []RatchetBinding    `json:"bindings"`
	Cohorts            []RatchetCohort     `json:"cohorts"`
	Languages          []RatchetLanguage   `json:"languages"`
	Coverage           []ExecutionCoverage `json:"coverage"`
}

// LegacyAvailability records fields that v1 never produced. It is intentionally explicit rather than inferred.
type LegacyAvailability string

const LegacyUnavailable LegacyAvailability = "unavailable"

// LegacyCaseReference preserves a v1 corpus case identity during one-way migration.
type LegacyCaseReference struct {
	OriginalCorpusDigest string `json:"original_corpus_digest"`
	OriginalCaseID       string `json:"original_case_id"`
}

// LegacyLabel preserves a v1 observation label without reinterpreting it as v2 production proof.
type LegacyLabel struct {
	CaseID string `json:"case_id"`
	Label  Label  `json:"label"`
}

// LegacyV1Evidence retains exact source bytes and limitations. It cannot be evaluated as a v2 baseline or candidate.
type LegacyV1Evidence struct {
	OriginalBytes         []byte             `json:"original_bytes"`
	OriginalDigest        string             `json:"original_digest"`
	Labels                []LegacyLabel      `json:"labels"`
	Coverage              LegacyAvailability `json:"coverage"`
	SuppressionCapture    LegacyAvailability `json:"suppression_capture"`
	AnalyzerIdentity      LegacyAvailability `json:"analyzer_identity"`
	ConfigurationIdentity LegacyAvailability `json:"configuration_identity"`
	SnapshotIdentity      LegacyAvailability `json:"snapshot_identity"`
	Authority             LegacyAvailability `json:"authority"`
}

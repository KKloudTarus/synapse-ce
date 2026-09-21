// Package scabench defines the pure, provenance-backed contract for SCA accuracy benchmarks.
// It deliberately contains no scanner execution, persistence, or network behavior.
package scabench

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const (
	CatalogSchemaVersion     = "synapse-sca-benchmark-catalog-v1"
	OracleSchemaVersion      = "synapse-sca-benchmark-oracle-v1"
	ObservationSchemaVersion = "synapse-sca-benchmark-observation-v1"
	ResultSchemaVersion      = "synapse-sca-benchmark-result-v1"
	RatchetSchemaVersion     = "synapse-sca-benchmark-ratchet-v1"
)

// Engine identifies an engine evaluated against the same independently reviewed oracle.
type Engine string

const (
	EngineOwned      Engine = "owned"
	EngineGrype      Engine = "grype"
	EngineTrivy      Engine = "trivy"
	EngineOSVScanner Engine = "osv-scanner"
)

// Engines returns the supported engines in deterministic display and result order.
func Engines() []Engine {
	return []Engine{EngineOwned, EngineGrype, EngineTrivy, EngineOSVScanner}
}

func (e Engine) valid() bool {
	switch e {
	case EngineOwned, EngineGrype, EngineTrivy, EngineOSVScanner:
		return true
	default:
		return false
	}
}

// CaseClassification records whether a reviewed case was observed in a real target or constructed synthetically.
type CaseClassification string

const (
	CaseReal      CaseClassification = "real"
	CaseSynthetic CaseClassification = "synthetic"
)

// Truth is the independently reviewed advisory state for a target component.
type Truth string

const (
	TruthAffected    Truth = "affected"
	TruthFixed       Truth = "fixed"
	TruthNotAffected Truth = "not_affected"
	TruthWithdrawn   Truth = "withdrawn"
)

func (t Truth) valid() bool {
	switch t {
	case TruthAffected, TruthFixed, TruthNotAffected, TruthWithdrawn:
		return true
	default:
		return false
	}
}

// Coverage is the expected evaluability of one oracle case by an engine.
type Coverage string

const (
	CoverageCovered     Coverage = "covered"
	CoverageUnknown     Coverage = "unknown"
	CoverageUnsupported Coverage = "unsupported"
	CoverageIncomplete  Coverage = "incomplete"
)

func (c Coverage) valid() bool {
	switch c {
	case CoverageCovered, CoverageUnknown, CoverageUnsupported, CoverageIncomplete:
		return true
	default:
		return false
	}
}

// ReviewStatus is the approval state of an independently reviewed oracle case.
type ReviewStatus string

const (
	ReviewApproved ReviewStatus = "approved"
)

// Provenance declares the source class for an oracle case. Scanner output is never an oracle source.
type Provenance string

const (
	ProvenanceIndependent Provenance = "independent"
)

// Component is a neutral PURL-based component identity for independently labeled benchmark cases.
type Component struct {
	PURL    string `json:"purl"`
	Version string `json:"version,omitempty"`
}

// Target is a digest-pinned OCI target and the components catalogued from that exact target.
type Target struct {
	ID         string      `json:"id"`
	OCIRef     string      `json:"oci_ref"`
	Digest     string      `json:"digest"`
	SBOMDigest string      `json:"sbom_digest"`
	Components []Component `json:"components"`
}

// ArtifactPin identifies immutable benchmark input other than the target OCI image.
type ArtifactPin struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// Catalog identifies the fixed input set shared by every engine.
type Catalog struct {
	SchemaVersion string        `json:"schema_version"`
	Revision      string        `json:"revision"`
	Targets       []Target      `json:"targets"`
	Pins          []ArtifactPin `json:"pins,omitempty"`
}

// Citation is independently retrievable, immutable evidence supporting an oracle case.
type Citation struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// OracleCase states one independently labeled component/advisory truth.
type OracleCase struct {
	ID               string              `json:"id"`
	Classification   CaseClassification  `json:"classification"`
	TargetID         string              `json:"target_id"`
	Component        Component           `json:"component"`
	AdvisoryID       string              `json:"advisory_id"`
	Aliases          []string            `json:"aliases,omitempty"`
	Truth            Truth               `json:"truth"`
	ExpectedCoverage map[Engine]Coverage `json:"expected_coverage"`
	Provenance       Provenance          `json:"provenance"`
	ReviewStatus     ReviewStatus        `json:"review_status"`
	LabelerIDs       []string            `json:"labeler_ids"`
	ReviewerIDs      []string            `json:"reviewer_ids"`
	Rationale        string              `json:"rationale"`
	Citations        []Citation          `json:"citations"`
}

// Oracle is a versioned collection of independent reviewed truth cases for one catalog revision.
type Oracle struct {
	SchemaVersion   string       `json:"schema_version"`
	CatalogRevision string       `json:"catalog_revision"`
	Cases           []OracleCase `json:"cases"`
}

// ObservationState records whether a scanner completed a usable run for its target.
type ObservationState string

const (
	ObservationComplete    ObservationState = "complete"
	ObservationUnknown     ObservationState = "unknown"
	ObservationUnsupported ObservationState = "unsupported"
	ObservationIncomplete  ObservationState = "incomplete"
)

func (s ObservationState) valid() bool {
	switch s {
	case ObservationComplete, ObservationUnknown, ObservationUnsupported, ObservationIncomplete:
		return true
	default:
		return false
	}
}

// CapabilityKind identifies an attested, zero-dispatch scanner limitation.
type CapabilityKind string

const (
	CapabilityKindOSVScannerSUSERPM                  CapabilityKind = "osv-scanner-v2.5.1-suse-rpm-same-sbom-v1"
	CapabilityKindOSVScannerRedHatEnterpriseLinuxRPM CapabilityKind = "osv-scanner-v2.5.1-red-hat-enterprise-linux-rpm-same-sbom-v1"
)

func (kind CapabilityKind) valid() bool {
	return kind == CapabilityKindOSVScannerSUSERPM || kind == CapabilityKindOSVScannerRedHatEnterpriseLinuxRPM
}

func capabilityKindEngine(kind CapabilityKind) (Engine, bool) {
	switch kind {
	case CapabilityKindOSVScannerSUSERPM, CapabilityKindOSVScannerRedHatEnterpriseLinuxRPM:
		return EngineOSVScanner, true
	default:
		return "", false
	}
}

// Finding is one scanner-reported component/advisory pair.
type Finding struct {
	Component  Component `json:"component"`
	AdvisoryID string    `json:"advisory_id"`
}

// Observation is a captured result from one engine for one pinned target. It is data only; this package does not run engines.
type Observation struct {
	SchemaVersion      string           `json:"schema_version"`
	CatalogRevision    string           `json:"catalog_revision"`
	CatalogDigest      string           `json:"catalog_digest"`
	Engine             Engine           `json:"engine"`
	EngineVersion      string           `json:"engine_version"`
	EngineBinaryDigest string           `json:"engine_binary_digest"`
	DatabaseBuild      string           `json:"database_build"`
	DatabaseDigest     string           `json:"database_digest"`
	EnvironmentID      string           `json:"environment_id"`
	EnvironmentDigest  string           `json:"environment_digest"`
	TargetID           string           `json:"target_id"`
	TargetDigest       string           `json:"target_digest"`
	SBOMDigest         string           `json:"sbom_digest"`
	State              ObservationState `json:"state"`
	RawOutputDigest    string           `json:"raw_output_digest"`
	ConfigDigest       string           `json:"config_digest"`
	CapabilityKind     CapabilityKind   `json:"capability_kind,omitempty"`
	CapabilityDigest   string           `json:"capability_digest,omitempty"`
	Findings           []Finding        `json:"findings,omitempty"`
}

// ObservationSet is the strict JSON transport envelope for captured observations.
type ObservationSet struct {
	SchemaVersion   string        `json:"schema_version"`
	CatalogRevision string        `json:"catalog_revision"`
	CatalogDigest   string        `json:"catalog_digest"`
	Observations    []Observation `json:"observations"`
}

// DiagnosticCode categorizes fail-friendly reducer evidence that is excluded from metrics.
type DiagnosticCode string

const (
	DiagnosticUnreviewedFinding DiagnosticCode = "unreviewed_finding"
	DiagnosticInvalidFinding    DiagnosticCode = "invalid_finding_component"
)

// Diagnostic is stable, machine-readable reduction context.
type Diagnostic struct {
	Engine   Engine         `json:"engine"`
	TargetID string         `json:"target_id"`
	Code     DiagnosticCode `json:"code"`
	Detail   string         `json:"detail"`
}

// EngineResult is an honest per-engine score. Nil metrics encode as JSON null when the denominator is zero.
type EngineResult struct {
	Engine            Engine   `json:"engine"`
	Covered           int      `json:"covered"`
	Unknown           int      `json:"unknown"`
	Unsupported       int      `json:"unsupported"`
	Incomplete        int      `json:"incomplete"`
	AffectedRelations int      `json:"affected_relations"`
	NegativeRelations int      `json:"negative_relations"`
	TruePositives     int      `json:"true_positives"`
	FalsePositives    int      `json:"false_positives"`
	FalseNegatives    int      `json:"false_negatives"`
	MetricsComplete   bool     `json:"metrics_complete"`
	Precision         *float64 `json:"precision"`
	Recall            *float64 `json:"recall"`
}

// Result is a deterministic reduction of one catalog, oracle, and observation set.
// Result is a deterministic reduction of one catalog, oracle, and observation set.
// TargetIdentity records immutable target and SBOM content identities covered by a result.
type TargetIdentity struct {
	ID         string `json:"id"`
	Digest     string `json:"digest"`
	SBOMDigest string `json:"sbom_digest"`
}

// RunIdentity records the complete immutable provenance of a scanner capture.
// RunIdentity records the score-bearing identity of a scanner capture.
type RunIdentity struct {
	CatalogRevision    string           `json:"catalog_revision"`
	CatalogDigest      string           `json:"catalog_digest"`
	Engine             Engine           `json:"engine"`
	EngineVersion      string           `json:"engine_version"`
	EngineBinaryDigest string           `json:"engine_binary_digest"`
	DatabaseBuild      string           `json:"database_build"`
	DatabaseDigest     string           `json:"database_digest"`
	EnvironmentID      string           `json:"environment_id"`
	EnvironmentDigest  string           `json:"environment_digest"`
	TargetID           string           `json:"target_id"`
	TargetDigest       string           `json:"target_digest"`
	SBOMDigest         string           `json:"sbom_digest"`
	State              ObservationState `json:"state"`
	ConfigDigest       string           `json:"config_digest"`
	CapabilityKind     CapabilityKind   `json:"capability_kind,omitempty"`
	CapabilityDigest   string           `json:"capability_digest,omitempty"`
}

// ExpectedRunIdentity pins the immutable inputs used to select a benchmark run.
// It deliberately excludes observation state and raw output, which describe one capture.
type ExpectedRunIdentity struct {
	TargetID           string         `json:"target_id"`
	TargetDigest       string         `json:"target_digest"`
	SBOMDigest         string         `json:"sbom_digest"`
	Engine             Engine         `json:"engine"`
	EngineVersion      string         `json:"engine_version"`
	EngineBinaryDigest string         `json:"engine_binary_digest"`
	DatabaseBuild      string         `json:"database_build"`
	DatabaseDigest     string         `json:"database_digest"`
	EnvironmentID      string         `json:"environment_id"`
	EnvironmentDigest  string         `json:"environment_digest"`
	ConfigDigest       string         `json:"config_digest"`
	CapabilityKind     CapabilityKind `json:"capability_kind,omitempty"`
	CapabilityDigest   string         `json:"capability_digest,omitempty"`
}

// RunMetric is a target-and-engine score bound to one immutable capture identity.
type RunMetric struct {
	Run     RunIdentity  `json:"run"`
	Metrics EngineResult `json:"metrics"`
}

// GateReasonCode is a stable machine-readable explanation for a ratchet check failure.
type GateReasonCode string

const (
	GateReasonThresholdBreach        GateReasonCode = "threshold_breach"
	GateReasonPinMismatch            GateReasonCode = "pin_mismatch"
	GateReasonMissingObservation     GateReasonCode = "missing_observation"
	GateReasonMetricsIncomplete      GateReasonCode = "metrics_incomplete"
	GateReasonMetricUnavailable      GateReasonCode = "metric_unavailable"
	GateReasonCoverageContractBreach GateReasonCode = "coverage_contract_breach"
)

// FloorGateMode selects the semantics used to evaluate a ratchet floor.
type FloorGateMode string

const (
	FloorGateModeAccuracy        FloorGateMode = "accuracy"
	FloorGateModeUnsupportedOnly FloorGateMode = "unsupported_only"
)

func (mode FloorGateMode) valid() bool {
	switch mode {
	case "", FloorGateModeAccuracy, FloorGateModeUnsupportedOnly:
		return true
	default:
		return false
	}
}

func (mode FloorGateMode) canonical() FloorGateMode {
	if mode == "" || mode == FloorGateModeAccuracy {
		return ""
	}
	return mode
}

func (mode FloorGateMode) effective() FloorGateMode {
	if mode.canonical() == "" {
		return FloorGateModeAccuracy
	}
	return mode
}

func validateFloorGateModeJSON(fields map[string]json.RawMessage) error {
	raw, exists := fields["mode"]
	if !exists {
		return nil
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return fmt.Errorf("mode must be an exact string value")
	}
	var mode FloorGateMode
	if err := json.Unmarshal(raw, &mode); err != nil {
		return fmt.Errorf("mode must be an exact string value: %w", err)
	}
	if !mode.valid() || mode == "" {
		return fmt.Errorf("mode must be %q or %q", FloorGateModeAccuracy, FloorGateModeUnsupportedOnly)
	}
	return nil
}

// GateCheck records the expected floor identity and its observed run, if supplied.
type GateCheck struct {
	Expected    ExpectedRunIdentity `json:"expected"`
	Mode        FloorGateMode       `json:"mode,omitempty"`
	Actual      *RunIdentity        `json:"actual,omitempty"`
	Passed      bool                `json:"passed"`
	ReasonCodes []GateReasonCode    `json:"reason_codes"`
}

// UnmarshalJSON rejects a supplied null or non-canonical gate mode while allowing legacy omission.
func (check *GateCheck) UnmarshalJSON(data []byte) error {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := validateFloorGateModeJSON(fields); err != nil {
		return err
	}
	type decodedGateCheck GateCheck
	var decoded decodedGateCheck
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*check = GateCheck(decoded)
	return nil
}

// Gate records deterministic ratchet evidence embedded in a re-identified result.
type Gate struct {
	RatchetDigest string      `json:"ratchet_digest"`
	Ratchet       Ratchet     `json:"ratchet"`
	Passed        bool        `json:"passed"`
	Checks        []GateCheck `json:"checks"`
}

// Result is a deterministic reduction of one catalog, oracle, and observation set.
type Result struct {
	SchemaVersion            string           `json:"schema_version"`
	ID                       string           `json:"id"`
	CatalogRevision          string           `json:"catalog_revision"`
	CatalogDigest            string           `json:"catalog_digest"`
	OracleDigest             string           `json:"oracle_digest"`
	ScoringObservationDigest string           `json:"scoring_observation_digest"`
	Targets                  []TargetIdentity `json:"targets"`
	Runs                     []RunIdentity    `json:"runs"`
	RunMetrics               []RunMetric      `json:"run_metrics"`
	Engines                  []EngineResult   `json:"engines"`
	Diagnostics              []Diagnostic     `json:"diagnostics"`
	Gate                     *Gate            `json:"gate,omitempty"`
}

// RatchetFloor is a pinned expected input identity and its non-vacuous score floors.
type RatchetFloor struct {
	Expected                 ExpectedRunIdentity `json:"expected"`
	Mode                     FloorGateMode       `json:"mode,omitempty"`
	AllowUndefinedPrecision  bool                `json:"allow_undefined_precision,omitempty"`
	MinimumCovered           *int                `json:"minimum_covered"`
	MinimumAffectedRelations *int                `json:"minimum_affected_relations"`
	MinimumNegativeRelations *int                `json:"minimum_negative_relations"`
	MinimumPrecision         *float64            `json:"minimum_precision"`
	MinimumRecall            *float64            `json:"minimum_recall"`
	MaximumFalsePositives    *int                `json:"maximum_false_positives"`
	MaximumFalseNegatives    *int                `json:"maximum_false_negatives"`
	MaximumUnknown           *int                `json:"maximum_unknown"`
	MaximumIncomplete        *int                `json:"maximum_incomplete"`
	MaximumUnsupported       *int                `json:"maximum_unsupported"`
}

// UnmarshalJSON requires the expected identity and every threshold, including intentional zeroes.
func (floor *RatchetFloor) UnmarshalJSON(data []byte) error {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{
		"expected", "minimum_covered", "minimum_affected_relations", "minimum_negative_relations",
		"minimum_precision", "minimum_recall", "maximum_false_positives", "maximum_false_negatives",
		"maximum_unknown", "maximum_incomplete", "maximum_unsupported",
	} {
		if _, exists := fields[name]; !exists {
			return fmt.Errorf("ratchet floor field %q is required", name)
		}
	}
	if err := validateFloorGateModeJSON(fields); err != nil {
		return err
	}
	type decodedFloor RatchetFloor
	var decoded decodedFloor
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*floor = RatchetFloor(decoded)
	return nil
}

// Ratchet is the checked-in, fully pinned threshold envelope for one catalog and oracle.
type Ratchet struct {
	SchemaVersion   string         `json:"schema_version"`
	CatalogRevision string         `json:"catalog_revision"`
	CatalogDigest   string         `json:"catalog_digest"`
	OracleDigest    string         `json:"oracle_digest"`
	Floors          []RatchetFloor `json:"floors"`
}

// ComponentBenchmarkKey is the benchmark-local, raw-PURL-independent component/advisory identity.
type ComponentBenchmarkKey struct {
	Ecosystem string
	Package   string
	Version   string
	Advisory  string
}

// BenchmarkKey derives an identity from resolved ecosystem, package, version, and advisory representative.
// It intentionally never includes sbom.ComponentIdentity.Fingerprint because it embeds raw PURL details.
func BenchmarkKey(component Component, advisoryRepresentative string) (ComponentBenchmarkKey, error) {
	identity, err := structuralComponentIdentity(component)
	if err != nil {
		return ComponentBenchmarkKey{}, err
	}
	advisory := canonicalAdvisory(advisoryRepresentative)
	if strings.TrimSpace(advisory) == "" {
		return ComponentBenchmarkKey{}, fmt.Errorf("advisory representative is required")
	}
	identity.Advisory = advisory
	return identity, nil
}

// ComponentKey is an alias for BenchmarkKey.
func ComponentKey(component Component, advisoryRepresentative string) (ComponentBenchmarkKey, error) {
	return BenchmarkKey(component, advisoryRepresentative)
}

// structuralComponentIdentity derives a benchmark-local identity without relying on
// any engine's supported-ecosystem or package-normalization policy.
func structuralComponentIdentity(component Component) (ComponentBenchmarkKey, error) {
	purl := strings.TrimSpace(component.PURL)
	if !strings.HasPrefix(purl, "pkg:") {
		return ComponentBenchmarkKey{}, fmt.Errorf("component purl must begin with pkg")
	}
	query := ""
	if queryStart := strings.IndexByte(purl, '?'); queryStart >= 0 {
		queryEnd := len(purl)
		if fragment := strings.IndexByte(purl[queryStart+1:], '#'); fragment >= 0 {
			queryEnd = queryStart + 1 + fragment
		}
		query = purl[queryStart+1 : queryEnd]
	}
	path := purl[len("pkg:"):]
	if delimiter := strings.IndexAny(path, "?#"); delimiter >= 0 {
		path = path[:delimiter]
	}
	slash := strings.IndexByte(path, '/')
	if slash <= 0 || slash == len(path)-1 {
		return ComponentBenchmarkKey{}, fmt.Errorf("component purl must contain a type and package")
	}
	ecosystem, err := url.PathUnescape(path[:slash])
	if err != nil || ecosystem == "" || containsControlCharacter(ecosystem) {
		return ComponentBenchmarkKey{}, fmt.Errorf("component purl type is invalid")
	}
	for _, character := range ecosystem {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-') {
			return ComponentBenchmarkKey{}, fmt.Errorf("component purl type is invalid")
		}
	}
	packageAndVersion := path[slash+1:]
	separator := strings.LastIndexByte(packageAndVersion, '@')
	packagePath := packageAndVersion
	purlVersion := ""
	if separator >= 0 {
		packagePath = packageAndVersion[:separator]
		purlVersion, err = url.PathUnescape(packageAndVersion[separator+1:])
		if err != nil || strings.TrimSpace(purlVersion) == "" || containsControlCharacter(purlVersion) {
			return ComponentBenchmarkKey{}, fmt.Errorf("component purl version is invalid")
		}
	}
	packageName, err := url.PathUnescape(packagePath)
	if err != nil || packageName == "" || containsControlCharacter(packageName) {
		return ComponentBenchmarkKey{}, fmt.Errorf("component purl package is invalid")
	}
	for _, segment := range strings.Split(packageName, "/") {
		if strings.TrimSpace(segment) == "" {
			return ComponentBenchmarkKey{}, fmt.Errorf("component purl package is invalid")
		}
	}
	effectivePURLVersion := purlVersion
	if ecosystem == "rpm" && query != "" {
		qualifiers, err := url.ParseQuery(query)
		if err != nil {
			return ComponentBenchmarkKey{}, fmt.Errorf("component purl qualifiers are invalid")
		}
		if epochs, ok := qualifiers["epoch"]; ok {
			if len(epochs) != 1 || purlVersion == "" || strings.TrimSpace(epochs[0]) == "" || strings.Contains(purlVersion, ":") {
				return ComponentBenchmarkKey{}, fmt.Errorf("component rpm epoch is invalid")
			}
			epoch := strings.TrimSpace(epochs[0])
			for _, character := range epoch {
				if character < '0' || character > '9' {
					return ComponentBenchmarkKey{}, fmt.Errorf("component rpm epoch is invalid")
				}
			}
			effectivePURLVersion = epoch + ":" + purlVersion
		}
	}
	version := strings.TrimSpace(component.Version)
	if version == "" {
		version = effectivePURLVersion
	}
	if version == "" || containsControlCharacter(version) {
		return ComponentBenchmarkKey{}, fmt.Errorf("component version is required")
	}
	if effectivePURLVersion != "" && version != effectivePURLVersion {
		return ComponentBenchmarkKey{}, fmt.Errorf("component purl and explicit version disagree")
	}
	return ComponentBenchmarkKey{
		Ecosystem: ecosystem,
		Package:   packageName,
		Version:   version,
	}, nil
}

// Validate validates a catalog and an oracle together, including target/component cross-references.
func Validate(catalog Catalog, oracle Oracle) error {
	if err := catalog.Validate(); err != nil {
		return err
	}
	if err := oracle.Validate(); err != nil {
		return err
	}
	if oracle.CatalogRevision != catalog.Revision {
		return fmt.Errorf("oracle catalog revision %q does not match catalog revision %q", oracle.CatalogRevision, catalog.Revision)
	}
	return validateOracleAgainstCatalog(catalog, oracle)
}

// Validate validates a catalog's self-contained invariants.
func (catalog Catalog) Validate() error {
	if catalog.SchemaVersion != CatalogSchemaVersion {
		return fmt.Errorf("unsupported catalog schema %q", catalog.SchemaVersion)
	}
	if strings.TrimSpace(catalog.Revision) == "" {
		return fmt.Errorf("catalog revision is required")
	}
	if len(catalog.Targets) == 0 {
		return fmt.Errorf("catalog must contain at least one target")
	}
	targets := make(map[string]struct{}, len(catalog.Targets))
	for i, target := range catalog.Targets {
		if !validPortableTargetID(target.ID) {
			return fmt.Errorf("catalog target %d id must be a portable path segment", i)
		}
		if _, exists := targets[target.ID]; exists {
			return fmt.Errorf("catalog target id %q is duplicated", target.ID)
		}
		targets[target.ID] = struct{}{}
		if !validSHA256Digest(target.Digest) || !validSHA256Digest(target.SBOMDigest) {
			return fmt.Errorf("catalog target %q target and SBOM digests must be immutable sha256 digests", target.ID)
		}
		if !validPinnedOCIRef(target.OCIRef, target.Digest) {
			return fmt.Errorf("catalog target %q OCI ref must be pinned to its sha256 digest", target.ID)
		}
		if len(target.Components) == 0 {
			return fmt.Errorf("catalog target %q must contain at least one component", target.ID)
		}
		components := make(map[ComponentBenchmarkKey]struct{}, len(target.Components))
		for j, component := range target.Components {
			key, err := componentIdentityKey(component)
			if err != nil {
				return fmt.Errorf("catalog target %q component %d: %w", target.ID, j, err)
			}
			if _, exists := components[key]; exists {
				return fmt.Errorf("catalog target %q has duplicate structural component identity", target.ID)
			}
			components[key] = struct{}{}
		}
	}
	pins := make(map[string]struct{}, len(catalog.Pins))
	for i, pin := range catalog.Pins {
		if err := validatePin(pin.Reference, pin.Digest); err != nil {
			return fmt.Errorf("catalog pin %d: %w", i, err)
		}
		reference := strings.TrimSpace(pin.Reference)
		if _, exists := pins[reference]; exists {
			return fmt.Errorf("catalog pin reference %q is duplicated", reference)
		}
		pins[reference] = struct{}{}
	}
	return nil
}

// Validate validates an oracle's self-contained independent-review invariants.
func (oracle Oracle) Validate() error {
	if oracle.SchemaVersion != OracleSchemaVersion {
		return fmt.Errorf("unsupported oracle schema %q", oracle.SchemaVersion)
	}
	if strings.TrimSpace(oracle.CatalogRevision) == "" {
		return fmt.Errorf("oracle catalog revision is required")
	}
	if len(oracle.Cases) == 0 {
		return fmt.Errorf("oracle must contain at least one case")
	}
	caseIDs := make(map[string]struct{}, len(oracle.Cases))
	benchmarkKeys := make(map[benchmarkCaseKey]string, len(oracle.Cases))
	aliases := make(map[advisoryLookupKey]string, len(oracle.Cases))
	hasAffected := false
	for i, oracleCase := range oracle.Cases {
		if err := validateOracleCase(oracleCase); err != nil {
			return fmt.Errorf("oracle case %d: %w", i, err)
		}
		if _, exists := caseIDs[oracleCase.ID]; exists {
			return fmt.Errorf("oracle case id %q is duplicated", oracleCase.ID)
		}
		caseIDs[oracleCase.ID] = struct{}{}
		componentKey, err := componentIdentityKey(oracleCase.Component)
		if err != nil {
			return fmt.Errorf("oracle case %q component: %w", oracleCase.ID, err)
		}
		canonical := canonicalAdvisory(oracleCase.AdvisoryID)
		for _, identifier := range append([]string{oracleCase.AdvisoryID}, oracleCase.Aliases...) {
			lookup := advisoryLookupKey{
				TargetID:  oracleCase.TargetID,
				Component: componentKey,
				Advisory:  canonicalAdvisory(identifier),
			}
			if previous, exists := aliases[lookup]; exists && previous != canonical {
				return fmt.Errorf("oracle alias closure %q conflicts for target %q component", lookup.Advisory, oracleCase.TargetID)
			}
			aliases[lookup] = canonical
		}
		key, err := BenchmarkKey(oracleCase.Component, canonical)
		if err != nil {
			return fmt.Errorf("oracle case %q: %w", oracleCase.ID, err)
		}
		caseKey := benchmarkCaseKey{TargetID: oracleCase.TargetID, Key: key}
		if previous, exists := benchmarkKeys[caseKey]; exists {
			return fmt.Errorf("oracle cases %q and %q have the same target benchmark key", previous, oracleCase.ID)
		}
		benchmarkKeys[caseKey] = oracleCase.ID
		if oracleCase.Truth == TruthAffected {
			hasAffected = true
		}
	}
	if !hasAffected {
		return fmt.Errorf("oracle must contain at least one affected case for non-vacuous recall")
	}
	return nil
}

// Validate validates a fully pinned ratchet envelope before it is evaluated.
func (ratchet Ratchet) Validate() error {
	if ratchet.SchemaVersion != RatchetSchemaVersion {
		return fmt.Errorf("unsupported ratchet schema %q", ratchet.SchemaVersion)
	}
	if strings.TrimSpace(ratchet.CatalogRevision) == "" {
		return fmt.Errorf("ratchet catalog revision is required")
	}
	if !validSHA256Digest(ratchet.CatalogDigest) || !validSHA256Digest(ratchet.OracleDigest) {
		return fmt.Errorf("ratchet catalog and oracle digests must be immutable sha256 digests")
	}
	if len(ratchet.Floors) == 0 {
		return fmt.Errorf("ratchet must contain at least one floor")
	}
	seen := make(map[observationKey]struct{}, len(ratchet.Floors))
	for i, floor := range ratchet.Floors {
		if !floor.Mode.valid() {
			return fmt.Errorf("ratchet floor %d has unsupported mode %q", i, floor.Mode)
		}
		if err := validateExpectedRunIdentity(floor.Expected); err != nil {
			return fmt.Errorf("ratchet floor %d: %w", i, err)
		}
		key := observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("ratchet floor %d has a duplicate engine and target", i)
		}
		seen[key] = struct{}{}
		for _, minimum := range []*int{floor.MinimumCovered, floor.MinimumAffectedRelations, floor.MinimumNegativeRelations} {
			if minimum == nil || *minimum < 0 {
				return fmt.Errorf("ratchet floor %d minimum is required and must not be negative", i)
			}
		}
		for _, maximum := range []*int{floor.MaximumFalsePositives, floor.MaximumFalseNegatives, floor.MaximumUnknown, floor.MaximumIncomplete, floor.MaximumUnsupported} {
			if maximum == nil || *maximum < 0 {
				return fmt.Errorf("ratchet floor %d maximum is required and must not be negative", i)
			}
		}
		for _, metric := range []*float64{floor.MinimumPrecision, floor.MinimumRecall} {
			if metric == nil || math.IsNaN(*metric) || math.IsInf(*metric, 0) || *metric < 0 || *metric > 1 {
				return fmt.Errorf("ratchet floor %d metric is required, finite, and between zero and one", i)
			}
		}
		if floor.AllowUndefinedPrecision {
			if floor.Mode.effective() != FloorGateModeAccuracy {
				return fmt.Errorf("ratchet floor %d allow undefined precision requires accuracy mode", i)
			}
			if *floor.MinimumPrecision != 0 {
				return fmt.Errorf("ratchet floor %d allow undefined precision requires minimum precision zero", i)
			}
		}
		if floor.Mode.effective() == FloorGateModeUnsupportedOnly {
			if err := validateUnsupportedOnlyFloor(floor); err != nil {
				return fmt.Errorf("ratchet floor %d: %w", i, err)
			}
		} else if floor.Expected.CapabilityKind != "" || floor.Expected.CapabilityDigest != "" {
			return fmt.Errorf("ratchet floor %d accuracy mode must not carry a capability identity", i)
		} else if *floor.MinimumCovered == 0 || *floor.MinimumAffectedRelations == 0 || *floor.MinimumNegativeRelations == 0 {
			return fmt.Errorf("ratchet floor %d accuracy minimum covered, affected relations, and negative relations must each be greater than zero", i)
		}
	}
	return nil
}

// ValidateRatchetTightening rejects a current ratchet that weakens a reviewed
// threshold policy. Pin identities may refresh, so floors are matched by target
// and engine while every metric and coverage threshold remains monotonic.
func ValidateRatchetTightening(baseline, current Ratchet) error {
	if err := baseline.Validate(); err != nil {
		return fmt.Errorf("validate baseline ratchet: %w", err)
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("validate current ratchet: %w", err)
	}
	if current.CatalogRevision != baseline.CatalogRevision {
		return fmt.Errorf("ratchet catalog revision %q does not match baseline revision %q", current.CatalogRevision, baseline.CatalogRevision)
	}
	if current.OracleDigest != baseline.OracleDigest {
		return fmt.Errorf("ratchet changes baseline oracle digest")
	}
	currentFloors := make(map[observationKey]RatchetFloor, len(current.Floors))
	for _, floor := range current.Floors {
		currentFloors[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}] = floor
	}
	for _, baselineFloor := range baseline.Floors {
		key := observationKey{Engine: baselineFloor.Expected.Engine, TargetID: baselineFloor.Expected.TargetID}
		currentFloor, exists := currentFloors[key]
		if !exists {
			return fmt.Errorf("ratchet removes baseline floor for engine %q target %q", key.Engine, key.TargetID)
		}
		if currentFloor.Mode.effective() != baselineFloor.Mode.effective() {
			return fmt.Errorf("ratchet changes baseline mode for engine %q target %q", key.Engine, key.TargetID)
		}
		stableIdentity := []struct {
			name              string
			baseline, current string
		}{
			{"target digest", baselineFloor.Expected.TargetDigest, currentFloor.Expected.TargetDigest},
			{"SBOM digest", baselineFloor.Expected.SBOMDigest, currentFloor.Expected.SBOMDigest},
			{"environment id", baselineFloor.Expected.EnvironmentID, currentFloor.Expected.EnvironmentID},
			{"environment digest", baselineFloor.Expected.EnvironmentDigest, currentFloor.Expected.EnvironmentDigest},
			{"config digest", baselineFloor.Expected.ConfigDigest, currentFloor.Expected.ConfigDigest},
			{"capability kind", string(baselineFloor.Expected.CapabilityKind), string(currentFloor.Expected.CapabilityKind)},
		}
		for _, identity := range stableIdentity {
			if identity.current != identity.baseline {
				return fmt.Errorf("ratchet changes baseline %s for engine %q target %q", identity.name, key.Engine, key.TargetID)
			}
		}
		if currentFloor.AllowUndefinedPrecision && !baselineFloor.AllowUndefinedPrecision {
			return fmt.Errorf("ratchet enables undefined precision for engine %q target %q", key.Engine, key.TargetID)
		}
		minimums := []struct {
			name              string
			baseline, current int
		}{
			{"covered", *baselineFloor.MinimumCovered, *currentFloor.MinimumCovered},
			{"affected relations", *baselineFloor.MinimumAffectedRelations, *currentFloor.MinimumAffectedRelations},
			{"negative relations", *baselineFloor.MinimumNegativeRelations, *currentFloor.MinimumNegativeRelations},
		}
		for _, threshold := range minimums {
			if threshold.current < threshold.baseline {
				return fmt.Errorf("ratchet lowers minimum %s for engine %q target %q", threshold.name, key.Engine, key.TargetID)
			}
		}
		minimumMetrics := []struct {
			name              string
			baseline, current float64
		}{
			{"precision", *baselineFloor.MinimumPrecision, *currentFloor.MinimumPrecision},
			{"recall", *baselineFloor.MinimumRecall, *currentFloor.MinimumRecall},
		}
		for _, threshold := range minimumMetrics {
			if threshold.current < threshold.baseline {
				return fmt.Errorf("ratchet lowers minimum %s for engine %q target %q", threshold.name, key.Engine, key.TargetID)
			}
		}
		maximums := []struct {
			name              string
			baseline, current int
		}{
			{"false positives", *baselineFloor.MaximumFalsePositives, *currentFloor.MaximumFalsePositives},
			{"false negatives", *baselineFloor.MaximumFalseNegatives, *currentFloor.MaximumFalseNegatives},
			{"unknown", *baselineFloor.MaximumUnknown, *currentFloor.MaximumUnknown},
			{"incomplete", *baselineFloor.MaximumIncomplete, *currentFloor.MaximumIncomplete},
			{"unsupported", *baselineFloor.MaximumUnsupported, *currentFloor.MaximumUnsupported},
		}
		for _, threshold := range maximums {
			if threshold.current > threshold.baseline {
				return fmt.Errorf("ratchet raises maximum %s for engine %q target %q", threshold.name, key.Engine, key.TargetID)
			}
		}
	}
	return nil
}

func validateUnsupportedOnlyFloor(floor RatchetFloor) error {
	if *floor.MinimumCovered != 0 ||
		*floor.MinimumAffectedRelations != 0 ||
		*floor.MinimumNegativeRelations != 0 ||
		*floor.MinimumPrecision != 0 ||
		*floor.MinimumRecall != 0 {
		return fmt.Errorf("unsupported-only minimums must all be zero")
	}
	if *floor.MaximumFalsePositives != 0 || *floor.MaximumFalseNegatives != 0 || *floor.MaximumUnknown != 0 || *floor.MaximumIncomplete != 0 {
		return fmt.Errorf("unsupported-only false-positive, false-negative, unknown, and incomplete ceilings must all be zero")
	}
	if *floor.MaximumUnsupported <= 0 {
		return fmt.Errorf("unsupported-only maximum unsupported must be greater than zero")
	}
	if err := validateRequiredCapabilityIdentity(floor.Expected.CapabilityKind, floor.Expected.CapabilityDigest); err != nil {
		return fmt.Errorf("unsupported-only capability identity: %w", err)
	}
	return nil
}

// Validate verifies that a result carries complete provenance and a digest bound to its content.
// Validate verifies that a result carries complete provenance and a digest bound to its content.
func (result Result) Validate() error {
	if result.SchemaVersion != ResultSchemaVersion {
		return fmt.Errorf("unsupported result schema %q", result.SchemaVersion)
	}
	if strings.TrimSpace(result.CatalogRevision) == "" {
		return fmt.Errorf("result catalog revision is required")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{name: "result id", value: result.ID},
		{name: "catalog digest", value: result.CatalogDigest},
		{name: "oracle digest", value: result.OracleDigest},
		{name: "scoring observation digest", value: result.ScoringObservationDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("result %s must be an immutable sha256 digest", digest.name)
		}
	}
	if len(result.Targets) == 0 || len(result.Runs) == 0 || len(result.RunMetrics) != len(result.Runs) || len(result.Engines) != len(Engines()) {
		return fmt.Errorf("result must contain targets, runs, per-run metrics, and one summary for every engine")
	}
	targets := make(map[string]TargetIdentity, len(result.Targets))
	for i, target := range result.Targets {
		if strings.TrimSpace(target.ID) == "" || !validSHA256Digest(target.Digest) || !validSHA256Digest(target.SBOMDigest) {
			return fmt.Errorf("result target %d must identify a target and immutable target/SBOM digests", i)
		}
		if _, exists := targets[target.ID]; exists {
			return fmt.Errorf("result target %q is duplicated", target.ID)
		}
		targets[target.ID] = target
	}
	runs := make(map[observationKey]RunIdentity, len(result.Runs))
	for i, run := range result.Runs {
		if err := validateRunIdentity(run, targets, result.CatalogRevision, result.CatalogDigest); err != nil {
			return fmt.Errorf("result run %d: %w", i, err)
		}
		key := observationKey{Engine: run.Engine, TargetID: run.TargetID}
		if _, exists := runs[key]; exists {
			return fmt.Errorf("result run for engine %q and target %q is duplicated", run.Engine, run.TargetID)
		}
		runs[key] = run
	}
	runMetrics := make(map[observationKey]RunMetric, len(result.RunMetrics))
	for i, metric := range result.RunMetrics {
		key := observationKey{Engine: metric.Run.Engine, TargetID: metric.Run.TargetID}
		run, exists := runs[key]
		if !exists || !sameRunIdentity(metric.Run, run) {
			return fmt.Errorf("result run metric %d does not bind a result run", i)
		}
		if err := validateEngineResult(metric.Metrics); err != nil || metric.Metrics.Engine != metric.Run.Engine {
			if err != nil {
				return fmt.Errorf("result run metric %d: %w", i, err)
			}
			return fmt.Errorf("result run metric %d engine does not match its run", i)
		}
		if _, exists := runMetrics[key]; exists {
			return fmt.Errorf("result run metric for engine %q and target %q is duplicated", metric.Run.Engine, metric.Run.TargetID)
		}
		runMetrics[key] = metric
	}
	engines := make(map[Engine]struct{}, len(result.Engines))
	for i, summary := range result.Engines {
		if err := validateEngineResult(summary); err != nil {
			return fmt.Errorf("result engine %d: %w", i, err)
		}
		if _, exists := engines[summary.Engine]; exists {
			return fmt.Errorf("result engine %q is duplicated", summary.Engine)
		}
		engines[summary.Engine] = struct{}{}
	}
	for _, engine := range Engines() {
		if _, exists := engines[engine]; !exists {
			return fmt.Errorf("result engine %q is missing", engine)
		}
	}
	if err := validateRunMetricSummaries(result.RunMetrics, result.Engines); err != nil {
		return err
	}
	for i, diagnostic := range result.Diagnostics {
		if !diagnostic.Engine.valid() {
			return fmt.Errorf("result diagnostic %d has unsupported engine %q", i, diagnostic.Engine)
		}
		if _, exists := targets[diagnostic.TargetID]; !exists {
			return fmt.Errorf("result diagnostic %d references unknown target %q", i, diagnostic.TargetID)
		}
		if diagnostic.Code != DiagnosticUnreviewedFinding && diagnostic.Code != DiagnosticInvalidFinding {
			return fmt.Errorf("result diagnostic %d has unsupported code %q", i, diagnostic.Code)
		}
		if strings.TrimSpace(diagnostic.Detail) == "" {
			return fmt.Errorf("result diagnostic %d detail is required", i)
		}
	}
	if err := validateGate(result); err != nil {
		return err
	}
	digest, err := DigestResult(result)
	if err != nil {
		return fmt.Errorf("digest result: %w", err)
	}
	if result.ID != digest {
		return fmt.Errorf("result id does not match content digest")
	}
	return nil
}

func validateRunMetricSummaries(runMetrics []RunMetric, summaries []EngineResult) error {
	totals := make(map[Engine]EngineResult, len(Engines()))
	for _, runMetric := range runMetrics {
		total, exists := totals[runMetric.Run.Engine]
		if !exists {
			total = EngineResult{Engine: runMetric.Run.Engine, MetricsComplete: true}
		}
		addMetrics(&total, runMetric.Metrics)
		totals[runMetric.Run.Engine] = total
	}
	for _, summary := range summaries {
		total := totals[summary.Engine]
		if summary.Covered != total.Covered ||
			summary.AffectedRelations != total.AffectedRelations ||
			summary.NegativeRelations != total.NegativeRelations ||
			summary.TruePositives != total.TruePositives ||
			summary.FalsePositives != total.FalsePositives ||
			summary.FalseNegatives != total.FalseNegatives {
			return fmt.Errorf("result engine %q aggregate score counts do not match its run metrics", summary.Engine)
		}
		if summary.Unknown < total.Unknown || summary.Unsupported < total.Unsupported || summary.Incomplete < total.Incomplete {
			return fmt.Errorf("result engine %q aggregate status counts are below its run metrics", summary.Engine)
		}
		if !total.MetricsComplete && summary.MetricsComplete {
			return fmt.Errorf("result engine %q marks incomplete run metrics as complete", summary.Engine)
		}
	}
	return nil
}

func validateRequiredCapabilityIdentity(kind CapabilityKind, digest string) error {
	if kind == "" || strings.TrimSpace(digest) == "" {
		return fmt.Errorf("kind and digest are both required")
	}
	if !kind.valid() || !validSHA256Digest(digest) {
		return fmt.Errorf("kind and digest must identify a supported immutable capability")
	}
	return nil
}

func validateOptionalCapabilityIdentity(kind CapabilityKind, digest string) error {
	if kind == "" && digest == "" {
		return nil
	}
	return validateRequiredCapabilityIdentity(kind, digest)
}

func validateRunIdentity(run RunIdentity, targets map[string]TargetIdentity, catalogRevision, catalogDigest string) error {
	if !run.Engine.valid() || !run.State.valid() {
		return fmt.Errorf("engine and state must be supported")
	}
	if strings.TrimSpace(run.CatalogRevision) == "" || run.CatalogRevision != catalogRevision || run.CatalogDigest != catalogDigest {
		return fmt.Errorf("run catalog identity does not match result")
	}
	if strings.TrimSpace(run.EngineVersion) == "" || strings.TrimSpace(run.DatabaseBuild) == "" || strings.TrimSpace(run.EnvironmentID) == "" {
		return fmt.Errorf("engine version, database build, and environment are required")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{name: "engine binary", value: run.EngineBinaryDigest},
		{name: "database", value: run.DatabaseDigest},
		{name: "environment", value: run.EnvironmentDigest},
		{name: "config", value: run.ConfigDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("%s digest must be an immutable sha256 digest", digest.name)
		}
	}
	if run.State == ObservationUnsupported {
		if err := validateRequiredCapabilityIdentity(run.CapabilityKind, run.CapabilityDigest); err != nil {
			return fmt.Errorf("unsupported run capability identity: %w", err)
		}
	} else if run.CapabilityKind != "" || run.CapabilityDigest != "" {
		return fmt.Errorf("only unsupported runs may carry a capability identity")
	}
	target, exists := targets[run.TargetID]
	if !exists || run.TargetDigest != target.Digest || run.SBOMDigest != target.SBOMDigest {
		return fmt.Errorf("target and SBOM identities do not match result targets")
	}
	return nil
}

func validateEngineResult(summary EngineResult) error {
	if !summary.Engine.valid() {
		return fmt.Errorf("unsupported engine %q", summary.Engine)
	}
	for _, count := range []int{summary.Covered, summary.Unknown, summary.Unsupported, summary.Incomplete, summary.AffectedRelations, summary.NegativeRelations, summary.TruePositives, summary.FalsePositives, summary.FalseNegatives} {
		if count < 0 {
			return fmt.Errorf("counts must not be negative")
		}
	}
	if summary.AffectedRelations != summary.TruePositives+summary.FalseNegatives {
		return fmt.Errorf("affected relations do not match TP/FN counts")
	}
	if summary.Covered != summary.AffectedRelations+summary.NegativeRelations {
		return fmt.Errorf("covered cases do not match affected and negative relations")
	}
	if summary.FalsePositives > summary.NegativeRelations {
		return fmt.Errorf("false positives exceed negative relations")
	}
	if !summary.MetricsComplete {
		if summary.Precision != nil || summary.Recall != nil {
			return fmt.Errorf("partial metrics must be null")
		}
		return nil
	}
	if err := validateMetric("precision", summary.Precision, summary.TruePositives, summary.TruePositives+summary.FalsePositives); err != nil {
		return err
	}
	return validateMetric("recall", summary.Recall, summary.TruePositives, summary.TruePositives+summary.FalseNegatives)
}

func validateMetric(name string, value *float64, numerator, denominator int) error {
	if denominator == 0 {
		if value != nil {
			return fmt.Errorf("%s must be null when its denominator is zero", name)
		}
		return nil
	}
	if value == nil {
		return fmt.Errorf("%s is required when its denominator is nonzero", name)
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1 {
		return fmt.Errorf("%s must be finite and between zero and one", name)
	}
	expected := float64(numerator) / float64(denominator)
	if *value != expected {
		return fmt.Errorf("%s does not match counts", name)
	}
	return nil
}

func expectedRunIdentityFromRun(run RunIdentity) ExpectedRunIdentity {
	return ExpectedRunIdentity{
		TargetID:           run.TargetID,
		TargetDigest:       run.TargetDigest,
		SBOMDigest:         run.SBOMDigest,
		Engine:             run.Engine,
		EngineVersion:      run.EngineVersion,
		EngineBinaryDigest: run.EngineBinaryDigest,
		DatabaseBuild:      run.DatabaseBuild,
		DatabaseDigest:     run.DatabaseDigest,
		EnvironmentID:      run.EnvironmentID,
		EnvironmentDigest:  run.EnvironmentDigest,
		ConfigDigest:       run.ConfigDigest,
		CapabilityKind:     run.CapabilityKind,
		CapabilityDigest:   run.CapabilityDigest,
	}
}

func validateExpectedRunIdentity(expected ExpectedRunIdentity) error {
	if !expected.Engine.valid() {
		return fmt.Errorf("engine must be supported")
	}
	if strings.TrimSpace(expected.TargetID) == "" || strings.TrimSpace(expected.EngineVersion) == "" || strings.TrimSpace(expected.DatabaseBuild) == "" || strings.TrimSpace(expected.EnvironmentID) == "" {
		return fmt.Errorf("target ID, engine version, database build, and environment are required")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{name: "target", value: expected.TargetDigest},
		{name: "SBOM", value: expected.SBOMDigest},
		{name: "engine binary", value: expected.EngineBinaryDigest},
		{name: "database", value: expected.DatabaseDigest},
		{name: "environment", value: expected.EnvironmentDigest},
		{name: "config", value: expected.ConfigDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("%s digest must be an immutable sha256 digest", digest.name)
		}
	}
	if err := validateOptionalCapabilityIdentity(expected.CapabilityKind, expected.CapabilityDigest); err != nil {
		return fmt.Errorf("capability identity: %w", err)
	}
	return nil
}

func sameRunIdentity(left, right RunIdentity) bool {
	return left == right
}

func sameExpectedRunIdentity(left, right ExpectedRunIdentity) bool {
	return left == right
}

func runIdentityKey(run RunIdentity) string {
	values := []string{
		run.CatalogRevision, run.CatalogDigest, string(run.Engine), run.EngineVersion, run.EngineBinaryDigest,
		run.DatabaseBuild, run.DatabaseDigest, run.EnvironmentID, run.EnvironmentDigest,
		run.TargetID, run.TargetDigest, run.SBOMDigest, string(run.State), run.ConfigDigest,
		string(run.CapabilityKind), run.CapabilityDigest,
	}
	var key strings.Builder
	for _, value := range values {
		fmt.Fprintf(&key, "%d:%s", len(value), value)
	}
	return key.String()
}

func expectedRunIdentityKey(expected ExpectedRunIdentity) string {
	values := []string{
		expected.TargetID, expected.TargetDigest, expected.SBOMDigest, string(expected.Engine), expected.EngineVersion,
		expected.EngineBinaryDigest, expected.DatabaseBuild, expected.DatabaseDigest, expected.EnvironmentID,
		expected.EnvironmentDigest, expected.ConfigDigest, string(expected.CapabilityKind), expected.CapabilityDigest,
	}
	var key strings.Builder
	for _, value := range values {
		fmt.Fprintf(&key, "%d:%s", len(value), value)
	}
	return key.String()
}

func expectedRunIdentityLess(left, right ExpectedRunIdentity) bool {
	return expectedRunIdentityKey(left) < expectedRunIdentityKey(right)
}

func validateGate(result Result) error {
	if result.Gate == nil {
		return nil
	}
	gate := result.Gate
	canonical := canonicalRatchet(gate.Ratchet)
	if !sameRatchet(gate.Ratchet, canonical) {
		return fmt.Errorf("result gate embedded ratchet must be canonical")
	}
	expected, err := evaluateGate(result, gate.Ratchet)
	if err != nil {
		return fmt.Errorf("evaluate result gate: %w", err)
	}
	if gate.RatchetDigest != expected.RatchetDigest {
		return fmt.Errorf("result gate ratchet digest does not match embedded ratchet")
	}
	if !sameGateEvidence(*gate, expected) {
		return fmt.Errorf("result gate evidence does not match its embedded ratchet evaluation")
	}
	return nil
}

func sameRatchet(left, right Ratchet) bool {
	if left.SchemaVersion != right.SchemaVersion ||
		left.CatalogRevision != right.CatalogRevision ||
		left.CatalogDigest != right.CatalogDigest ||
		left.OracleDigest != right.OracleDigest ||
		len(left.Floors) != len(right.Floors) {
		return false
	}
	for i := range left.Floors {
		if !sameRatchetFloor(left.Floors[i], right.Floors[i]) {
			return false
		}
	}
	return true
}

func sameRatchetFloor(left, right RatchetFloor) bool {
	return left.Expected == right.Expected &&
		left.Mode == right.Mode &&
		left.AllowUndefinedPrecision == right.AllowUndefinedPrecision &&
		sameIntPointer(left.MinimumCovered, right.MinimumCovered) &&
		sameIntPointer(left.MinimumAffectedRelations, right.MinimumAffectedRelations) &&
		sameIntPointer(left.MinimumNegativeRelations, right.MinimumNegativeRelations) &&
		sameFloatPointer(left.MinimumPrecision, right.MinimumPrecision) &&
		sameFloatPointer(left.MinimumRecall, right.MinimumRecall) &&
		sameIntPointer(left.MaximumFalsePositives, right.MaximumFalsePositives) &&
		sameIntPointer(left.MaximumFalseNegatives, right.MaximumFalseNegatives) &&
		sameIntPointer(left.MaximumUnknown, right.MaximumUnknown) &&
		sameIntPointer(left.MaximumIncomplete, right.MaximumIncomplete) &&
		sameIntPointer(left.MaximumUnsupported, right.MaximumUnsupported)
}

func sameIntPointer(left, right *int) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func sameFloatPointer(left, right *float64) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func sameGateEvidence(actual, expected Gate) bool {
	if actual.RatchetDigest != expected.RatchetDigest || actual.Passed != expected.Passed || len(actual.Checks) != len(expected.Checks) {
		return false
	}
	for i := range actual.Checks {
		if !sameGateCheck(actual.Checks[i], expected.Checks[i]) {
			return false
		}
	}
	return true
}

func sameGateCheck(actual, expected GateCheck) bool {
	if actual.Expected != expected.Expected ||
		actual.Mode.effective() != expected.Mode.effective() ||
		actual.Passed != expected.Passed ||
		!sameGateReasons(actual.ReasonCodes, expected.ReasonCodes) {
		return false
	}
	if actual.Actual == nil || expected.Actual == nil {
		return actual.Actual == nil && expected.Actual == nil
	}
	return sameRunIdentity(*actual.Actual, *expected.Actual)
}

func sameGateReasons(left, right []GateReasonCode) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func hasUnsupportedOnlyMetricShape(metrics EngineResult) bool {
	return metrics.Covered == 0 &&
		metrics.AffectedRelations == 0 &&
		metrics.NegativeRelations == 0 &&
		metrics.TruePositives == 0 &&
		metrics.FalsePositives == 0 &&
		metrics.FalseNegatives == 0 &&
		metrics.Unknown == 0 &&
		metrics.Incomplete == 0 &&
		metrics.Unsupported > 0 &&
		metrics.Precision == nil &&
		metrics.Recall == nil
}

func validateOracleCase(oracleCase OracleCase) error {
	if strings.TrimSpace(oracleCase.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if oracleCase.Classification != CaseReal && oracleCase.Classification != CaseSynthetic {
		return fmt.Errorf("classification must be explicit real or synthetic")
	}
	if strings.TrimSpace(oracleCase.TargetID) == "" {
		return fmt.Errorf("target id is required")
	}
	if _, err := componentIdentityKey(oracleCase.Component); err != nil {
		return fmt.Errorf("component identity: %w", err)
	}
	if err := validateCanonicalAdvisory(oracleCase.AdvisoryID); err != nil {
		return fmt.Errorf("advisory id: %w", err)
	}
	if !oracleCase.Truth.valid() {
		return fmt.Errorf("truth must be affected, fixed, not_affected, or withdrawn")
	}
	if oracleCase.Provenance != ProvenanceIndependent {
		return fmt.Errorf("provenance must be independent")
	}
	if oracleCase.ReviewStatus != ReviewApproved {
		return fmt.Errorf("review status must be approved")
	}
	if strings.TrimSpace(oracleCase.Rationale) == "" {
		return fmt.Errorf("reviewed rationale is required")
	}
	if err := validateReviewerSets(oracleCase.LabelerIDs, oracleCase.ReviewerIDs); err != nil {
		return err
	}
	if len(oracleCase.Citations) == 0 {
		return fmt.Errorf("at least one immutable citation is required")
	}
	for i, citation := range oracleCase.Citations {
		if err := validateCitation(citation); err != nil {
			return fmt.Errorf("citation %d: %w", i, err)
		}
	}
	if len(oracleCase.ExpectedCoverage) != len(Engines()) {
		return fmt.Errorf("expected coverage must be explicit for every engine")
	}
	for _, engine := range Engines() {
		coverage, exists := oracleCase.ExpectedCoverage[engine]
		if !exists || !coverage.valid() {
			return fmt.Errorf("expected coverage for engine %q is required and must be valid", engine)
		}
	}
	localAliases := map[string]struct{}{canonicalAdvisory(oracleCase.AdvisoryID): {}}
	for _, alias := range oracleCase.Aliases {
		if err := validateCanonicalAdvisory(alias); err != nil {
			return fmt.Errorf("alias: %w", err)
		}
		canonical := canonicalAdvisory(alias)
		if _, exists := localAliases[canonical]; exists {
			return fmt.Errorf("alias closure contains duplicate %q", canonical)
		}
		localAliases[canonical] = struct{}{}
	}
	return nil
}

type benchmarkCaseKey struct {
	TargetID string
	Key      ComponentBenchmarkKey
}

type advisoryLookupKey struct {
	TargetID  string
	Component ComponentBenchmarkKey
	Advisory  string
}

func validateOracleAgainstCatalog(catalog Catalog, oracle Oracle) error {
	targets := make(map[string]map[ComponentBenchmarkKey]struct{}, len(catalog.Targets))
	for _, target := range catalog.Targets {
		components := make(map[ComponentBenchmarkKey]struct{}, len(target.Components))
		for _, component := range target.Components {
			key, err := componentIdentityKey(component)
			if err != nil {
				return err // catalog.Validate already supplies contextual details.
			}
			components[key] = struct{}{}
		}
		targets[target.ID] = components
	}
	benchmarkKeys := make(map[benchmarkCaseKey]string, len(oracle.Cases))
	aliases := make(map[advisoryLookupKey]string, len(oracle.Cases))
	for _, oracleCase := range oracle.Cases {
		components, exists := targets[oracleCase.TargetID]
		if !exists {
			return fmt.Errorf("oracle case %q references unknown target %q", oracleCase.ID, oracleCase.TargetID)
		}
		componentKey, err := componentIdentityKey(oracleCase.Component)
		if err != nil {
			return fmt.Errorf("oracle case %q: %w", oracleCase.ID, err)
		}
		if _, exists := components[componentKey]; !exists {
			return fmt.Errorf("oracle case %q component is not catalogued in target %q", oracleCase.ID, oracleCase.TargetID)
		}
		canonical := canonicalAdvisory(oracleCase.AdvisoryID)
		for _, identifier := range append([]string{oracleCase.AdvisoryID}, oracleCase.Aliases...) {
			lookup := advisoryLookupKey{
				TargetID:  oracleCase.TargetID,
				Component: componentKey,
				Advisory:  canonicalAdvisory(identifier),
			}
			if previous, exists := aliases[lookup]; exists && previous != canonical {
				return fmt.Errorf("oracle alias closure %q conflicts for target %q component", lookup.Advisory, oracleCase.TargetID)
			}
			aliases[lookup] = canonical
		}
		key, err := BenchmarkKey(oracleCase.Component, oracleCase.AdvisoryID)
		if err != nil {
			return fmt.Errorf("oracle case %q: %w", oracleCase.ID, err)
		}
		caseKey := benchmarkCaseKey{TargetID: oracleCase.TargetID, Key: key}
		if previous, exists := benchmarkKeys[caseKey]; exists {
			return fmt.Errorf("oracle cases %q and %q have the same target benchmark key", previous, oracleCase.ID)
		}
		benchmarkKeys[caseKey] = oracleCase.ID
	}
	return nil
}

func componentIdentityKey(component Component) (ComponentBenchmarkKey, error) {
	return structuralComponentIdentity(component)
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validPortableTargetID(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validateCitation(citation Citation) error {
	if err := validatePin(citation.Reference, citation.Digest); err != nil {
		return err
	}
	if competitorCitation(citation.Reference) {
		return fmt.Errorf("competitor scanner output cannot be oracle evidence")
	}
	return nil
}

func validatePin(reference, digest string) error {
	if strings.TrimSpace(reference) == "" {
		return fmt.Errorf("reference is required")
	}
	if hasCredentialBearingAuthority(reference) {
		return fmt.Errorf("credential-bearing reference is forbidden")
	}
	if !validSHA256Digest(digest) {
		return fmt.Errorf("digest must be an immutable sha256 digest")
	}
	return nil
}

func validateReviewerSets(labelers, reviewers []string) error {
	if len(labelers) == 0 || len(reviewers) == 0 {
		return fmt.Errorf("nonempty labeler and reviewer identities are required")
	}
	labelerSet := make(map[string]struct{}, len(labelers))
	for _, id := range labelers {
		id = strings.TrimSpace(id)
		if id == "" {
			return fmt.Errorf("labeler identity is required")
		}
		if _, exists := labelerSet[id]; exists {
			return fmt.Errorf("labeler identity %q is duplicated", id)
		}
		labelerSet[id] = struct{}{}
	}
	reviewerSet := make(map[string]struct{}, len(reviewers))
	for _, id := range reviewers {
		id = strings.TrimSpace(id)
		if id == "" {
			return fmt.Errorf("reviewer identity is required")
		}
		if _, exists := reviewerSet[id]; exists {
			return fmt.Errorf("reviewer identity %q is duplicated", id)
		}
		if _, overlaps := labelerSet[id]; overlaps {
			return fmt.Errorf("labeler and reviewer identity %q overlap", id)
		}
		reviewerSet[id] = struct{}{}
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validPinnedOCIRef(reference, digest string) bool {
	if strings.TrimSpace(reference) == "" || hasCredentialBearingAuthority(reference) {
		return false
	}
	at := strings.LastIndexByte(reference, '@')
	if at <= 0 || at == len(reference)-1 || strings.Contains(reference[:at], "@") {
		return false
	}
	return reference[at+1:] == digest && validSHA256Digest(reference[at+1:])
}

func hasCredentialBearingAuthority(reference string) bool {
	authority := ""
	if scheme := strings.Index(reference, "://"); scheme >= 0 {
		authority = reference[scheme+3:]
	} else if strings.HasPrefix(reference, "//") {
		authority = strings.TrimPrefix(reference, "//")
	} else {
		return false
	}
	if stop := strings.IndexAny(authority, "/?#"); stop >= 0 {
		authority = authority[:stop]
	}
	return strings.Contains(authority, "@")
}

func competitorCitation(reference string) bool {
	lower := strings.ToLower(reference)
	return strings.Contains(lower, "grype") ||
		strings.Contains(lower, "trivy") ||
		strings.Contains(lower, "osv-scanner") ||
		strings.Contains(lower, "scanner output") ||
		strings.Contains(lower, "scanner-output") ||
		strings.Contains(lower, "scanner_output")
}

func canonicalAdvisory(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	lower := strings.ToLower(identifier)
	switch {
	case strings.HasPrefix(lower, "cve-"):
		return strings.ToUpper(identifier)
	case strings.HasPrefix(lower, "ghsa-"):
		return "GHSA-" + strings.ToLower(identifier[len("GHSA-"):])
	default:
		return identifier
	}
}

func validateCanonicalAdvisory(identifier string) error {
	trimmed := strings.TrimSpace(identifier)
	if trimmed == "" {
		return fmt.Errorf("identifier is required")
	}
	if identifier != trimmed {
		return fmt.Errorf("identifier must not contain surrounding whitespace")
	}
	lower := strings.ToLower(identifier)
	switch {
	case strings.HasPrefix(lower, "cve-"):
		if !validCVE(identifier) || identifier != strings.ToUpper(identifier) {
			return fmt.Errorf("CVE identifier must use canonical uppercase form")
		}
	case strings.HasPrefix(lower, "ghsa-"):
		if !validGHSA(identifier) || identifier != canonicalAdvisory(identifier) {
			return fmt.Errorf("GHSA identifier must use canonical form")
		}
	}
	return nil
}

func validCVE(identifier string) bool {
	parts := strings.Split(identifier, "-")
	if len(parts) != 3 || len(parts[1]) != 4 || len(parts[2]) < 4 {
		return false
	}
	return decimal(parts[1]) && decimal(parts[2])
}

func validGHSA(identifier string) bool {
	parts := strings.Split(identifier, "-")
	if len(parts) != 4 || parts[0] != "GHSA" {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) != 4 {
			return false
		}
		for _, char := range part {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
				return false
			}
		}
	}
	return true
}

func decimal(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func sortedEngines(results []EngineResult) {
	rank := make(map[Engine]int, len(Engines()))
	for i, engine := range Engines() {
		rank[engine] = i
	}
	sort.Slice(results, func(i, j int) bool { return rank[results[i].Engine] < rank[results[j].Engine] })
}

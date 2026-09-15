package scabench

import (
	"fmt"
	"sort"
	"strings"
)

// Reduce validates benchmark inputs and reduces scanner observations into honest, per-engine metrics.
// Only cases with covered expected coverage and complete observations contribute to TP, FP, or FN counts.
// Reduce validates benchmark inputs and reduces scanner observations into honest per-run and aggregate metrics.
// Only expected-covered cases with complete observations contribute to TP, FP, or FN counts.
func Reduce(catalog Catalog, oracle Oracle, observations []Observation) (Result, error) {
	if len(observations) == 0 {
		return Result{}, fmt.Errorf("at least one observation is required")
	}
	if err := Validate(catalog, oracle); err != nil {
		return Result{}, err
	}
	catalogDigest, err := DigestCatalog(catalog)
	if err != nil {
		return Result{}, fmt.Errorf("digest catalog: %w", err)
	}
	oracleDigest, err := DigestOracle(oracle)
	if err != nil {
		return Result{}, fmt.Errorf("digest oracle: %w", err)
	}
	observationsByTarget, err := indexObservations(catalog, catalogDigest, observations)
	if err != nil {
		return Result{}, err
	}
	scoringObservationDigest, err := DigestScoringObservations(observations)
	if err != nil {
		return Result{}, fmt.Errorf("digest scoring observations: %w", err)
	}
	aliases, casesByKey, err := indexOracle(oracle)
	if err != nil {
		return Result{}, err
	}

	findingsByObservation := make(map[observationKey]map[benchmarkCaseKey]struct{}, len(observationsByTarget))
	diagnosticCount := make(map[observationKey]int, len(observationsByTarget))
	result := Result{
		SchemaVersion:            ResultSchemaVersion,
		CatalogRevision:          catalog.Revision,
		CatalogDigest:            catalogDigest,
		OracleDigest:             oracleDigest,
		ScoringObservationDigest: scoringObservationDigest,
	}
	for _, target := range catalog.Targets {
		result.Targets = append(result.Targets, TargetIdentity{ID: target.ID, Digest: target.Digest, SBOMDigest: target.SBOMDigest})
	}
	for _, observation := range canonicalScoringObservations(observations) {
		result.Runs = append(result.Runs, scoringRunIdentityFromObservation(observation.asObservation()))
	}
	for key, observation := range observationsByTarget {
		if observation.State != ObservationComplete {
			continue
		}
		findings, diagnostics := indexFindings(*observation, aliases, casesByKey)
		findingsByObservation[key] = findings
		diagnosticCount[key] = len(diagnostics)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
	}

	for _, engine := range Engines() {
		aggregate := EngineResult{Engine: engine, MetricsComplete: true}
		for _, target := range catalog.Targets {
			key := observationKey{Engine: engine, TargetID: target.ID}
			observation := observationsByTarget[key]
			score, err := scoreTarget(engine, target.ID, oracle.Cases, observation, findingsByObservation[key], diagnosticCount[key])
			if err != nil {
				return Result{}, err
			}
			addMetrics(&aggregate, score)
			if observation != nil {
				result.RunMetrics = append(result.RunMetrics, RunMetric{Run: scoringRunIdentityFromObservation(*observation), Metrics: score})
			}
		}
		setMetrics(&aggregate)
		result.Engines = append(result.Engines, aggregate)
	}
	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].ID < result.Targets[j].ID })
	sortedEngines(result.Engines)
	sort.Slice(result.RunMetrics, func(i, j int) bool { return runIdentityLess(result.RunMetrics[i].Run, result.RunMetrics[j].Run) })
	sortDiagnostics(result.Diagnostics)
	result.Diagnostics = deduplicateDiagnostics(result.Diagnostics)

	result.ID, err = DigestResult(result)
	if err != nil {
		return Result{}, fmt.Errorf("digest result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate reduced result: %w", err)
	}
	return result, nil
}

// Evaluate is an alias for Reduce.
func Evaluate(catalog Catalog, oracle Oracle, observations []Observation) (Result, error) {
	return Reduce(catalog, oracle, observations)
}

func scoringRunIdentityFromObservation(observation Observation) RunIdentity {
	return RunIdentity{
		CatalogRevision:    observation.CatalogRevision,
		CatalogDigest:      observation.CatalogDigest,
		Engine:             observation.Engine,
		EngineVersion:      observation.EngineVersion,
		EngineBinaryDigest: observation.EngineBinaryDigest,
		DatabaseBuild:      observation.DatabaseBuild,
		DatabaseDigest:     observation.DatabaseDigest,
		EnvironmentID:      observation.EnvironmentID,
		EnvironmentDigest:  observation.EnvironmentDigest,
		TargetID:           observation.TargetID,
		TargetDigest:       observation.TargetDigest,
		SBOMDigest:         observation.SBOMDigest,
		State:              observation.State,
		ConfigDigest:       observation.ConfigDigest,
		CapabilityKind:     observation.CapabilityKind,
		CapabilityDigest:   observation.CapabilityDigest,
	}
}

func scoreTarget(engine Engine, targetID string, cases []OracleCase, observation *Observation, findings map[benchmarkCaseKey]struct{}, diagnostics int) (EngineResult, error) {
	summary := EngineResult{Engine: engine, MetricsComplete: true}
	for _, oracleCase := range cases {
		if oracleCase.TargetID != targetID {
			continue
		}
		switch coverage := oracleCase.ExpectedCoverage[engine]; coverage {
		case CoverageUnknown:
			// Coverage is reported explicitly but does not alter covered-only metrics.
			summary.Unknown++
			continue
		case CoverageUnsupported:
			// Coverage is reported explicitly but does not alter covered-only metrics.
			summary.Unsupported++
			continue
		case CoverageIncomplete:
			// Coverage is reported explicitly but does not alter covered-only metrics.
			summary.Incomplete++
			continue
		case CoverageCovered:
			// Continue below only when the capture is complete.
		default:
			return EngineResult{}, fmt.Errorf("oracle case %q has unsupported coverage %q for %q", oracleCase.ID, coverage, engine)
		}
		if observation == nil {
			summary.Incomplete++
			summary.MetricsComplete = false
			continue
		}
		switch observation.State {
		case ObservationUnknown:
			summary.Unknown++
			summary.MetricsComplete = false
			continue
		case ObservationUnsupported:
			summary.Unsupported++
			summary.MetricsComplete = false
			continue
		case ObservationIncomplete:
			summary.Incomplete++
			summary.MetricsComplete = false
			continue
		case ObservationComplete:
			// Score below.
		default:
			return EngineResult{}, fmt.Errorf("observation state %q is unsupported", observation.State)
		}
		summary.Covered++
		caseKey, err := BenchmarkKey(oracleCase.Component, oracleCase.AdvisoryID)
		if err != nil {
			return EngineResult{}, fmt.Errorf("normalize oracle case %q: %w", oracleCase.ID, err)
		}
		_, found := findings[benchmarkCaseKey{TargetID: targetID, Key: caseKey}]
		switch oracleCase.Truth {
		case TruthAffected:
			summary.AffectedRelations++
			if found {
				summary.TruePositives++
			} else {
				summary.FalseNegatives++
			}
		case TruthFixed, TruthNotAffected, TruthWithdrawn:
			summary.NegativeRelations++
			if found {
				summary.FalsePositives++
			}
		default:
			return EngineResult{}, fmt.Errorf("oracle case %q has unsupported truth %q", oracleCase.ID, oracleCase.Truth)
		}
	}
	// Scanner-only findings are diagnostic/unknown evidence, not oracle truth or automatic false positives.
	// They remain visible to the ratchet without invalidating covered-only metrics.
	summary.Unknown += diagnostics
	setMetrics(&summary)
	return summary, nil
}

func addMetrics(total *EngineResult, part EngineResult) {
	total.Covered += part.Covered
	total.Unknown += part.Unknown
	total.Unsupported += part.Unsupported
	total.Incomplete += part.Incomplete
	total.AffectedRelations += part.AffectedRelations
	total.NegativeRelations += part.NegativeRelations
	total.TruePositives += part.TruePositives
	total.FalsePositives += part.FalsePositives
	total.FalseNegatives += part.FalseNegatives
	total.MetricsComplete = total.MetricsComplete && part.MetricsComplete
}

type observationKey struct {
	Engine   Engine
	TargetID string
}

func indexObservations(catalog Catalog, catalogDigest string, observations []Observation) (map[observationKey]*Observation, error) {
	targets := make(map[string]Target, len(catalog.Targets))
	for _, target := range catalog.Targets {
		targets[target.ID] = target
	}
	indexed := make(map[observationKey]*Observation, len(observations))
	for i := range observations {
		observation := &observations[i]
		if err := validateObservation(*observation, catalog.Revision, catalogDigest, targets); err != nil {
			return nil, fmt.Errorf("observation %d: %w", i, err)
		}
		key := observationKey{Engine: observation.Engine, TargetID: observation.TargetID}
		if _, exists := indexed[key]; exists {
			return nil, fmt.Errorf("observation for engine %q and target %q is duplicated", observation.Engine, observation.TargetID)
		}
		indexed[key] = observation
	}
	return indexed, nil
}

func validateObservation(observation Observation, catalogRevision, catalogDigest string, targets map[string]Target) error {
	if err := validateObservationEnvelope(observation, catalogRevision, catalogDigest); err != nil {
		return err
	}
	target, exists := targets[observation.TargetID]
	if !exists {
		return fmt.Errorf("unknown target %q", observation.TargetID)
	}
	if observation.TargetDigest != target.Digest || observation.SBOMDigest != target.SBOMDigest {
		return fmt.Errorf("target or SBOM digest does not match catalog pin")
	}
	return nil
}

func validateObservationEnvelope(observation Observation, catalogRevision, catalogDigest string) error {
	if observation.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("unsupported observation schema %q", observation.SchemaVersion)
	}
	if strings.TrimSpace(catalogRevision) == "" || observation.CatalogRevision != catalogRevision || observation.CatalogDigest != catalogDigest {
		return fmt.Errorf("catalog identity does not match observation envelope")
	}
	if !observation.Engine.valid() {
		return fmt.Errorf("unsupported engine %q", observation.Engine)
	}
	if strings.TrimSpace(observation.EngineVersion) == "" || strings.TrimSpace(observation.DatabaseBuild) == "" || strings.TrimSpace(observation.EnvironmentID) == "" {
		return fmt.Errorf("engine version, database build, and environment identity are required")
	}
	if strings.TrimSpace(observation.TargetID) == "" || !validSHA256Digest(observation.TargetDigest) || !validSHA256Digest(observation.SBOMDigest) {
		return fmt.Errorf("target id and immutable target/SBOM digests are required")
	}
	if !observation.State.valid() {
		return fmt.Errorf("unsupported observation state %q", observation.State)
	}
	if observation.State == ObservationUnsupported {
		if len(observation.Findings) != 0 {
			return fmt.Errorf("unsupported observation must not contain findings")
		}
		if err := validateRequiredCapabilityIdentity(observation.CapabilityKind, observation.CapabilityDigest); err != nil {
			return fmt.Errorf("unsupported observation capability identity: %w", err)
		}
	} else if observation.CapabilityKind != "" || observation.CapabilityDigest != "" {
		return fmt.Errorf("only unsupported observations may carry a capability identity")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{name: "engine binary", value: observation.EngineBinaryDigest},
		{name: "database", value: observation.DatabaseDigest},
		{name: "environment", value: observation.EnvironmentDigest},
		{name: "raw output", value: observation.RawOutputDigest},
		{name: "config", value: observation.ConfigDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("%s digest must be an immutable sha256 digest", digest.name)
		}
	}
	for i, finding := range observation.Findings {
		if strings.TrimSpace(finding.AdvisoryID) == "" {
			return fmt.Errorf("finding %d advisory id is required", i)
		}
	}
	return nil
}

func indexOracle(oracle Oracle) (map[advisoryLookupKey]string, map[benchmarkCaseKey]OracleCase, error) {
	aliases := make(map[advisoryLookupKey]string, len(oracle.Cases))
	cases := make(map[benchmarkCaseKey]OracleCase, len(oracle.Cases))
	for _, oracleCase := range oracle.Cases {
		canonical := canonicalAdvisory(oracleCase.AdvisoryID)
		componentKey, err := componentIdentityKey(oracleCase.Component)
		if err != nil {
			return nil, nil, fmt.Errorf("normalize oracle case %q component: %w", oracleCase.ID, err)
		}
		for _, identifier := range append([]string{oracleCase.AdvisoryID}, oracleCase.Aliases...) {
			aliases[advisoryLookupKey{
				TargetID:  oracleCase.TargetID,
				Component: componentKey,
				Advisory:  canonicalAdvisory(identifier),
			}] = canonical
		}
		key, err := BenchmarkKey(oracleCase.Component, canonical)
		if err != nil {
			return nil, nil, fmt.Errorf("normalize oracle case %q: %w", oracleCase.ID, err)
		}
		cases[benchmarkCaseKey{TargetID: oracleCase.TargetID, Key: key}] = oracleCase
	}
	return aliases, cases, nil
}

func indexFindings(observation Observation, aliases map[advisoryLookupKey]string, cases map[benchmarkCaseKey]OracleCase) (map[benchmarkCaseKey]struct{}, []Diagnostic) {
	known := make(map[benchmarkCaseKey]struct{}, len(observation.Findings))
	unknown := make(map[ComponentBenchmarkKey]struct{})
	invalid := make(map[string]struct{})
	for _, finding := range observation.Findings {
		advisory := canonicalAdvisory(finding.AdvisoryID)
		componentKey, err := componentIdentityKey(finding.Component)
		if err != nil {
			invalid[advisory] = struct{}{}
			continue
		}
		if canonical, exists := aliases[advisoryLookupKey{
			TargetID:  observation.TargetID,
			Component: componentKey,
			Advisory:  advisory,
		}]; exists {
			advisory = canonical
		}
		key, err := BenchmarkKey(finding.Component, advisory)
		if err != nil {
			invalid[advisory] = struct{}{}
			continue
		}
		caseKey := benchmarkCaseKey{TargetID: observation.TargetID, Key: key}
		if _, exists := cases[caseKey]; exists {
			known[caseKey] = struct{}{}
			continue
		}
		unknown[key] = struct{}{}
	}
	diagnostics := make([]Diagnostic, 0, len(unknown)+len(invalid))
	for key := range unknown {
		diagnostics = append(diagnostics, Diagnostic{
			Engine:   observation.Engine,
			TargetID: observation.TargetID,
			Code:     DiagnosticUnreviewedFinding,
			Detail: fmt.Sprintf(
				"scanner finding is not in the reviewed oracle: ecosystem=%q package=%q version=%q advisory=%q",
				key.Ecosystem,
				key.Package,
				key.Version,
				key.Advisory,
			),
		})
	}
	for advisory := range invalid {
		diagnostics = append(diagnostics, Diagnostic{
			Engine:   observation.Engine,
			TargetID: observation.TargetID,
			Code:     DiagnosticInvalidFinding,
			Detail:   "scanner finding has unsupported or ambiguous component identity: " + advisory,
		})
	}
	sortDiagnostics(diagnostics)
	return known, diagnostics
}

func setMetrics(summary *EngineResult) {
	summary.Precision = nil
	summary.Recall = nil
	if !summary.MetricsComplete {
		return
	}
	precisionDenominator := summary.TruePositives + summary.FalsePositives
	if precisionDenominator > 0 {
		value := float64(summary.TruePositives) / float64(precisionDenominator)
		summary.Precision = &value
	}
	recallDenominator := summary.TruePositives + summary.FalseNegatives
	if recallDenominator > 0 {
		value := float64(summary.TruePositives) / float64(recallDenominator)
		summary.Recall = &value
	}
}

func sortDiagnostics(diagnostics []Diagnostic) {
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Engine != diagnostics[j].Engine {
			return diagnostics[i].Engine < diagnostics[j].Engine
		}
		if diagnostics[i].TargetID != diagnostics[j].TargetID {
			return diagnostics[i].TargetID < diagnostics[j].TargetID
		}
		if diagnostics[i].Code != diagnostics[j].Code {
			return diagnostics[i].Code < diagnostics[j].Code
		}
		return diagnostics[i].Detail < diagnostics[j].Detail
	})
}

func deduplicateDiagnostics(diagnostics []Diagnostic) []Diagnostic {
	if len(diagnostics) < 2 {
		return diagnostics
	}
	out := diagnostics[:0]
	for _, diagnostic := range diagnostics {
		if len(out) == 0 || out[len(out)-1] != diagnostic {
			out = append(out, diagnostic)
		}
	}
	return out
}

func validateRatchetCoverage(result Result, ratchet Ratchet) error {
	required := len(result.Targets) * len(Engines())
	if len(ratchet.Floors) != required {
		return fmt.Errorf("ratchet must contain exactly one floor for each engine and target (got %d, want %d)", len(ratchet.Floors), required)
	}
	floors := make(map[observationKey]struct{}, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		floors[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}] = struct{}{}
	}
	for _, target := range result.Targets {
		for _, engine := range Engines() {
			if _, exists := floors[observationKey{Engine: engine, TargetID: target.ID}]; !exists {
				return fmt.Errorf("ratchet is missing a floor for engine %q and target %q", engine, target.ID)
			}
		}
	}
	return nil
}

// ApplyRatchet evaluates every required pinned floor against per-run metrics and embeds deterministic gate evidence.
// A failed gate is a valid result; callers inspect Gate.Passed rather than treating it as a reduction error.
func ApplyRatchet(result Result, ratchet Ratchet) (Result, error) {
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate result: %w", err)
	}
	gate, err := evaluateGate(result, ratchet)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate ratchet: %w", err)
	}
	out := result
	out.Gate = &gate
	out.ID, err = DigestResult(out)
	if err != nil {
		return Result{}, fmt.Errorf("digest gated result: %w", err)
	}
	if err := out.Validate(); err != nil {
		return Result{}, fmt.Errorf("validate gated result: %w", err)
	}
	return out, nil
}

// evaluateGate deterministically derives gate evidence from a structurally valid result and ratchet.
// It does not call public validation so Result.Validate can independently replay existing gate evidence.
func evaluateGate(result Result, ratchet Ratchet) (Gate, error) {
	ratchet = canonicalRatchet(ratchet)
	if err := ratchet.Validate(); err != nil {
		return Gate{}, fmt.Errorf("validate ratchet: %w", err)
	}
	if err := validateRatchetCoverage(result, ratchet); err != nil {
		return Gate{}, err
	}
	ratchetDigest, err := DigestRatchet(ratchet)
	if err != nil {
		return Gate{}, fmt.Errorf("digest ratchet: %w", err)
	}
	byLogicalRun := make(map[observationKey]RunMetric, len(result.RunMetrics))
	for _, metric := range result.RunMetrics {
		byLogicalRun[observationKey{Engine: metric.Run.Engine, TargetID: metric.Run.TargetID}] = metric
	}
	catalogMatches := result.CatalogRevision == ratchet.CatalogRevision && result.CatalogDigest == ratchet.CatalogDigest && result.OracleDigest == ratchet.OracleDigest
	gate := Gate{RatchetDigest: ratchetDigest, Ratchet: ratchet, Passed: true, Checks: make([]GateCheck, 0, len(ratchet.Floors))}
	for _, floor := range ratchet.Floors {
		check := GateCheck{Expected: floor.Expected, Mode: floor.Mode.canonical(), Passed: true, ReasonCodes: []GateReasonCode{}}
		metric, exists := byLogicalRun[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}]
		if !exists {
			addGateReason(&check, GateReasonMissingObservation)
		} else {
			actual := metric.Run
			check.Actual = &actual
			if !catalogMatches || !sameExpectedRunIdentity(expectedRunIdentityFromRun(metric.Run), floor.Expected) {
				// Pins are compared only after the logical target+engine lookup. Never apply thresholds to a different run.
				addGateReason(&check, GateReasonPinMismatch)
			} else {
				switch floor.Mode.effective() {
				case FloorGateModeUnsupportedOnly:
					applyUnsupportedOnlyFloor(&check, metric, floor)
				case FloorGateModeAccuracy:
					applyCountFloors(&check, metric.Metrics, floor)
					if !metric.Metrics.MetricsComplete {
						addGateReason(&check, GateReasonMetricsIncomplete)
					} else {
						applyMetricFloors(&check, metric.Metrics, floor)
					}
				}
			}
		}
		check.Passed = len(check.ReasonCodes) == 0
		gate.Passed = gate.Passed && check.Passed
		gate.Checks = append(gate.Checks, check)
	}
	sort.Slice(gate.Checks, func(i, j int) bool {
		return expectedRunIdentityLess(gate.Checks[i].Expected, gate.Checks[j].Expected)
	})
	return gate, nil
}

// EvaluateRatchet is an alias for ApplyRatchet.
func EvaluateRatchet(result Result, ratchet Ratchet) (Result, error) {
	return ApplyRatchet(result, ratchet)
}

func addGateReason(check *GateCheck, reason GateReasonCode) {
	for _, existing := range check.ReasonCodes {
		if existing == reason {
			return
		}
	}
	check.ReasonCodes = append(check.ReasonCodes, reason)
	sort.Slice(check.ReasonCodes, func(i, j int) bool { return check.ReasonCodes[i] < check.ReasonCodes[j] })
}

func applyUnsupportedOnlyFloor(check *GateCheck, metric RunMetric, floor RatchetFloor) {
	if metric.Run.State != ObservationUnsupported {
		addGateReason(check, GateReasonCoverageContractBreach)
	}
	if !metric.Metrics.MetricsComplete {
		addGateReason(check, GateReasonMetricsIncomplete)
	}
	if !hasUnsupportedOnlyMetricShape(metric.Metrics) {
		addGateReason(check, GateReasonCoverageContractBreach)
	}
	if metric.Metrics.Unsupported > *floor.MaximumUnsupported {
		addGateReason(check, GateReasonThresholdBreach)
	}
}

func applyCountFloors(check *GateCheck, metrics EngineResult, floor RatchetFloor) {
	if metrics.Covered < *floor.MinimumCovered ||
		metrics.AffectedRelations < *floor.MinimumAffectedRelations ||
		metrics.NegativeRelations < *floor.MinimumNegativeRelations ||
		metrics.FalsePositives > *floor.MaximumFalsePositives ||
		metrics.FalseNegatives > *floor.MaximumFalseNegatives ||
		metrics.Unknown > *floor.MaximumUnknown ||
		metrics.Incomplete > *floor.MaximumIncomplete ||
		metrics.Unsupported > *floor.MaximumUnsupported {
		addGateReason(check, GateReasonThresholdBreach)
	}
}

func applyMetricFloors(check *GateCheck, metrics EngineResult, floor RatchetFloor) {
	if metrics.Precision == nil {
		if !floor.AllowUndefinedPrecision {
			addGateReason(check, GateReasonMetricUnavailable)
		}
	} else if *metrics.Precision < *floor.MinimumPrecision {
		addGateReason(check, GateReasonThresholdBreach)
	}
	if metrics.Recall == nil {
		addGateReason(check, GateReasonMetricUnavailable)
	} else if *metrics.Recall < *floor.MinimumRecall {
		addGateReason(check, GateReasonThresholdBreach)
	}
}

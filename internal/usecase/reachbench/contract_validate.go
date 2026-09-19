package reachbench

import (
	"fmt"
	"math/big"
	"strings"
)

func (inventory ProductionInventory) Validate() error {
	if inventory.SchemaVersion != ProductionInventorySchemaVersion {
		return fmt.Errorf("unsupported production inventory schema %q", inventory.SchemaVersion)
	}
	if !validID(inventory.ID) || len(inventory.Cohorts) != len(requiredProductionCohorts) {
		return fmt.Errorf("production inventory requires its closed cohort set")
	}
	seen := make(map[string]struct{}, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		key := cohortKey(cohort.ID, cohort.Mode)
		if !validID(cohort.ID) || !validID(cohort.Language) || !validID(cohort.Mode) || !validID(cohort.AnalyzerID) || !validID(cohort.BoundaryID) {
			return fmt.Errorf("production inventory has invalid cohort %q", key)
		}
		if language, required := requiredProductionCohorts[key]; !required || language != cohort.Language {
			return fmt.Errorf("production inventory contains unknown cohort %q", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate production cohort %q", key)
		}
		seen[key] = struct{}{}
		if !cohort.BenchmarkRequired || len(cohort.Bindings) == 0 {
			return fmt.Errorf("benchmark-required production cohort %q has no complete binding declaration", key)
		}
		bindings := map[string]struct{}{}
		enabled := 0
		for _, binding := range cohort.Bindings {
			if !validID(binding.ID) || !validID(binding.Root) || !validID(binding.BoundaryID) || !binding.State.valid() {
				return fmt.Errorf("production cohort %q has invalid binding", key)
			}
			if err := binding.Configuration.validate("production binding configuration"); err != nil {
				return fmt.Errorf("production cohort %q binding %q: %w", key, binding.ID, err)
			}
			if binding.State == BindingEnabled && binding.BoundaryID != cohort.BoundaryID+"/"+binding.ID {
				return fmt.Errorf("enabled production cohort %q binding %q lacks a cohort-specific boundary", key, binding.ID)
			}
			if binding.State != BindingEnabled && strings.TrimSpace(binding.Reason) == "" {
				return fmt.Errorf("production cohort %q binding %q requires reason when not enabled", key, binding.ID)
			}
			if binding.State == BindingEnabled && strings.TrimSpace(binding.Reason) != "" {
				return fmt.Errorf("production cohort %q binding %q cannot have an enabled reason", key, binding.ID)
			}
			if _, exists := bindings[binding.ID]; exists {
				return fmt.Errorf("duplicate production binding %q for cohort %q", binding.ID, key)
			}
			bindings[binding.ID] = struct{}{}
			if binding.State == BindingEnabled {
				enabled++
			}
		}
		if enabled == 0 {
			return fmt.Errorf("benchmark-required production cohort %q has no enabled binding", key)
		}
	}
	return nil
}

var requiredProductionCohorts = map[string]string{
	"go/source_tier2":            "go",
	"go/binary":                  "go",
	"python/import":              "python",
	"python/semantic":            "python",
	"javascript/import":          "javascript",
	"javascript/lexical":         "javascript",
	"javascript/interprocedural": "javascript",
	"rust/import":                "rust",
	"rust/symbols_tier2":         "rust",
	"php/import":                 "php",
	"php/symbols_tier2":          "php",
	"ruby/import":                "ruby",
	"ruby/symbols_tier2":         "ruby",
	"dotnet/build_aware_import":  "dotnet",
	"dotnet/symbols_tier2":       "dotnet",
	"c_cpp/symbols_tier2":        "c_cpp",
	"jvm/coarse":                 "jvm",
	"jvm/tier2":                  "jvm",
	"runtime/library_loads":      "runtime",
}

func (inventory ProductionInventory) cohort(key string) (ProductionCohort, bool) {
	for _, cohort := range inventory.Cohorts {
		if cohortKey(cohort.ID, cohort.Mode) == key {
			return cohort, true
		}
	}
	return ProductionCohort{}, false
}

func (corpus ContractCorpus) Validate() error {
	if corpus.SchemaVersion != ContractCorpusSchemaVersion {
		return fmt.Errorf("unsupported reachability corpus schema %q", corpus.SchemaVersion)
	}
	if !validID(corpus.ID) || len(corpus.Cases) == 0 {
		return fmt.Errorf("reachability corpus requires id and cases")
	}
	seen := make(map[string]struct{}, len(corpus.Cases))
	for _, item := range corpus.Cases {
		if !validID(item.ID) || !validSubjectID(item.SubjectID) || !validID(item.CohortID) || !validID(item.ModeID) {
			return fmt.Errorf("reachability corpus has invalid case")
		}
		if _, exists := seen[item.ID]; exists {
			return fmt.Errorf("duplicate reachability corpus case %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if (item.Fixture == nil) == (item.LegacyOrigin == nil) {
			return fmt.Errorf("reachability corpus case %q requires exactly one fixture identity or legacy origin", item.ID)
		}
		if item.Fixture != nil {
			if err := item.Fixture.validate("fixture"); err != nil {
				return fmt.Errorf("reachability corpus case %q: %w", item.ID, err)
			}
		}
		if item.LegacyOrigin != nil && (!validLegacyDigest(item.LegacyOrigin.OriginalCorpusDigest) || !validID(item.LegacyOrigin.OriginalCaseID)) {
			return fmt.Errorf("reachability corpus case %q has invalid legacy origin", item.ID)
		}
	}
	return nil
}

func (oracle ReachabilityOracle) Validate() error {
	if oracle.SchemaVersion != OracleSchemaVersion {
		return fmt.Errorf("unsupported reachability oracle schema %q", oracle.SchemaVersion)
	}
	if !validID(oracle.ID) || len(oracle.Cases) == 0 {
		return fmt.Errorf("reachability oracle requires id and cases")
	}
	seen := make(map[string]struct{}, len(oracle.Cases))
	for _, item := range oracle.Cases {
		if !validID(item.CaseID) || !item.Expected.valid() || !item.Category.valid() || !item.CoverageExpectation.valid() {
			return fmt.Errorf("reachability oracle has invalid case %q", item.CaseID)
		}
		if item.SuppressionApplicable {
			if item.Category != OracleTrulyUnreachable || item.Expected != OutcomePresentUnreached || item.CoverageExpectation != CoverageComplete {
				return fmt.Errorf("suppression-applicable oracle case %q must be truly unreachable, present_unreached, and coverage-complete", item.CaseID)
			}
			if item.CompletenessContract == nil {
				return fmt.Errorf("suppression-applicable oracle case %q lacks completeness contract", item.CaseID)
			}
			if err := item.CompletenessContract.validate("oracle completeness contract"); err != nil {
				return fmt.Errorf("oracle case %q: %w", item.CaseID, err)
			}
		} else if item.CompletenessContract != nil {
			return fmt.Errorf("non-suppression oracle case %q carries completeness contract", item.CaseID)
		}
		if _, exists := seen[item.CaseID]; exists {
			return fmt.Errorf("duplicate reachability oracle case %q", item.CaseID)
		}
		seen[item.CaseID] = struct{}{}
	}
	return nil
}

func (oracle ReachabilityOracle) ValidateAgainst(corpus ContractCorpus) error {
	if err := oracle.Validate(); err != nil {
		return err
	}
	if err := corpus.Validate(); err != nil {
		return err
	}
	cases := make(map[string]struct{}, len(corpus.Cases))
	for _, item := range corpus.Cases {
		cases[item.ID] = struct{}{}
	}
	if len(oracle.Cases) != len(cases) {
		return fmt.Errorf("reachability oracle case count does not match corpus")
	}
	for _, item := range oracle.Cases {
		if _, ok := cases[item.CaseID]; !ok {
			return fmt.Errorf("reachability oracle references unknown case %q", item.CaseID)
		}
	}
	return nil
}

func (policy MeasurementPolicy) Validate() error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("unsupported measurement policy schema %q", policy.SchemaVersion)
	}
	if !validID(policy.ID) {
		return fmt.Errorf("measurement policy requires id")
	}
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"inventory", policy.Inventory}, {"corpus", policy.Corpus}, {"oracle", policy.Oracle}, {"exception manifest", policy.ExceptionManifest},
		{"schema definition", policy.SchemaDefinition}, {"run-purpose rules", policy.RunPurposeRules}, {"ratchet-construction rule", policy.RatchetConstructionRule},
		{"evaluator", policy.Evaluator}, {"metric definition", policy.MetricDefinition},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	if len(policy.Adapters) == 0 {
		return fmt.Errorf("measurement policy requires workload adapter identities")
	}
	adapters := map[string]struct{}{}
	for _, adapter := range policy.Adapters {
		if err := adapter.validate("workload adapter"); err != nil {
			return err
		}
		if _, exists := adapters[adapter.ID]; exists {
			return fmt.Errorf("duplicate measurement policy workload adapter %q", adapter.ID)
		}
		adapters[adapter.ID] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, rule := range policy.Rules {
		key := cohortKey(rule.CohortID, rule.ModeID)
		if !validID(rule.CohortID) || !validID(rule.ModeID) || !rule.Disposition.valid() {
			return fmt.Errorf("measurement policy has invalid suppression rule %q", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate measurement policy suppression rule %q", key)
		}
		seen[key] = struct{}{}
		if rule.Disposition == SuppressionEligible {
			if rule.CompletenessContract == nil {
				return fmt.Errorf("eligible suppression rule %q lacks completeness contract", key)
			}
			if err := rule.CompletenessContract.validate("completeness contract"); err != nil {
				return fmt.Errorf("suppression rule %q: %w", key, err)
			}
			if !validID(rule.ApprovedProposer) || !validID(rule.ApprovedVerifier) || rule.ApprovedProposer == rule.ApprovedVerifier {
				return fmt.Errorf("eligible suppression rule %q requires a distinct approved actor pair", key)
			}
		} else if rule.CompletenessContract != nil || rule.ApprovedProposer != "" || rule.ApprovedVerifier != "" || rule.RuntimeDeploymentComplete || rule.ComposerBootstrapComplete {
			return fmt.Errorf("non-eligible suppression rule %q carries approval metadata", key)
		}
		if err := validateInitialPermission(rule); err != nil {
			return err
		}
	}
	return nil
}

func validateInitialPermission(rule SuppressionPolicyRule) error {
	key := cohortKey(rule.CohortID, rule.ModeID)
	mustProhibit := key == "rust/import" || key == "ruby/import"
	if mustProhibit {
		if rule.Disposition != SuppressionProhibited {
			return fmt.Errorf("suppression rule %q must remain suppression_prohibited", key)
		}
		return nil
	}
	mustRaiseOnly := key == "go/binary" || key == "javascript/interprocedural" || strings.HasPrefix(key, "jvm/") ||
		key == "runtime/library_loads" || strings.HasSuffix(rule.ModeID, "symbols_tier2")
	if mustRaiseOnly && rule.Disposition != SuppressionRaiseOnly {
		return fmt.Errorf("suppression rule %q must remain raise_only", key)
	}
	if rule.Disposition != SuppressionEligible {
		return nil
	}
	switch key {
	case "go/source_tier2", "python/import", "python/semantic", "dotnet/build_aware_import":
		return nil
	case "javascript/import", "javascript/lexical":
		if !rule.RuntimeDeploymentComplete {
			return fmt.Errorf("suppression rule %q requires runtime/deployment completeness approval", key)
		}
		return nil
	case "php/import":
		if !rule.ComposerBootstrapComplete {
			return fmt.Errorf("suppression rule %q requires Composer bootstrap completeness approval", key)
		}
		return nil
	default:
		return fmt.Errorf("suppression rule %q is not initially eligible", key)
	}
}

func (manifest ExceptionManifest) Validate() error {
	if manifest.SchemaVersion != ExceptionManifestSchemaVersion || !validID(manifest.ID) {
		return fmt.Errorf("invalid reachability exception manifest")
	}
	seen := map[string]struct{}{}
	for _, entry := range manifest.Entries {
		if !validID(entry.ID) || !validID(entry.CohortID) || !validID(entry.ModeID) || !validID(entry.BindingID) || !validID(entry.CaseID) || strings.TrimSpace(entry.Reason) == "" {
			return fmt.Errorf("invalid reachability coverage exception")
		}
		if _, exists := seen[entry.ID]; exists {
			return fmt.Errorf("duplicate reachability coverage exception %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
	}
	return nil
}

func (snapshot SnapshotIdentity) Validate() error {
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"source snapshot", snapshot.Source}, {"SBOM snapshot", snapshot.SBOM}, {"run snapshot", snapshot.Run},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	return nil
}

func (input MeasurementInput) Validate() error {
	if input.SchemaVersion != MeasurementInputSchemaVersion || !input.Purpose.valid() {
		return fmt.Errorf("unsupported reachability measurement input")
	}
	if err := input.Inventory.Validate(); err != nil {
		return err
	}
	if err := input.Corpus.Validate(); err != nil {
		return err
	}
	if err := input.Oracle.ValidateAgainst(input.Corpus); err != nil {
		return err
	}
	if err := input.Exceptions.Validate(); err != nil {
		return err
	}
	if err := input.Policy.Validate(); err != nil {
		return err
	}
	if err := input.ActiveSnapshot.Validate(); err != nil {
		return err
	}
	if err := validateContractBindings(input); err != nil {
		return err
	}
	if err := validateInputLifecycle(input); err != nil {
		return err
	}
	return validateRawObservations(input)
}

func validateContractBindings(input MeasurementInput) error {
	inventoryDigest, err := DigestProductionInventory(input.Inventory)
	if err != nil {
		return err
	}
	corpusDigest, err := DigestContractCorpus(input.Corpus)
	if err != nil {
		return err
	}
	oracleDigest, err := DigestReachabilityOracle(input.Oracle)
	if err != nil {
		return err
	}
	exceptionsDigest, err := DigestExceptionManifest(input.Exceptions)
	if err != nil {
		return err
	}
	if !sameRef(input.Policy.Inventory, artifactRef(input.Inventory.ID, inventoryDigest)) ||
		!sameRef(input.Policy.Corpus, artifactRef(input.Corpus.ID, corpusDigest)) ||
		!sameRef(input.Policy.Oracle, artifactRef(input.Oracle.ID, oracleDigest)) ||
		!sameRef(input.Policy.ExceptionManifest, artifactRef(input.Exceptions.ID, exceptionsDigest)) {
		return fmt.Errorf("measurement policy artifact references do not bind the supplied contract")
	}
	policyRules := map[string]SuppressionPolicyRule{}
	for _, rule := range input.Policy.Rules {
		key := cohortKey(rule.CohortID, rule.ModeID)
		if _, ok := input.Inventory.cohort(key); !ok {
			return fmt.Errorf("measurement policy contains rule for non-inventory cohort %q", key)
		}
		policyRules[key] = rule
	}
	for _, cohort := range input.Inventory.Cohorts {
		key := cohortKey(cohort.ID, cohort.Mode)
		if _, ok := policyRules[key]; !ok {
			return fmt.Errorf("measurement policy omits production cohort %q", key)
		}
	}
	oracleByCase := make(map[string]OracleCase, len(input.Oracle.Cases))
	for _, item := range input.Oracle.Cases {
		oracleByCase[item.CaseID] = item
	}
	for _, item := range input.Corpus.Cases {
		if item.LegacyOrigin != nil {
			return fmt.Errorf("legacy v1 case %q cannot serve as a %s input", item.ID, input.Purpose)
		}
		if _, ok := input.Inventory.cohort(cohortKey(item.CohortID, item.ModeID)); !ok {
			return fmt.Errorf("reachability corpus case %q references unknown production cohort %q", item.ID, cohortKey(item.CohortID, item.ModeID))
		}
		oracle := oracleByCase[item.ID]
		if oracle.SuppressionApplicable {
			rule := policyRules[cohortKey(item.CohortID, item.ModeID)]
			if rule.CompletenessContract == nil || oracle.CompletenessContract == nil || !sameRef(*oracle.CompletenessContract, *rule.CompletenessContract) {
				return fmt.Errorf("suppression-applicable oracle case %q does not bind the policy completeness contract", item.ID)
			}
		}
	}
	return nil
}

func validateInputLifecycle(input MeasurementInput) error {
	if input.Purpose == BaselineMeasurement {
		if input.Baseline != nil || input.Checkpoint != nil || input.Ratchet != nil {
			return fmt.Errorf("baseline measurement cannot bind a baseline checkpoint or candidate ratchet")
		}
		return nil
	}
	if input.Baseline == nil || input.Checkpoint == nil || input.Ratchet == nil {
		return fmt.Errorf("candidate acceptance requires baseline report, checkpoint, and ratchet")
	}
	if err := input.Baseline.Validate(); err != nil {
		return fmt.Errorf("candidate baseline report: %w", err)
	}
	if input.Baseline.Purpose != BaselineMeasurement || input.Baseline.RatchetDigest != "" {
		return fmt.Errorf("candidate baseline report is not an acyclic baseline measurement")
	}
	policyDigest, err := DigestMeasurementPolicy(input.Policy)
	if err != nil {
		return err
	}
	inventoryDigest, err := DigestProductionInventory(input.Inventory)
	if err != nil {
		return err
	}
	corpusDigest, err := DigestContractCorpus(input.Corpus)
	if err != nil {
		return err
	}
	oracleDigest, err := DigestReachabilityOracle(input.Oracle)
	if err != nil {
		return err
	}
	exceptionsDigest, err := DigestExceptionManifest(input.Exceptions)
	if err != nil {
		return err
	}
	baseline := input.Baseline
	if !sameRef(baseline.Policy, artifactRef(input.Policy.ID, policyDigest)) ||
		!sameRef(baseline.Inventory, artifactRef(input.Inventory.ID, inventoryDigest)) ||
		!sameRef(baseline.Corpus, artifactRef(input.Corpus.ID, corpusDigest)) ||
		!sameRef(baseline.Oracle, artifactRef(input.Oracle.ID, oracleDigest)) ||
		!sameRef(baseline.ExceptionManifest, artifactRef(input.Exceptions.ID, exceptionsDigest)) {
		return fmt.Errorf("candidate baseline report binds a different measurement contract")
	}
	if err := replayBaselineReport(input, *baseline); err != nil {
		return err
	}
	if err := input.Checkpoint.Validate(input.Policy, *baseline); err != nil {
		return err
	}
	if err := input.Ratchet.Validate(); err != nil {
		return fmt.Errorf("candidate ratchet: %w", err)
	}
	derived, err := DeriveCandidateRatchet(input.Policy, *baseline, *input.Checkpoint, input.Exceptions)
	if err != nil {
		return err
	}
	if !sameCandidateRatchet(*input.Ratchet, derived) {
		return fmt.Errorf("candidate ratchet is not the deterministic derivative of the baseline checkpoint")
	}
	return nil
}

func replayBaselineReport(input MeasurementInput, baseline MeasurementReport) error {
	replay := input
	replay.Purpose = BaselineMeasurement
	replay.ActiveSnapshot = baseline.ActiveSnapshot
	replay.Observations = append([]MeasuredObservation(nil), baseline.Observations...)
	replay.Baseline = nil
	replay.Checkpoint = nil
	replay.Ratchet = nil
	reduced, err := EvaluateMeasurement(replay)
	if err != nil {
		return fmt.Errorf("replay candidate baseline report: %w", err)
	}
	if !sameMeasurementReport(reduced, baseline) {
		return fmt.Errorf("candidate baseline report does not match reducer replay")
	}
	return nil
}

func validateRawObservations(input MeasurementInput) error {
	cases := make(map[string]ContractCase, len(input.Corpus.Cases))
	for _, item := range input.Corpus.Cases {
		cases[item.ID] = item
	}
	seen := map[string]struct{}{}
	for _, observation := range input.Observations {
		item, ok := cases[observation.CaseID]
		if !ok {
			return fmt.Errorf("observation references unknown corpus case %q", observation.CaseID)
		}
		cohort, _ := input.Inventory.cohort(cohortKey(item.CohortID, item.ModeID))
		binding, ok := findBinding(cohort, observation.BindingID)
		if !ok || binding.State != BindingEnabled {
			return fmt.Errorf("observation %q references non-enabled binding %q", observation.CaseID, observation.BindingID)
		}
		key := executionKey(item.CohortID, item.ModeID, observation.BindingID, observation.CaseID)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate raw reachability observation %q", key)
		}
		seen[key] = struct{}{}
		if observation.Analyzer.ID != cohort.AnalyzerID {
			return fmt.Errorf("observation %q analyzer does not match production cohort", observation.CaseID)
		}
		if !sameRef(observation.Configuration, binding.Configuration) {
			return fmt.Errorf("observation %q configuration does not match production binding", observation.CaseID)
		}
		if err := observation.validate(input.ActiveSnapshot); err != nil {
			return fmt.Errorf("observation %q: %w", observation.CaseID, err)
		}
	}
	return nil
}

func (observation MeasuredObservation) validate(active SnapshotIdentity) error {
	if !validID(observation.CaseID) || !validID(observation.BindingID) || !observation.Outcome.valid() || !observation.OutputCapture.valid() {
		return fmt.Errorf("invalid measured output")
	}
	if !observation.Invoked && observation.OutputCapture == CaptureComplete {
		return fmt.Errorf("uninvoked boundary cannot have complete output capture")
	}
	if err := observation.Coverage.validate(); err != nil {
		return err
	}
	if err := observation.Analyzer.validate("observation analyzer"); err != nil {
		return err
	}
	if err := observation.Configuration.validate("observation configuration"); err != nil {
		return err
	}
	if !observation.Suppression.Claim.valid() || !observation.Suppression.Status.valid() {
		return fmt.Errorf("invalid suppression capture")
	}
	if observation.Suppression.Claim == SuppressionNone && len(observation.Suppression.Effects) != 0 {
		return fmt.Errorf("suppression claim none contradicts produced effects")
	}
	for _, effect := range observation.Suppression.Effects {
		if !effect.Kind.valid() {
			return fmt.Errorf("unknown suppression effect %q", effect.Kind)
		}
	}
	if observation.Positive != nil {
		if err := observation.Positive.Evidence.validate("positive evidence"); err != nil {
			return err
		}
		if !sameSnapshot(observation.Positive.Snapshot, active) {
			return fmt.Errorf("positive evidence references stale snapshot")
		}
	}
	return nil
}

func (coverage ObservedCoverage) validate() error {
	if !coverage.Status.valid() || len(coverage.Obligations) == 0 {
		return fmt.Errorf("coverage requires a closed status and obligations")
	}
	seen := map[string]struct{}{}
	allComplete := true
	allNotApplicable := true
	for _, obligation := range coverage.Obligations {
		if !validID(obligation.ID) || !obligation.Status.valid() {
			return fmt.Errorf("coverage has invalid obligation")
		}
		if _, exists := seen[obligation.ID]; exists {
			return fmt.Errorf("coverage duplicates obligation %q", obligation.ID)
		}
		seen[obligation.ID] = struct{}{}
		allComplete = allComplete && obligation.Status == CoverageComplete
		allNotApplicable = allNotApplicable && obligation.Status == CoverageNotApplicable
	}
	for _, reason := range coverage.Reasons {
		if !reason.Code.valid() {
			return fmt.Errorf("coverage has unknown reason %q", reason.Code)
		}
	}
	if coverage.Status == CoverageComplete && (!allComplete || len(coverage.Reasons) != 0) {
		return fmt.Errorf("incomplete, unknown, stale, failed, skipped, unsupported, or opaque coverage cannot be complete")
	}
	if coverage.Status == CoverageNotApplicable && (!allNotApplicable || len(coverage.Reasons) != 0) {
		return fmt.Errorf("not_applicable coverage requires only not_applicable obligations")
	}
	if coverage.Status == CoveragePartial && allComplete {
		return fmt.Errorf("partial coverage cannot contain only complete obligations")
	}
	if coverage.Status == CoverageUnavailable && len(coverage.Reasons) == 0 {
		return fmt.Errorf("unavailable coverage requires a bounded reason")
	}
	return nil
}

func (checkpoint ProceduralBaselineCheckpoint) Validate(policy MeasurementPolicy, baseline MeasurementReport) error {
	if checkpoint.SchemaVersion != BaselineCheckpointSchemaVersion || checkpoint.AuthorityClass != "procedural" || checkpoint.OriginAuthenticated || checkpoint.StartingRevision != TrustedBaselineRevision {
		return fmt.Errorf("invalid procedural baseline checkpoint authority")
	}
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"checkpoint policy", checkpoint.Policy}, {"checkpoint baseline result", checkpoint.BaselineResult}, {"checkpoint harness contract", checkpoint.HarnessContract}, {"checkpoint allowlist evidence", checkpoint.AllowlistEvidence}, {"checkpoint review evidence", checkpoint.ReviewEvidence}, {"checkpoint disposition evidence", checkpoint.DispositionEvidence},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	if !validID(checkpoint.ID) || !validID(checkpoint.Producer) || !validID(checkpoint.Reviewer) || !validID(checkpoint.Maintainer) {
		return fmt.Errorf("procedural baseline checkpoint requires identities")
	}
	// Distinct declared strings protect against trivial self-attestation but cannot prove real-world identity.
	if checkpoint.Producer == checkpoint.Reviewer || checkpoint.Producer == checkpoint.Maintainer || checkpoint.Reviewer == checkpoint.Maintainer {
		return fmt.Errorf("procedural baseline checkpoint requires distinct producer, reviewer, and maintainer")
	}
	policyDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		return err
	}
	if !sameRef(checkpoint.Policy, artifactRef(policy.ID, policyDigest)) || !sameRef(checkpoint.BaselineResult, artifactRef(baseline.ID, baseline.ID)) {
		return fmt.Errorf("procedural baseline checkpoint does not bind supplied policy and baseline bytes")
	}
	digest, err := DigestProceduralBaselineCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	if checkpoint.ID != digest {
		return fmt.Errorf("procedural baseline checkpoint digest does not bind its contents")
	}
	return nil
}

func (report MeasurementReport) Validate() error {
	if report.SchemaVersion != MeasurementReportSchemaVersion || !report.Purpose.valid() || !validDigest(report.ID) {
		return fmt.Errorf("invalid reachability measurement report")
	}
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"report policy", report.Policy}, {"report inventory", report.Inventory}, {"report corpus", report.Corpus}, {"report oracle", report.Oracle}, {"report exception manifest", report.ExceptionManifest},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	if err := report.ActiveSnapshot.Validate(); err != nil {
		return err
	}
	if report.Purpose == BaselineMeasurement {
		if report.RatchetDigest != "" || report.Candidate.Evaluated || report.Candidate.Accepted || len(report.Candidate.Reasons) != 0 {
			return fmt.Errorf("baseline report must not bind candidate acceptance state")
		}
	}
	if report.Purpose == CandidateAcceptance {
		if !validDigest(report.RatchetDigest) || !report.Candidate.Evaluated || report.Candidate.Accepted != (len(report.Candidate.Reasons) == 0) {
			return fmt.Errorf("candidate report has invalid ratchet or disposition")
		}
	}
	if err := validateReportStructure(report); err != nil {
		return err
	}
	digest, err := DigestMeasurementReport(report)
	if err != nil {
		return err
	}
	if report.ID != digest {
		return fmt.Errorf("measurement report digest does not bind its contents")
	}
	return nil
}

// Validate verifies the exact shape of a serialized ratio. Unavailable and not-applicable values
// intentionally carry no invented numerator or denominator.
func (ratio Ratio) Validate() error {
	if !ratio.Status.valid() {
		return fmt.Errorf("invalid ratio status %q", ratio.Status)
	}
	if ratio.Status != RatioAvailable {
		if ratio.Numerator != "" || ratio.Denominator != "" {
			return fmt.Errorf("%s ratio must not carry numerator or denominator", ratio.Status)
		}
		return nil
	}
	numerator, numeratorOK := new(big.Int).SetString(ratio.Numerator, 10)
	denominator, denominatorOK := new(big.Int).SetString(ratio.Denominator, 10)
	if !numeratorOK || !denominatorOK || numerator.Sign() < 0 || denominator.Sign() <= 0 || numerator.String() != ratio.Numerator || denominator.String() != ratio.Denominator {
		return fmt.Errorf("available ratio requires canonical non-negative numerator and positive denominator")
	}
	return nil
}

func validateReachabilityMetrics(metrics ReachabilityMetrics) error {
	if metrics.Expected < 0 || metrics.Found < 0 || metrics.Produced < 0 || metrics.Found > metrics.Expected || metrics.Found > metrics.Produced {
		return fmt.Errorf("invalid reachability metric counts")
	}
	if err := metrics.Precision.Validate(); err != nil {
		return err
	}
	if err := metrics.Recall.Validate(); err != nil {
		return err
	}
	if !sameRatio(metrics.Precision, ratioFromCounts(metrics.Found, metrics.Produced)) || !sameRatio(metrics.Recall, ratioFromCounts(metrics.Found, metrics.Expected)) {
		return fmt.Errorf("reachability ratios do not match metric counts")
	}
	return nil
}

func validateSuppressionMetrics(metrics SuppressionMetrics) error {
	if !metrics.Status.valid() || metrics.Eligible < 0 || metrics.Found < 0 || metrics.Produced < 0 || metrics.Valid < 0 || metrics.False < 0 || metrics.Invalid < 0 || metrics.Found > metrics.Eligible || metrics.Valid > metrics.Produced || metrics.Found != metrics.Valid {
		return fmt.Errorf("invalid suppression metric counts")
	}
	if err := metrics.Precision.Validate(); err != nil {
		return err
	}
	if err := metrics.Recall.Validate(); err != nil {
		return err
	}
	switch metrics.Status {
	case RatioUnavailable:
		if metrics.Precision.Status != RatioUnavailable || metrics.Recall.Status != RatioUnavailable {
			return fmt.Errorf("unavailable suppression metrics require unavailable ratios")
		}
	case RatioNotApplicable:
		if metrics.Precision.Status != RatioNotApplicable || metrics.Recall.Status != RatioNotApplicable {
			return fmt.Errorf("not-applicable suppression metrics require not-applicable ratios")
		}
	case RatioAvailable:
		if metrics.Precision.Status == RatioUnavailable || metrics.Recall.Status == RatioUnavailable {
			return fmt.Errorf("available suppression metrics cannot carry unavailable ratios")
		}
	}
	return nil
}

func validateCoverageCounts(counts []CoverageCount, observed int64) error {
	seen := map[CoverageStatus]struct{}{}
	total := int64(0)
	for _, count := range counts {
		if !count.Status.valid() || count.Count < 0 {
			return fmt.Errorf("invalid coverage summary count")
		}
		if _, exists := seen[count.Status]; exists {
			return fmt.Errorf("duplicate coverage summary status %q", count.Status)
		}
		seen[count.Status] = struct{}{}
		total += count.Count
	}
	if total != observed {
		return fmt.Errorf("coverage summary count %d does not match observed executions %d", total, observed)
	}
	return nil
}

func validateExecutionCoverage(coverage []ExecutionCoverage, required, observed int64) error {
	if int64(len(coverage)) != required {
		return fmt.Errorf("execution coverage count does not match required executions")
	}
	seen := map[string]struct{}{}
	observedCount := int64(0)
	for _, item := range coverage {
		if !validID(item.CohortID) || !validID(item.ModeID) || !validID(item.BindingID) || !validID(item.CaseID) {
			return fmt.Errorf("invalid execution coverage identity")
		}
		key := executionCoverageKey(item)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate execution coverage %q", key)
		}
		seen[key] = struct{}{}
		if item.Observed {
			observedCount++
			if item.Coverage == nil || !item.Coverage.valid() {
				return fmt.Errorf("observed execution coverage %q lacks coverage status", key)
			}
		} else if item.Assessed || item.Coverage != nil {
			return fmt.Errorf("unobserved execution coverage %q carries assessment", key)
		}
		if item.Assessed && !item.Observed {
			return fmt.Errorf("unobserved execution coverage %q is assessed", key)
		}
	}
	if observedCount != observed {
		return fmt.Errorf("execution coverage observed count does not match report")
	}
	return nil
}

func validateReportStructure(report MeasurementReport) error {
	if report.RequiredExecutions < 0 || report.ObservedExecutions < 0 || report.UnobservedExecutions < 0 || report.RequiredExecutions != report.ObservedExecutions+report.UnobservedExecutions {
		return fmt.Errorf("invalid measurement execution counts")
	}
	if err := validateReachabilityMetrics(report.Reachability); err != nil {
		return fmt.Errorf("report reachability: %w", err)
	}
	if err := validateSuppressionMetrics(report.Suppressions); err != nil {
		return fmt.Errorf("report suppressions: %w", err)
	}
	if err := report.CoverageRate.Validate(); err != nil {
		return err
	}
	if err := report.NoAnalysisRate.Validate(); err != nil {
		return err
	}
	if report.NoAnalysis < 0 || report.NoAnalysis > report.ObservedExecutions || !sameRatio(report.CoverageRate, ratioFromCounts(coverageCompleteCount(report.Coverage), report.RequiredExecutions)) || !sameRatio(report.NoAnalysisRate, ratioFromCounts(report.NoAnalysis, report.RequiredExecutions)) {
		return fmt.Errorf("report coverage or no-analysis ratio does not match counts")
	}
	if err := validateCoverageCounts(report.Coverage, report.ObservedExecutions); err != nil {
		return err
	}
	if err := validateExecutionCoverage(report.ExecutionCoverage, report.RequiredExecutions, report.ObservedExecutions); err != nil {
		return err
	}
	if int64(len(report.Observations)) != report.ObservedExecutions {
		return fmt.Errorf("retained observations do not match observed execution count")
	}
	observationKeys := map[string]struct{}{}
	for _, observation := range report.Observations {
		if err := observation.validate(report.ActiveSnapshot); err != nil {
			return fmt.Errorf("retained observation: %w", err)
		}
		key := observation.CaseID + "\x00" + observation.BindingID
		if _, exists := observationKeys[key]; exists {
			return fmt.Errorf("duplicate retained observation %q", key)
		}
		observationKeys[key] = struct{}{}
	}
	if err := validateOutcomeConfusion(report.OutcomeConfusion, report.ObservedExecutions); err != nil {
		return err
	}
	if err := validateReportSummaries(report); err != nil {
		return err
	}
	if report.EnabledCohorts < 0 || report.AssessedEnabledCohorts < 0 || report.ProductionPositiveCohorts < 0 || report.AssessedEnabledCohorts > report.EnabledCohorts || report.ProductionPositiveCohorts > report.EnabledCohorts {
		return fmt.Errorf("invalid cohort aggregate counts")
	}
	if err := validateC2Vector(report.C2); err != nil {
		return err
	}
	if report.Safety.Pass != (len(report.Safety.Findings) == 0) {
		return fmt.Errorf("safety disposition does not match findings")
	}
	return nil
}

func validateOutcomeConfusion(cells []OutcomeConfusion, observed int64) error {
	seen := map[string]struct{}{}
	total := int64(0)
	for _, cell := range cells {
		if !cell.Expected.valid() || !cell.Observed.valid() || cell.Count <= 0 {
			return fmt.Errorf("invalid outcome confusion cell")
		}
		key := outcomePairKey(cell)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate outcome confusion cell")
		}
		seen[key] = struct{}{}
		total += cell.Count
	}
	if total != observed {
		return fmt.Errorf("outcome confusion count does not match observed executions")
	}
	return nil
}

func validateReportSummaries(report MeasurementReport) error {
	bindings := map[string]struct{}{}
	for _, summary := range report.Bindings {
		key := bindingSummaryKey(summary)
		if !validID(summary.CohortID) || !validID(summary.ModeID) || !validID(summary.BindingID) || summary.RequiredExecutions < 0 || summary.ObservedExecutions < 0 || summary.ObservedExecutions > summary.RequiredExecutions || !summary.Assessment.valid() {
			return fmt.Errorf("invalid binding summary %q", key)
		}
		if _, exists := bindings[key]; exists {
			return fmt.Errorf("duplicate binding summary %q", key)
		}
		bindings[key] = struct{}{}
		if err := validateReachabilityMetrics(summary.Reachability); err != nil {
			return fmt.Errorf("binding %q: %w", key, err)
		}
		if err := validateSuppressionMetrics(summary.Suppressions); err != nil {
			return fmt.Errorf("binding %q: %w", key, err)
		}
		if err := summary.CoverageRate.Validate(); err != nil {
			return err
		}
		if err := summary.NoAnalysisRate.Validate(); err != nil {
			return err
		}
		if summary.NoAnalysis < 0 || summary.NoAnalysis > summary.ObservedExecutions || !sameRatio(summary.CoverageRate, ratioFromCounts(coverageCompleteCount(summary.Coverage), summary.RequiredExecutions)) || !sameRatio(summary.NoAnalysisRate, ratioFromCounts(summary.NoAnalysis, summary.RequiredExecutions)) {
			return fmt.Errorf("binding %q coverage or no-analysis ratios do not match counts", key)
		}
		if err := validateCoverageCounts(summary.Coverage, summary.ObservedExecutions); err != nil {
			return err
		}
	}
	cohorts := map[string]struct{}{}
	for _, summary := range report.Cohorts {
		key := cohortKey(summary.CohortID, summary.ModeID)
		if !validID(summary.CohortID) || !validID(summary.ModeID) || !validID(summary.Language) || !summary.Assessment.valid() || summary.Cases < 0 || summary.RequiredExecutions < 0 || summary.ObservedExecutions < 0 || summary.ObservedExecutions > summary.RequiredExecutions || summary.CorrectPositiveCases < 0 {
			return fmt.Errorf("invalid cohort summary %q", key)
		}
		if _, exists := cohorts[key]; exists {
			return fmt.Errorf("duplicate cohort summary %q", key)
		}
		cohorts[key] = struct{}{}
		if err := validateOutcomeCounts(summary.OutcomeCounts, summary.Cases); err != nil {
			return fmt.Errorf("cohort %q: %w", key, err)
		}
		if err := validateCategoryCounts(summary.CategoryCounts, summary.Cases); err != nil {
			return fmt.Errorf("cohort %q: %w", key, err)
		}
		if err := validateReachabilityMetrics(summary.Reachability); err != nil {
			return fmt.Errorf("cohort %q: %w", key, err)
		}
		if err := validateSuppressionMetrics(summary.Suppressions); err != nil {
			return fmt.Errorf("cohort %q: %w", key, err)
		}
		if err := summary.CoverageRate.Validate(); err != nil {
			return err
		}
		if err := summary.NoAnalysisRate.Validate(); err != nil {
			return err
		}
		if summary.NoAnalysis < 0 || summary.NoAnalysis > summary.ObservedExecutions || !sameRatio(summary.CoverageRate, ratioFromCounts(coverageCompleteCount(summary.Coverage), summary.RequiredExecutions)) || !sameRatio(summary.NoAnalysisRate, ratioFromCounts(summary.NoAnalysis, summary.RequiredExecutions)) {
			return fmt.Errorf("cohort %q coverage or no-analysis ratios do not match counts", key)
		}
		if err := validateCoverageCounts(summary.Coverage, summary.ObservedExecutions); err != nil {
			return err
		}
	}
	languages := map[string]struct{}{}
	for _, summary := range report.Languages {
		if !validID(summary.Language) || summary.Cohorts < 0 || summary.NoAnalysis < 0 {
			return fmt.Errorf("invalid language summary")
		}
		if _, exists := languages[summary.Language]; exists {
			return fmt.Errorf("duplicate language summary %q", summary.Language)
		}
		languages[summary.Language] = struct{}{}
		if err := validateReachabilityMetrics(summary.Reachability); err != nil {
			return fmt.Errorf("language %q: %w", summary.Language, err)
		}
		if err := validateSuppressionMetrics(summary.Suppressions); err != nil {
			return fmt.Errorf("language %q: %w", summary.Language, err)
		}
		if err := summary.CoverageRate.Validate(); err != nil {
			return err
		}
		if err := summary.NoAnalysisRate.Validate(); err != nil {
			return err
		}
		if summary.NoAnalysis > coverageTotal(summary.Coverage) {
			return fmt.Errorf("language %q no-analysis count exceeds observed coverage", summary.Language)
		}
		if err := validateCoverageCounts(summary.Coverage, coverageTotal(summary.Coverage)); err != nil {
			return err
		}
	}
	return nil
}

func validateOutcomeCounts(counts []OutcomeCount, total int64) error {
	seen := map[Outcome]struct{}{}
	sum := int64(0)
	for _, count := range counts {
		if !count.Outcome.valid() || count.Count < 0 {
			return fmt.Errorf("invalid outcome count")
		}
		if _, exists := seen[count.Outcome]; exists {
			return fmt.Errorf("duplicate outcome count %q", count.Outcome)
		}
		seen[count.Outcome] = struct{}{}
		sum += count.Count
	}
	if sum != total {
		return fmt.Errorf("outcome counts do not match case count")
	}
	return nil
}

func validateCategoryCounts(counts []OracleCategoryCount, total int64) error {
	seen := map[OracleCategory]struct{}{}
	sum := int64(0)
	for _, count := range counts {
		if !count.Category.valid() || count.Count < 0 {
			return fmt.Errorf("invalid oracle category count")
		}
		if _, exists := seen[count.Category]; exists {
			return fmt.Errorf("duplicate oracle category count %q", count.Category)
		}
		seen[count.Category] = struct{}{}
		sum += count.Count
	}
	if sum != total {
		return fmt.Errorf("oracle category counts do not match case count")
	}
	return nil
}

func validateC2Vector(vector C2Vector) error {
	if vector.ProductionBreadth < 0 || vector.CorrectPositiveCases < 0 {
		return fmt.Errorf("invalid C2 counts")
	}
	return vector.MacroReachableRecall.Validate()
}

func coverageTotal(counts []CoverageCount) int64 {
	total := int64(0)
	for _, count := range counts {
		total += count.Count
	}
	return total
}

func coverageCompleteCount(counts []CoverageCount) int64 {
	for _, count := range counts {
		if count.Status == CoverageComplete {
			return count.Count
		}
	}
	return 0
}

func sameRatio(left, right Ratio) bool {
	return left.Status == right.Status && left.Numerator == right.Numerator && left.Denominator == right.Denominator
}

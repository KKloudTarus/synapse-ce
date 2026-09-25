package reachbench

import (
	"embed"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ReachabilityProfileStatus identifies whether a profile has authority for candidate acceptance.
type ReachabilityProfileStatus string

const (
	ReachabilityProfileAuthoritative            ReachabilityProfileStatus = "authoritative"
	ReachabilityProfilePendingIndependentReview ReachabilityProfileStatus = "pending_independent_review"
)

const (
	defaultReachabilityProfileID = "synapse-reachability-profile-v2"
	goBinaryVersionedProfileID   = "synapse-reachability-go-binary-versioned-profile-v3"
)

// ReachabilityProfile is the package-owned static contract selected for one measurement input.
// A pending profile is diagnostic only and cannot become acceptance authority.
type ReachabilityProfile struct {
	ID             string
	Status         ReachabilityProfileStatus
	Authoritative  bool
	Fixtures       FixtureManifest
	Inventory      ProductionInventory
	Corpus         ContractCorpus
	Oracle         ReachabilityOracle
	Policy         MeasurementPolicy
	Exceptions     ExceptionManifest
	ActiveSnapshot SnapshotIdentity

	profileKey string
	fixtureFS  fs.FS
}

type successorEvaluatorDescriptor struct {
	SchemaVersion                      string            `json:"schema_version"`
	ID                                 string            `json:"id"`
	BaseEvaluator                      ArtifactReference `json:"base_evaluator"`
	RequiresPerCellOutcomeDebtGuard    bool              `json:"requires_per_cell_outcome_debt_guard"`
	RequiresBaselineMeasurementContext bool              `json:"requires_baseline_measurement_context"`
}

type successorMetricDefinitionDescriptor struct {
	SchemaVersion                       string            `json:"schema_version"`
	ID                                  string            `json:"id"`
	BaseMetricDefinition                ArtifactReference `json:"base_metric_definition"`
	CandidateOutcomeDebtRule            string            `json:"candidate_outcome_debt_rule"`
	RequiresPerCellOutcomeNonRegression bool              `json:"requires_per_cell_outcome_non_regression"`
}

//go:embed all:successor/go_binary_versioned
var successorProfileFiles embed.FS

var reachabilityProfileRegistry struct {
	once     sync.Once
	profiles []ReachabilityProfile
	err      error
}

var reachabilityProfileRegistryBuilds atomic.Uint32

// DefaultReachabilityProfile returns the legacy v2 profile without changing its assets or default builders.
func DefaultReachabilityProfile() (ReachabilityProfile, error) {
	input, err := DefaultBaselineMeasurementInput()
	if err != nil {
		return ReachabilityProfile{}, fmt.Errorf("build default reachability profile: %w", err)
	}
	root, err := fs.Sub(reachabilityBenchmarkFiles, benchmarkAssetRoot)
	if err != nil {
		return ReachabilityProfile{}, fmt.Errorf("open default profile fixtures: %w", err)
	}
	return newReachabilityProfile(defaultReachabilityProfileID, ReachabilityProfileAuthoritative, true, input, DefaultFixtureManifest(), root)
}

// GoBinaryVersionedBaselineMeasurementInput returns the pending, non-authoritative successor baseline template.
func GoBinaryVersionedBaselineMeasurementInput() (MeasurementInput, error) {
	profile, err := goBinaryVersionedProfile()
	if err != nil {
		return MeasurementInput{}, err
	}
	return profile.measurementInput(), nil
}

// ResolveReachabilityProfile accepts only an exact package-owned static tuple.
func ResolveReachabilityProfile(input MeasurementInput) (ReachabilityProfile, error) {
	if err := input.Validate(); err != nil {
		return ReachabilityProfile{}, fmt.Errorf("validate reachability profile input: %w", err)
	}
	profiles, err := registeredReachabilityProfiles()
	if err != nil {
		return ReachabilityProfile{}, err
	}
	for _, profile := range profiles {
		if profile.matchesInput(input) {
			return profile, nil
		}
	}
	return ReachabilityProfile{}, fmt.Errorf("reachability measurement input does not match a registered profile")
}

// ResolveFixtureSpecification resolves a fixture only when this profile is still package-owned and unchanged.
func (profile ReachabilityProfile) ResolveFixtureSpecification(reference ArtifactReference) (FixtureSpecification, error) {
	if err := profile.validateRegistered(); err != nil {
		return FixtureSpecification{}, err
	}
	for _, specification := range profile.Fixtures.Fixtures {
		if specification.ID != reference.ID {
			continue
		}
		digest, err := DigestFixtureSpecification(specification)
		if err != nil {
			return FixtureSpecification{}, err
		}
		if digest != reference.Digest {
			return FixtureSpecification{}, fmt.Errorf("fixture reference digest mismatch for %q", reference.ID)
		}
		return canonicalFixtureSpecification(specification), nil
	}
	return FixtureSpecification{}, fmt.Errorf("unknown fixture %q", reference.ID)
}

// ReadFixtureFile returns verified bytes only from this registered profile.
func (profile ReachabilityProfile) ReadFixtureFile(file FixtureFile) ([]byte, error) {
	if err := profile.validateRegistered(); err != nil {
		return nil, err
	}
	return readProfileFixtureFile(profile, file)
}

// ResolveRegisteredFixtureSpecification resolves a checked-in fixture identity across registered profiles.
func ResolveRegisteredFixtureSpecification(reference ArtifactReference) (FixtureSpecification, error) {
	if err := reference.validate("fixture reference"); err != nil {
		return FixtureSpecification{}, err
	}
	var result *FixtureSpecification
	profiles, err := registeredReachabilityProfiles()
	if err != nil {
		return FixtureSpecification{}, err
	}
	for _, profile := range profiles {
		for _, specification := range profile.Fixtures.Fixtures {
			digest, err := DigestFixtureSpecification(specification)
			if err != nil {
				return FixtureSpecification{}, err
			}
			if specification.ID != reference.ID || digest != reference.Digest {
				continue
			}
			candidate := specification
			if result != nil && !sameFixtureSpecification(*result, candidate) {
				return FixtureSpecification{}, fmt.Errorf("registered fixture %q has conflicting declarations", reference.ID)
			}
			result = &candidate
		}
	}
	if result == nil {
		return FixtureSpecification{}, fmt.Errorf("unknown registered fixture %q", reference.ID)
	}
	return canonicalFixtureSpecification(*result), nil
}

// ReadRegisteredFixtureFile returns verified bytes from exactly one registered fixture declaration.
func ReadRegisteredFixtureFile(file FixtureFile) ([]byte, error) {
	var profile *ReachabilityProfile
	profiles, err := registeredReachabilityProfiles()
	if err != nil {
		return nil, err
	}
	for _, candidate := range profiles {
		if !profileDeclaresFile(candidate, file) {
			continue
		}
		if profile != nil {
			if !sameProfileFile(*profile, candidate, file) {
				return nil, fmt.Errorf("registered fixture file %q has conflicting declarations", file.Path)
			}
			continue
		}
		copy := candidate
		profile = &copy
	}
	if profile == nil {
		return nil, fmt.Errorf("fixture file %q is not registered", file.Path)
	}
	return readProfileFixtureFile(*profile, file)
}

func registeredReachabilityProfiles() ([]ReachabilityProfile, error) {
	reachabilityProfileRegistry.once.Do(func() {
		reachabilityProfileRegistryBuilds.Add(1)
		defaultProfile, err := DefaultReachabilityProfile()
		if err != nil {
			reachabilityProfileRegistry.err = fmt.Errorf("build default profile: %w", err)
			return
		}
		successor, err := goBinaryVersionedProfile()
		if err != nil {
			reachabilityProfileRegistry.err = fmt.Errorf("build versioned Go binary profile: %w", err)
			return
		}
		reachabilityProfileRegistry.profiles = []ReachabilityProfile{defaultProfile, successor}
	})
	if reachabilityProfileRegistry.err != nil {
		return nil, reachabilityProfileRegistry.err
	}
	profiles := make([]ReachabilityProfile, len(reachabilityProfileRegistry.profiles))
	for index, profile := range reachabilityProfileRegistry.profiles {
		profiles[index] = cloneReachabilityProfile(profile)
	}
	return profiles, nil
}

func goBinaryVersionedProfile() (ReachabilityProfile, error) {
	legacy := DefaultReachabilityBenchmark()
	fixtures, fileSystem, err := goBinaryVersionedFixtures(legacy.Fixtures)
	if err != nil {
		return ReachabilityProfile{}, err
	}
	inventory, err := goBinaryVersionedInventory()
	if err != nil {
		return ReachabilityProfile{}, err
	}
	corpus, oracle, err := goBinaryVersionedContract(legacy, fixtures)
	if err != nil {
		return ReachabilityProfile{}, err
	}
	exceptions := DefaultExceptionManifest()
	policy, err := profileMeasurementPolicy(goBinaryVersionedProfileID+"-policy", inventory, corpus, oracle, exceptions)
	if err != nil {
		return ReachabilityProfile{}, err
	}
	snapshot, err := profileActiveSnapshot(goBinaryVersionedProfileID+"-run", fixtures, inventory, policy)
	if err != nil {
		return ReachabilityProfile{}, err
	}
	input := MeasurementInput{SchemaVersion: MeasurementInputSchemaVersion, Purpose: BaselineMeasurement, Inventory: inventory, Corpus: corpus, Oracle: oracle, Policy: policy, Exceptions: exceptions, ActiveSnapshot: snapshot}
	return newReachabilityProfile(goBinaryVersionedProfileID, ReachabilityProfilePendingIndependentReview, false, input, fixtures, fileSystem)
}

func newReachabilityProfile(id string, status ReachabilityProfileStatus, authoritative bool, input MeasurementInput, fixtures FixtureManifest, files fs.FS) (ReachabilityProfile, error) {
	if (status == ReachabilityProfileAuthoritative) != authoritative || (status != ReachabilityProfileAuthoritative && status != ReachabilityProfilePendingIndependentReview) {
		return ReachabilityProfile{}, fmt.Errorf("invalid reachability profile authority")
	}
	if err := input.Validate(); err != nil {
		return ReachabilityProfile{}, err
	}
	fixtureDigest, err := DigestFixtureManifest(fixtures)
	if err != nil {
		return ReachabilityProfile{}, err
	}
	if !sameRef(input.ActiveSnapshot.Source, artifactRef(fixtures.ID, fixtureDigest)) {
		return ReachabilityProfile{}, fmt.Errorf("profile fixture manifest does not bind active snapshot")
	}
	profile := ReachabilityProfile{ID: id, Status: status, Authoritative: authoritative, Fixtures: fixtures, Inventory: input.Inventory, Corpus: input.Corpus, Oracle: input.Oracle, Policy: input.Policy, Exceptions: input.Exceptions, ActiveSnapshot: input.ActiveSnapshot, fixtureFS: files}
	key, err := profile.identityKey()
	if err != nil {
		return ReachabilityProfile{}, err
	}
	profile.profileKey = key
	return profile, nil
}

func (profile ReachabilityProfile) measurementInput() MeasurementInput {
	return MeasurementInput{SchemaVersion: MeasurementInputSchemaVersion, Purpose: BaselineMeasurement, Inventory: profile.Inventory, Corpus: profile.Corpus, Oracle: profile.Oracle, Policy: profile.Policy, Exceptions: profile.Exceptions, ActiveSnapshot: profile.ActiveSnapshot}
}

func (profile ReachabilityProfile) matchesInput(input MeasurementInput) bool {
	if err := profile.validateRegistered(); err != nil {
		return false
	}
	return sameProfileStaticInput(profile.measurementInput(), input)
}

func sameProfileStaticInput(left, right MeasurementInput) bool {
	leftInventory, _ := DigestProductionInventory(left.Inventory)
	rightInventory, _ := DigestProductionInventory(right.Inventory)
	leftCorpus, _ := DigestContractCorpus(left.Corpus)
	rightCorpus, _ := DigestContractCorpus(right.Corpus)
	leftOracle, _ := DigestReachabilityOracle(left.Oracle)
	rightOracle, _ := DigestReachabilityOracle(right.Oracle)
	leftPolicy, _ := DigestMeasurementPolicy(left.Policy)
	rightPolicy, _ := DigestMeasurementPolicy(right.Policy)
	leftExceptions, _ := DigestExceptionManifest(left.Exceptions)
	rightExceptions, _ := DigestExceptionManifest(right.Exceptions)
	return sameRef(artifactRef(left.Inventory.ID, leftInventory), artifactRef(right.Inventory.ID, rightInventory)) &&
		sameRef(artifactRef(left.Corpus.ID, leftCorpus), artifactRef(right.Corpus.ID, rightCorpus)) &&
		sameRef(artifactRef(left.Oracle.ID, leftOracle), artifactRef(right.Oracle.ID, rightOracle)) &&
		sameRef(artifactRef(left.Policy.ID, leftPolicy), artifactRef(right.Policy.ID, rightPolicy)) &&
		sameRef(artifactRef(left.Exceptions.ID, leftExceptions), artifactRef(right.Exceptions.ID, rightExceptions)) &&
		sameSnapshot(left.ActiveSnapshot, right.ActiveSnapshot)
}

func (profile ReachabilityProfile) validateRegistered() error {
	if profile.profileKey == "" || profile.fixtureFS == nil {
		return fmt.Errorf("reachability profile is not package-owned")
	}
	key, err := profile.identityKey()
	if err != nil || key != profile.profileKey {
		return fmt.Errorf("reachability profile was modified")
	}
	expected, err := registeredProfileKey(profile.ID)
	if err != nil || expected != profile.profileKey {
		return fmt.Errorf("unknown reachability profile %q", profile.ID)
	}
	return nil
}

func registeredProfileKey(id string) (string, error) {
	profiles, err := registeredReachabilityProfiles()
	if err != nil {
		return "", err
	}
	for _, profile := range profiles {
		if profile.ID == id {
			return profile.profileKey, nil
		}
	}
	return "", fmt.Errorf("unknown reachability profile %q", id)
}

func cloneReachabilityProfile(profile ReachabilityProfile) ReachabilityProfile {
	out := profile
	out.Fixtures = cloneFixtureManifest(profile.Fixtures)
	out.Inventory = canonicalInventory(profile.Inventory)
	out.Corpus = cloneContractCorpus(profile.Corpus)
	out.Oracle = cloneReachabilityOracle(profile.Oracle)
	out.Policy = cloneMeasurementPolicy(profile.Policy)
	out.Exceptions = profile.Exceptions
	out.Exceptions.Entries = make([]CoverageException, len(profile.Exceptions.Entries))
	copy(out.Exceptions.Entries, profile.Exceptions.Entries)
	return out
}

func cloneFixtureManifest(manifest FixtureManifest) FixtureManifest {
	out := canonicalFixtureManifest(manifest)
	for index := range out.Fixtures {
		fixture := &out.Fixtures[index]
		fixture.Files = append([]FixtureFile(nil), fixture.Files...)
		fixture.Entries = append([]FixtureEntry(nil), fixture.Entries...)
		fixture.Subjects = append([]FixtureSubject(nil), fixture.Subjects...)
		if fixture.Build == nil {
			continue
		}
		build := *fixture.Build
		build.Steps = append([]FixtureBuildStep(nil), fixture.Build.Steps...)
		for stepIndex := range build.Steps {
			build.Steps[stepIndex].Argv = append([]string(nil), build.Steps[stepIndex].Argv...)
		}
		build.Env = append([]FixtureBuildEnv(nil), fixture.Build.Env...)
		build.Outputs = append([]FixtureOutput(nil), fixture.Build.Outputs...)
		fixture.Build = &build
	}
	return out
}

func cloneContractCorpus(corpus ContractCorpus) ContractCorpus {
	out := canonicalCorpus(corpus)
	for index := range out.Cases {
		if out.Cases[index].Fixture != nil {
			fixture := *out.Cases[index].Fixture
			out.Cases[index].Fixture = &fixture
		}
		if out.Cases[index].LegacyOrigin != nil {
			origin := *out.Cases[index].LegacyOrigin
			out.Cases[index].LegacyOrigin = &origin
		}
	}
	return out
}

func cloneReachabilityOracle(oracle ReachabilityOracle) ReachabilityOracle {
	out := canonicalOracle(oracle)
	for index := range out.Cases {
		if out.Cases[index].CompletenessContract != nil {
			contract := *out.Cases[index].CompletenessContract
			out.Cases[index].CompletenessContract = &contract
		}
	}
	return out
}

func cloneMeasurementPolicy(policy MeasurementPolicy) MeasurementPolicy {
	out := canonicalPolicy(policy)
	for index := range out.Rules {
		if out.Rules[index].CompletenessContract != nil {
			contract := *out.Rules[index].CompletenessContract
			out.Rules[index].CompletenessContract = &contract
		}
	}
	return out
}

func (profile ReachabilityProfile) identityKey() (string, error) {
	value := struct {
		ID             string
		Status         ReachabilityProfileStatus
		Authoritative  bool
		Fixtures       FixtureManifest
		Inventory      ProductionInventory
		Corpus         ContractCorpus
		Oracle         ReachabilityOracle
		Policy         MeasurementPolicy
		Exceptions     ExceptionManifest
		ActiveSnapshot SnapshotIdentity
	}{profile.ID, profile.Status, profile.Authoritative, profile.Fixtures, profile.Inventory, profile.Corpus, profile.Oracle, profile.Policy, profile.Exceptions, profile.ActiveSnapshot}
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

func goBinaryVersionedInventory() (ProductionInventory, error) {
	inventory := DefaultProductionInventory()
	for cohortIndex := range inventory.Cohorts {
		cohort := &inventory.Cohorts[cohortIndex]
		if cohort.ID != "go" || cohort.Mode != "binary" {
			continue
		}
		for bindingIndex := range cohort.Bindings {
			binding := &cohort.Bindings[bindingIndex]
			if binding.ID == "worker" {
				binding.State = BindingEnabled
				binding.Reason = ""
			}
		}
	}
	if err := inventory.Validate(); err != nil {
		return ProductionInventory{}, err
	}
	return canonicalInventory(inventory), nil
}

func profileMeasurementPolicy(id string, inventory ProductionInventory, corpus ContractCorpus, oracle ReachabilityOracle, exceptions ExceptionManifest) (MeasurementPolicy, error) {
	inventoryDigest, err := DigestProductionInventory(inventory)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	corpusDigest, err := DigestContractCorpus(corpus)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	oracleDigest, err := DigestReachabilityOracle(oracle)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	exceptionsDigest, err := DigestExceptionManifest(exceptions)
	if err != nil {
		return MeasurementPolicy{}, err
	}
	registry, err := judgment.NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		return MeasurementPolicy{}, err
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
	evaluator, err := successorDescriptorReference(successorEvaluatorDescriptor{SchemaVersion: defaultDescriptorSchemaVersion, ID: goBinaryVersionedProfileID + "-evaluator", BaseEvaluator: descriptors.evaluator, RequiresPerCellOutcomeDebtGuard: true, RequiresBaselineMeasurementContext: true})
	if err != nil {
		return MeasurementPolicy{}, err
	}
	metrics, err := successorDescriptorReference(successorMetricDefinitionDescriptor{SchemaVersion: defaultDescriptorSchemaVersion, ID: goBinaryVersionedProfileID + "-metric-definition", BaseMetricDefinition: descriptors.metrics, CandidateOutcomeDebtRule: "candidate acceptance requires each baseline-resolved public outcome cell to remain non-regressed; unresolved cells remain outcome debt", RequiresPerCellOutcomeNonRegression: true})
	if err != nil {
		return MeasurementPolicy{}, err
	}
	policy := MeasurementPolicy{SchemaVersion: PolicySchemaVersion, ID: id, Inventory: artifactRef(inventory.ID, inventoryDigest), Corpus: artifactRef(corpus.ID, corpusDigest), Oracle: artifactRef(oracle.ID, oracleDigest), ExceptionManifest: artifactRef(exceptions.ID, exceptionsDigest), SchemaDefinition: descriptors.schema, RunPurposeRules: descriptors.runPurpose, RatchetConstructionRule: descriptors.ratchet, Evaluator: evaluator, MetricDefinition: metrics, Adapters: adapters, Rules: rules}
	if err := policy.Validate(); err != nil {
		return MeasurementPolicy{}, err
	}
	return canonicalPolicy(policy), nil
}

func successorDescriptorReference(value any) (ArtifactReference, error) {
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return ArtifactReference{}, err
	}
	switch descriptor := value.(type) {
	case successorEvaluatorDescriptor:
		return artifactRef(descriptor.ID, benchmark.SHA256Digest(encoded)), nil
	case successorMetricDefinitionDescriptor:
		return artifactRef(descriptor.ID, benchmark.SHA256Digest(encoded)), nil
	default:
		return ArtifactReference{}, fmt.Errorf("unknown successor descriptor")
	}
}

func profileActiveSnapshot(id string, fixtures FixtureManifest, inventory ProductionInventory, policy MeasurementPolicy) (SnapshotIdentity, error) {
	fixtureDigest, err := DigestFixtureManifest(fixtures)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	inventoryDigest, err := DigestProductionInventory(inventory)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	policyDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		return SnapshotIdentity{}, err
	}
	fixturesReference := artifactRef(fixtures.ID, fixtureDigest)
	inventoryReference := artifactRef(inventory.ID, inventoryDigest)
	policyReference := artifactRef(policy.ID, policyDigest)
	run, err := descriptorReference(frozenContractRunDescriptor{SchemaVersion: defaultDescriptorSchemaVersion, ID: id, Fixtures: fixturesReference, Inventory: inventoryReference, Policy: policyReference})
	if err != nil {
		return SnapshotIdentity{}, err
	}
	return SnapshotIdentity{Source: fixturesReference, SBOM: inventoryReference, Run: run}, nil
}

func goBinaryVersionedContract(legacy ReachabilityBenchmark, fixtures FixtureManifest) (ContractCorpus, ReachabilityOracle, error) {
	corpus := legacy.Corpus
	oracle := legacy.Oracle
	corpus.ID = "synapse-ce-reachability-go-binary-versioned-benchmark"
	oracle.ID = "synapse-ce-reachability-go-binary-versioned-oracle"
	var removed map[string]struct{}
	corpus.Cases, removed = removeLegacyGoBinaryCases(corpus.Cases)
	oracle.Cases = removeOracleCases(oracle.Cases, removed)
	cases, err := goBinaryVersionedCases(fixtures)
	if err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	for _, item := range cases {
		corpus.Cases = append(corpus.Cases, item.contract)
		oracle.Cases = append(oracle.Cases, item.oracle)
	}
	corpus = canonicalCorpus(corpus)
	oracle = canonicalOracle(oracle)
	if err := oracle.ValidateAgainst(corpus); err != nil {
		return ContractCorpus{}, ReachabilityOracle{}, err
	}
	return corpus, oracle, nil
}

type goBinaryVersionedCase struct {
	contract ContractCase
	oracle   OracleCase
}

func goBinaryVersionedCases(fixtures FixtureManifest) ([]goBinaryVersionedCase, error) {
	byID := map[string]FixtureSpecification{}
	for _, fixture := range fixtures.Fixtures {
		byID[fixture.ID] = fixture
	}
	caseFor := func(id, fixtureID, subjectID string, expected Outcome, category OracleCategory, coverage CoverageStatus) (goBinaryVersionedCase, error) {
		digest, err := DigestFixtureSpecification(byID[fixtureID])
		if err != nil {
			return goBinaryVersionedCase{}, err
		}
		return goBinaryVersionedCase{contract: ContractCase{ID: id, SubjectID: subjectID, CohortID: "go", ModeID: "binary", Fixture: ptrArtifact(artifactRef(fixtureID, digest))}, oracle: OracleCase{CaseID: id, Expected: expected, Category: category, CoverageExpectation: coverage}}, nil
	}
	definitions := []struct {
		id, fixtureID, subjectID string
		expected                 Outcome
		category                 OracleCategory
		coverage                 CoverageStatus
	}{
		{"go-binary-versioned-direct-call", "go-binary-versioned-direct-call", "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", OutcomeReachable, OracleReachable, CoverageComplete},
		{"go-binary-versioned-retained-but-uncalled", "go-binary-versioned-retained-but-uncalled", "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", OutcomePresentUnreached, OracleTrulyUnreachable, CoverageComplete},
		{"go-binary-versioned-retained-and-called", "go-binary-versioned-retained-and-called", "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", OutcomeReachable, OracleReachable, CoverageComplete},
		{"go-binary-versioned-indirect-function-value-call", "go-binary-versioned-indirect-function-value-call", "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", OutcomeConditionallyReachable, OracleOpaque, CoveragePartial},
		{"go-binary-versioned-empty-root-unavailable", "go-binary-versioned-empty-root-unavailable", "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", OutcomeNoAnalysis, OracleNoCoverage, CoverageUnavailable},
	}
	result := make([]goBinaryVersionedCase, 0, len(definitions))
	for _, definition := range definitions {
		item, err := caseFor(definition.id, definition.fixtureID, definition.subjectID, definition.expected, definition.category, definition.coverage)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func ptrArtifact(value ArtifactReference) *ArtifactReference { return &value }

func removeLegacyGoBinaryCases(items []ContractCase) ([]ContractCase, map[string]struct{}) {
	out := make([]ContractCase, 0, len(items))
	removed := make(map[string]struct{})
	for _, item := range items {
		if item.CohortID == "go" && item.ModeID == "binary" && item.Fixture != nil && item.Fixture.ID == "go-binary-input" {
			removed[item.ID] = struct{}{}
			continue
		}
		out = append(out, item)
	}
	return out, removed
}
func removeOracleCases(items []OracleCase, removed map[string]struct{}) []OracleCase {
	out := make([]OracleCase, 0, len(items))
	for _, item := range items {
		if _, exists := removed[item.CaseID]; exists {
			continue
		}
		out = append(out, item)
	}
	return out
}

func goBinaryVersionedFixtures(legacy FixtureManifest) (FixtureManifest, fs.FS, error) {
	root, err := fs.Sub(successorProfileFiles, "successor")
	if err != nil {
		return FixtureManifest{}, nil, err
	}
	manifest := legacy
	manifest.ID = "synapse-ce-reachability-go-binary-versioned-fixtures"
	manifest.Fixtures = make([]FixtureSpecification, 0, len(legacy.Fixtures)+4)
	for _, fixture := range legacy.Fixtures {
		if fixture.ID != "go-binary-input" {
			manifest.Fixtures = append(manifest.Fixtures, fixture)
		}
	}
	for _, item := range []struct {
		id, source string
		line       int
	}{{"go-binary-versioned-direct-call", "go_binary_versioned/direct.go.txt", 8}, {"go-binary-versioned-retained-but-uncalled", "go_binary_versioned/retained.go.txt", 14}, {"go-binary-versioned-retained-and-called", "go_binary_versioned/retained_called.go.txt", 15}, {"go-binary-versioned-indirect-function-value-call", "go_binary_versioned/indirect.go.txt", 11}} {
		fixture, err := versionedGoFixture(root, item.id, item.source, item.line)
		if err != nil {
			return FixtureManifest{}, nil, err
		}
		manifest.Fixtures = append(manifest.Fixtures, fixture)
	}
	empty, err := emptyGoBinaryFixture(root)
	if err != nil {
		return FixtureManifest{}, nil, err
	}
	manifest.Fixtures = append(manifest.Fixtures, empty)
	manifest = canonicalFixtureManifest(manifest)
	if err := manifest.Validate(); err != nil {
		return FixtureManifest{}, nil, err
	}
	return manifest, root, nil
}

func versionedGoFixture(root fs.FS, id, source string, line int) (FixtureSpecification, error) {
	files := []FixtureFile{}
	for _, item := range []struct{ path, materialized string }{{source, "main.go"}, {"go_binary_versioned/go.mod.txt", "go.mod"}, {"go_binary_versioned/go.sum", "go.sum"}} {
		file, err := embeddedFixtureFile(root, item.path, item.materialized)
		if err != nil {
			return FixtureSpecification{}, err
		}
		files = append(files, file)
	}
	vendor, err := versionedGoVendorFiles(root)
	if err != nil {
		return FixtureSpecification{}, err
	}
	files = append(files, vendor...)
	return FixtureSpecification{SchemaVersion: FixtureManifestSchemaVersion, ID: id, Files: files, Entries: []FixtureEntry{{Role: FixtureEntrySource, Path: source}, {Role: FixtureEntryManifest, Path: "go_binary_versioned/go.mod.txt"}, {Role: FixtureEntryLockfile, Path: "go_binary_versioned/go.sum"}}, Subjects: []FixtureSubject{{ID: "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", PackageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", Locator: FixtureLocator{Kind: FixtureLocatorPackageDependency, ModulePath: "main.go", Symbol: "idna.ToASCII", Line: line}}}, Build: &FixtureBuild{Kind: FixtureBuildGoBinary, Toolchain: FixtureToolchainRequirement{Family: "go", Version: "1.27.0", TargetPlatform: "linux/amd64", Resolution: FixtureToolchainMaterializerRequired}, TargetPlatform: "linux/amd64", WorkingDirectory: ".", Steps: []FixtureBuildStep{{Argv: []string{"go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-o", "./generated/app", "."}}}, Constraints: FixtureBuildConstraints{Network: "disabled", DependencyResolution: "offline", InheritedConfig: false}, Outputs: []FixtureOutput{{Path: "generated/app", Format: "elf", SemanticIdentity: "go-binary-versioned-idna", Materialization: "materializer_required"}}}, Provenance: FixtureProvenance{Kind: FixtureRepositoryAuthored, Description: "pending independent review versioned Go binary diagnostic fixture"}}, nil
}

func versionedGoVendorFiles(root fs.FS) ([]FixtureFile, error) {
	const vendorRoot = "go_binary_versioned/vendor"
	files := make([]FixtureFile, 0, 30)
	err := fs.WalkDir(root, vendorRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("vendor fixture path %q is not a regular file", path)
		}
		materialized := path[len("go_binary_versioned/"):]
		file, err := embeddedFixtureFile(root, path, materialized)
		if err != nil {
			return err
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read versioned Go vendor fixture: %w", err)
	}
	if len(files) != 30 {
		return nil, fmt.Errorf("versioned Go vendor fixture has %d files, want 30", len(files))
	}
	return files, nil
}

func emptyGoBinaryFixture(root fs.FS) (FixtureSpecification, error) {
	file, err := embeddedFixtureFile(root, "go_binary_versioned/empty-root.txt", "empty-root.txt")
	if err != nil {
		return FixtureSpecification{}, err
	}
	return FixtureSpecification{SchemaVersion: FixtureManifestSchemaVersion, ID: "go-binary-versioned-empty-root-unavailable", Files: []FixtureFile{file}, Entries: []FixtureEntry{{Role: FixtureEntryManifest, Path: file.Path}}, Subjects: []FixtureSubject{{ID: "pkg:golang/golang.org/x/net@v0.59.0#idna.ToASCII", PackageIdentity: "pkg:golang/golang.org/x/net@v0.59.0", Locator: FixtureLocator{Kind: FixtureLocatorPackageDependency, ModulePath: "empty-root.txt", Symbol: "idna.ToASCII", Line: 1}}}, Provenance: FixtureProvenance{Kind: FixtureRepositoryAuthored, Description: "pending independent review empty materialization-root control"}}, nil
}

func embeddedFixtureFile(root fs.FS, path, materialized string) (FixtureFile, error) {
	raw, err := fs.ReadFile(root, path)
	if err != nil {
		return FixtureFile{}, err
	}
	return FixtureFile{Path: path, MaterializedPath: materialized, Size: int64(len(raw)), Digest: benchmark.SHA256Digest(raw)}, nil
}

func readProfileFixtureFile(profile ReachabilityProfile, file FixtureFile) ([]byte, error) {
	if !profileDeclaresFile(profile, file) {
		return nil, fmt.Errorf("fixture file %q is not declared by profile %q", file.Path, profile.ID)
	}
	if profile.ID == goBinaryVersionedProfileID {
		legacy, err := DefaultReachabilityProfile()
		if err != nil {
			return nil, err
		}
		if profileDeclaresFile(legacy, file) {
			return ReadFixtureFile(file)
		}
	}
	if profile.fixtureFS == nil {
		return ReadFixtureFile(file)
	}
	return readFixtureFile(profile.fixtureFS, file)
}

func profileDeclaresFile(profile ReachabilityProfile, file FixtureFile) bool {
	for _, fixture := range profile.Fixtures.Fixtures {
		for _, candidate := range fixture.Files {
			if sameFixtureFile(candidate, file) {
				return true
			}
		}
	}
	return false
}
func sameProfileFile(left, right ReachabilityProfile, file FixtureFile) bool {
	return profileDeclaresFile(left, file) && profileDeclaresFile(right, file)
}
func sameFixtureSpecification(left, right FixtureSpecification) bool {
	left = canonicalFixtureSpecification(left)
	right = canonicalFixtureSpecification(right)
	encodedLeft, err := benchmark.CanonicalJSON(left)
	if err != nil {
		return false
	}
	encodedRight, err := benchmark.CanonicalJSON(right)
	return err == nil && string(encodedLeft) == string(encodedRight)
}

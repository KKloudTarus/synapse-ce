package reachbench

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

const (
	ChallengeManifestSchemaVersion = "synapse-reachability-challenge-manifest-v2"
	FixtureManifestSchemaVersion   = "synapse-reachability-fixture-manifest-v2"

	maxFixtureDocumentBytes int64 = 1 << 20
	maxFixtureFileCount           = 256
	maxFixtureFileBytes     int64 = 1 << 20
	maxFixtureTotalBytes    int64 = 8 << 20
	maxFixtureBuildSteps          = 8
	maxFixtureBuildEnv            = 16
)

// ChallengeKind identifies a predeclared positive case that is not a cohort control.
type ChallengeKind string

const (
	ChallengeGoBinaryPCLNTABCall        ChallengeKind = "go_binary_pclntab_entry_call"
	ChallengeJavaScriptFunctionAlias    ChallengeKind = "javascript_function_alias"
	ChallengeJavaScriptSyncCallback     ChallengeKind = "javascript_synchronous_callback"
	ChallengeJavaScriptReturnedCallable ChallengeKind = "javascript_returned_callable"
	ChallengeJavaScriptCrossModuleCall  ChallengeKind = "javascript_cross_module_call"
	ChallengePHPSymbolProvenance        ChallengeKind = "php_symbol_provenance"
	ChallengeRubySymbolProvenance       ChallengeKind = "ruby_symbol_provenance"
)

func (kind ChallengeKind) valid() bool {
	switch kind {
	case ChallengeGoBinaryPCLNTABCall, ChallengeJavaScriptFunctionAlias, ChallengeJavaScriptSyncCallback,
		ChallengeJavaScriptReturnedCallable, ChallengeJavaScriptCrossModuleCall, ChallengePHPSymbolProvenance,
		ChallengeRubySymbolProvenance:
		return true
	default:
		return false
	}
}

// ChallengeDeclaration describes one independently established reachable challenge.
type ChallengeDeclaration struct {
	CaseID     string        `json:"case_id"`
	CohortID   string        `json:"cohort_id"`
	ModeID     string        `json:"mode_id"`
	Kind       ChallengeKind `json:"kind"`
	ModulePath string        `json:"module_path,omitempty"`
	Line       int           `json:"line,omitempty"`
}

// ChallengeManifest is static contract data; it carries no lifecycle or observation state.
type ChallengeManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	ID            string                 `json:"id"`
	Challenges    []ChallengeDeclaration `json:"challenges"`
}

// FixtureProvenanceKind identifies the honest origin class of a fixture specification.
// It deliberately does not assert a digest for a source revision or a future materialization.
type FixtureProvenanceKind string

const (
	FixtureRepositoryAuthored            FixtureProvenanceKind = "repository_authored"
	FixtureDeterministicReplay           FixtureProvenanceKind = "deterministic_replay"
	FixtureGeneratedFromRepositoryInputs FixtureProvenanceKind = "generated_from_repository_inputs"
)

func (kind FixtureProvenanceKind) valid() bool {
	switch kind {
	case FixtureRepositoryAuthored, FixtureDeterministicReplay, FixtureGeneratedFromRepositoryInputs:
		return true
	default:
		return false
	}
}

// FixtureFile is one package-owned input, pinned by raw bytes as well as byte length.
type FixtureFile struct {
	Path             string `json:"path"`
	MaterializedPath string `json:"materialized_path,omitempty"`
	Size             int64  `json:"size"`
	Digest           string `json:"digest"`
}

// FixtureEntryRole identifies a material entrypoint. It is deliberately smaller than a build language.
type FixtureEntryRole string

const (
	FixtureEntrySource          FixtureEntryRole = "source"
	FixtureEntryManifest        FixtureEntryRole = "manifest"
	FixtureEntryLockfile        FixtureEntryRole = "lockfile"
	FixtureEntryReplay          FixtureEntryRole = "replay"
	FixtureEntryOwnership       FixtureEntryRole = "ownership"
	FixtureEntryRestoreMetadata FixtureEntryRole = "restore_metadata"
)

func (role FixtureEntryRole) valid() bool {
	switch role {
	case FixtureEntrySource, FixtureEntryManifest, FixtureEntryLockfile, FixtureEntryReplay, FixtureEntryOwnership, FixtureEntryRestoreMetadata:
		return true
	default:
		return false
	}
}

// FixtureEntry assigns an explicit role to one material input.
type FixtureEntry struct {
	Role FixtureEntryRole `json:"role"`
	Path string           `json:"path"`
}

// FixtureLocatorKind describes how an adapter resolves the subject without consulting an oracle.
type FixtureLocatorKind string

const (
	FixtureLocatorSourceSymbol       FixtureLocatorKind = "source_symbol"
	FixtureLocatorPackageDependency  FixtureLocatorKind = "package_dependency"
	FixtureLocatorManifestCapability FixtureLocatorKind = "manifest_capability"
	FixtureLocatorRuntimeObservation FixtureLocatorKind = "runtime_observation"
	FixtureLocatorGeneratedSymbol    FixtureLocatorKind = "generated_symbol"
)

func (kind FixtureLocatorKind) valid() bool {
	switch kind {
	case FixtureLocatorSourceSymbol, FixtureLocatorPackageDependency, FixtureLocatorManifestCapability, FixtureLocatorRuntimeObservation, FixtureLocatorGeneratedSymbol:
		return true
	default:
		return false
	}
}

// FixtureLocator is a closed, logical subject location. Its paths are package-relative data, never host paths.
type FixtureLocator struct {
	Kind       FixtureLocatorKind `json:"kind"`
	ModulePath string             `json:"module_path"`
	Symbol     string             `json:"symbol"`
	Line       int                `json:"line"`
}

// FixtureSubject binds the immutable public subject identity to its package and locator.
type FixtureSubject struct {
	ID              string         `json:"id"`
	PackageIdentity string         `json:"package_identity"`
	Locator         FixtureLocator `json:"locator"`
}

// FixtureBuildKind remains closed to the generated fixture families currently exercised by production adapters.
type FixtureBuildKind string

const (
	FixtureBuildGoBinary      FixtureBuildKind = "go_binary"
	FixtureBuildDotNetPublish FixtureBuildKind = "dotnet_publish"
	FixtureBuildJVMPackage    FixtureBuildKind = "jvm_package"
)

func (kind FixtureBuildKind) valid() bool {
	switch kind {
	case FixtureBuildGoBinary, FixtureBuildDotNetPublish, FixtureBuildJVMPackage:
		return true
	default:
		return false
	}
}

// FixtureBuildStep is an argv-only tool invocation. It never carries a shell command or script path.
type FixtureBuildStep struct {
	Argv []string `json:"argv"`
}

// FixtureBuildEnv is a bounded deterministic environment input.
type FixtureBuildEnv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FixtureOutput describes one required materialized output. Final bytes are verified by the controlled materializer.
type FixtureOutput struct {
	Path             string `json:"path"`
	Format           string `json:"format"`
	SemanticIdentity string `json:"semantic_identity"`
	Materialization  string `json:"materialization"`
}

// FixtureBuildConstraints pin the build isolation required to avoid ambient inputs.
type FixtureBuildConstraints struct {
	Network              string `json:"network"`
	DependencyResolution string `json:"dependency_resolution"`
	InheritedConfig      bool   `json:"inherited_config"`
}

// FixtureToolchainResolution describes how task-owned materialization will obtain a toolchain.
type FixtureToolchainResolution string

const (
	FixtureToolchainControllerPinned     FixtureToolchainResolution = "controller_pinned"
	FixtureToolchainMaterializerRequired FixtureToolchainResolution = "materializer_required"
)

func (resolution FixtureToolchainResolution) valid() bool {
	switch resolution {
	case FixtureToolchainControllerPinned, FixtureToolchainMaterializerRequired:
		return true
	default:
		return false
	}
}

// FixtureToolchainRequirement is an exact requirement, not an invented content address for an unavailable toolchain.
type FixtureToolchainRequirement struct {
	Family         string                     `json:"family"`
	Version        string                     `json:"version"`
	TargetPlatform string                     `json:"target_platform"`
	Resolution     FixtureToolchainResolution `json:"resolution"`
}

// FixtureBuild is a narrow materialization recipe for generated Go, .NET, and JVM inputs.
type FixtureBuild struct {
	Kind             FixtureBuildKind            `json:"kind"`
	Toolchain        FixtureToolchainRequirement `json:"toolchain"`
	TargetPlatform   string                      `json:"target_platform"`
	WorkingDirectory string                      `json:"working_directory"`
	Steps            []FixtureBuildStep          `json:"steps"`
	Env              []FixtureBuildEnv           `json:"env,omitempty"`
	Constraints      FixtureBuildConstraints     `json:"constraints"`
	Outputs          []FixtureOutput             `json:"outputs"`
}

// FixtureProvenance records the origin class and optional human-readable, non-artifact context.
type FixtureProvenance struct {
	Kind             FixtureProvenanceKind `json:"kind"`
	Description      string                `json:"description,omitempty"`
	StartingRevision string                `json:"starting_revision,omitempty"`
}

// FixtureSpecification is the complete canonical fixture input. It intentionally has no digest field: the
// computed digest is the identity used by ContractCase.Fixture.
type FixtureSpecification struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Files         []FixtureFile     `json:"files"`
	Entries       []FixtureEntry    `json:"entries"`
	Subjects      []FixtureSubject  `json:"subjects"`
	Build         *FixtureBuild     `json:"build,omitempty"`
	Provenance    FixtureProvenance `json:"provenance"`
}

// FixtureManifest is the closed catalog of package-owned benchmark inputs.
type FixtureManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	ID            string                 `json:"id"`
	Fixtures      []FixtureSpecification `json:"fixtures"`
}

// ResolvedFixtureSubject is an adapter-facing fixture/subject resolution that carries no oracle decision.
type ResolvedFixtureSubject struct {
	Specification FixtureSpecification
	Subject       FixtureSubject
}

// ReachabilityBenchmark is the static production corpus/oracle contract. It does not own execution lifecycle state.
type ReachabilityBenchmark struct {
	Corpus     ContractCorpus     `json:"corpus"`
	Oracle     ReachabilityOracle `json:"oracle"`
	Challenges ChallengeManifest  `json:"challenges"`
	Fixtures   FixtureManifest    `json:"fixtures"`
}

//go:embed all:contract
var reachabilityBenchmarkFiles embed.FS

const (
	benchmarkAssetRoot       = "contract"
	benchmarkCorpusAsset     = "corpus.json"
	benchmarkOracleAsset     = "oracle.json"
	benchmarkChallengesAsset = "challenges.json"
	benchmarkFixturesAsset   = "fixtures.json"
)

// DefaultReachabilityBenchmark returns the checked-in static benchmark contract. It is deliberately separate
// from DefaultCorpus, which remains the legacy comparator corpus.
func DefaultReachabilityBenchmark() ReachabilityBenchmark {
	contract, err := LoadReachabilityBenchmark()
	if err != nil {
		panic("reachbench: embedded benchmark contract is invalid: " + err.Error())
	}
	return contract
}

// LoadReachabilityBenchmark reads only the package-owned embedded asset tree and verifies every physical input.
func LoadReachabilityBenchmark() (ReachabilityBenchmark, error) {
	root, err := fs.Sub(reachabilityBenchmarkFiles, benchmarkAssetRoot)
	if err != nil {
		return ReachabilityBenchmark{}, fmt.Errorf("open reachability benchmark assets: %w", err)
	}
	return loadReachabilityBenchmark(root)
}

func loadReachabilityBenchmark(root fs.FS) (ReachabilityBenchmark, error) {
	corpus, err := loadBenchmarkCorpusFile(root, benchmarkCorpusAsset)
	if err != nil {
		return ReachabilityBenchmark{}, err
	}
	oracle, err := loadBenchmarkOracleFile(root, benchmarkOracleAsset)
	if err != nil {
		return ReachabilityBenchmark{}, err
	}
	challenges, err := loadChallengeManifestFile(root, benchmarkChallengesAsset)
	if err != nil {
		return ReachabilityBenchmark{}, err
	}
	fixtures, err := loadFixtureManifestFile(root, benchmarkFixturesAsset)
	if err != nil {
		return ReachabilityBenchmark{}, err
	}
	if err := validateFixtureFiles(root, fixtures); err != nil {
		return ReachabilityBenchmark{}, err
	}
	contract := ReachabilityBenchmark{Corpus: corpus, Oracle: oracle, Challenges: challenges, Fixtures: fixtures}
	if err := contract.Validate(); err != nil {
		return ReachabilityBenchmark{}, err
	}
	return canonicalReachabilityBenchmark(contract), nil
}

// LoadBenchmarkCorpus strictly decodes the static corpus without changing the legacy DefaultCorpus API.
func LoadBenchmarkCorpus(reader io.Reader) (ContractCorpus, error) {
	raw, err := readFixtureReader(reader)
	if err != nil {
		return ContractCorpus{}, fmt.Errorf("read benchmark corpus: %w", err)
	}
	var corpus ContractCorpus
	if err := benchmark.StrictDecode(bytes.NewReader(raw), &corpus); err != nil {
		return ContractCorpus{}, fmt.Errorf("decode benchmark corpus: %w", err)
	}
	if err := corpus.Validate(); err != nil {
		return ContractCorpus{}, err
	}
	return canonicalCorpus(corpus), nil
}

// LoadBenchmarkOracle strictly decodes the static oracle without changing legacy scoring behavior.
func LoadBenchmarkOracle(reader io.Reader) (ReachabilityOracle, error) {
	raw, err := readFixtureReader(reader)
	if err != nil {
		return ReachabilityOracle{}, fmt.Errorf("read benchmark oracle: %w", err)
	}
	var oracle ReachabilityOracle
	if err := benchmark.StrictDecode(bytes.NewReader(raw), &oracle); err != nil {
		return ReachabilityOracle{}, fmt.Errorf("decode benchmark oracle: %w", err)
	}
	if err := oracle.Validate(); err != nil {
		return ReachabilityOracle{}, err
	}
	return canonicalOracle(oracle), nil
}

// LoadChallengeManifest strictly decodes the positive challenge declaration.
func LoadChallengeManifest(reader io.Reader) (ChallengeManifest, error) {
	raw, err := readFixtureReader(reader)
	if err != nil {
		return ChallengeManifest{}, fmt.Errorf("read reachability challenge manifest: %w", err)
	}
	var manifest ChallengeManifest
	if err := benchmark.StrictDecode(bytes.NewReader(raw), &manifest); err != nil {
		return ChallengeManifest{}, fmt.Errorf("decode reachability challenge manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return ChallengeManifest{}, err
	}
	return canonicalChallengeManifest(manifest), nil
}

// LoadFixtureManifest strictly decodes complete fixture specifications.
func LoadFixtureManifest(reader io.Reader) (FixtureManifest, error) {
	raw, err := readFixtureReader(reader)
	if err != nil {
		return FixtureManifest{}, fmt.Errorf("read reachability fixture manifest: %w", err)
	}
	var manifest FixtureManifest
	if err := benchmark.StrictDecode(bytes.NewReader(raw), &manifest); err != nil {
		return FixtureManifest{}, fmt.Errorf("decode reachability fixture manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return FixtureManifest{}, err
	}
	return canonicalFixtureManifest(manifest), nil
}

func loadBenchmarkCorpusFile(root fs.FS, path string) (ContractCorpus, error) {
	raw, err := readFixtureDocument(root, path)
	if err != nil {
		return ContractCorpus{}, fmt.Errorf("read benchmark corpus: %w", err)
	}
	return LoadBenchmarkCorpus(bytes.NewReader(raw))
}

func loadBenchmarkOracleFile(root fs.FS, path string) (ReachabilityOracle, error) {
	raw, err := readFixtureDocument(root, path)
	if err != nil {
		return ReachabilityOracle{}, fmt.Errorf("read benchmark oracle: %w", err)
	}
	return LoadBenchmarkOracle(bytes.NewReader(raw))
}

func loadChallengeManifestFile(root fs.FS, path string) (ChallengeManifest, error) {
	raw, err := readFixtureDocument(root, path)
	if err != nil {
		return ChallengeManifest{}, fmt.Errorf("read reachability challenge manifest: %w", err)
	}
	return LoadChallengeManifest(bytes.NewReader(raw))
}

func loadFixtureManifestFile(root fs.FS, path string) (FixtureManifest, error) {
	raw, err := readFixtureDocument(root, path)
	if err != nil {
		return FixtureManifest{}, fmt.Errorf("read reachability fixture manifest: %w", err)
	}
	return LoadFixtureManifest(bytes.NewReader(raw))
}

func readFixtureDocument(root fs.FS, path string) ([]byte, error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := readFixtureReader(file)
	if err != nil {
		return nil, fmt.Errorf("document %q: %w", path, err)
	}
	return raw, nil
}

func readFixtureReader(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxFixtureDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxFixtureDocumentBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", maxFixtureDocumentBytes)
	}
	return raw, nil
}

func (manifest ChallengeManifest) Validate() error {
	if manifest.SchemaVersion != ChallengeManifestSchemaVersion || !validID(manifest.ID) {
		return fmt.Errorf("invalid reachability challenge manifest")
	}
	if len(manifest.Challenges) != len(requiredChallenges) {
		return fmt.Errorf("reachability challenge manifest requires exactly %d challenges", len(requiredChallenges))
	}
	seen := make(map[string]struct{}, len(manifest.Challenges))
	for _, challenge := range manifest.Challenges {
		if !validID(challenge.CaseID) || !validID(challenge.CohortID) || !validID(challenge.ModeID) || !challenge.Kind.valid() {
			return fmt.Errorf("reachability challenge manifest has invalid challenge %q", challenge.CaseID)
		}
		if _, duplicate := seen[challenge.CaseID]; duplicate {
			return fmt.Errorf("duplicate reachability challenge %q", challenge.CaseID)
		}
		seen[challenge.CaseID] = struct{}{}
		if requiresSymbolProvenance(challenge.Kind) {
			if !validFixturePath(challenge.ModulePath) || challenge.Line <= 0 {
				return fmt.Errorf("reachability challenge %q requires module and line provenance", challenge.CaseID)
			}
		} else if challenge.ModulePath != "" || challenge.Line != 0 {
			return fmt.Errorf("reachability challenge %q has unexpected module or line provenance", challenge.CaseID)
		}
		required, ok := requiredChallenges[challenge.CaseID]
		if !ok || !sameChallenge(challenge, required) {
			return fmt.Errorf("unknown or changed reachability challenge %q", challenge.CaseID)
		}
	}
	return nil
}

func (manifest FixtureManifest) Validate() error {
	if manifest.SchemaVersion != FixtureManifestSchemaVersion || !validID(manifest.ID) || len(manifest.Fixtures) == 0 || len(manifest.Fixtures) > maxFixtureFileCount {
		return fmt.Errorf("invalid reachability fixture manifest")
	}
	seen := make(map[string]struct{}, len(manifest.Fixtures))
	declaredFiles := make(map[string]FixtureFile, len(manifest.Fixtures)*4)
	for _, fixture := range manifest.Fixtures {
		if !validID(fixture.ID) {
			return fmt.Errorf("invalid reachability fixture %q", fixture.ID)
		}
		if _, duplicate := seen[fixture.ID]; duplicate {
			return fmt.Errorf("duplicate reachability fixture %q", fixture.ID)
		}
		seen[fixture.ID] = struct{}{}
		if err := fixture.validate(); err != nil {
			return fmt.Errorf("fixture %q: %w", fixture.ID, err)
		}
		for _, file := range fixture.Files {
			if existing, duplicate := declaredFiles[file.Path]; duplicate && !sameFixtureFile(existing, file) {
				return fmt.Errorf("fixture %q has conflicting declaration for physical path %q", fixture.ID, file.Path)
			}
			declaredFiles[file.Path] = file
		}
	}
	return validateFixturePathSet(keysOf(declaredFiles))
}

func (fixture FixtureSpecification) validate() error {
	if fixture.SchemaVersion != FixtureManifestSchemaVersion || len(fixture.Files) == 0 || len(fixture.Files) > maxFixtureFileCount || len(fixture.Entries) == 0 || len(fixture.Subjects) == 0 {
		return fmt.Errorf("incomplete fixture specification")
	}
	if err := fixture.Provenance.validate(fixture.ID); err != nil {
		return err
	}
	paths := make(map[string]struct{}, len(fixture.Files))
	materializedPaths := make(map[string]struct{}, len(fixture.Files))
	for _, file := range fixture.Files {
		if err := file.validate("fixture file"); err != nil {
			return err
		}
		if _, duplicate := paths[file.Path]; duplicate {
			return fmt.Errorf("duplicates file %q", file.Path)
		}
		paths[file.Path] = struct{}{}
		materializedPath := file.Path
		if file.MaterializedPath != "" {
			materializedPath = file.MaterializedPath
		}
		if _, duplicate := materializedPaths[materializedPath]; duplicate {
			return fmt.Errorf("duplicates materialized file %q", materializedPath)
		}
		materializedPaths[materializedPath] = struct{}{}
	}
	if err := validateFixturePathSet(keysOf(paths)); err != nil {
		return err
	}
	if err := validateFixturePathSet(keysOf(materializedPaths)); err != nil {
		return fmt.Errorf("materialized fixture paths: %w", err)
	}
	roles := make(map[FixtureEntryRole]struct{}, len(fixture.Entries))
	entryPaths := make(map[string]struct{}, len(fixture.Entries))
	for _, entry := range fixture.Entries {
		if !entry.Role.valid() || !validFixturePath(entry.Path) {
			return fmt.Errorf("has unknown entry role or unsafe entry path")
		}
		if _, known := paths[entry.Path]; !known {
			return fmt.Errorf("entry %q references undeclared file", entry.Path)
		}
		if _, duplicate := roles[entry.Role]; duplicate {
			return fmt.Errorf("duplicates entry role %q", entry.Role)
		}
		if _, duplicate := entryPaths[entry.Path]; duplicate {
			return fmt.Errorf("duplicates entry path %q", entry.Path)
		}
		roles[entry.Role] = struct{}{}
		entryPaths[entry.Path] = struct{}{}
	}
	subjects := make(map[string]struct{}, len(fixture.Subjects))
	for _, subject := range fixture.Subjects {
		if !validSubjectID(subject.ID) || !validPackageIdentity(subject.PackageIdentity) || !subject.Locator.Kind.valid() || !validFixturePath(subject.Locator.ModulePath) || !validLocatorSymbol(subject.Locator.Symbol) || subject.Locator.Line <= 0 {
			return fmt.Errorf("has invalid subject locator")
		}
		if _, known := paths[subject.Locator.ModulePath]; !known {
			if _, materialized := materializedPaths[subject.Locator.ModulePath]; !materialized && (fixture.Build == nil || !fixtureOutputPath(fixture.Build, subject.Locator.ModulePath)) {
				return fmt.Errorf("subject %q references undeclared module %q", subject.ID, subject.Locator.ModulePath)
			}
		}
		if _, duplicate := subjects[subject.ID]; duplicate {
			return fmt.Errorf("duplicates subject %q", subject.ID)
		}
		subjects[subject.ID] = struct{}{}
	}
	if fixture.Build != nil {
		for path := range materializedPaths {
			paths[path] = struct{}{}
		}
		if err := fixture.Build.validate(fixture.ID, paths); err != nil {
			return err
		}
	}
	return nil
}

func (provenance FixtureProvenance) validate(fixtureID string) error {
	if !provenance.Kind.valid() || !validFixtureProvenanceText(provenance.Description) || !validFixtureRevision(provenance.StartingRevision) {
		return fmt.Errorf("fixture %q has invalid provenance", fixtureID)
	}
	return nil
}

func (requirement FixtureToolchainRequirement) validate(kind FixtureBuildKind, targetPlatform string) error {
	if !validID(requirement.Family) || !validToolchainVersion(requirement.Version) || !validTargetPlatform(requirement.TargetPlatform) || requirement.TargetPlatform != targetPlatform || !requirement.Resolution.valid() {
		return fmt.Errorf("has invalid toolchain requirement")
	}
	if requirement.Family != fixtureToolchainFamily(kind) {
		return fmt.Errorf("has unexpected toolchain family %q", requirement.Family)
	}
	return nil
}

func (build FixtureBuild) validate(fixtureID string, inputPaths map[string]struct{}) error {
	if !build.Kind.valid() || build.WorkingDirectory != "." || !validTargetPlatform(build.TargetPlatform) || len(build.Steps) == 0 || len(build.Steps) > maxFixtureBuildSteps || len(build.Env) > maxFixtureBuildEnv {
		return fmt.Errorf("has invalid build declaration")
	}
	if err := build.Toolchain.validate(build.Kind, build.TargetPlatform); err != nil {
		return err
	}
	if build.Constraints.Network != "disabled" || build.Constraints.DependencyResolution != "offline" || build.Constraints.InheritedConfig {
		return fmt.Errorf("has ambient build inputs")
	}
	seenEnv := map[string]struct{}{}
	for _, env := range build.Env {
		if !validBuildEnvKey(env.Key) || env.Value != strings.TrimSpace(env.Value) || len(env.Value) > 512 {
			return fmt.Errorf("has invalid build environment")
		}
		if _, duplicate := seenEnv[env.Key]; duplicate {
			return fmt.Errorf("duplicates build environment %q", env.Key)
		}
		seenEnv[env.Key] = struct{}{}
	}
	expectedCommands := fixtureBuildCommands(fixtureID, build.Kind)
	if len(build.Steps) != len(expectedCommands) {
		return fmt.Errorf("has incomplete ordered build recipe")
	}
	for index, step := range build.Steps {
		if len(step.Argv) == 0 || len(step.Argv) > 16 {
			return fmt.Errorf("has invalid build step")
		}
		if step.Argv[0] != expectedCommands[index] {
			return fmt.Errorf("has unexpected build command %q", step.Argv[0])
		}
		for _, arg := range step.Argv {
			if !validBuildArg(arg) {
				return fmt.Errorf("has shell-like build step")
			}
			if strings.HasPrefix(arg, "fixtures/") || strings.HasPrefix(arg, "generated/") {
				return fmt.Errorf("has non-root-relative build path %q", arg)
			}
		}
	}
	if len(build.Outputs) == 0 {
		return fmt.Errorf("requires generated output declaration")
	}
	outputs := map[string]struct{}{}
	for _, output := range build.Outputs {
		if !validFixturePath(output.Path) || !validID(output.Format) || !validID(output.SemanticIdentity) || output.Materialization != "materializer_required" {
			return fmt.Errorf("has invalid generated output declaration")
		}
		if _, collision := inputPaths[output.Path]; collision || pathOverlapsAny(output.Path, keysOf(inputPaths)) {
			return fmt.Errorf("generated output overwrites input %q", output.Path)
		}
		if _, duplicate := outputs[output.Path]; duplicate {
			return fmt.Errorf("duplicates generated output %q", output.Path)
		}
		outputs[output.Path] = struct{}{}
	}
	if err := validateFixturePathSet(keysOf(outputs)); err != nil {
		return fmt.Errorf("generated output paths: %w", err)
	}
	return nil
}

func fixtureToolchainFamily(kind FixtureBuildKind) string {
	switch kind {
	case FixtureBuildGoBinary:
		return "go"
	case FixtureBuildDotNetPublish:
		return "dotnet-sdk"
	case FixtureBuildJVMPackage:
		return "openjdk"
	default:
		return ""
	}
}

func fixtureBuildCommands(fixtureID string, kind FixtureBuildKind) []string {
	switch fixtureID {
	case "go-binary-input":
		if kind == FixtureBuildGoBinary {
			return []string{"go"}
		}
	case "dotnet-build-aware-import-input":
		if kind == FixtureBuildDotNetPublish {
			return []string{"dotnet", "dotnet", "dotnet", "dotnet"}
		}
	case "dotnet-symbols-tier2-input":
		if kind == FixtureBuildDotNetPublish {
			return []string{"dotnet", "dotnet"}
		}
	case "jvm-coarse-input", "jvm-tier2-input":
		if kind == FixtureBuildJVMPackage {
			return []string{"javac", "jar", "javac", "jar", "javac", "jar", "javac"}
		}
	}
	return nil
}

func (file FixtureFile) validate(name string) error {
	if !validFixturePath(file.Path) || (file.MaterializedPath != "" && (!validFixturePath(file.MaterializedPath) || file.MaterializedPath == file.Path)) || file.Size < 0 || file.Size > maxFixtureFileBytes || !validDigest(file.Digest) {
		return fmt.Errorf("%s requires a safe path, bounded size, and sha256 digest", name)
	}
	return nil
}

func sameFixtureFile(left, right FixtureFile) bool {
	return left.Path == right.Path && left.MaterializedPath == right.MaterializedPath && left.Size == right.Size && left.Digest == right.Digest
}

// ResolveFixtureSubject resolves a corpus-facing fixture reference and subject without loading or exposing the oracle.
func (manifest FixtureManifest) ResolveFixtureSubject(reference ArtifactReference, subjectID string) (ResolvedFixtureSubject, error) {
	if err := reference.validate("fixture reference"); err != nil || !validSubjectID(subjectID) {
		return ResolvedFixtureSubject{}, fmt.Errorf("invalid fixture subject reference")
	}
	for _, specification := range manifest.Fixtures {
		if specification.ID != reference.ID {
			continue
		}
		digest, err := DigestFixtureSpecification(specification)
		if err != nil {
			return ResolvedFixtureSubject{}, err
		}
		if digest != reference.Digest {
			return ResolvedFixtureSubject{}, fmt.Errorf("fixture reference digest mismatch for %q", reference.ID)
		}
		for _, subject := range specification.Subjects {
			if subject.ID == subjectID {
				return ResolvedFixtureSubject{Specification: specification, Subject: subject}, nil
			}
		}
		return ResolvedFixtureSubject{}, fmt.Errorf("fixture %q does not declare subject %q", reference.ID, subjectID)
	}
	return ResolvedFixtureSubject{}, fmt.Errorf("unknown fixture %q", reference.ID)
}

func (contract ReachabilityBenchmark) Validate() error {
	if err := contract.Corpus.Validate(); err != nil {
		return err
	}
	if err := contract.Oracle.ValidateAgainst(contract.Corpus); err != nil {
		return err
	}
	if err := contract.Challenges.Validate(); err != nil {
		return err
	}
	if err := contract.Fixtures.Validate(); err != nil {
		return err
	}
	if err := validateBenchmarkShape(contract); err != nil {
		return err
	}
	root, err := fs.Sub(reachabilityBenchmarkFiles, benchmarkAssetRoot)
	if err != nil {
		return fmt.Errorf("open runtime fixture corpus: %w", err)
	}
	return validateRuntimeReplayContract(root, contract)
}

func validateBenchmarkShape(contract ReachabilityBenchmark) error {
	inventory := DefaultProductionInventory()
	expectedCounts := requiredCohortCaseCounts()
	inventoryKeys := make(map[string]struct{}, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		if !cohort.BenchmarkRequired {
			continue
		}
		key := cohortKey(cohort.ID, cohort.Mode)
		if _, declared := expectedCounts[key]; !declared {
			return fmt.Errorf("benchmark cohort contract omits production cohort %q", key)
		}
		inventoryKeys[key] = struct{}{}
	}
	if len(expectedCounts) != len(inventoryKeys) {
		return fmt.Errorf("benchmark cohort contract and production inventory differ")
	}
	fixtures := make(map[string]FixtureSpecification, len(contract.Fixtures.Fixtures))
	for _, fixture := range contract.Fixtures.Fixtures {
		fixtures[fixture.ID] = fixture
	}
	oracleByCase := make(map[string]OracleCase, len(contract.Oracle.Cases))
	for _, oracle := range contract.Oracle.Cases {
		oracleByCase[oracle.CaseID] = oracle
	}
	challenges := make(map[string]ChallengeDeclaration, len(contract.Challenges.Challenges))
	for _, challenge := range contract.Challenges.Challenges {
		challenges[challenge.CaseID] = challenge
	}

	cohortCases := make(map[string]int, len(expectedCounts))
	controlCounts := make(map[string]map[OracleCategory]int, len(expectedCounts))
	categoryTotals := map[OracleCategory]int{}
	fixtureUses := map[string]int{}
	for _, item := range contract.Corpus.Cases {
		if item.LegacyOrigin != nil || item.Fixture == nil {
			return fmt.Errorf("benchmark case %q cannot carry legacy origin", item.ID)
		}
		key := cohortKey(item.CohortID, item.ModeID)
		if _, exists := expectedCounts[key]; !exists {
			return fmt.Errorf("benchmark case %q references unknown production cohort %q", item.ID, key)
		}
		fixture, exists := fixtures[item.Fixture.ID]
		if !exists {
			return fmt.Errorf("benchmark case %q does not bind a declared fixture", item.ID)
		}
		resolved, err := contract.Fixtures.ResolveFixtureSubject(*item.Fixture, item.SubjectID)
		if err != nil || resolved.Specification.ID != fixture.ID {
			return fmt.Errorf("benchmark case %q does not resolve a declared fixture subject: %w", item.ID, err)
		}
		fixtureUses[fixture.ID]++
		cohortCases[key]++
		oracle := oracleByCase[item.ID]
		categoryTotals[oracle.Category]++
		if challenge, isChallenge := challenges[item.ID]; isChallenge {
			if challenge.CohortID != item.CohortID || challenge.ModeID != item.ModeID || oracle.Category != OracleReachable || oracle.Expected != OutcomeReachable || oracle.CoverageExpectation != CoverageComplete || oracle.SuppressionApplicable {
				return fmt.Errorf("challenge case %q is not a complete reachable positive", item.ID)
			}
			if requiresSymbolProvenance(challenge.Kind) && !fixtureHasSubject(fixture, item.SubjectID, challenge.ModulePath, challenge.Line) {
				return fmt.Errorf("challenge case %q lacks declared symbol provenance", item.ID)
			}
			continue
		}
		if oracle.SuppressionApplicable || oracle.CompletenessContract != nil {
			return fmt.Errorf("benchmark control %q cannot pre-authorize suppression", item.ID)
		}
		if !isControlOracle(oracle) {
			return fmt.Errorf("benchmark case %q is neither a control nor a declared challenge", item.ID)
		}
		if controlCounts[key] == nil {
			controlCounts[key] = map[OracleCategory]int{}
		}
		controlCounts[key][oracle.Category]++
	}
	if len(contract.Corpus.Cases) != 83 || len(contract.Oracle.Cases) != 83 {
		return fmt.Errorf("reachability benchmark requires exactly 83 corpus and oracle cases")
	}
	for key, expected := range expectedCounts {
		if got := cohortCases[key]; got != expected {
			return fmt.Errorf("benchmark cohort %q has %d cases, want %d", key, got, expected)
		}
		for _, category := range []OracleCategory{OracleReachable, OracleTrulyUnreachable, OracleOpaque, OracleNoCoverage} {
			if got := controlCounts[key][category]; got != 1 {
				return fmt.Errorf("benchmark cohort %q has %d %s controls, want 1", key, got, category)
			}
		}
	}
	for id := range fixtures {
		if fixtureUses[id] == 0 {
			return fmt.Errorf("benchmark fixture %q is not referenced by a case", id)
		}
	}
	for category, want := range map[OracleCategory]int{OracleReachable: 26, OracleTrulyUnreachable: 19, OracleOpaque: 19, OracleNoCoverage: 19} {
		if got := categoryTotals[category]; got != want {
			return fmt.Errorf("benchmark has %d %s cases, want %d", got, category, want)
		}
	}
	return nil
}

func isControlOracle(oracle OracleCase) bool {
	switch oracle.Category {
	case OracleReachable:
		return oracle.Expected == OutcomeReachable && oracle.CoverageExpectation == CoverageComplete
	case OracleTrulyUnreachable:
		return oracle.Expected == OutcomePresentUnreached && oracle.CoverageExpectation == CoverageComplete
	case OracleOpaque:
		return oracle.Expected == OutcomeConditionallyReachable && oracle.CoverageExpectation == CoveragePartial
	case OracleNoCoverage:
		return oracle.Expected == OutcomeNoAnalysis && (oracle.CoverageExpectation == CoverageUnavailable || oracle.CoverageExpectation == CoverageNotApplicable)
	default:
		return false
	}
}

// RuntimePackage identifies the exact frozen package owner of a runtime library.
type RuntimePackage struct {
	Identity string
	Name     string
	Version  string
}

// RuntimeReplayEvent is one ordered runtime library observation.
type RuntimeReplayEvent struct {
	Sequence  int
	Operation string
	Library   string
	Owner     RuntimePackage
}

// RuntimeReplayOwner binds a runtime library to its exact package owner.
type RuntimeReplayOwner struct {
	Library string
	Owner   RuntimePackage
}

// RuntimeReplay is a complete, lossless runtime replay and its ownership mapping.
type RuntimeReplay struct {
	Session   string
	Complete  bool
	LossState string
	Events    []RuntimeReplayEvent
	Owners    []RuntimeReplayOwner
}

// DecodeRuntimeReplay strictly decodes bounded replay and ownership documents from materialized files.
func DecodeRuntimeReplay(replayReader, ownershipReader io.Reader) (RuntimeReplay, error) {
	replay, ownership, err := decodeRuntimeReplayDocuments(replayReader, ownershipReader)
	if err != nil {
		return RuntimeReplay{}, err
	}
	if err := validateRuntimeReplayDocuments(replay, ownership); err != nil {
		return RuntimeReplay{}, err
	}
	return runtimeReplayValue(replay, ownership), nil
}

type runtimeReplayEvent struct {
	Sequence  int    `json:"sequence"`
	Operation string `json:"operation"`
	Library   string `json:"library"`
	Owner     string `json:"owner"`
}

type runtimeReplayDocument struct {
	SchemaVersion string               `json:"schema_version"`
	Session       string               `json:"session"`
	Complete      bool                 `json:"complete"`
	LossState     string               `json:"loss_state"`
	Events        []runtimeReplayEvent `json:"events"`
}

type runtimeOwnershipDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Owners        map[string]string `json:"owners"`
}

func validateRuntimeReplay(root fs.FS, fixture FixtureSpecification) error {
	if fixture.ID != "runtime-library-loads-input" {
		return nil
	}
	replay, ownership, err := readRuntimeReplayDocuments(root, fixture)
	if err != nil {
		return err
	}
	return validateRuntimeReplayDocuments(replay, ownership)
}

func readRuntimeReplayDocuments(root fs.FS, fixture FixtureSpecification) (runtimeReplayDocument, runtimeOwnershipDocument, error) {
	var replayPath, ownershipPath string
	for _, entry := range fixture.Entries {
		switch entry.Role {
		case FixtureEntryReplay:
			replayPath = entry.Path
		case FixtureEntryOwnership:
			ownershipPath = entry.Path
		}
	}
	if replayPath == "" || ownershipPath == "" {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("runtime replay requires replay and ownership entries")
	}
	replayRaw, err := readFixtureDocument(root, replayPath)
	if err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("read runtime replay: %w", err)
	}
	ownershipRaw, err := readFixtureDocument(root, ownershipPath)
	if err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("read runtime ownership: %w", err)
	}
	return decodeRuntimeReplayDocuments(bytes.NewReader(replayRaw), bytes.NewReader(ownershipRaw))
}

func decodeRuntimeReplayDocuments(replayReader, ownershipReader io.Reader) (runtimeReplayDocument, runtimeOwnershipDocument, error) {
	if replayReader == nil || ownershipReader == nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("runtime replay requires replay and ownership readers")
	}
	replayRaw, err := readFixtureReader(replayReader)
	if err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("read runtime replay: %w", err)
	}
	ownershipRaw, err := readFixtureReader(ownershipReader)
	if err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("read runtime ownership: %w", err)
	}
	var replay runtimeReplayDocument
	if err := benchmark.StrictDecode(bytes.NewReader(replayRaw), &replay); err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("decode runtime replay: %w", err)
	}
	var ownership runtimeOwnershipDocument
	if err := benchmark.StrictDecode(bytes.NewReader(ownershipRaw), &ownership); err != nil {
		return runtimeReplayDocument{}, runtimeOwnershipDocument{}, fmt.Errorf("decode runtime ownership: %w", err)
	}
	return replay, ownership, nil
}

func validateRuntimeReplayDocuments(replay runtimeReplayDocument, ownership runtimeOwnershipDocument) error {
	if replay.SchemaVersion != "synapse-runtime-library-replay-v2" || !validID(replay.Session) || !replay.Complete || replay.LossState != "none" {
		return fmt.Errorf("runtime replay requires complete lossless ordered event data")
	}
	if ownership.SchemaVersion != "synapse-runtime-library-ownership-v2" || len(ownership.Owners) != 4 {
		return fmt.Errorf("runtime replay requires complete ownership mapping")
	}
	seenLibraries := map[string]struct{}{}
	for index, event := range replay.Events {
		if event.Sequence != index+1 || !validRuntimeLibrary(event.Library) {
			return fmt.Errorf("runtime replay has incomplete event %d", index+1)
		}
		if _, ok := parseRuntimePackage(event.Owner); !ok {
			return fmt.Errorf("runtime replay event %q has invalid owner", event.Library)
		}
		if event.Operation != "load" && event.Operation != "opaque" && event.Operation != "unsupported" {
			return fmt.Errorf("runtime replay has unknown event operation %q", event.Operation)
		}
		if owner, exists := ownership.Owners[event.Library]; !exists || owner != event.Owner {
			return fmt.Errorf("runtime replay event %q lacks matching ownership", event.Library)
		}
		if _, duplicate := seenLibraries[event.Library]; duplicate {
			return fmt.Errorf("runtime replay duplicates library %q", event.Library)
		}
		seenLibraries[event.Library] = struct{}{}
	}
	for library, owner := range ownership.Owners {
		if !validRuntimeLibrary(library) {
			return fmt.Errorf("runtime replay has invalid ownership mapping")
		}
		if _, ok := parseRuntimePackage(owner); !ok {
			return fmt.Errorf("runtime replay has invalid ownership mapping")
		}
	}
	return nil
}

func runtimeReplayValue(replay runtimeReplayDocument, ownership runtimeOwnershipDocument) RuntimeReplay {
	events := make([]RuntimeReplayEvent, 0, len(replay.Events))
	for _, event := range replay.Events {
		owner, _ := parseRuntimePackage(event.Owner)
		events = append(events, RuntimeReplayEvent{
			Sequence:  event.Sequence,
			Operation: event.Operation,
			Library:   event.Library,
			Owner:     owner,
		})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })

	owners := make([]RuntimeReplayOwner, 0, len(ownership.Owners))
	for library, identity := range ownership.Owners {
		owner, _ := parseRuntimePackage(identity)
		owners = append(owners, RuntimeReplayOwner{Library: library, Owner: owner})
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].Library < owners[j].Library })
	return RuntimeReplay{
		Session:   replay.Session,
		Complete:  replay.Complete,
		LossState: replay.LossState,
		Events:    events,
		Owners:    owners,
	}
}

func parseRuntimePackage(identity string) (RuntimePackage, bool) {
	const prefix = "pkg:runtime/"
	if !strings.HasPrefix(identity, prefix) || identity != strings.TrimSpace(identity) || len(identity) > 256 {
		return RuntimePackage{}, false
	}
	nameVersion := strings.TrimPrefix(identity, prefix)
	separator := strings.LastIndex(nameVersion, "@")
	if separator <= len("reachbench-") || separator == len(nameVersion)-1 {
		return RuntimePackage{}, false
	}
	name, version := nameVersion[:separator], nameVersion[separator+1:]
	if !strings.HasPrefix(name, "reachbench-") || version != "benchmark-v1" {
		return RuntimePackage{}, false
	}
	for _, character := range name {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return RuntimePackage{}, false
		}
	}
	return RuntimePackage{Identity: identity, Name: name, Version: version}, true
}

func validateRuntimeReplayContract(root fs.FS, contract ReachabilityBenchmark) error {
	var fixture *FixtureSpecification
	for index := range contract.Fixtures.Fixtures {
		if contract.Fixtures.Fixtures[index].ID == "runtime-library-loads-input" {
			fixture = &contract.Fixtures.Fixtures[index]
			break
		}
	}
	if fixture == nil {
		return fmt.Errorf("runtime replay fixture is missing")
	}
	if err := validateRuntimeReplay(root, *fixture); err != nil {
		return err
	}
	replay, ownership, err := readRuntimeReplayDocuments(root, *fixture)
	if err != nil {
		return err
	}

	oracles := make(map[string]OracleCase, len(contract.Oracle.Cases))
	for _, oracle := range contract.Oracle.Cases {
		oracles[oracle.CaseID] = oracle
	}
	categories := make(map[string]OracleCategory, len(fixture.Subjects))
	for _, item := range contract.Corpus.Cases {
		if item.Fixture == nil || item.Fixture.ID != fixture.ID {
			continue
		}
		oracle, exists := oracles[item.ID]
		if !exists {
			return fmt.Errorf("runtime replay case %q lacks oracle", item.ID)
		}
		if _, duplicate := categories[item.SubjectID]; duplicate {
			return fmt.Errorf("runtime replay subject %q has duplicate corpus cases", item.SubjectID)
		}
		categories[item.SubjectID] = oracle.Category
	}
	if len(categories) != len(fixture.Subjects) {
		return fmt.Errorf("runtime replay corpus does not cover every runtime subject")
	}

	type runtimeExpectation struct {
		operation string
		owner     string
	}
	expectedEvents := make(map[string]runtimeExpectation, len(fixture.Subjects)-1)
	subjectByLibrary := make(map[string]FixtureSubject, len(fixture.Subjects))
	unreachable := make(map[string]struct{}, 1)
	for _, subject := range fixture.Subjects {
		category, exists := categories[subject.ID]
		if !exists || subject.Locator.Kind != FixtureLocatorRuntimeObservation || !validRuntimeLibrary(subject.Locator.Symbol) {
			return fmt.Errorf("runtime replay subject %q lacks runtime provenance", subject.ID)
		}
		if _, duplicate := subjectByLibrary[subject.Locator.Symbol]; duplicate {
			return fmt.Errorf("runtime replay duplicates subject library %q", subject.Locator.Symbol)
		}
		subjectByLibrary[subject.Locator.Symbol] = subject
		switch category {
		case OracleReachable:
			expectedEvents[subject.Locator.Symbol] = runtimeExpectation{operation: "load", owner: subject.PackageIdentity}
		case OracleOpaque:
			expectedEvents[subject.Locator.Symbol] = runtimeExpectation{operation: "opaque", owner: subject.PackageIdentity}
		case OracleNoCoverage:
			expectedEvents[subject.Locator.Symbol] = runtimeExpectation{operation: "unsupported", owner: subject.PackageIdentity}
		case OracleTrulyUnreachable:
			unreachable[subject.Locator.Symbol] = struct{}{}
		default:
			return fmt.Errorf("runtime replay subject %q has unsupported oracle category %q", subject.ID, category)
		}
	}
	if len(expectedEvents) != 3 || len(unreachable) != 1 {
		return fmt.Errorf("runtime replay requires reachable, opaque, no-coverage, and truly-unreachable controls")
	}
	if len(ownership.Owners) != len(subjectByLibrary) {
		return fmt.Errorf("runtime replay ownership does not cover the frozen runtime subjects")
	}
	for library, owner := range ownership.Owners {
		subject, exists := subjectByLibrary[library]
		if !exists || subject.PackageIdentity != owner {
			return fmt.Errorf("runtime replay ownership for %q does not match the frozen subject", library)
		}
	}

	seenEvents := make(map[string]struct{}, len(replay.Events))
	for _, event := range replay.Events {
		expectation, expected := expectedEvents[event.Library]
		if !expected {
			if _, absent := unreachable[event.Library]; absent {
				return fmt.Errorf("runtime replay observes truly-unreachable subject %q", event.Library)
			}
			return fmt.Errorf("runtime replay has event outside the frozen corpus %q", event.Library)
		}
		if event.Operation != expectation.operation || event.Owner != expectation.owner {
			return fmt.Errorf("runtime replay event/category mapping mismatch for %q", event.Library)
		}
		seenEvents[event.Library] = struct{}{}
	}
	for library := range expectedEvents {
		if _, seen := seenEvents[library]; !seen {
			return fmt.Errorf("runtime replay omits required event %q", library)
		}
	}
	return nil
}

func validRuntimeLibrary(value string) bool {
	return value != "" && len(value) <= 256 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "/\\:\r\n\t")
}

func validateFixtureFiles(root fs.FS, manifest FixtureManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	declared := map[string]FixtureFile{}
	var total int64
	for _, fixture := range manifest.Fixtures {
		for _, file := range fixture.Files {
			if existing, exists := declared[file.Path]; exists {
				if !sameFixtureFile(existing, file) {
					return fmt.Errorf("fixture %q has conflicting declaration for physical path %q", fixture.ID, file.Path)
				}
				continue
			}
			if len(declared) == maxFixtureFileCount {
				return fmt.Errorf("fixture inventory exceeds %d files", maxFixtureFileCount)
			}
			if err := validateFixtureFile(root, file); err != nil {
				return fmt.Errorf("fixture %q: %w", fixture.ID, err)
			}
			total += file.Size
			if total > maxFixtureTotalBytes {
				return fmt.Errorf("fixture inventory exceeds %d bytes", maxFixtureTotalBytes)
			}
			declared[file.Path] = file
		}
	}
	for _, fixture := range manifest.Fixtures {
		if err := validateRuntimeReplay(root, fixture); err != nil {
			return fmt.Errorf("fixture %q: %w", fixture.ID, err)
		}
	}
	return fs.WalkDir(root, "fixtures", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "fixtures" || entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fixture path %q is not a regular file", path)
		}
		if _, known := declared[path]; !known {
			return fmt.Errorf("fixture inventory omits package-owned file %q", path)
		}
		return nil
	})
}

// ReadFixtureFile returns a fresh verified copy of one frozen fixture input. It accepts
// only an exact file declaration from the embedded reachability fixture manifest.
func ReadFixtureFile(file FixtureFile) ([]byte, error) {
	if err := file.validate("fixture file"); err != nil {
		return nil, err
	}
	root, err := fs.Sub(reachabilityBenchmarkFiles, benchmarkAssetRoot)
	if err != nil {
		return nil, fmt.Errorf("open reachability benchmark assets: %w", err)
	}
	contract, err := loadReachabilityBenchmark(root)
	if err != nil {
		return nil, err
	}
	declared := false
	for _, fixture := range contract.Fixtures.Fixtures {
		for _, candidate := range fixture.Files {
			if sameFixtureFile(candidate, file) {
				declared = true
				break
			}
		}
		if declared {
			break
		}
	}
	if !declared {
		return nil, fmt.Errorf("fixture file %q is not declared by the frozen reachability contract", file.Path)
	}
	contents, err := readFixtureFile(root, file)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), contents...), nil
}

func validateFixtureFile(root fs.FS, file FixtureFile) error {
	_, err := readFixtureFile(root, file)
	return err
}

func readFixtureFile(root fs.FS, file FixtureFile) ([]byte, error) {
	if err := file.validate("fixture file"); err != nil {
		return nil, err
	}
	info, err := fs.Stat(root, file.Path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", file.Path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("fixture path %q is not a regular file", file.Path)
	}
	if info.Size() != file.Size {
		return nil, fmt.Errorf("fixture path %q size mismatch: got %d", file.Path, info.Size())
	}
	opened, err := root.Open(file.Path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", file.Path, err)
	}
	defer func() { _ = opened.Close() }()
	contents, err := io.ReadAll(io.LimitReader(opened, maxFixtureFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", file.Path, err)
	}
	if int64(len(contents)) > maxFixtureFileBytes {
		return nil, fmt.Errorf("fixture path %q exceeds %d bytes", file.Path, maxFixtureFileBytes)
	}
	if got := benchmark.SHA256Digest(contents); got != file.Digest {
		return nil, fmt.Errorf("fixture path %q digest mismatch: got %s", file.Path, got)
	}
	return contents, nil
}

// DigestChallengeManifest returns the canonical digest of the positive challenge declaration.
func DigestChallengeManifest(manifest ChallengeManifest) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalChallengeManifest(manifest))
}

// DigestFixtureSpecification returns the complete identity of a fixture specification and excludes no material field.
func DigestFixtureSpecification(specification FixtureSpecification) (string, error) {
	if err := specification.validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalFixtureSpecification(specification))
}

// DigestFixtureManifest returns the canonical digest of the content-pinned fixture declaration.
func DigestFixtureManifest(manifest FixtureManifest) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalFixtureManifest(manifest))
}

// DigestReachabilityBenchmark returns the canonical digest of the entire static contract.
func DigestReachabilityBenchmark(contract ReachabilityBenchmark) (string, error) {
	if err := contract.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalReachabilityBenchmark(contract))
}

func canonicalReachabilityBenchmark(contract ReachabilityBenchmark) ReachabilityBenchmark {
	contract.Corpus = canonicalCorpus(contract.Corpus)
	contract.Oracle = canonicalOracle(contract.Oracle)
	contract.Challenges = canonicalChallengeManifest(contract.Challenges)
	contract.Fixtures = canonicalFixtureManifest(contract.Fixtures)
	return contract
}

func canonicalChallengeManifest(manifest ChallengeManifest) ChallengeManifest {
	out := manifest
	out.Challenges = append([]ChallengeDeclaration(nil), manifest.Challenges...)
	sort.Slice(out.Challenges, func(left, right int) bool { return out.Challenges[left].CaseID < out.Challenges[right].CaseID })
	return out
}

func canonicalFixtureSpecification(specification FixtureSpecification) FixtureSpecification {
	out := specification
	out.Files = append([]FixtureFile(nil), specification.Files...)
	sort.Slice(out.Files, func(left, right int) bool { return out.Files[left].Path < out.Files[right].Path })
	out.Entries = append([]FixtureEntry(nil), specification.Entries...)
	sort.Slice(out.Entries, func(left, right int) bool {
		if out.Entries[left].Role != out.Entries[right].Role {
			return out.Entries[left].Role < out.Entries[right].Role
		}
		return out.Entries[left].Path < out.Entries[right].Path
	})
	out.Subjects = append([]FixtureSubject(nil), specification.Subjects...)
	sort.Slice(out.Subjects, func(left, right int) bool { return out.Subjects[left].ID < out.Subjects[right].ID })
	if out.Build != nil {
		build := *out.Build
		build.Steps = append([]FixtureBuildStep(nil), build.Steps...)
		build.Env = append([]FixtureBuildEnv(nil), build.Env...)
		sort.Slice(build.Env, func(left, right int) bool { return build.Env[left].Key < build.Env[right].Key })
		build.Outputs = append([]FixtureOutput(nil), build.Outputs...)
		sort.Slice(build.Outputs, func(left, right int) bool { return build.Outputs[left].Path < build.Outputs[right].Path })
		out.Build = &build
	}
	return out
}

func canonicalFixtureManifest(manifest FixtureManifest) FixtureManifest {
	out := manifest
	out.Fixtures = append([]FixtureSpecification(nil), manifest.Fixtures...)
	for index := range out.Fixtures {
		out.Fixtures[index] = canonicalFixtureSpecification(out.Fixtures[index])
	}
	sort.Slice(out.Fixtures, func(left, right int) bool { return out.Fixtures[left].ID < out.Fixtures[right].ID })
	return out
}

func validFixturePath(path string) bool {
	return path != "" && path == strings.TrimSpace(path) && !strings.Contains(path, `\\`) && !strings.Contains(path, ":") && !strings.HasPrefix(path, ".") && fs.ValidPath(path)
}

func validPackageIdentity(value string) bool {
	return validSubjectID(value) && len(value) <= 512 && !strings.Contains(value, `\\`) && !strings.Contains(value, " ")
}

func validLocatorSymbol(value string) bool {
	return value != "" && len(value) <= 512 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\\\r\n\t")
}

func validTargetPlatform(value string) bool {
	return value == "linux/amd64" || value == "any"
}

func validBuildEnvKey(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if (char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

func validBuildArg(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 || strings.ContainsAny(value, "\r\n;|&`$<>") {
		return false
	}
	lower := strings.ToLower(value)
	return lower != "sh" && lower != "bash" && lower != "zsh" && lower != "cmd" && lower != "powershell" && value != "-c" && !strings.HasSuffix(lower, ".sh") && !strings.HasSuffix(lower, ".bash") && !strings.HasSuffix(lower, ".cmd") && !strings.HasSuffix(lower, ".ps1") && !strings.HasPrefix(value, "/") && !strings.Contains(value, `\\`)
}

func validFixtureProvenanceText(value string) bool {
	return len(value) <= 512 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\t")
}

func validFixtureRevision(value string) bool {
	if value == "" {
		return true
	}
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validToolchainVersion(value string) bool {
	if len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func validateFixturePathSet(paths []string) error {
	folded := make(map[string]string, len(paths))
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	for _, path := range sorted {
		fold := strings.ToLower(path)
		if existing, exists := folded[fold]; exists && existing != path {
			return fmt.Errorf("case-fold fixture path collision %q and %q", existing, path)
		}
		folded[fold] = path
	}
	for index := 1; index < len(sorted); index++ {
		if strings.HasPrefix(sorted[index], sorted[index-1]+"/") {
			return fmt.Errorf("fixture file/directory prefix collision %q and %q", sorted[index-1], sorted[index])
		}
	}
	return nil
}

func pathOverlapsAny(path string, paths []string) bool {
	for _, other := range paths {
		if path == other || strings.HasPrefix(path, other+"/") || strings.HasPrefix(other, path+"/") {
			return true
		}
	}
	return false
}

func keysOf[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	return keys
}

func fixtureOutputPath(build *FixtureBuild, path string) bool {
	for _, output := range build.Outputs {
		if output.Path == path {
			return true
		}
	}
	return false
}

func requiresSymbolProvenance(kind ChallengeKind) bool {
	return kind == ChallengePHPSymbolProvenance || kind == ChallengeRubySymbolProvenance
}

func fixtureHasSubject(fixture FixtureSpecification, id, module string, line int) bool {
	for _, subject := range fixture.Subjects {
		if subject.ID == id && subject.Locator.ModulePath == module && subject.Locator.Line == line {
			return true
		}
	}
	return false
}

func sameChallenge(left, right ChallengeDeclaration) bool {
	return left.CaseID == right.CaseID && left.CohortID == right.CohortID && left.ModeID == right.ModeID && left.Kind == right.Kind && left.ModulePath == right.ModulePath && left.Line == right.Line
}

func requiredCohortCaseCounts() map[string]int {
	return map[string]int{
		"go/source_tier2": 4, "go/binary": 5, "python/import": 4, "python/semantic": 4,
		"javascript/import": 4, "javascript/lexical": 4, "javascript/interprocedural": 8,
		"rust/import": 4, "rust/symbols_tier2": 4, "php/import": 4, "php/symbols_tier2": 5,
		"ruby/import": 4, "ruby/symbols_tier2": 5, "dotnet/build_aware_import": 4,
		"dotnet/symbols_tier2": 4, "c_cpp/symbols_tier2": 4, "jvm/coarse": 4, "jvm/tier2": 4,
		"runtime/library_loads": 4,
	}
}

var requiredChallenges = map[string]ChallengeDeclaration{
	"go-binary-challenge-pclntab-entry-call":                    {CaseID: "go-binary-challenge-pclntab-entry-call", CohortID: "go", ModeID: "binary", Kind: ChallengeGoBinaryPCLNTABCall},
	"javascript-interprocedural-challenge-cross-module-call":    {CaseID: "javascript-interprocedural-challenge-cross-module-call", CohortID: "javascript", ModeID: "interprocedural", Kind: ChallengeJavaScriptCrossModuleCall},
	"javascript-interprocedural-challenge-function-alias":       {CaseID: "javascript-interprocedural-challenge-function-alias", CohortID: "javascript", ModeID: "interprocedural", Kind: ChallengeJavaScriptFunctionAlias},
	"javascript-interprocedural-challenge-returned-callable":    {CaseID: "javascript-interprocedural-challenge-returned-callable", CohortID: "javascript", ModeID: "interprocedural", Kind: ChallengeJavaScriptReturnedCallable},
	"javascript-interprocedural-challenge-synchronous-callback": {CaseID: "javascript-interprocedural-challenge-synchronous-callback", CohortID: "javascript", ModeID: "interprocedural", Kind: ChallengeJavaScriptSyncCallback},
	"php-symbols-tier2-challenge-symbol-provenance":             {CaseID: "php-symbols-tier2-challenge-symbol-provenance", CohortID: "php", ModeID: "symbols_tier2", Kind: ChallengePHPSymbolProvenance, ModulePath: "fixtures/php/symbols_tier2/main.php", Line: 25},
	"ruby-symbols-tier2-challenge-symbol-provenance":            {CaseID: "ruby-symbols-tier2-challenge-symbol-provenance", CohortID: "ruby", ModeID: "symbols_tier2", Kind: ChallengeRubySymbolProvenance, ModulePath: "fixtures/ruby/symbols_tier2/main.rb", Line: 18},
}

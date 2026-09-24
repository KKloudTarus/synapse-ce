package scabench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	runResultSchemaVersion                 = "synapse-sca-benchmark-run-v1"
	fixedRepetitions                       = 2
	fixedMatrixCells                       = 12
	ownedBenchmarkVersion                  = "devel"
	ownedBenchmarkVersionLinkerSymbol      = "github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo.version"
	maxPublicationFileBytes                = 512 << 20
	maxPublicationTotalBytes               = 6 * maxPublicationFileBytes
	publicationCleanupTimeout              = 2 * time.Minute
	fixedCapabilitySourceArtifacts         = 2
	maxRawBundleArtifacts                  = 5 + 1 + fixedCapabilitySourceArtifacts
	reviewCaptureSchemaVersion             = "review-v1"
	dispositionCaptureSchemaVersion        = "disposition-v1"
	trustedEnvironmentAttestationReference = "environment-attestation:al2023-amd64-trusted-sandbox-v1"
	trustedEnvironmentAttestationLocator   = "evidence-assets/environment/environment-attestation.json"
)

var fixedTargetIDs = []string{
	"debian-12-13-slim-amd64",
	"sles-15-6-bci-base-45-31-amd64",
	"rhel-9-8-ubi-amd64",
}

type trustedCaptureInput struct {
	engineVersion     string
	binaryReference   string
	binaryLocator     string
	databaseReference string
	databaseLocator   string
}

type trustedCapabilitySource struct {
	locator      string
	pinReference string
}

type trustedManifestPaths struct {
	binary                 string
	database               string
	sbom                   string
	environmentAttestation string
}

var fixedTrustedSBOMLocators = map[string]string{
	"debian-12-13-slim-amd64":        "sboms/debian-12-13-slim-amd64.cdx.json",
	"sles-15-6-bci-base-45-31-amd64": "sboms/sles-15-6-bci-base-45-31-amd64.cdx.json",
	"rhel-9-8-ubi-amd64":             "sboms/rhel-9-8-ubi-amd64.cdx.json",
}

var fixedTrustedCompetitorInputs = map[bench.Engine]trustedCaptureInput{
	bench.EngineGrype: {
		engineVersion: "0.115.0", binaryReference: "binary:grype:v0.115.0", binaryLocator: "tools/grype",
		databaseReference: "database:grype:v6.1.9-2026-09-20T00:35:35Z-1789885674", databaseLocator: "databases/grype",
	},
	bench.EngineTrivy: {
		engineVersion: "0.74.0", binaryReference: "binary:trivy:v0.74.0", binaryLocator: "tools/trivy",
		databaseReference: "database:trivy:v2-2026-09-20T13:18:06.422928923Z", databaseLocator: "databases/trivy",
	},
	bench.EngineOSVScanner: {
		engineVersion: "v2.5.1", binaryReference: "binary:osv-scanner:v2.5.1", binaryLocator: "tools/osv-scanner",
		databaseReference: "database:osv-scanner:debian-all-2026-09-20", databaseLocator: "databases/osv",
	},
}

var fixedTrustedOwnedInputs = map[string]trustedCaptureInput{
	"debian-12-13-slim-amd64": {
		engineVersion: ownedBenchmarkVersion, binaryReference: "binary:synapse-sca-bench:reproducible-v1",
		databaseReference: "database:owned:debian-bookworm-oval-2026-09-20", databaseLocator: "databases/owned-debian",
	},
	"sles-15-6-bci-base-45-31-amd64": {
		engineVersion: ownedBenchmarkVersion, binaryReference: "binary:synapse-sca-bench:reproducible-v1",
		databaseReference: "database:owned:sles-15-sp6-affected-oval-2026-09-20", databaseLocator: "databases/owned-sles",
	},
	"rhel-9-8-ubi-amd64": {
		engineVersion: ownedBenchmarkVersion, binaryReference: "binary:synapse-sca-bench:reproducible-v1",
		databaseReference: "database:owned:redhat-rhel9-8-vex-2026-09-21", databaseLocator: "databases/owned-redhat",
	},
}

var fixedTrustedCapabilitySources = map[string]trustedCapabilitySource{
	"https://github.com/google/osv-scanner/blob/c84fa4568f2526d0333e9a914ea8a0a5f74ad68b/internal/utility/purl/purl_to_package.go": {
		locator: "capability/osv-scanner-v2.5.1/purl_to_package.go", pinReference: "capability-source:osv-scanner:c84fa4568f2526d0333e9a914ea8a0a5f74ad68b",
	},
	"https://github.com/google/osv-scalibr/blob/23fa66ca68dd17bfdbe0b8b3536d1887a3a940da/purl/ecosystem/ecosystem.go": {
		locator: "capability/osv-scanner-v2.5.1/ecosystem.go", pinReference: "capability-source:osv-scalibr:23fa66ca68dd17bfdbe0b8b3536d1887a3a940da",
	},
}

var fixedPublicationArtifactPaths = [...]string{
	"catalog.json",
	"oracle.json",
	"ratchet.json",
	"cycle-policy.json",
	"run.json",
	"result.json",
	"report.md",
	"reviews/review.json",
	"reviews/disposition.json",
}

func expectedPublicationFileCount() int {
	return len(fixedPublicationArtifactPaths) + len(fixedTargetIDs)
}

// RunInput is the complete operator contract. All paths must be absolute.
type RunInput struct {
	CorpusRoot           string
	TrustedInputRoot     string
	OutputRoot           string
	RawRetentionRoot     string
	ImplementationCommit string
	RunKey               string
}

type InputDigests struct {
	Catalog     string `json:"catalog"`
	Oracle      string `json:"oracle"`
	Ratchet     string `json:"ratchet"`
	Policy      string `json:"policy"`
	Review      string `json:"review"`
	Disposition string `json:"disposition"`
}

type CleanupResult struct {
	RawRunRemoved bool `json:"raw_run_removed"`
	DockerCleaned bool `json:"docker_cleaned"`
}

// RunResult is the one authoritative, sanitized result of a completed cycle.
type RunResult struct {
	SchemaVersion        string                     `json:"schema_version"`
	ImplementationCommit string                     `json:"implementation_commit"`
	RunKey               string                     `json:"run_key"`
	InputDigests         InputDigests               `json:"input_digests"`
	Repetitions          int                        `json:"repetitions"`
	Observations         [][]bench.Observation      `json:"observations"`
	Comparisons          []SemanticBundleComparison `json:"comparisons"`
	RawBundles           [][]BundleIdentity         `json:"raw_bundles"`
	Result               bench.Result               `json:"result"`
	Cleanup              CleanupResult              `json:"cleanup"`
}

type RunnerFactory func(RuntimeLimits) (ports.ToolRunner, error)

type runState struct {
	input           RunInput
	catalog         bench.Catalog
	oracle          bench.Oracle
	ratchet         bench.Ratchet
	policy          cyclePolicy
	inputDigests    InputDigests
	manifests       map[string]CaptureManifest
	expectedStates  map[string]bench.ObservationState
	review          []byte
	disposition     []byte
	workspace       benchcycle.Workspace
	workRoot        string
	rawRunRoot      string
	cleanup         CleanupResult
	cleanupRequired bool
	runtimeCleanup  func(context.Context) error
	stageVerifier   benchcycle.PublicationVerifier
}

type cyclePolicy struct {
	SchemaVersion                 string `json:"schema_version"`
	AcceptedArtifactRetentionDays int    `json:"accepted_artifact_retention_days"`
	RawRetention                  string `json:"raw_retention"`
	Repetitions                   int    `json:"repetitions"`
}

type captureManifestTemplate struct {
	SchemaVersion           string                `json:"schema_version"`
	TargetID                string                `json:"target_id"`
	Engine                  bench.Engine          `json:"engine"`
	EngineVersion           string                `json:"engine_version"`
	Binary                  Artifact              `json:"binary"`
	Database                DatabaseArtifact      `json:"database"`
	Environment             EnvironmentDescriptor `json:"environment"`
	EnvironmentAttestation  Artifact              `json:"environment_attestation"`
	EnvironmentPinReference string                `json:"environment_pin_reference"`
	ProfilePinReference     string                `json:"profile_pin_reference"`
	Limits                  RuntimeLimits         `json:"limits"`
	Capability              *capabilityTemplate   `json:"capability,omitempty"`
}

type capabilityTemplate struct {
	Kind               bench.CapabilityKind       `json:"kind"`
	StatementReference string                     `json:"statement_reference"`
	Sources            []capabilitySourceTemplate `json:"sources"`
}

type capabilitySourceTemplate struct {
	Reference string `json:"reference"`
	Locator   string `json:"locator"`
	Digest    string `json:"digest"`
}

type reviewCapture struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	URL           string `json:"url"`
	Login         string `json:"login"`
	State         string `json:"state"`
	SubmittedAt   string `json:"submitted_at"`
	CommitID      string `json:"commit_id"`
	Body          string `json:"body"`
}

type dispositionCapture struct {
	SchemaVersion        string `json:"schema_version"`
	ID                   string `json:"id"`
	URL                  string `json:"url"`
	Login                string `json:"login"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	ReviewID             string `json:"review_id"`
	ReviewedCommit       string `json:"reviewed_commit"`
	ImplementationCommit string `json:"implementation_commit"`
	Decision             string `json:"decision"`
	Body                 string `json:"body"`
}

type cycleCell struct {
	key      string
	manifest CaptureManifest
	expected bench.ObservationState
}

type cycleCapture struct {
	observation bench.Observation
	identity    BundleIdentity
	path        string
}

type publicationArtifact struct {
	path string
	body []byte
}

func Run(ctx context.Context, input RunInput, runnerFactory RunnerFactory) (result RunResult, runErr error) {
	if ctx == nil {
		return RunResult{}, errors.New("run context is required")
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	state, err := prepareRun(input)
	if err != nil {
		return RunResult{}, err
	}
	publication, err := state.beginPublication()
	if err != nil {
		_ = state.workspace.RemoveWork()
		return RunResult{}, err
	}
	publicationOpen := true
	defer func() {
		if !publicationOpen {
			return
		}
		if abortErr := publication.Abort(); abortErr != nil {
			runErr = errors.Join(runErr, abortErr)
		}
	}()

	if err := state.loadFrozenInputs(); err != nil {
		return RunResult{}, err
	}
	if err := state.buildAndBindOwnedBinary(ctx); err != nil {
		return RunResult{}, err
	}
	if err := state.materializeManifests(); err != nil {
		return RunResult{}, err
	}
	if err := state.validateRatchetBindings(); err != nil {
		return RunResult{}, err
	}
	store, err := state.newEvidenceStore()
	if err != nil {
		return RunResult{}, err
	}

	observations, comparisons, rawBundles, err := executeCaptureCycle(ctx, state, runnerFactory, store)
	if err != nil {
		return RunResult{}, err
	}

	finalResult, resultBytes, report, err := reduceRepetitionsContext(ctx, state.catalog, state.oracle, state.ratchet, observations)
	if err != nil {
		return RunResult{}, err
	}
	result = RunResult{
		SchemaVersion: runResultSchemaVersion, ImplementationCommit: input.ImplementationCommit, RunKey: input.RunKey,
		InputDigests: state.inputDigests, Repetitions: fixedRepetitions, Observations: observations,
		Comparisons: comparisons, RawBundles: rawBundles, Result: finalResult,
	}
	if err := state.stagePublication(ctx, publication, &result, resultBytes, report); err != nil {
		return RunResult{}, err
	}
	if err := publication.Commit(ctx); err != nil {
		publicationOpen = false
		return RunResult{}, err
	}
	publicationOpen = false
	result.Cleanup = state.cleanup
	return result, nil
}

// executeCaptureCycle records the fixed two-pass matrix without imposing trusted-publication semantics.
func executeCaptureCycle(ctx context.Context, state *runState, runnerFactory RunnerFactory, store *benchcycle.EvidenceStore) ([][]bench.Observation, []SemanticBundleComparison, [][]BundleIdentity, error) {
	if ctx == nil {
		return nil, nil, nil, errors.New("capture cycle context is required")
	}
	if state == nil {
		return nil, nil, nil, errors.New("capture cycle state is required")
	}
	if store == nil {
		return nil, nil, nil, errors.New("capture cycle evidence store is required")
	}
	cells := state.cyclePlan()
	comparisons := make([]SemanticBundleComparison, 0, len(cells))
	pairs, err := benchcycle.ExecuteTwoPass(ctx, benchcycle.TwoPassPlan[cycleCell]{Cells: cells},
		func(ctx context.Context, attempt benchcycle.Attempt[cycleCell]) (benchcycle.AttemptOutcome[cycleCapture], error) {
			state.cleanupRequired = true
			cell := attempt.Cell
			observation, identity, path, captureErr := state.captureCell(ctx, attempt.Address, cell.manifest, runnerFactory, store)
			if captureErr != nil {
				return benchcycle.AttemptOutcome[cycleCapture]{}, fmt.Errorf("capture repetition %d %s: %w", attempt.Address.Repetition, cell.key, captureErr)
			}
			if observation.State != cell.expected {
				return benchcycle.AttemptOutcome[cycleCapture]{}, fmt.Errorf("capture repetition %d %s returned %q, want %q", attempt.Address.Repetition, cell.key, observation.State, cell.expected)
			}
			return benchcycle.AttemptOutcome[cycleCapture]{
				Address: attempt.Address,
				Outcome: cycleCapture{observation: observation, identity: identity, path: path},
			}, nil
		},
		func(ctx context.Context, pair benchcycle.PairOutcome[cycleCell, cycleCapture]) error {
			comparison, compareErr := CompareBundlesForCellContext(ctx, pair.Outcomes[0].Outcome.path, pair.Outcomes[1].Outcome.path, pair.Cell.Cell.manifest.TargetID, pair.Cell.Cell.manifest.Engine, pair.Cell.Cell.expected)
			if compareErr != nil {
				return fmt.Errorf("compare repetitions for %s: %w", pair.Cell.Key, compareErr)
			}
			comparisons = append(comparisons, comparison)
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	observations := make([][]bench.Observation, fixedRepetitions)
	rawBundles := make([][]BundleIdentity, fixedRepetitions)
	for repetition := range fixedRepetitions {
		observations[repetition] = make([]bench.Observation, 0, len(pairs))
		rawBundles[repetition] = make([]BundleIdentity, 0, len(pairs))
		for _, pair := range pairs {
			captured := pair.Outcomes[repetition].Outcome
			observations[repetition] = append(observations[repetition], captured.observation)
			rawBundles[repetition] = append(rawBundles[repetition], captured.identity)
		}
	}
	return observations, comparisons, rawBundles, nil
}

func (state *runState) cyclePlan() []benchcycle.PlanCell[cycleCell] {
	cells := make([]benchcycle.PlanCell[cycleCell], 0, len(state.manifests))
	for _, target := range state.catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			cells = append(cells, benchcycle.PlanCell[cycleCell]{
				Key: key,
				Cell: cycleCell{
					key:      key,
					manifest: state.manifests[key],
					expected: state.expectedStates[key],
				},
			})
		}
	}
	return cells
}

func prepareRun(input RunInput) (*runState, error) {
	if err := validateRunInput(input); err != nil {
		return nil, err
	}
	workspace, err := benchcycle.PrepareWorkspace(input.RawRetentionRoot, input.RunKey)
	if err != nil {
		return nil, err
	}
	return &runState{
		input: input, workspace: workspace,
		workRoot: workspace.WorkRoot(), rawRunRoot: workspace.RawRunRoot(),
	}, nil
}

func validateRunInput(input RunInput) error {
	for _, item := range []struct{ name, value string }{
		{"corpus root", input.CorpusRoot}, {"trusted input root", input.TrustedInputRoot},
		{"output root", input.OutputRoot}, {"raw retention root", input.RawRetentionRoot},
	} {
		if err := benchcycle.ValidateAbsolutePath(item.name, item.value); err != nil {
			return err
		}
	}
	if err := benchcycle.ValidateIdentity(input.ImplementationCommit, input.RunKey); err != nil {
		return err
	}
	if err := benchcycle.EnsureAbsent(input.OutputRoot, "output root"); err != nil {
		return err
	}
	if _, err := benchcycle.RealDirectory(input.CorpusRoot); err != nil {
		return fmt.Errorf("validate corpus root: %w", err)
	}
	if _, err := benchcycle.RealDirectory(input.TrustedInputRoot); err != nil {
		return fmt.Errorf("validate trusted input root: %w", err)
	}
	return nil
}

func (state *runState) loadFrozenInputs() error {
	catalogPath := filepath.Join(state.input.CorpusRoot, "catalog.json")
	oraclePath := filepath.Join(state.input.CorpusRoot, "oracle.json")
	ratchetPath := filepath.Join(state.input.CorpusRoot, "ratchet.json")
	policyPath := filepath.Join(state.input.CorpusRoot, "cycle-policy.json")
	var err error
	if state.catalog, err = decodeCatalogFile(catalogPath); err != nil {
		return err
	}
	if state.oracle, err = decodeOracleFile(oraclePath); err != nil {
		return err
	}
	if err := validateFixedTargetMatrix(state.catalog); err != nil {
		return err
	}
	if err := bench.Validate(state.catalog, state.oracle); err != nil {
		return fmt.Errorf("validate frozen catalog and oracle: %w", err)
	}
	if state.ratchet, err = decodeRatchetFile(ratchetPath); err != nil {
		return err
	}
	if state.policy, err = decodePolicyFile(policyPath); err != nil {
		return err
	}
	if state.policy.Repetitions != fixedRepetitions {
		return fmt.Errorf("cycle policy repetitions must be %d", fixedRepetitions)
	}
	if state.policy.RawRetention != "delete_after_verification" || state.policy.AcceptedArtifactRetentionDays != 90 {
		return errors.New("cycle policy does not require the fixed retention contract")
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return fmt.Errorf("digest frozen catalog: %w", err)
	}
	oracleDigest, err := bench.DigestOracle(state.oracle)
	if err != nil {
		return fmt.Errorf("digest frozen oracle: %w", err)
	}
	ratchetDigest, err := bench.DigestRatchet(state.ratchet)
	if err != nil {
		return fmt.Errorf("digest frozen ratchet: %w", err)
	}
	policyBytes, err := readRegularFile(policyPath)
	if err != nil {
		return err
	}
	state.inputDigests = InputDigests{Catalog: catalogDigest, Oracle: oracleDigest, Ratchet: ratchetDigest, Policy: sha256Digest(policyBytes)}
	if state.ratchet.CatalogDigest != catalogDigest || state.ratchet.OracleDigest != oracleDigest || state.ratchet.CatalogRevision != state.catalog.Revision {
		return errors.New("ratchet does not bind the frozen catalog and oracle")
	}
	states, err := expectedCellStates(state.catalog, state.oracle)
	if err != nil {
		return err
	}
	state.expectedStates = states
	review, disposition, err := readReviewEvidence(state.input.TrustedInputRoot, state.input.ImplementationCommit)
	if err != nil {
		return err
	}
	state.bindReviewEvidence(review, disposition)
	return nil
}

func ownedBuildArguments(binaryPath string) []string {
	return []string{
		"build",
		"-ldflags", "-X " + ownedBenchmarkVersionLinkerSymbol + "=" + ownedBenchmarkVersion,
		"-o", binaryPath,
		"./cmd/synapse-sca-bench",
	}
}

func (state *runState) buildAndBindOwnedBinary(ctx context.Context) error {
	binaryPath := filepath.Join(state.workRoot, "tools", "synapse-sca-bench")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		return fmt.Errorf("create owned binary directory: %w", err)
	}
	command := exec.CommandContext(ctx, "go", ownedBuildArguments(binaryPath)...)
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return fmt.Errorf("build owned benchmark binary: %w", err)
	}
	_, err := state.bindOwnedBinaryDigest(binaryPath)
	return err
}

func (state *runState) bindOwnedBinaryDigest(binaryPath string) (string, error) {
	if state == nil {
		return "", errors.New("owned binary state is required")
	}
	digest, err := digestFile(binaryPath)
	if err != nil {
		return "", fmt.Errorf("digest owned benchmark binary: %w", err)
	}
	updated := false
	for index := range state.catalog.Pins {
		if state.catalog.Pins[index].Reference == "binary:synapse-sca-bench:reproducible-v1" {
			state.catalog.Pins[index].Digest = digest
			updated = true
		}
	}
	if !updated {
		return "", errors.New("catalog does not pin the owned benchmark binary")
	}
	if err := state.catalog.Validate(); err != nil {
		return "", fmt.Errorf("validate rebound catalog: %w", err)
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return "", fmt.Errorf("digest rebound catalog: %w", err)
	}
	state.ratchet.CatalogDigest = catalogDigest
	for index := range state.ratchet.Floors {
		if state.ratchet.Floors[index].Expected.Engine == bench.EngineOwned {
			state.ratchet.Floors[index].Expected.EngineBinaryDigest = digest
		}
	}
	return digest, nil
}

func (state *runState) materializeManifests() error {
	templates, err := state.loadTemplates()
	if err != nil {
		return err
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return err
	}
	manifests := make(map[string]CaptureManifest, len(templates))
	for _, target := range state.catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			template, ok := templates[key]
			if !ok {
				return fmt.Errorf("missing capture manifest template for %s", key)
			}
			manifest, err := state.materializeManifest(catalogDigest, target, template)
			if err != nil {
				return fmt.Errorf("materialize %s: %w", key, err)
			}
			manifests[key] = manifest
		}
	}
	state.manifests = manifests
	return nil
}

func (state *runState) loadTemplates() (map[string]captureManifestTemplate, error) {
	directory := filepath.Join(state.input.CorpusRoot, "capture-manifests")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read capture manifest templates: %w", err)
	}
	templates := make(map[string]captureManifestTemplate, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		var template captureManifestTemplate
		if err := strictDecodeFile(path, &template); err != nil {
			return nil, err
		}
		key := runCellKey(template.TargetID, template.Engine)
		if template.SchemaVersion != "synapse-sca-benchmark-capture-manifest-template-v1" || template.TargetID == "" || template.Engine == "" || template.EngineVersion == "" {
			return nil, fmt.Errorf("capture manifest template %q is incomplete", entry.Name())
		}
		if _, exists := templates[key]; exists {
			return nil, fmt.Errorf("duplicate capture manifest template for %s", key)
		}
		templates[key] = template
	}
	if len(templates) != fixedMatrixCells {
		return nil, errors.New("capture manifest templates do not cover the fixed twelve-cell matrix")
	}
	return templates, nil
}

func (state *runState) materializeManifest(catalogDigest string, target bench.Target, template captureManifestTemplate) (CaptureManifest, error) {
	if template.TargetID != target.ID {
		return CaptureManifest{}, errors.New("capture manifest template target does not match the catalog target")
	}
	paths, err := state.resolveTrustedManifestPaths(template)
	if err != nil {
		return CaptureManifest{}, err
	}
	manifest := CaptureManifest{
		SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: state.catalog.Revision, CatalogDigest: catalogDigest,
		TargetID: target.ID, SBOMPath: paths.sbom, Engine: template.Engine, EngineVersion: template.EngineVersion,
		Binary:                  Artifact{Reference: template.Binary.Reference, Path: paths.binary},
		Database:                DatabaseArtifact{Reference: template.Database.Reference, Path: paths.database, Build: template.Database.Build, Format: template.Database.Format},
		Environment:             template.Environment,
		EnvironmentAttestation:  Artifact{Reference: template.EnvironmentAttestation.Reference, Path: paths.environmentAttestation},
		EnvironmentPinReference: template.EnvironmentPinReference, ProfilePinReference: template.ProfilePinReference, Limits: template.Limits,
	}
	if state.expectedStates[runCellKey(target.ID, template.Engine)] == bench.ObservationUnsupported {
		if template.Capability == nil {
			return CaptureManifest{}, errors.New("unsupported cell has no capability template")
		}
		statement, digest, err := state.materializeCapability(catalogDigest, target, template)
		if err != nil {
			return CaptureManifest{}, err
		}
		path := filepath.Join(state.workRoot, "capabilities", target.ID+"--"+string(template.Engine)+".json")
		body, err := bench.CanonicalJSON(statement)
		if err != nil {
			return CaptureManifest{}, err
		}
		if err := writeNewFile(path, body, 0o600); err != nil {
			return CaptureManifest{}, err
		}
		sources, err := state.capabilitySources(template.Capability.Sources)
		if err != nil {
			return CaptureManifest{}, err
		}
		manifest.Capability = &CapabilityManifest{
			Statement: CapabilityArtifact{Reference: template.Capability.StatementReference, Path: path, Digest: digest}, Sources: sources,
		}
	} else if template.Capability != nil {
		return CaptureManifest{}, errors.New("dispatched cell carries a capability template")
	}
	if err := manifest.Validate(); err != nil {
		return CaptureManifest{}, err
	}
	return manifest, nil
}

func (state *runState) resolveTrustedManifestPaths(template captureManifestTemplate) (trustedManifestPaths, error) {
	root, err := benchcycle.RealDirectory(state.input.TrustedInputRoot)
	if err != nil {
		return trustedManifestPaths{}, fmt.Errorf("resolve trusted input root: %w", err)
	}
	identity, err := trustedCaptureInputForTemplate(template)
	if err != nil {
		return trustedManifestPaths{}, err
	}
	sbomPath, err := belowRoot(root, fixedTrustedSBOMLocators[template.TargetID])
	if err != nil {
		return trustedManifestPaths{}, fmt.Errorf("resolve trusted SBOM: %w", err)
	}
	databasePath, err := belowRootDirectory(root, identity.databaseLocator)
	if err != nil {
		return trustedManifestPaths{}, fmt.Errorf("resolve trusted database: %w", err)
	}
	environmentPath, err := belowRoot(root, trustedEnvironmentAttestationLocator)
	if err != nil {
		return trustedManifestPaths{}, fmt.Errorf("resolve trusted environment attestation: %w", err)
	}
	binaryPath := filepath.Join(state.workRoot, "tools", "synapse-sca-bench")
	if template.Engine != bench.EngineOwned {
		binaryPath, err = belowRoot(root, identity.binaryLocator)
		if err != nil {
			return trustedManifestPaths{}, fmt.Errorf("resolve trusted engine binary: %w", err)
		}
	}
	if !filepath.IsAbs(binaryPath) {
		return trustedManifestPaths{}, errors.New("materialized engine binary path is not absolute")
	}
	return trustedManifestPaths{
		binary: binaryPath, database: databasePath, sbom: sbomPath, environmentAttestation: environmentPath,
	}, nil
}

func trustedCaptureInputForTemplate(template captureManifestTemplate) (trustedCaptureInput, error) {
	if _, exists := fixedTrustedSBOMLocators[template.TargetID]; !exists {
		return trustedCaptureInput{}, fmt.Errorf("capture manifest template target %q is not fixed", template.TargetID)
	}
	if template.EnvironmentAttestation.Reference != trustedEnvironmentAttestationReference {
		return trustedCaptureInput{}, errors.New("capture manifest template has an unknown environment attestation")
	}
	var identity trustedCaptureInput
	var exists bool
	switch template.Engine {
	case bench.EngineOwned:
		identity, exists = fixedTrustedOwnedInputs[template.TargetID]
	default:
		identity, exists = fixedTrustedCompetitorInputs[template.Engine]
	}
	if !exists || template.EngineVersion != identity.engineVersion || template.Binary.Reference != identity.binaryReference || template.Database.Reference != identity.databaseReference {
		return trustedCaptureInput{}, errors.New("capture manifest template has an unrecognized trusted input identity")
	}
	return identity, nil
}

func canonicalCapabilityComponents(kind bench.CapabilityKind, input []bench.Component) ([]bench.Component, error) {
	type keyedComponent struct {
		component bench.Component
		key       string
	}
	keyed := make([]keyedComponent, 0, len(input))
	for i, component := range input {
		if !isCapabilityRPMCandidate(kind, component.PURL) {
			continue
		}
		key, err := capabilityComponentKey(kind, component)
		if err != nil {
			return nil, fmt.Errorf("capability component %d: %w", i, err)
		}
		keyed = append(keyed, keyedComponent{
			component: component,
			key:       key.Ecosystem + "\x00" + key.Package + "\x00" + key.Version,
		})
	}
	sort.Slice(keyed, func(i, j int) bool { return keyed[i].key < keyed[j].key })
	components := make([]bench.Component, len(keyed))
	for i := range keyed {
		components[i] = keyed[i].component
	}
	return components, nil
}

func (state *runState) materializeCapability(catalogDigest string, target bench.Target, template captureManifestTemplate) (CapabilityStatement, string, error) {
	if template.Capability == nil {
		return CapabilityStatement{}, "", errors.New("capability template is required")
	}
	rule, ok := capabilityRule(template.Capability.Kind)
	if !ok {
		return CapabilityStatement{}, "", errors.New("capability template has an unsupported kind")
	}
	binaryDigest, err := catalogPin(state.catalog, template.Binary.Reference)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	databaseDigest, err := catalogPin(state.catalog, template.Database.Reference)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	environmentDigest, err := catalogPin(state.catalog, template.EnvironmentPinReference)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	configDigest, err := catalogPin(state.catalog, template.ProfilePinReference)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	sources, err := state.capabilitySources(template.Capability.Sources)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	components, err := canonicalCapabilityComponents(template.Capability.Kind, target.Components)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	statementSources := make([]CapabilityStatementSource, 0, len(sources))
	for _, source := range sources {
		statementSources = append(statementSources, CapabilityStatementSource{Reference: source.Reference, Digest: source.Digest})
	}
	statement := CapabilityStatement{
		SchemaVersion: CapabilityStatementSchemaVersion, Kind: template.Capability.Kind,
		DecisionRuleRevision: rule.decisionRuleRevision, Scope: CapabilityScopeSameSBOMOSPackageMatching,
		CatalogRevision: state.catalog.Revision, CatalogDigest: catalogDigest, TargetID: target.ID, TargetDigest: target.Digest,
		SBOMDigest: target.SBOMDigest, Engine: template.Engine, EngineVersion: template.EngineVersion,
		EngineBinaryDigest: binaryDigest, DatabaseBuild: template.Database.Build, DatabaseDigest: databaseDigest,
		EnvironmentID: template.Environment.ID, EnvironmentDigest: environmentDigest, ConfigDigest: configDigest,
		Components: components, Sources: statementSources,
	}
	if err := statement.Validate(); err != nil {
		return CapabilityStatement{}, "", err
	}
	body, err := bench.CanonicalJSON(statement)
	if err != nil {
		return CapabilityStatement{}, "", err
	}
	return statement, bench.SHA256Digest(body), nil
}

func (state *runState) capabilitySources(templates []capabilitySourceTemplate) ([]CapabilityArtifact, error) {
	if len(templates) == 0 {
		return nil, errors.New("capability source templates are required")
	}
	root, err := benchcycle.RealDirectory(state.input.TrustedInputRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted input root: %w", err)
	}
	artifacts := make([]CapabilityArtifact, 0, len(templates))
	for _, template := range templates {
		identity, exists := fixedTrustedCapabilitySources[template.Reference]
		if !exists || template.Locator != identity.locator || template.Digest == "" {
			return nil, errors.New("capability source template has an unrecognized trusted input identity")
		}
		path, err := belowRoot(root, "repository/"+identity.locator)
		if err != nil {
			return nil, err
		}
		digest, err := digestFile(path)
		if err != nil {
			return nil, err
		}
		if digest != template.Digest {
			return nil, fmt.Errorf("capability source %q digest differs from its frozen template", identity.locator)
		}
		if catalogDigest, exists := catalogPinOptional(state.catalog, identity.pinReference); exists && catalogDigest != digest {
			return nil, fmt.Errorf("capability source %q differs from its catalog pin", identity.locator)
		}
		artifacts = append(artifacts, CapabilityArtifact{Reference: template.Reference, Path: path, Digest: digest})
	}
	return artifacts, nil
}

func (state *runState) validateRatchetBindings() error {
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return err
	}
	floors := make(map[string]*bench.RatchetFloor, len(state.ratchet.Floors))
	for index := range state.ratchet.Floors {
		floor := &state.ratchet.Floors[index]
		floors[runCellKey(floor.Expected.TargetID, floor.Expected.Engine)] = floor
	}
	for key, manifest := range state.manifests {
		floor := floors[key]
		if floor == nil {
			return fmt.Errorf("ratchet omits floor for %s", key)
		}
		target, ok := catalogTarget(state.catalog, manifest.TargetID)
		if !ok {
			return fmt.Errorf("manifest target %q is absent", manifest.TargetID)
		}
		binaryDigest, err := catalogPin(state.catalog, manifest.Binary.Reference)
		if err != nil {
			return err
		}
		databaseDigest, err := catalogPin(state.catalog, manifest.Database.Reference)
		if err != nil {
			return err
		}
		environmentDigest, err := catalogPin(state.catalog, manifest.EnvironmentPinReference)
		if err != nil {
			return err
		}
		configDigest, err := catalogPin(state.catalog, manifest.ProfilePinReference)
		if err != nil {
			return err
		}
		expected := &floor.Expected
		if expected.TargetDigest != target.Digest || expected.SBOMDigest != target.SBOMDigest || expected.EngineVersion != manifest.EngineVersion || expected.EngineBinaryDigest != binaryDigest || expected.DatabaseBuild != manifest.Database.Build || expected.DatabaseDigest != databaseDigest || expected.EnvironmentID != manifest.Environment.ID || expected.EnvironmentDigest != environmentDigest || expected.ConfigDigest != configDigest {
			return fmt.Errorf("ratchet floor %s does not bind the materialized capture", key)
		}
		if manifest.Capability != nil {
			body, err := readRegularFile(manifest.Capability.Statement.Path)
			if err != nil {
				return fmt.Errorf("read capability statement for %s: %w", key, err)
			}
			statement, err := decodeCapabilityStatement(body)
			if err != nil {
				return fmt.Errorf("decode capability statement for %s: %w", key, err)
			}
			expected.CapabilityKind = statement.Kind
			expected.CapabilityDigest = manifest.Capability.Statement.Digest
		} else if expected.CapabilityDigest != "" || expected.CapabilityKind != "" {
			return fmt.Errorf("ratchet floor %s has unexpected capability identity", key)
		}
	}
	state.ratchet.CatalogDigest = catalogDigest
	if err := state.ratchet.Validate(); err != nil {
		return fmt.Errorf("validate rebound ratchet: %w", err)
	}
	if err := state.refreshBoundInputDigests(); err != nil {
		return err
	}
	return nil
}

func (state *runState) refreshBoundInputDigests() error {
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return fmt.Errorf("digest rebound catalog: %w", err)
	}
	ratchetDigest, err := bench.DigestRatchet(state.ratchet)
	if err != nil {
		return fmt.Errorf("digest rebound ratchet: %w", err)
	}
	state.inputDigests.Catalog = catalogDigest
	state.inputDigests.Ratchet = ratchetDigest
	return nil
}

func (state *runState) bindReviewEvidence(review, disposition []byte) {
	state.review = review
	state.disposition = disposition
	state.inputDigests.Review = sha256Digest(review)
	state.inputDigests.Disposition = sha256Digest(disposition)
}

func (state *runState) captureCell(ctx context.Context, address benchcycle.AttemptAddress, manifest CaptureManifest, runnerFactory RunnerFactory, store *benchcycle.EvidenceStore) (bench.Observation, BundleIdentity, string, error) {
	if err := ctx.Err(); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", err
	}
	prepared, err := Prepare(state.catalog, manifest)
	if err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("prepare capture: %w", err)
	}
	defer func() { _ = prepared.Close() }()
	var captured CaptureResult
	if manifest.Capability != nil {
		captured, err = CaptureCapabilityPrepared(prepared)
	} else {
		if runnerFactory == nil {
			return bench.Observation{}, BundleIdentity{}, "", errors.New("runner factory is required")
		}
		runner, runnerErr := runnerFactory(manifest.Limits)
		if runnerErr != nil {
			return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("create capture runner: %w", runnerErr)
		}
		captured, err = NewCapturer(runner).CapturePrepared(ctx, prepared)
	}
	if err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("capture bundle: %w", err)
	}
	path, err := state.storeBundle(ctx, store, address, captured)
	if err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("write capture bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", err
	}
	if err := ValidateBundleContext(ctx, path); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("validate written capture bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", err
	}
	identity, err := BundleIdentityFromPathContext(ctx, path)
	if err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("identify written capture bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", err
	}
	return captured.Observation(), identity, path, nil
}

func (state *runState) newEvidenceStore() (*benchcycle.EvidenceStore, error) {
	if err := os.MkdirAll(state.rawRunRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create protected raw evidence root: %w", err)
	}
	return benchcycle.NewEvidenceStore(state.rawRunRoot, evidenceStoreLimits())
}

func evidenceStoreLimits() benchcycle.EvidenceLimits {
	// A capture retains evidence.json plus four base manifests and, for capability
	// cells, one statement and the fixed pair of authoritative sources.
	maxCaptureBytes := maxBundleArtifactBytes + int64(maxRawBundleArtifacts-1)*maxManifestBytes
	return benchcycle.EvidenceLimits{
		MaxArtifactBytes: maxBundleArtifactBytes,
		MaxTotalBytes:    int64(fixedMatrixCells*fixedRepetitions) * maxCaptureBytes,
		MaxFiles:         fixedMatrixCells * fixedRepetitions * maxRawBundleArtifacts,
	}
}

func (state *runState) storeBundle(ctx context.Context, store *benchcycle.EvidenceStore, address benchcycle.AttemptAddress, result CaptureResult) (string, error) {
	if store == nil {
		return "", errors.New("raw evidence store is required")
	}
	artifacts, err := bundleArtifactsContext(ctx, result)
	if err != nil {
		return "", err
	}
	var directory string
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := validateBundleArtifactData(artifact.name, artifact.data); err != nil {
			return "", err
		}
		receipt, err := store.Write(ctx, address, artifact.name, bytes.NewReader(artifact.data))
		if err != nil {
			return "", err
		}
		current := filepath.Dir(receipt.Reference)
		if directory == "" {
			directory = current
		} else if directory != current {
			return "", errors.New("raw evidence artifacts do not share an attempt directory")
		}
	}
	if directory == "" {
		return "", errors.New("capture bundle has no artifacts")
	}
	return filepath.Join(state.rawRunRoot, filepath.FromSlash(directory)), nil
}

func reduceRepetitions(catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, observations [][]bench.Observation) (bench.Result, []byte, []byte, error) {
	return reduceRepetitionsContext(context.Background(), catalog, oracle, ratchet, observations)
}

func requireTrustedCycleResult(result bench.Result) error {
	if result.Gate == nil {
		return errors.New("absolute ratchet gate is missing")
	}
	if !result.Gate.Passed {
		return errors.New("absolute ratchet gate did not pass")
	}
	if err := bench.ValidateMeasuredPerTargetRecallParity(result, fixedTargetIDs); err != nil {
		return fmt.Errorf("measured per-target recall parity: %w", err)
	}
	return nil
}

func reduceRepetitionsContext(ctx context.Context, catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, observations [][]bench.Observation) (bench.Result, []byte, []byte, error) {
	if ctx == nil {
		return bench.Result{}, nil, nil, errors.New("reduction context is required")
	}
	var expectedResult []byte
	var expectedReport []byte
	for index, repetition := range observations {
		if err := ctx.Err(); err != nil {
			return bench.Result{}, nil, nil, err
		}
		result, err := bench.Reduce(catalog, oracle, repetition)
		if err != nil {
			return bench.Result{}, nil, nil, fmt.Errorf("reduce repetition %d: %w", index+1, err)
		}
		result, err = bench.ApplyRatchet(result, ratchet)
		if err != nil {
			return bench.Result{}, nil, nil, fmt.Errorf("apply ratchet to repetition %d: %w", index+1, err)
		}
		if err := requireTrustedCycleResult(result); err != nil {
			return bench.Result{}, nil, nil, fmt.Errorf("validate trusted result for repetition %d: %w", index+1, err)
		}
		if err := ctx.Err(); err != nil {
			return bench.Result{}, nil, nil, err
		}
		var resultBuffer bytes.Buffer
		if err := bench.EncodeResult(&resultBuffer, result); err != nil {
			return bench.Result{}, nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return bench.Result{}, nil, nil, err
		}
		var reportBuffer bytes.Buffer
		if err := bench.RenderResult(&reportBuffer, result); err != nil {
			return bench.Result{}, nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return bench.Result{}, nil, nil, err
		}
		if index == 0 {
			expectedResult, expectedReport = resultBuffer.Bytes(), reportBuffer.Bytes()
			continue
		}
		if !bytes.Equal(expectedResult, resultBuffer.Bytes()) || !bytes.Equal(expectedReport, reportBuffer.Bytes()) {
			return bench.Result{}, nil, nil, fmt.Errorf("repetition %d reduction differs", index+1)
		}
	}
	final, err := bench.DecodeResult(bytes.NewReader(expectedResult))
	if err != nil {
		return bench.Result{}, nil, nil, fmt.Errorf("decode canonical result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return bench.Result{}, nil, nil, err
	}
	return final, expectedResult, expectedReport, nil
}

func (state *runState) clean(ctx context.Context) error {
	if state.cleanup.RawRunRemoved && (!state.cleanupRequired || state.cleanup.DockerCleaned) {
		return nil
	}
	var runtimeCleanup func(context.Context) error
	if state.cleanupRequired {
		runtimeCleanup = state.runtimeCleanup
		if runtimeCleanup == nil {
			runtimeCleanup = func(ctx context.Context) error {
				return cleanDocker(ctx, "docker")
			}
		}
	}
	if err := state.workspace.Cleanup(ctx, runtimeCleanup); err != nil {
		return err
	}
	state.cleanup.RawRunRemoved = true
	state.cleanup.DockerCleaned = state.cleanupRequired
	return nil
}

func cleanDocker(ctx context.Context, binary string) error {
	for _, args := range [][]string{{"container", "prune", "-f"}, {"volume", "prune", "-af"}, {"image", "prune", "-af"}, {"builder", "prune", "-af"}} {
		if err := exec.CommandContext(ctx, binary, args...).Run(); err != nil {
			return fmt.Errorf("clean Docker state: %w", err)
		}
	}
	return nil
}

func (state *runState) beginPublication() (*benchcycle.Publication, error) {
	verify := state.stageVerifier
	if verify == nil {
		verify = verifyFinalPublication
	}
	return benchcycle.BeginPublication(state.input.OutputRoot, benchcycle.PublicationLimits{
		MaxFileBytes:   maxPublicationFileBytes,
		MaxTotalBytes:  maxPublicationTotalBytes,
		MaxFiles:       expectedPublicationFileCount(),
		CleanupTimeout: publicationCleanupTimeout,
	}, state.clean, verify)
}

func (state *runState) stagePublication(ctx context.Context, publication *benchcycle.Publication, result *RunResult, resultBytes, report []byte) error {
	if publication == nil {
		return errors.New("publication is required")
	}
	if result == nil {
		return errors.New("run result is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The staged run can only be published after the cleanup barrier succeeds.
	result.Cleanup = CleanupResult{RawRunRemoved: true, DockerCleaned: true}
	artifacts, err := state.publicationArtifacts(ctx, *result, resultBytes, report)
	if err != nil {
		return err
	}
	if len(artifacts) != expectedPublicationFileCount() {
		return errors.New("sanitized publication artifact set is incomplete")
	}
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := publication.WriteBytes(ctx, artifact.path, artifact.body); err != nil {
			return fmt.Errorf("stage sanitized artifact %q: %w", artifact.path, err)
		}
	}
	return ctx.Err()
}

func (state *runState) publicationArtifacts(ctx context.Context, result RunResult, resultBytes, report []byte) ([]publicationArtifact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	catalog, err := bench.CanonicalJSON(state.catalog)
	if err != nil {
		return nil, err
	}
	oracle, err := bench.CanonicalJSON(state.oracle)
	if err != nil {
		return nil, err
	}
	ratchet, err := bench.CanonicalJSON(state.ratchet)
	if err != nil {
		return nil, err
	}
	run, err := bench.CanonicalJSON(result)
	if err != nil {
		return nil, err
	}
	policy, err := readRegularFileContext(ctx, filepath.Join(state.input.CorpusRoot, "cycle-policy.json"), maxPublicationFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read cycle policy for publication: %w", err)
	}
	artifacts := []publicationArtifact{
		{path: "catalog.json", body: catalog},
		{path: "oracle.json", body: oracle},
		{path: "ratchet.json", body: ratchet},
		{path: "cycle-policy.json", body: policy},
		{path: "run.json", body: run},
		{path: "result.json", body: resultBytes},
		{path: "report.md", body: report},
		{path: "reviews/review.json", body: state.review},
		{path: "reviews/disposition.json", body: state.disposition},
	}
	for _, target := range state.catalog.Targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, readErr := readRegularFileContext(ctx, filepath.Join(state.input.TrustedInputRoot, "sboms", target.ID+".cdx.json"), maxPublicationFileBytes)
		if readErr != nil {
			return nil, readErr
		}
		artifacts = append(artifacts, publicationArtifact{path: "sboms/" + target.ID + ".cdx.json", body: body})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func verifyFinalPublication(ctx context.Context, stage string, identities []benchcycle.FileIdentity) error {
	if ctx == nil {
		return errors.New("publication verification context is required")
	}
	files, err := publicationStageFiles(ctx, stage, identities)
	if err != nil {
		return err
	}
	catalog, err := bench.DecodeCatalog(bytes.NewReader(files["catalog.json"]))
	if err != nil {
		return fmt.Errorf("decode staged catalog: %w", err)
	}
	if err := validateFixedTargetMatrix(catalog); err != nil {
		return err
	}
	oracle, err := bench.DecodeOracle(bytes.NewReader(files["oracle.json"]))
	if err != nil {
		return fmt.Errorf("decode staged oracle: %w", err)
	}
	if err := bench.Validate(catalog, oracle); err != nil {
		return fmt.Errorf("validate staged catalog and oracle: %w", err)
	}
	ratchet, err := bench.DecodeRatchet(bytes.NewReader(files["ratchet.json"]))
	if err != nil {
		return fmt.Errorf("decode staged ratchet: %w", err)
	}
	if err := ratchet.Validate(); err != nil {
		return fmt.Errorf("validate staged ratchet: %w", err)
	}
	policy, err := decodePolicyBytes(files["cycle-policy.json"])
	if err != nil {
		return fmt.Errorf("decode staged cycle policy: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var run RunResult
	if err := strictDecodeBytes(files["run.json"], &run); err != nil {
		return fmt.Errorf("decode staged run: %w", err)
	}
	if err := validateStagedRun(ctx, run, catalog, oracle, ratchet, policy, files); err != nil {
		return err
	}
	return ctx.Err()
}

func publicationStageFiles(ctx context.Context, stage string, identities []benchcycle.FileIdentity) (map[string][]byte, error) {
	if len(identities) != expectedPublicationFileCount() {
		return nil, errors.New("sanitized publication artifact set is incomplete")
	}
	files := make(map[string][]byte, len(identities))
	for _, identity := range identities {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, exists := files[identity.Path]; exists {
			return nil, fmt.Errorf("staged artifact %q is duplicated", identity.Path)
		}
		path := filepath.Join(stage, filepath.FromSlash(identity.Path))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != identity.Size {
			return nil, fmt.Errorf("staged artifact %q does not match its durable identity", identity.Path)
		}
		body, digest, err := readRegularFileDigestContext(ctx, path, identity.Size)
		if err != nil || int64(len(body)) != identity.Size || digest != "sha256:"+identity.Digest {
			return nil, fmt.Errorf("read staged artifact %q", identity.Path)
		}
		files[identity.Path] = body
	}
	return files, nil
}

func validateStagedRun(ctx context.Context, run RunResult, catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, policy cyclePolicy, files map[string][]byte) error {
	if run.SchemaVersion != runResultSchemaVersion || run.Repetitions != fixedRepetitions || run.Cleanup != (CleanupResult{RawRunRemoved: true, DockerCleaned: true}) {
		return errors.New("staged run does not carry the fixed lifecycle contract")
	}
	if err := benchcycle.ValidateIdentity(run.ImplementationCommit, run.RunKey); err != nil {
		return fmt.Errorf("validate staged run identity: %w", err)
	}
	if policy.Repetitions != fixedRepetitions {
		return errors.New("staged cycle policy repetitions differ from run")
	}
	if err := validateStagedArtifactSet(catalog, files); err != nil {
		return err
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return err
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return err
	}
	if run.InputDigests.Catalog != catalogDigest || run.InputDigests.Oracle != oracleDigest || run.InputDigests.Ratchet != ratchetDigest ||
		run.InputDigests.Policy != sha256Digest(files["cycle-policy.json"]) || run.InputDigests.Review != sha256Digest(files["reviews/review.json"]) || run.InputDigests.Disposition != sha256Digest(files["reviews/disposition.json"]) {
		return errors.New("staged run input digests do not bind staged artifacts")
	}
	if err := validateReviewEvidence(files["reviews/review.json"], files["reviews/disposition.json"], run.ImplementationCommit); err != nil {
		return fmt.Errorf("validate staged review evidence: %w", err)
	}
	if err := validateStagedCycleOrder(run, catalog, oracle); err != nil {
		return err
	}
	final, resultBytes, report, err := reduceRepetitionsContext(ctx, catalog, oracle, ratchet, run.Observations)
	if err != nil {
		return fmt.Errorf("replay staged reduction: %w", err)
	}
	if !bytes.Equal(resultBytes, files["result.json"]) || !bytes.Equal(report, files["report.md"]) {
		return errors.New("staged result or report does not match replay")
	}
	stagedResult, err := bench.DecodeResult(bytes.NewReader(files["result.json"]))
	if err != nil {
		return fmt.Errorf("decode staged result: %w", err)
	}
	var runResult bytes.Buffer
	if err := bench.EncodeResult(&runResult, run.Result); err != nil || !bytes.Equal(runResult.Bytes(), resultBytes) {
		return errors.New("staged run result does not match replay")
	}
	var decodedResult bytes.Buffer
	if err := bench.EncodeResult(&decodedResult, stagedResult); err != nil || !bytes.Equal(decodedResult.Bytes(), resultBytes) {
		return errors.New("staged result encoding is not canonical")
	}
	if encoded, err := bench.CanonicalJSON(final); err != nil || len(encoded) == 0 {
		return errors.New("replayed staged result is not canonical")
	}
	return ctx.Err()
}

func validateStagedArtifactSet(catalog bench.Catalog, files map[string][]byte) error {
	expected := make(map[string]struct{}, expectedPublicationFileCount())
	for _, path := range fixedPublicationArtifactPaths {
		expected[path] = struct{}{}
	}
	for _, target := range catalog.Targets {
		path := "sboms/" + target.ID + ".cdx.json"
		expected[path] = struct{}{}
		body, found := files[path]
		if !found || bench.SHA256Digest(body) != target.SBOMDigest {
			return fmt.Errorf("staged SBOM %q does not match catalog", target.ID)
		}
	}
	if len(files) != len(expected) {
		return errors.New("staged artifact set is incomplete or unexpected")
	}
	for path := range files {
		if _, found := expected[path]; !found {
			return fmt.Errorf("staged artifact %q is unexpected", path)
		}
	}
	return nil
}

func validateStagedCycleOrder(run RunResult, catalog bench.Catalog, oracle bench.Oracle) error {
	if len(run.Observations) != fixedRepetitions || len(run.RawBundles) != fixedRepetitions || len(run.Comparisons) != fixedMatrixCells {
		return errors.New("staged run has an incomplete fixed cycle")
	}
	expectedStates, err := expectedCellStates(catalog, oracle)
	if err != nil {
		return err
	}
	for repetition := range fixedRepetitions {
		if len(run.Observations[repetition]) != fixedMatrixCells || len(run.RawBundles[repetition]) != fixedMatrixCells {
			return errors.New("staged run repetitions do not cover the fixed matrix")
		}
	}
	index := 0
	for _, target := range catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			for repetition := range fixedRepetitions {
				observation := run.Observations[repetition][index]
				identity := run.RawBundles[repetition][index]
				if observation.TargetID != target.ID || observation.Engine != engine || observation.State != expectedStates[key] || identity.TargetID != target.ID || identity.Engine != engine {
					return fmt.Errorf("staged run cell %q is out of canonical order", key)
				}
			}
			comparison := run.Comparisons[index]
			if comparison.TargetID != target.ID || comparison.Engine != engine || comparison.ExpectedState != expectedStates[key] || !comparison.SemanticEqual || len(comparison.UnclassifiedDifferences) != 0 {
				return fmt.Errorf("staged comparison for %q is invalid", key)
			}
			index++
		}
	}
	return nil
}

func decodeCatalogFile(path string) (bench.Catalog, error) {
	body, err := readRegularFile(path)
	if err != nil {
		return bench.Catalog{}, fmt.Errorf("read catalog: %w", err)
	}
	return bench.DecodeCatalog(bytes.NewReader(body))
}

func decodeOracleFile(path string) (bench.Oracle, error) {
	body, err := readRegularFile(path)
	if err != nil {
		return bench.Oracle{}, fmt.Errorf("read oracle: %w", err)
	}
	return bench.DecodeOracle(bytes.NewReader(body))
}

func decodeRatchetFile(path string) (bench.Ratchet, error) {
	body, err := readRegularFile(path)
	if err != nil {
		return bench.Ratchet{}, fmt.Errorf("read ratchet: %w", err)
	}
	return bench.DecodeRatchet(bytes.NewReader(body))
}

func decodePolicyFile(path string) (cyclePolicy, error) {
	body, err := readRegularFile(path)
	if err != nil {
		return cyclePolicy{}, err
	}
	return decodePolicyBytes(body)
}

func decodePolicyBytes(body []byte) (cyclePolicy, error) {
	var policy cyclePolicy
	if err := strictDecodeBytes(body, &policy); err != nil {
		return cyclePolicy{}, err
	}
	if policy.SchemaVersion != "synapse-sca-benchmark-cycle-policy-v1" || policy.AcceptedArtifactRetentionDays != 90 || policy.RawRetention != "delete_after_verification" || policy.Repetitions != fixedRepetitions {
		return cyclePolicy{}, errors.New("invalid fixed cycle policy")
	}
	return policy, nil
}

func strictDecodeFile(path string, output any) error {
	body, err := readRegularFile(path)
	if err != nil {
		return err
	}
	if err := strictDecodeBytes(body, output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func strictDecodeBytes(body []byte, output any) error {
	if err := bench.ValidateJSONDocument(bytes.NewReader(body)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func ensureEOF(decoder *json.Decoder) error {
	var value any
	if err := decoder.Decode(&value); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func expectedCellStates(catalog bench.Catalog, oracle bench.Oracle) (map[string]bench.ObservationState, error) {
	cases := make(map[string][]bench.OracleCase, len(catalog.Targets))
	for _, item := range oracle.Cases {
		cases[item.TargetID] = append(cases[item.TargetID], item)
	}
	states := make(map[string]bench.ObservationState, len(catalog.Targets)*len(bench.Engines()))
	for _, target := range catalog.Targets {
		if len(cases[target.ID]) == 0 {
			return nil, fmt.Errorf("target %q has no oracle cases", target.ID)
		}
		for _, engine := range bench.Engines() {
			unsupported := true
			for _, item := range cases[target.ID] {
				coverage, ok := item.ExpectedCoverage[engine]
				if !ok {
					return nil, fmt.Errorf("oracle case %q omits coverage for %q", item.ID, engine)
				}
				if coverage != bench.CoverageUnsupported {
					unsupported = false
				}
			}
			state := bench.ObservationComplete
			if unsupported {
				state = bench.ObservationUnsupported
			}
			states[runCellKey(target.ID, engine)] = state
		}
	}
	return states, nil
}

func validateFixedTargetMatrix(catalog bench.Catalog) error {
	if len(catalog.Targets) != len(fixedTargetIDs) {
		return fmt.Errorf("frozen catalog must contain exactly %d benchmark targets", len(fixedTargetIDs))
	}
	seen := make(map[string]struct{}, len(catalog.Targets))
	for _, target := range catalog.Targets {
		seen[target.ID] = struct{}{}
	}
	for _, targetID := range fixedTargetIDs {
		if _, ok := seen[targetID]; !ok {
			return fmt.Errorf("frozen catalog omits fixed benchmark target %q", targetID)
		}
	}
	return nil
}

func readReviewEvidence(root, implementationCommit string) ([]byte, []byte, error) {
	reviewPath, err := singleJSONFile(root, "repository/reviews/github")
	if err != nil {
		return nil, nil, fmt.Errorf("read independent review: %w", err)
	}
	dispositionPath, err := singleJSONFile(root, "repository/reviews/dispositions/github")
	if err != nil {
		return nil, nil, fmt.Errorf("read maintainer disposition: %w", err)
	}
	review, err := readRegularFile(reviewPath)
	if err != nil {
		return nil, nil, err
	}
	disposition, err := readRegularFile(dispositionPath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateReviewEvidence(review, disposition, implementationCommit); err != nil {
		return nil, nil, err
	}
	return review, disposition, nil
}

func validateReviewEvidence(review, disposition []byte, implementationCommit string) error {
	var reviewRecord reviewCapture
	var dispositionRecord dispositionCapture
	if err := strictDecodeBytes(review, &reviewRecord); err != nil {
		return err
	}
	if err := strictDecodeBytes(disposition, &dispositionRecord); err != nil {
		return err
	}
	if reviewRecord.SchemaVersion != reviewCaptureSchemaVersion || reviewRecord.State != "COMMENTED" || reviewRecord.ID == "" || reviewRecord.URL == "" || reviewRecord.Login == "" || reviewRecord.CommitID == "" || reviewRecord.Body == "" {
		return errors.New("independent review must be a complete COMMENTED review")
	}
	if _, err := time.Parse(time.RFC3339, reviewRecord.SubmittedAt); err != nil {
		return errors.New("independent review timestamp is invalid")
	}
	if err := validateGitHubPRURL(reviewRecord.URL, reviewRecord.ID, "pullrequestreview-"); err != nil {
		return fmt.Errorf("independent review URL is invalid: %w", err)
	}
	if reviewRecord.CommitID != implementationCommit {
		return errors.New("independent review does not match the implementation commit")
	}
	if dispositionRecord.SchemaVersion != dispositionCaptureSchemaVersion || dispositionRecord.Decision != "approved" || dispositionRecord.ID == "" || dispositionRecord.URL == "" || dispositionRecord.Login == "" || dispositionRecord.Login == reviewRecord.Login || dispositionRecord.ReviewID != reviewRecord.ID || dispositionRecord.ReviewedCommit != reviewRecord.CommitID || dispositionRecord.ImplementationCommit != implementationCommit || dispositionRecord.CreatedAt != dispositionRecord.UpdatedAt || dispositionRecord.Body == "" {
		return errors.New("maintainer disposition does not separately accept the COMMENTED review")
	}
	if _, err := time.Parse(time.RFC3339, dispositionRecord.CreatedAt); err != nil {
		return errors.New("maintainer disposition creation timestamp is invalid")
	}
	if _, err := time.Parse(time.RFC3339, dispositionRecord.UpdatedAt); err != nil {
		return errors.New("maintainer disposition update timestamp is invalid")
	}
	if err := validateGitHubPRURL(dispositionRecord.URL, dispositionRecord.ID, "issuecomment-"); err != nil {
		return fmt.Errorf("maintainer disposition URL is invalid: %w", err)
	}
	return nil
}

func validateGitHubPRURL(rawURL, id, fragmentPrefix string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" {
		return errors.New("URL must be a credential-free canonical HTTPS github.com URL")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) != 4 || segments[0] == "" || segments[1] == "" || segments[2] != "pull" || !positiveDecimal(segments[3]) {
		return errors.New("URL must identify a GitHub pull request")
	}
	if parsed.Fragment != fragmentPrefix+id {
		return errors.New("URL fragment does not match the captured ID")
	}
	return nil
}

func positiveDecimal(value string) bool {
	if value == "" || value == "0" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func singleJSONFile(root, locator string) (string, error) {
	directory, err := belowRootDirectory(root, locator)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	var path string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if path != "" {
			return "", errors.New("review directory must contain exactly one JSON file")
		}
		path, err = belowRoot(root, filepath.ToSlash(filepath.Join(locator, entry.Name())))
		if err != nil {
			return "", err
		}
	}
	if path == "" {
		return "", errors.New("review directory has no JSON file")
	}
	return path, nil
}

func catalogPin(catalog bench.Catalog, reference string) (string, error) {
	digest, exists := catalogPinOptional(catalog, reference)
	if !exists {
		return "", fmt.Errorf("catalog omits pin %q", reference)
	}
	return digest, nil
}

func catalogPinOptional(catalog bench.Catalog, reference string) (string, bool) {
	for _, pin := range catalog.Pins {
		if pin.Reference == reference {
			return pin.Digest, true
		}
	}
	return "", false
}

func catalogTarget(catalog bench.Catalog, targetID string) (bench.Target, bool) {
	for _, target := range catalog.Targets {
		if target.ID == targetID {
			return target, true
		}
	}
	return bench.Target{}, false
}

func runCellKey(targetID string, engine bench.Engine) string {
	sum := sha256.Sum256([]byte(targetID + "\x00" + string(engine)))
	return "sca-cell-" + hex.EncodeToString(sum[:])
}

func belowRoot(root, locator string) (string, error) {
	return benchcycle.BelowRoot(root, locator)
}

func belowRootDirectory(root, locator string) (string, error) {
	return benchcycle.BelowRootDirectory(root, locator)
}

func readRegularFile(path string) ([]byte, error) {
	return readRegularFileContext(context.Background(), path, -1)
}

func writeNewFile(path string, body []byte, mode os.FileMode) error {
	return benchcycle.WriteNewFile(path, body, mode)
}

func digestFile(path string) (string, error) {
	body, err := readRegularFile(path)
	if err != nil {
		return "", err
	}
	return sha256Digest(body), nil
}
func sha256Digest(body []byte) string {
	hash := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(hash[:])
}

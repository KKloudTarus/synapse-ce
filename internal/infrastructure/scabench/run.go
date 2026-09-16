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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	runResultSchemaVersion = "synapse-sca-benchmark-run-v1"
	fixedRepetitions       = 2
	fixedMatrixCells       = 8
)

var fixedTargetIDs = []string{
	"debian-12-13-slim-amd64",
	"sles-15-6-bci-base-45-31-amd64",
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
	workRoot        string
	rawRunRoot      string
	cleanup         CleanupResult
	cleanupRequired bool
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

func Run(ctx context.Context, input RunInput, runnerFactory RunnerFactory) (result RunResult, runErr error) {
	state, err := prepareRun(input)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(state.workRoot) }()
	defer func() {
		if !state.cleanupRequired {
			return
		}
		cleanupErr := state.clean(ctx)
		if cleanupErr != nil {
			runErr = errors.Join(runErr, cleanupErr)
			return
		}
		result.Cleanup = state.cleanup
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

	observations := make([][]bench.Observation, fixedRepetitions)
	rawBundles := make([][]BundleIdentity, fixedRepetitions)
	bundlePaths := make(map[string][2]string, len(state.manifests))
	for repetition := 1; repetition <= fixedRepetitions; repetition++ {
		for _, target := range state.catalog.Targets {
			for _, engine := range bench.Engines() {
				key := runCellKey(target.ID, engine)
				manifest := state.manifests[key]
				state.cleanupRequired = true
				observation, identity, path, captureErr := state.captureCell(ctx, repetition, manifest, runnerFactory)
				if captureErr != nil {
					return RunResult{}, fmt.Errorf("capture repetition %d %s: %w", repetition, key, captureErr)
				}
				if observation.State != state.expectedStates[key] {
					return RunResult{}, fmt.Errorf("capture repetition %d %s returned %q, want %q", repetition, key, observation.State, state.expectedStates[key])
				}
				observations[repetition-1] = append(observations[repetition-1], observation)
				rawBundles[repetition-1] = append(rawBundles[repetition-1], identity)
				paths := bundlePaths[key]
				paths[repetition-1] = path
				bundlePaths[key] = paths
			}
		}
	}

	comparisons := make([]SemanticBundleComparison, 0, len(state.manifests))
	for _, target := range state.catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			paths := bundlePaths[key]
			comparison, compareErr := CompareBundlesForCell(paths[0], paths[1], target.ID, engine, state.expectedStates[key])
			if compareErr != nil {
				return RunResult{}, fmt.Errorf("compare repetitions for %s: %w", key, compareErr)
			}
			comparisons = append(comparisons, comparison)
		}
	}

	finalResult, resultBytes, report, err := reduceRepetitions(state.catalog, state.oracle, state.ratchet, observations)
	if err != nil {
		return RunResult{}, err
	}
	result = RunResult{
		SchemaVersion: runResultSchemaVersion, ImplementationCommit: input.ImplementationCommit, RunKey: input.RunKey,
		InputDigests: state.inputDigests, Repetitions: fixedRepetitions, Observations: observations,
		Comparisons: comparisons, RawBundles: rawBundles, Result: finalResult,
	}
	// The deferred cleanup must succeed before the result is published.
	if err := state.clean(ctx); err != nil {
		return RunResult{}, err
	}
	result.Cleanup = state.cleanup
	if err := state.publish(result, resultBytes, report); err != nil {
		return RunResult{}, err
	}
	return result, nil
}

func prepareRun(input RunInput) (*runState, error) {
	if err := validateRunInput(input); err != nil {
		return nil, err
	}
	workRoot, err := os.MkdirTemp("", "synapse-sca-cycle-")
	if err != nil {
		return nil, fmt.Errorf("create run workspace: %w", err)
	}
	rawRoot, err := realDirectory(input.RawRetentionRoot)
	if err != nil {
		_ = os.RemoveAll(workRoot)
		return nil, fmt.Errorf("validate raw retention root: %w", err)
	}
	parts := strings.Split(input.RunKey, "/")
	return &runState{
		input: input, workRoot: workRoot,
		rawRunRoot: filepath.Join(rawRoot, parts[0], parts[1]),
	}, nil
}

func validateRunInput(input RunInput) error {
	for _, item := range []struct{ name, value string }{
		{"corpus root", input.CorpusRoot}, {"trusted input root", input.TrustedInputRoot},
		{"output root", input.OutputRoot}, {"raw retention root", input.RawRetentionRoot},
	} {
		if strings.TrimSpace(item.value) == "" || !filepath.IsAbs(item.value) {
			return fmt.Errorf("%s must be an absolute path", item.name)
		}
	}
	if !fullSHA(input.ImplementationCommit) {
		return errors.New("implementation commit must be a 40-character lowercase SHA")
	}
	parts := strings.Split(input.RunKey, "/")
	if len(parts) != 2 || !portableRunSegment(parts[0]) || !portableRunSegment(parts[1]) {
		return errors.New("run key must contain exactly two portable path segments")
	}
	if _, err := os.Lstat(input.OutputRoot); err == nil {
		return errors.New("output root already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output root: %w", err)
	}
	if _, err := realDirectory(input.CorpusRoot); err != nil {
		return fmt.Errorf("validate corpus root: %w", err)
	}
	if _, err := realDirectory(input.TrustedInputRoot); err != nil {
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

func (state *runState) buildAndBindOwnedBinary(ctx context.Context) error {
	binaryPath := filepath.Join(state.workRoot, "tools", "synapse-sca-bench")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		return fmt.Errorf("create owned binary directory: %w", err)
	}
	command := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "./cmd/synapse-sca-bench")
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return fmt.Errorf("build owned benchmark binary: %w", err)
	}
	digest, err := digestFile(binaryPath)
	if err != nil {
		return fmt.Errorf("digest owned benchmark binary: %w", err)
	}
	updated := false
	for index := range state.catalog.Pins {
		if state.catalog.Pins[index].Reference == "binary:synapse-sca-bench:reproducible-v1" {
			state.catalog.Pins[index].Digest = digest
			updated = true
		}
	}
	if !updated {
		return errors.New("catalog does not pin the owned benchmark binary")
	}
	if err := state.catalog.Validate(); err != nil {
		return fmt.Errorf("validate rebound catalog: %w", err)
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return fmt.Errorf("digest rebound catalog: %w", err)
	}
	state.ratchet.CatalogDigest = catalogDigest
	for index := range state.ratchet.Floors {
		if state.ratchet.Floors[index].Expected.Engine == bench.EngineOwned {
			state.ratchet.Floors[index].Expected.EngineBinaryDigest = digest
		}
	}
	return nil
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
		return nil, errors.New("capture manifest templates do not cover the fixed eight-cell matrix")
	}
	return templates, nil
}

func (state *runState) materializeManifest(catalogDigest string, target bench.Target, template captureManifestTemplate) (CaptureManifest, error) {
	binaryPath := template.Binary.Path
	if template.Engine == bench.EngineOwned {
		binaryPath = filepath.Join(state.workRoot, "tools", "synapse-sca-bench")
	}
	databasePath := template.Database.Path
	environmentPath := template.EnvironmentAttestation.Path
	manifest := CaptureManifest{
		SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: state.catalog.Revision, CatalogDigest: catalogDigest,
		TargetID: target.ID, SBOMPath: filepath.Join(state.input.TrustedInputRoot, "sboms", target.ID+".cdx.json"),
		Engine: template.Engine, EngineVersion: template.EngineVersion,
		Binary:                  Artifact{Reference: template.Binary.Reference, Path: binaryPath},
		Database:                DatabaseArtifact{Reference: template.Database.Reference, Path: databasePath, Build: template.Database.Build, Format: template.Database.Format},
		Environment:             template.Environment,
		EnvironmentAttestation:  Artifact{Reference: template.EnvironmentAttestation.Reference, Path: environmentPath},
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

func (state *runState) materializeCapability(catalogDigest string, target bench.Target, template captureManifestTemplate) (CapabilityStatement, string, error) {
	if template.Capability == nil {
		return CapabilityStatement{}, "", errors.New("capability template is required")
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
	components := append([]bench.Component(nil), target.Components...)
	sort.Slice(components, func(i, j int) bool {
		return components[i].PURL+"\x00"+components[i].Version < components[j].PURL+"\x00"+components[j].Version
	})
	statementSources := make([]CapabilityStatementSource, 0, len(sources))
	for _, source := range sources {
		statementSources = append(statementSources, CapabilityStatementSource{Reference: source.Reference, Digest: source.Digest})
	}
	statement := CapabilityStatement{
		SchemaVersion: CapabilityStatementSchemaVersion, Kind: bench.CapabilityKindOSVScannerSUSERPM,
		DecisionRuleRevision: CapabilityDecisionRuleRevision, Scope: CapabilityScopeSameSBOMOSPackageMatching,
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
	artifacts := make([]CapabilityArtifact, 0, len(templates))
	for _, template := range templates {
		if template.Reference == "" || template.Locator == "" || template.Digest == "" {
			return nil, errors.New("capability source template is incomplete")
		}
		path, err := belowRoot(filepath.Join(state.input.TrustedInputRoot, "repository"), template.Locator)
		if err != nil {
			return nil, err
		}
		digest, err := digestFile(path)
		if err != nil {
			return nil, err
		}
		if digest != template.Digest {
			return nil, fmt.Errorf("capability source %q digest differs from its frozen template", template.Locator)
		}
		if catalogDigest, exists := catalogPinOptional(state.catalog, capabilityPinReference(template.Locator)); exists && catalogDigest != digest {
			return nil, fmt.Errorf("capability source %q differs from its catalog pin", template.Locator)
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
			expected.CapabilityKind = bench.CapabilityKindOSVScannerSUSERPM
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

func (state *runState) captureCell(ctx context.Context, repetition int, manifest CaptureManifest, runnerFactory RunnerFactory) (bench.Observation, BundleIdentity, string, error) {
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
	path := filepath.Join(state.rawRunRoot, fmt.Sprintf("repetition-%d", repetition), manifest.TargetID+"--"+string(manifest.Engine))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", err
	}
	if err := WriteBundle(path, captured); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("write capture bundle: %w", err)
	}
	if err := ValidateBundle(path); err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("validate written capture bundle: %w", err)
	}
	identity, err := BundleIdentityFromPath(path)
	if err != nil {
		return bench.Observation{}, BundleIdentity{}, "", fmt.Errorf("identify written capture bundle: %w", err)
	}
	return captured.Observation(), identity, path, nil
}

func reduceRepetitions(catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, observations [][]bench.Observation) (bench.Result, []byte, []byte, error) {
	var expectedResult []byte
	var expectedReport []byte
	var final bench.Result
	for index, repetition := range observations {
		result, err := bench.Reduce(catalog, oracle, repetition)
		if err != nil {
			return bench.Result{}, nil, nil, fmt.Errorf("reduce repetition %d: %w", index+1, err)
		}
		result, err = bench.ApplyRatchet(result, ratchet)
		if err != nil {
			return bench.Result{}, nil, nil, fmt.Errorf("apply ratchet to repetition %d: %w", index+1, err)
		}
		var resultBuffer bytes.Buffer
		if err := bench.EncodeResult(&resultBuffer, result); err != nil {
			return bench.Result{}, nil, nil, err
		}
		var reportBuffer bytes.Buffer
		if err := bench.RenderResult(&reportBuffer, result); err != nil {
			return bench.Result{}, nil, nil, err
		}
		if index == 0 {
			final, expectedResult, expectedReport = result, resultBuffer.Bytes(), reportBuffer.Bytes()
			continue
		}
		if !bytes.Equal(expectedResult, resultBuffer.Bytes()) || !bytes.Equal(expectedReport, reportBuffer.Bytes()) {
			return bench.Result{}, nil, nil, fmt.Errorf("repetition %d reduction differs", index+1)
		}
	}
	return final, expectedResult, expectedReport, nil
}

func (state *runState) clean(ctx context.Context) error {
	if state.cleanup.RawRunRemoved && state.cleanup.DockerCleaned {
		return nil
	}
	if err := os.RemoveAll(state.rawRunRoot); err != nil {
		return fmt.Errorf("remove protected raw output: %w", err)
	}
	if _, err := os.Lstat(state.rawRunRoot); !os.IsNotExist(err) {
		if err == nil {
			return errors.New("protected raw output remains")
		}
		return err
	}
	state.cleanup.RawRunRemoved = true
	if err := cleanDocker(ctx, "docker"); err != nil {
		return err
	}
	state.cleanup.DockerCleaned = true
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

func (state *runState) publish(result RunResult, resultBytes, report []byte) error {
	if err := os.Mkdir(state.input.OutputRoot, 0o700); err != nil {
		return fmt.Errorf("create sanitized output: %w", err)
	}
	catalog, err := bench.CanonicalJSON(state.catalog)
	if err != nil {
		return err
	}
	oracle, err := bench.CanonicalJSON(state.oracle)
	if err != nil {
		return err
	}
	ratchet, err := bench.CanonicalJSON(state.ratchet)
	if err != nil {
		return err
	}
	run, err := bench.CanonicalJSON(result)
	if err != nil {
		return err
	}
	policy, err := readRegularFile(filepath.Join(state.input.CorpusRoot, "cycle-policy.json"))
	if err != nil {
		return fmt.Errorf("read cycle policy for publication: %w", err)
	}
	files := map[string][]byte{
		"catalog.json": catalog, "oracle.json": oracle, "ratchet.json": ratchet,
		"cycle-policy.json": policy,
		"run.json":          run, "result.json": resultBytes, "report.md": report,
		"reviews/review.json": state.review, "reviews/disposition.json": state.disposition,
	}
	for _, target := range state.catalog.Targets {
		body, readErr := readRegularFile(filepath.Join(state.input.TrustedInputRoot, "sboms", target.ID+".cdx.json"))
		if readErr != nil {
			return readErr
		}
		files[filepath.Join("sboms", target.ID+".cdx.json")] = body
	}
	for name, body := range files {
		if err := writeNewFile(filepath.Join(state.input.OutputRoot, name), body, 0o600); err != nil {
			return err
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
	var policy cyclePolicy
	if err := strictDecodeFile(path, &policy); err != nil {
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
	if err := bench.ValidateJSONDocument(bytes.NewReader(body)); err != nil {
		return fmt.Errorf("validate %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
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
	reviewPath, err := singleJSONFile(filepath.Join(root, "repository", "reviews", "github"))
	if err != nil {
		return nil, nil, fmt.Errorf("read independent review: %w", err)
	}
	dispositionPath, err := singleJSONFile(filepath.Join(root, "repository", "reviews", "dispositions", "github"))
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
	var reviewRecord reviewCapture
	var dispositionRecord dispositionCapture
	if err := strictDecodeFile(reviewPath, &reviewRecord); err != nil {
		return nil, nil, err
	}
	if err := strictDecodeFile(dispositionPath, &dispositionRecord); err != nil {
		return nil, nil, err
	}
	if reviewRecord.State != "COMMENTED" || reviewRecord.ID == "" || reviewRecord.Login == "" || reviewRecord.CommitID == "" || reviewRecord.Body == "" {
		return nil, nil, errors.New("independent review must be a complete COMMENTED review")
	}
	if _, err := time.Parse(time.RFC3339, reviewRecord.SubmittedAt); err != nil {
		return nil, nil, errors.New("independent review timestamp is invalid")
	}
	if dispositionRecord.Decision != "approved" || dispositionRecord.ID == "" || dispositionRecord.Login == "" || dispositionRecord.Login == reviewRecord.Login || dispositionRecord.ReviewID != reviewRecord.ID || dispositionRecord.ReviewedCommit != reviewRecord.CommitID || dispositionRecord.ImplementationCommit != implementationCommit || dispositionRecord.CreatedAt != dispositionRecord.UpdatedAt || dispositionRecord.Body == "" {
		return nil, nil, errors.New("maintainer disposition does not separately accept the COMMENTED review")
	}
	if _, err := time.Parse(time.RFC3339, dispositionRecord.CreatedAt); err != nil {
		return nil, nil, errors.New("maintainer disposition timestamp is invalid")
	}
	return review, disposition, nil
}

func singleJSONFile(directory string) (string, error) {
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
		path = filepath.Join(directory, entry.Name())
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
	return targetID + "\x00" + string(engine)
}

func capabilityPinReference(locator string) string {
	if strings.Contains(locator, "purl_to_package.go") {
		return "capability-source:osv-scanner:c84fa4568f2526d0333e9a914ea8a0a5f74ad68b"
	}
	if strings.Contains(locator, "ecosystem.go") {
		return "capability-source:osv-scalibr:23fa66ca68dd17bfdbe0b8b3536d1887a3a940da"
	}
	return ""
}

func belowRoot(root, locator string) (string, error) {
	if filepath.IsAbs(locator) {
		return "", errors.New("asset locator must be relative")
	}
	path := filepath.Join(root, filepath.FromSlash(locator))
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("asset locator escapes trusted input root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("asset must be a regular non-symlink file")
	}
	return path, nil
}

func realDirectory(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("path must be a real directory")
	}
	return filepath.Abs(path)
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file must be regular and not a symlink")
	}
	return os.ReadFile(path)
}

func writeNewFile(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
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
func fullSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
func portableRunSegment(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

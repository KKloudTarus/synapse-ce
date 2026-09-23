package scabench

import (
	"archive/tar"
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
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const (
	candidateResultSchemaVersion           = "synapse-sca-benchmark-candidate-v1"
	candidateCorpusFileBytes               = 16 << 20
	candidateSourceArchiveBytes      int64 = 64 << 20
	candidateSourceSnapshotBytes     int64 = 64 << 20
	candidateSourceSnapshotEntries         = 8192
	candidateSBOMBytes               int64 = 64 << 20
	candidateAttestationBytes        int64 = 4 << 20
	candidateSourceSnapshotDepth           = 32
	candidateSourceSnapshotFileBytes int64 = 4 << 20
	candidateSourceArchiveFile             = "source-archive.tar"
	candidateSourceSnapshotDirectory       = "source-snapshot"
)

func candidateSourceArchiveSelection() []string {
	return []string{
		"go.mod",
		"go.sum",
		"cmd/synapse-sca-bench",
		"internal",
	}
}

func candidateCorpusDocumentFiles() []string {
	return []string{
		"catalog.json",
		"oracle.json",
		"ratchet.json",
		"cycle-policy.json",
		"trusted-input-bindings.json",
	}
}

func candidateCorpusTemplateFiles() []string {
	return []string{
		"debian-12-13-slim-amd64--grype.json",
		"debian-12-13-slim-amd64--osv-scanner.json",
		"debian-12-13-slim-amd64--owned.json",
		"debian-12-13-slim-amd64--trivy.json",
		"rhel-9-8-ubi-amd64--grype.json",
		"rhel-9-8-ubi-amd64--osv-scanner.json",
		"rhel-9-8-ubi-amd64--owned.json",
		"rhel-9-8-ubi-amd64--trivy.json",
		"sles-15-6-bci-base-45-31-amd64--grype.json",
		"sles-15-6-bci-base-45-31-amd64--osv-scanner.json",
		"sles-15-6-bci-base-45-31-amd64--owned.json",
		"sles-15-6-bci-base-45-31-amd64--trivy.json",
	}
}

// CandidateInput identifies the checked-out source root, benchmark corpus locator, prepared offline
// inputs, and protected evidence root for one unsigned diagnostic cycle.
type CandidateInput struct {
	SourceRoot           string
	CorpusRoot           string
	OfflineInputRoot     string
	EvidenceRoot         string
	ImplementationCommit string
	RunKey               string
}

// CandidateArchive identifies the byte-complete input archive used for a candidate capture.
type CandidateArchive struct {
	CatalogDigest      string `json:"catalog_digest"`
	RootManifestDigest string `json:"root_manifest_digest"`
}

// CandidateSourceArchive identifies the selected Git object retained for a candidate run.
type CandidateSourceArchive struct {
	ImplementationCommit string   `json:"implementation_commit"`
	Digest               string   `json:"digest"`
	Bytes                int64    `json:"bytes"`
	Selection            []string `json:"selection"`
}

// CandidateToolchain identifies the Go executable that built the owned benchmark binary.
type CandidateToolchain struct {
	Binary  string `json:"binary"`
	Version string `json:"version"`
}

// CandidateBuiltBinary identifies the built owned benchmark binary before scanner dispatch.
type CandidateBuiltBinary struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// CandidateOwnedBuild records the controlled build used by a candidate cycle.
type CandidateOwnedBuild struct {
	Arguments   []string             `json:"arguments"`
	Toolchain   CandidateToolchain   `json:"toolchain"`
	BuiltBinary CandidateBuiltBinary `json:"built_binary"`
}

// CandidateSeal records the immutable identities retained under the candidate evidence root.
type CandidateSeal struct {
	ImplementationCommit   string                 `json:"implementation_commit"`
	SourceArchive          CandidateSourceArchive `json:"source_archive"`
	FrozenCorpusDigest     string                 `json:"frozen_corpus_digest"`
	CandidateCorpusDigest  string                 `json:"candidate_corpus_digest"`
	CandidateCatalogDigest string                 `json:"candidate_catalog_digest"`
	CandidateRatchetDigest string                 `json:"candidate_ratchet_digest"`
	InputArchive           CandidateArchive       `json:"input_archive"`
	OwnedBuild             CandidateOwnedBuild    `json:"owned_build"`
	OwnedBinaryDigest      string                 `json:"owned_binary_digest"`
	ManifestDigest         string                 `json:"manifest_digest"`
}

type candidateArchiveLimits struct {
	MaxBytes     int64
	MaxEntries   int
	MaxDepth     int
	MaxFileBytes int64
}

// CandidateGate reports diagnostic candidate and unchanged historical-ratchet status. A candidate
// can never become accepted through this unsigned path.
type CandidateGate struct {
	CandidatePassed  bool `json:"candidate_passed"`
	HistoricalPassed bool `json:"historical_passed"`
	Accepted         bool `json:"accepted"`
}

// CandidateResult is retained under EvidencePath for both successful and failed diagnostic cycles.
type CandidateResult struct {
	SchemaVersion          string                     `json:"schema_version"`
	Diagnostic             bool                       `json:"diagnostic"`
	RetentionPolicy        string                     `json:"retention_policy"`
	CyclePolicyScope       string                     `json:"cycle_policy_scope"`
	Sealed                 bool                       `json:"sealed"`
	ImplementationCommit   string                     `json:"implementation_commit"`
	RunKey                 string                     `json:"run_key"`
	EvidencePath           string                     `json:"evidence_path"`
	Seal                   *CandidateSeal             `json:"seal,omitempty"`
	InputDigests           InputDigests               `json:"input_digests"`
	Repetitions            int                        `json:"repetitions,omitempty"`
	Observations           [][]bench.Observation      `json:"observations,omitempty"`
	Comparisons            []SemanticBundleComparison `json:"comparisons,omitempty"`
	RawBundles             [][]BundleIdentity         `json:"raw_bundles,omitempty"`
	RetainedAttemptRecords int                        `json:"retained_attempt_records"`
	Candidate              *bench.Result              `json:"candidate_result,omitempty"`
	Historical             *bench.Result              `json:"historical_result,omitempty"`
	Gate                   CandidateGate              `json:"gate"`
}

// CandidateError returns the protected evidence path when a candidate cycle fails after its root
// was allocated. Its cause remains available through errors.Is and errors.As.
type CandidateError struct {
	EvidencePath string
	err          error
}

func (err *CandidateError) Error() string {
	return fmt.Sprintf("unsigned SCA candidate evidence retained at %s: %v", err.EvidencePath, err.err)
}

func (err *CandidateError) Unwrap() error {
	return err.err
}

// RunCandidate executes the unsigned, byte-frozen diagnostic benchmark path. It never publishes,
// signs, reviews, disposes, or accepts benchmark evidence.
func RunCandidate(ctx context.Context, input CandidateInput, runnerFactory RunnerFactory) (result CandidateResult, runErr error) {
	if ctx == nil {
		return CandidateResult{}, errors.New("candidate context is required")
	}
	if err := ctx.Err(); err != nil {
		return CandidateResult{}, err
	}
	var err error
	if input.SourceRoot, err = candidatePhysicalDirectory("source root", input.SourceRoot); err != nil {
		return CandidateResult{}, err
	}
	if input.CorpusRoot, err = candidatePhysicalDirectory("corpus root", input.CorpusRoot); err != nil {
		return CandidateResult{}, err
	}
	if input.OfflineInputRoot, err = candidatePhysicalDirectory("offline input root", input.OfflineInputRoot); err != nil {
		return CandidateResult{}, err
	}
	if input.EvidenceRoot, err = candidatePhysicalDirectory("evidence root", input.EvidenceRoot); err != nil {
		return CandidateResult{}, err
	}
	if err := validateCandidateInput(input); err != nil {
		return CandidateResult{}, err
	}
	evidencePath, err := createCandidateEvidenceRoot(input.EvidenceRoot, input.RunKey)
	if err != nil {
		return CandidateResult{}, err
	}
	result = CandidateResult{
		SchemaVersion:        candidateResultSchemaVersion,
		Diagnostic:           true,
		RetentionPolicy:      "retain_frozen_inputs_and_raw_bundles",
		CyclePolicyScope:     "inherited_capture_matrix_only",
		ImplementationCommit: input.ImplementationCommit,
		RunKey:               input.RunKey,
		EvidencePath:         evidencePath,
	}
	defer func() {
		attemptRecords, countErr := countCandidateAttemptRecords(evidencePath)
		result.RetainedAttemptRecords = attemptRecords
		if countErr != nil {
			runErr = errors.Join(runErr, countErr)
		}
		if reportErr := writeCandidateReport(evidencePath, result, runErr); reportErr != nil {
			runErr = errors.Join(runErr, reportErr)
		}
		if runErr != nil {
			runErr = candidateError(evidencePath, runErr)
		}
	}()

	if err := validateCandidateOfflineInputBounds(ctx, input.OfflineInputRoot); err != nil {
		return result, fmt.Errorf("validate candidate offline input bounds: %w", err)
	}
	sourceArchive, sourceSnapshotRoot, err := freezeCandidateSource(ctx, input.SourceRoot, input.ImplementationCommit, evidencePath)
	if err != nil {
		return result, err
	}
	frozenSourceCorpus, err := candidateCorpusSnapshotPath(input.SourceRoot, input.CorpusRoot, sourceSnapshotRoot)
	if err != nil {
		return result, err
	}
	frozenCorpusRoot := filepath.Join(evidencePath, "frozen-corpus")
	if err := copyCandidateCorpus(ctx, frozenSourceCorpus, frozenCorpusRoot); err != nil {
		return result, fmt.Errorf("freeze source corpus from snapshot: %w", err)
	}
	candidateCorpusRoot := filepath.Join(evidencePath, "candidate-corpus")
	if err := copyCandidateCorpus(ctx, frozenCorpusRoot, candidateCorpusRoot); err != nil {
		return result, fmt.Errorf("create candidate corpus copy: %w", err)
	}
	catalog, oracle, historicalRatchet, policy, err := loadCandidateCorpus(frozenCorpusRoot)
	if err != nil {
		return result, err
	}
	candidateRatchet, err := decodeRatchetFile(filepath.Join(frozenCorpusRoot, "ratchet.json"))
	if err != nil {
		return result, err
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(frozenCorpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		return result, err
	}
	templateState := runState{input: RunInput{CorpusRoot: candidateCorpusRoot}}
	templates, err := templateState.loadTemplates()
	if err != nil {
		return result, err
	}
	catalog, spec, templates, err = bindCandidateOfflineInputs(ctx, catalog, spec, templates, input.OfflineInputRoot)
	if err != nil {
		return result, fmt.Errorf("bind offline candidate inputs: %w", err)
	}
	captureInputRoot := filepath.Join(evidencePath, "capture-input")
	state := &runState{
		input: RunInput{
			CorpusRoot: candidateCorpusRoot, TrustedInputRoot: captureInputRoot,
			ImplementationCommit: input.ImplementationCommit, RunKey: input.RunKey,
		},
		catalog: catalog, oracle: oracle, ratchet: candidateRatchet, policy: policy,
		workRoot: evidencePath, rawRunRoot: evidencePath,
	}
	states, err := expectedCellStates(state.catalog, state.oracle)
	if err != nil {
		return result, err
	}
	state.expectedStates = states
	ownedBuild, err := state.buildAndBindCandidateOwnedBinary(ctx, sourceSnapshotRoot)
	if err != nil {
		return result, err
	}
	if err := bindCandidateSpecCatalog(&spec, state.catalog); err != nil {
		return result, err
	}
	if err := writeCandidateCatalog(candidateCorpusRoot, state.catalog); err != nil {
		return result, err
	}
	if err := writeCandidateInputBindingSpec(candidateCorpusRoot, spec); err != nil {
		return result, err
	}
	if err := writeCandidateTemplates(candidateCorpusRoot, templates); err != nil {
		return result, err
	}

	archiveStore, err := NewPinArchiveStore(filepath.Join(evidencePath, "input-cas"))
	if err != nil {
		return result, fmt.Errorf("create candidate input archive store: %w", err)
	}
	archive, err := CollectTrustedInputArchive(ctx, state.catalog, spec, input.OfflineInputRoot, archiveStore)
	if err != nil {
		return result, fmt.Errorf("collect candidate input archive: %w", err)
	}
	archiveBytes, err := bench.EncodeTrustedInputArchive(archive)
	if err != nil {
		return result, fmt.Errorf("encode candidate input archive: %w", err)
	}
	if err := writeNewFile(filepath.Join(evidencePath, "input-archive.json"), archiveBytes, 0o600); err != nil {
		return result, fmt.Errorf("record candidate input archive: %w", err)
	}
	if err := os.Mkdir(captureInputRoot, 0o700); err != nil {
		return result, fmt.Errorf("create candidate restored input root: %w", err)
	}
	if err := RestoreTrustedInputArchive(ctx, state.catalog, spec, archive, captureInputRoot, archiveStore); err != nil {
		return result, fmt.Errorf("restore candidate input archive: %w", err)
	}
	if err := state.materializeManifests(); err != nil {
		return result, err
	}
	if err := bindCandidateRatchet(state); err != nil {
		return result, err
	}
	state.inputDigests, err = candidateInputDigests(state.catalog, state.oracle, state.ratchet, candidateCorpusRoot)
	if err != nil {
		return result, err
	}
	if err := writeCandidateCorpusRatchet(candidateCorpusRoot, state.ratchet); err != nil {
		return result, err
	}
	if err := writeCandidateCatalog(evidencePath, state.catalog); err != nil {
		return result, err
	}
	if err := writeCandidateRatchet(evidencePath, state.ratchet); err != nil {
		return result, err
	}
	if err := writeCandidateManifests(evidencePath, state.manifests); err != nil {
		return result, err
	}
	seal, err := candidateSeal(ctx, evidencePath, sourceArchive, ownedBuild, archive, state.catalog, state.ratchet)
	if err != nil {
		return result, err
	}
	sealBytes, err := json.Marshal(seal)
	if err != nil {
		return result, fmt.Errorf("encode candidate seal: %w", err)
	}
	if err := writeNewFile(filepath.Join(evidencePath, "candidate-seal.json"), sealBytes, 0o600); err != nil {
		return result, fmt.Errorf("write candidate seal: %w", err)
	}
	result.Sealed = true
	result.Seal = &seal
	result.InputDigests = state.inputDigests

	if runtime.GOOS != "linux" {
		return result, errors.New("unsigned candidate capture requires a Linux hardened sandbox")
	}
	store, err := state.newEvidenceStore()
	if err != nil {
		return result, err
	}
	observations, comparisons, rawBundles, err := executeCaptureCycle(ctx, state, runnerFactory, store)
	if err != nil {
		return result, err
	}
	candidate, err := reduceCandidateRepetitions(ctx, state.catalog, state.oracle, state.ratchet, observations)
	if err != nil {
		return result, err
	}
	historical, err := reduceCandidateRepetitions(ctx, state.catalog, state.oracle, historicalRatchet, observations)
	if err != nil {
		return result, err
	}
	if candidate.Gate == nil || historical.Gate == nil {
		return result, errors.New("candidate reduction did not retain ratchet gates")
	}
	result.Repetitions = fixedRepetitions
	result.Observations = observations
	result.Comparisons = comparisons
	result.RawBundles = rawBundles
	result.Candidate = &candidate
	result.Historical = &historical
	result.Gate = CandidateGate{
		CandidatePassed: candidate.Gate.Passed, HistoricalPassed: historical.Gate.Passed,
		Accepted: false,
	}
	if !result.Gate.CandidatePassed {
		return result, errors.New("unsigned candidate gate failed")
	}
	return result, nil
}

func validateCandidateInput(input CandidateInput) error {
	for _, item := range []struct{ name, value string }{
		{"source root", input.SourceRoot},
		{"corpus root", input.CorpusRoot},
		{"offline input root", input.OfflineInputRoot},
		{"evidence root", input.EvidenceRoot},
	} {
		if err := benchcycle.ValidateAbsolutePath(item.name, item.value); err != nil {
			return err
		}
	}
	if err := benchcycle.ValidateIdentity(input.ImplementationCommit, input.RunKey); err != nil {
		return err
	}
	sourceRoot, err := candidatePhysicalDirectory("source root", input.SourceRoot)
	if err != nil {
		return err
	}
	corpusRoot, err := candidatePhysicalDirectory("corpus root", input.CorpusRoot)
	if err != nil {
		return err
	}
	if _, err := candidateCorpusRelativePath(sourceRoot, corpusRoot); err != nil {
		return err
	}
	offlineInputRoot, err := candidatePhysicalDirectory("offline input root", input.OfflineInputRoot)
	if err != nil {
		return err
	}
	if candidatePathsOverlap(corpusRoot, offlineInputRoot) || candidatePathsOverlap(sourceRoot, offlineInputRoot) {
		return errors.New("candidate source, corpus, and offline input roots must be disjoint")
	}
	if _, err := os.Lstat(filepath.Join(offlineInputRoot, "repository", "reviews")); err == nil {
		return errors.New("candidate offline input root must not include trusted review or disposition captures")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect candidate review inputs: %w", err)
	}
	evidenceRoot, err := candidatePhysicalDirectory("evidence root", input.EvidenceRoot)
	if err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		info, err := os.Stat(evidenceRoot)
		if err != nil {
			return fmt.Errorf("inspect protected evidence root: %w", err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("candidate evidence root must not be group- or world-writable")
		}
	}
	for _, item := range []struct {
		name string
		path string
	}{
		{"source root", sourceRoot},
		{"corpus root", corpusRoot},
		{"offline input root", offlineInputRoot},
	} {
		if candidatePathsOverlap(evidenceRoot, item.path) {
			return fmt.Errorf("evidence root must be disjoint from %s", item.name)
		}
	}
	path, err := candidateEvidencePath(evidenceRoot, input.RunKey)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		path string
	}{
		{"source root", sourceRoot},
		{"corpus root", corpusRoot},
		{"offline input root", offlineInputRoot},
	} {
		if candidatePathsOverlap(path, item.path) {
			return fmt.Errorf("candidate evidence path must be disjoint from %s", item.name)
		}
	}
	if err := benchcycle.EnsureAbsent(path, "candidate evidence path"); err != nil {
		return err
	}
	return nil
}

// validateCandidateOfflineInputBounds limits offline content before any input digest or archive read.
func validateCandidateOfflineInputBounds(ctx context.Context, root string) error {
	if ctx == nil {
		return errors.New("candidate offline input context is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect candidate offline input root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("candidate offline input root must be a real directory")
	}
	entries := 0
	var bytes int64
	var walk func(string, string, os.FileInfo) error
	walk = func(directory, relative string, expected os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		input, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open candidate offline input directory: %w", err)
		}
		opened, statErr := input.Stat()
		if statErr != nil || !sameStableFile(expected, opened) {
			_ = input.Close()
			return fmt.Errorf("candidate offline input directory %q changed while opening", relative)
		}
		members, readErr := input.ReadDir(bench.MaxTrustedInputArchiveEntries - entries + 1)
		closeErr := input.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read candidate offline input directory %q: %w", relative, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close candidate offline input directory %q: %w", relative, closeErr)
		}
		for _, member := range members {
			if err := ctx.Err(); err != nil {
				return err
			}
			entries++
			if entries > bench.MaxTrustedInputArchiveEntries {
				return fmt.Errorf("candidate offline input exceeds %d inventory members", bench.MaxTrustedInputArchiveEntries)
			}
			locator := member.Name()
			if relative != "" {
				locator = relative + "/" + locator
			}
			if trustedInputDepth(locator) > bench.MaxTrustedInputArchiveDepth {
				return fmt.Errorf("candidate offline input %q exceeds maximum depth %d", locator, bench.MaxTrustedInputArchiveDepth)
			}
			path := filepath.Join(directory, member.Name())
			memberInfo, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("inspect candidate offline input %q: %w", locator, err)
			}
			if memberInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("candidate offline input contains symlink %q", locator)
			}
			switch {
			case memberInfo.IsDir():
				if err := walk(path, locator, memberInfo); err != nil {
					return err
				}
			case memberInfo.Mode().IsRegular():
				size := memberInfo.Size()
				limit := candidateInputFileByteLimit(locator)
				if size < 0 || size > limit {
					return fmt.Errorf("candidate offline input %q exceeds %d bytes per file", locator, limit)
				}
				if size > bench.MaxTrustedInputArchiveBytes-bytes {
					return fmt.Errorf("candidate offline input exceeds %d bytes", bench.MaxTrustedInputArchiveBytes)
				}
				bytes += size
			default:
				return fmt.Errorf("candidate offline input contains special file %q", locator)
			}
		}
		after, err := os.Lstat(directory)
		if err != nil || !sameStableFile(expected, after) {
			return fmt.Errorf("candidate offline input directory %q changed during validation", relative)
		}
		return nil
	}
	return walk(root, "", info)
}

func candidateInputFileByteLimit(locator string) int64 {
	if locator == trustedEnvironmentAttestationLocator {
		return candidateAttestationBytes
	}
	for _, sbom := range fixedTrustedSBOMLocators {
		if locator == sbom {
			return candidateSBOMBytes
		}
	}
	return bench.MaxTrustedInputArchiveFileBytes
}

func candidateEvidencePath(evidenceRoot, runKey string) (string, error) {
	if err := benchcycle.ValidateRunKey(runKey); err != nil {
		return "", err
	}
	root, err := benchcycle.RealDirectory(evidenceRoot)
	if err != nil {
		return "", fmt.Errorf("validate evidence root: %w", err)
	}
	parts := strings.Split(runKey, "/")
	return filepath.Join(root, parts[0], parts[1]), nil
}

func candidatePhysicalDirectory(name, path string) (string, error) {
	if err := benchcycle.ValidateAbsolutePath(name, path); err != nil {
		return "", err
	}
	absolute, err := benchcycle.RealDirectory(path)
	if err != nil {
		return "", fmt.Errorf("validate %s: %w", name, err)
	}
	physical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	return benchcycle.RealDirectory(physical)
}

func candidatePathsOverlap(first, second string) bool {
	firstContainsSecond, firstComparable := candidatePathContains(first, second)
	secondContainsFirst, secondComparable := candidatePathContains(second, first)
	return (firstComparable && firstContainsSecond) || (secondComparable && secondContainsFirst)
}

func candidatePathContains(root, path string) (bool, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false, false
	}
	if relative == "." {
		return true, true
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), true
}

func candidateCorpusRelativePath(sourceRoot, corpusRoot string) (string, error) {
	relative, err := filepath.Rel(sourceRoot, corpusRoot)
	if err != nil {
		return "", fmt.Errorf("resolve candidate corpus relative path: %w", err)
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("candidate corpus root must be inside source root")
	}
	return relative, nil
}

func candidateCorpusSnapshotPath(sourceRoot, corpusRoot, snapshotRoot string) (string, error) {
	relative, err := candidateCorpusRelativePath(sourceRoot, corpusRoot)
	if err != nil {
		return "", err
	}
	path := filepath.Join(snapshotRoot, relative)
	if _, err := benchcycle.RealDirectory(path); err != nil {
		return "", fmt.Errorf("validate source-snapshot corpus root: %w", err)
	}
	return path, nil
}

func createCandidateEvidenceRoot(evidenceRoot, runKey string) (string, error) {
	path, err := candidateEvidencePath(evidenceRoot, runKey)
	if err != nil {
		return "", err
	}
	if err := benchcycle.EnsureAbsent(path, "candidate evidence path"); err != nil {
		return "", err
	}
	parent := filepath.Dir(path)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		if err := os.Mkdir(parent, 0o700); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("create candidate evidence parent: %w", err)
		}
	}
	if _, err := benchcycle.RealDirectory(parent); err != nil {
		return "", fmt.Errorf("validate candidate evidence parent: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", fmt.Errorf("create candidate evidence path: %w", err)
	}
	if _, err := benchcycle.RealDirectory(path); err != nil {
		return "", fmt.Errorf("validate candidate evidence path: %w", err)
	}
	return path, nil
}

func candidateError(evidencePath string, err error) error {
	if err == nil || evidencePath == "" {
		return err
	}
	var existing *CandidateError
	if errors.As(err, &existing) {
		return err
	}
	return &CandidateError{EvidencePath: evidencePath, err: err}
}

func writeCandidateReport(evidencePath string, result CandidateResult, runErr error) error {
	report := struct {
		CandidateResult
		Error string `json:"error,omitempty"`
	}{CandidateResult: result}
	if runErr != nil {
		report.Error = runErr.Error()
	}
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode candidate report: %w", err)
	}
	if err := writeNewFile(filepath.Join(evidencePath, "candidate-report.json"), body, 0o600); err != nil {
		return fmt.Errorf("write candidate report: %w", err)
	}
	return nil
}

func countCandidateAttemptRecords(evidencePath string) (int, error) {
	attempts := filepath.Join(evidencePath, "attempts")
	if _, err := os.Lstat(attempts); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("inspect retained candidate attempts: %w", err)
	}
	count := 0
	if err := filepath.WalkDir(attempts, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() && entry.Name() == "observation.json" {
			count++
		}
		return nil
	}); err != nil {
		return count, fmt.Errorf("count retained candidate attempt records: %w", err)
	}
	return count, nil
}

func copyCandidateCorpus(ctx context.Context, sourceRoot, destinationRoot string) error {
	source, err := benchcycle.RealDirectory(sourceRoot)
	if err != nil {
		return fmt.Errorf("validate source corpus: %w", err)
	}
	if err := os.Mkdir(destinationRoot, 0o700); err != nil {
		return fmt.Errorf("create destination corpus root: %w", err)
	}
	return copyCandidateCorpusDirectory(ctx, source, destinationRoot)
}

func copyCandidateCorpusDirectory(ctx context.Context, source, destination string) error {
	documentFiles := candidateCorpusDocumentFiles()
	allowedRoot := make(map[string]bool, len(documentFiles)+2)
	for _, name := range documentFiles {
		allowedRoot[name] = true
	}
	allowedRoot["capture-manifests"] = true
	allowedRoot["ratchet-baseline.json"] = true
	entries, err := candidateReadDirectoryEntries(source, len(allowedRoot)+1)
	if err != nil {
		return fmt.Errorf("read candidate corpus root: %w", err)
	}
	seen, err := candidateValidateCorpusEntries(entries, allowedRoot, append(append([]string(nil), documentFiles...), "capture-manifests"))
	if err != nil {
		return err
	}
	for _, name := range documentFiles {
		if err := copyCandidateCorpusFile(ctx, filepath.Join(source, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	if seen["ratchet-baseline.json"] {
		if err := copyCandidateCorpusFile(ctx, filepath.Join(source, "ratchet-baseline.json"), filepath.Join(destination, "ratchet-baseline.json")); err != nil {
			return err
		}
	}

	sourceTemplates := filepath.Join(source, "capture-manifests")
	templateInfo, err := os.Lstat(sourceTemplates)
	if err != nil {
		return fmt.Errorf("inspect candidate template directory: %w", err)
	}
	if templateInfo.Mode()&os.ModeSymlink != 0 || !templateInfo.IsDir() {
		return errors.New("candidate capture-manifests must be a non-symlink directory")
	}
	templateFiles := candidateCorpusTemplateFiles()
	allowedTemplates := make(map[string]bool, len(templateFiles))
	for _, name := range templateFiles {
		allowedTemplates[name] = true
	}
	templateEntries, err := candidateReadDirectoryEntries(sourceTemplates, len(allowedTemplates)+1)
	if err != nil {
		return fmt.Errorf("read candidate template directory: %w", err)
	}
	if _, err := candidateValidateCorpusEntries(templateEntries, allowedTemplates, templateFiles); err != nil {
		return fmt.Errorf("validate candidate templates: %w", err)
	}
	destinationTemplates := filepath.Join(destination, "capture-manifests")
	if err := os.Mkdir(destinationTemplates, 0o700); err != nil {
		return fmt.Errorf("create candidate template directory: %w", err)
	}
	for _, name := range templateFiles {
		if err := copyCandidateCorpusFile(ctx, filepath.Join(sourceTemplates, name), filepath.Join(destinationTemplates, name)); err != nil {
			return err
		}
	}
	return nil
}

func candidateReadDirectoryEntries(directory string, limit int) ([]os.DirEntry, error) {
	if limit < 1 {
		return nil, errors.New("candidate directory entry limit is required")
	}
	opened, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = opened.Close() }()
	entries, err := opened.ReadDir(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) == limit {
		return nil, fmt.Errorf("candidate corpus directory exceeds the %d-entry limit", limit-1)
	}
	return entries, nil
}

func candidateValidateCorpusEntries(entries []os.DirEntry, allowed map[string]bool, required []string) (map[string]bool, error) {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !allowed[name] {
			return nil, fmt.Errorf("candidate corpus has unrecognized corpus member %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("candidate corpus repeats member %q", name)
		}
		seen[name] = true
	}
	for _, name := range required {
		if !seen[name] {
			return nil, fmt.Errorf("candidate corpus is missing required member %q", name)
		}
	}
	return seen, nil
}

func copyCandidateCorpusFile(ctx context.Context, sourcePath, destinationPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect candidate corpus member: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("candidate corpus member must be a regular non-symlink file")
	}
	body, err := readRegularFileContext(ctx, sourcePath, candidateCorpusFileBytes)
	if err != nil {
		return fmt.Errorf("read candidate corpus member: %w", err)
	}
	if err := writeNewFile(destinationPath, body, 0o600); err != nil {
		return fmt.Errorf("write candidate corpus member: %w", err)
	}
	return nil
}

func freezeCandidateSource(ctx context.Context, sourceRoot, implementationCommit, evidencePath string) (CandidateSourceArchive, string, error) {
	if ctx == nil {
		return CandidateSourceArchive{}, "", errors.New("candidate source snapshot context is required")
	}
	gitRoot, err := candidateGitRoot(ctx, sourceRoot)
	if err != nil {
		return CandidateSourceArchive{}, "", err
	}
	archive, err := archiveCandidateSource(ctx, gitRoot, implementationCommit, evidencePath)
	if err != nil {
		return CandidateSourceArchive{}, "", err
	}
	snapshotRoot := filepath.Join(evidencePath, candidateSourceSnapshotDirectory)
	if err := extractCandidateSourceArchive(ctx, filepath.Join(evidencePath, candidateSourceArchiveFile), snapshotRoot); err != nil {
		return CandidateSourceArchive{}, "", err
	}
	if err := validateCandidateSnapshotModuleReplacements(ctx, snapshotRoot); err != nil {
		return CandidateSourceArchive{}, "", err
	}
	return archive, snapshotRoot, nil
}

func candidateGitRoot(ctx context.Context, sourceRoot string) (string, error) {
	physicalSourceRoot, err := candidatePhysicalDirectory("source root", sourceRoot)
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, "git", "-C", physicalSourceRoot, "rev-parse", "--show-toplevel")
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve candidate source repository: %w", err)
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return "", errors.New("candidate source repository has no root")
	}
	physicalRoot, err := candidatePhysicalDirectory("candidate source repository root", root)
	if err != nil {
		return "", err
	}
	if physicalSourceRoot != physicalRoot {
		return "", errors.New("candidate source root must be the Git repository root")
	}
	return physicalRoot, nil
}

func archiveCandidateSource(ctx context.Context, sourceRoot, implementationCommit, evidencePath string) (archive CandidateSourceArchive, err error) {
	if err := benchcycle.ValidateIdentity(implementationCommit, "candidate/source-archive"); err != nil {
		return CandidateSourceArchive{}, err
	}
	archivePath := filepath.Join(evidencePath, candidateSourceArchiveFile)
	output, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return CandidateSourceArchive{}, fmt.Errorf("create candidate source archive: %w", err)
	}
	removeArchive := true
	outputClosed := false
	defer func() {
		if !outputClosed {
			if closeErr := output.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("close candidate source archive: %w", closeErr)
			}
		}
		if removeArchive {
			if removeErr := os.Remove(archivePath); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
				err = fmt.Errorf("remove incomplete candidate source archive: %w", removeErr)
			}
		}
	}()
	archiveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	arguments := []string{
		"-c", "core.attributesfile=",
		"-c", "core.autocrlf=false",
		"-C", sourceRoot,
		"archive", "--format=tar", implementationCommit, "--",
	}
	arguments = append(arguments, candidateSourceArchiveSelection()...)
	objectType, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "cat-file", "-t", implementationCommit).Output()
	if err != nil {
		return CandidateSourceArchive{}, fmt.Errorf("identify candidate implementation commit: %w", err)
	}
	if strings.TrimSpace(string(objectType)) != "commit" {
		return CandidateSourceArchive{}, errors.New("candidate implementation identity must reference a Git commit")
	}
	command := exec.CommandContext(archiveContext, "git", arguments...)
	command.Stderr = io.Discard
	stream, err := command.StdoutPipe()
	if err != nil {
		return CandidateSourceArchive{}, fmt.Errorf("open candidate source archive stream: %w", err)
	}
	if err := command.Start(); err != nil {
		return CandidateSourceArchive{}, fmt.Errorf("start candidate source archive: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(stream, candidateSourceArchiveBytes+1))
	if copyErr != nil || written > candidateSourceArchiveBytes {
		cancel()
	}
	waitErr := command.Wait()
	if copyErr != nil {
		return CandidateSourceArchive{}, fmt.Errorf("write candidate source archive: %w", copyErr)
	}
	if written > candidateSourceArchiveBytes {
		return CandidateSourceArchive{}, fmt.Errorf("candidate source archive exceeds the %d-byte limit", candidateSourceArchiveBytes)
	}
	if waitErr != nil {
		return CandidateSourceArchive{}, fmt.Errorf("archive selected candidate source commit: %w", waitErr)
	}
	if err := ctx.Err(); err != nil {
		return CandidateSourceArchive{}, err
	}
	if err := output.Close(); err != nil {
		return CandidateSourceArchive{}, fmt.Errorf("close candidate source archive: %w", err)
	}
	outputClosed = true
	removeArchive = false
	return CandidateSourceArchive{
		ImplementationCommit: implementationCommit,
		Digest:               "sha256:" + hex.EncodeToString(hash.Sum(nil)),
		Bytes:                written,
		Selection:            candidateSourceArchiveSelection(),
	}, nil
}

func extractCandidateSourceArchive(ctx context.Context, archivePath, destinationRoot string) error {
	info, err := os.Lstat(archivePath)
	if err != nil {
		return fmt.Errorf("inspect candidate source archive: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > candidateSourceArchiveBytes {
		return errors.New("candidate source archive must be a bounded regular non-symlink file")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open candidate source archive: %w", err)
	}
	defer func() { _ = archive.Close() }()
	return extractCandidateSourceArchiveReader(ctx, archive, destinationRoot, candidateArchiveLimits{
		MaxBytes: candidateSourceSnapshotBytes, MaxEntries: candidateSourceSnapshotEntries,
		MaxDepth: candidateSourceSnapshotDepth, MaxFileBytes: candidateSourceSnapshotFileBytes,
	})
}

func digestCandidateSourceArchive(ctx context.Context, archivePath string) (string, int64, error) {
	if ctx == nil {
		return "", 0, errors.New("candidate source archive digest context is required")
	}
	info, err := os.Lstat(archivePath)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > candidateSourceArchiveBytes {
		return "", 0, errors.New("candidate source archive must be a bounded regular non-symlink file")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = archive.Close() }()
	hash := sha256.New()
	if err := copyCandidateArchiveFile(ctx, hash, archive, info.Size()); err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

func extractCandidateSourceArchiveReader(ctx context.Context, source io.Reader, destinationRoot string, limits candidateArchiveLimits) error {
	if ctx == nil {
		return errors.New("candidate source extraction context is required")
	}
	if limits.MaxBytes < 1 || limits.MaxEntries < 1 || limits.MaxDepth < 1 || limits.MaxFileBytes < 1 || limits.MaxBytes < limits.MaxFileBytes {
		return errors.New("candidate source extraction limits are invalid")
	}
	if err := os.Mkdir(destinationRoot, 0o700); err != nil {
		return fmt.Errorf("create candidate source snapshot: %w", err)
	}
	removeDestination := true
	defer func() {
		if removeDestination {
			_ = os.RemoveAll(destinationRoot)
		}
	}()
	reader := tar.NewReader(source)
	entries := 0
	var total int64
	seen := make(map[string]bool)
	parentsWithMembers := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read candidate source archive: %w", err)
		}
		entries++
		if entries > limits.MaxEntries {
			return fmt.Errorf("candidate source archive exceeds the %d-entry limit", limits.MaxEntries)
		}
		// Git's tar output carries one PAX global header. It is metadata, not a filesystem
		// member, so retain its entry bound but never extract it.
		if header.Typeflag == tar.TypeXGlobalHeader {
			if header.Name != "pax_global_header" || header.Size < 0 || header.Size > 4096 {
				return errors.New("candidate source archive has an unsafe PAX global header")
			}
			continue
		}
		name, err := candidateArchiveEntryName(header.Name, limits.MaxDepth)
		if err != nil {
			return err
		}
		if !candidateArchiveMemberSelected(name) {
			return fmt.Errorf("candidate source archive member %q is outside the selected source paths", name)
		}
		isDirectory := header.Typeflag == tar.TypeDir
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg {
			return fmt.Errorf("candidate source archive member %q must be a directory or regular file", name)
		}
		if err := candidateTrackArchiveMember(seen, parentsWithMembers, name, isDirectory); err != nil {
			return err
		}
		destination := filepath.Join(destinationRoot, filepath.FromSlash(name))
		if isDirectory {
			if header.Size != 0 {
				return fmt.Errorf("candidate source archive directory %q has data", name)
			}
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return fmt.Errorf("create candidate source directory: %w", err)
			}
			continue
		}
		if header.Size < 0 || header.Size > limits.MaxFileBytes {
			return fmt.Errorf("candidate source archive file %q exceeds the %d-byte per-file limit", name, limits.MaxFileBytes)
		}
		if header.Size > limits.MaxBytes-total {
			return fmt.Errorf("candidate source archive exceeds the %d-byte total extraction limit", limits.MaxBytes)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fmt.Errorf("create candidate source file directory: %w", err)
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create candidate source file: %w", err)
		}
		copyErr := copyCandidateArchiveFile(ctx, output, reader, header.Size)
		closeErr := output.Close()
		if copyErr != nil {
			return fmt.Errorf("extract candidate source file %q: %w", name, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close candidate source file %q: %w", name, closeErr)
		}
		total += header.Size
	}
	removeDestination = false
	return nil
}

func candidateArchiveEntryName(name string, maxDepth int) (string, error) {
	name = strings.TrimSuffix(name, "/")
	if name == "" || strings.Contains(name, "\\") || strings.Contains(name, "\x00") || strings.Contains(name, ":") || pathpkg.IsAbs(name) {
		return "", fmt.Errorf("candidate source archive member %q must have a safe relative path", name)
	}
	clean := pathpkg.Clean(name)
	if name != clean || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("candidate source archive member %q must have a safe relative path", name)
	}
	if depth := len(strings.Split(clean, "/")); depth > maxDepth {
		return "", fmt.Errorf("candidate source archive member %q exceeds the %d-level depth limit", name, maxDepth)
	}
	return clean, nil
}

func candidateArchiveMemberSelected(name string) bool {
	return name == "go.mod" || name == "go.sum" || name == "cmd" || name == "cmd/synapse-sca-bench" || name == "internal" || strings.HasPrefix(name, "cmd/synapse-sca-bench/") || strings.HasPrefix(name, "internal/")
}

func candidateTrackArchiveMember(seen, parentsWithMembers map[string]bool, name string, isDirectory bool) error {
	if _, exists := seen[name]; exists {
		return fmt.Errorf("candidate source archive has duplicate member %q", name)
	}
	if !isDirectory && parentsWithMembers[name] {
		return fmt.Errorf("candidate source archive regular file %q has an existing descendant", name)
	}
	for parent := pathpkg.Dir(name); parent != "."; parent = pathpkg.Dir(parent) {
		if parentDirectory, exists := seen[parent]; exists && !parentDirectory {
			return fmt.Errorf("candidate source archive member %q has a regular-file ancestor", name)
		}
		parentsWithMembers[parent] = true
	}
	seen[name] = isDirectory
	return nil
}

func copyCandidateArchiveFile(ctx context.Context, destination io.Writer, source io.Reader, size int64) error {
	buffer := make([]byte, 32<<10)
	for remaining := size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, readErr := source.Read(chunk)
		if read > 0 {
			written, writeErr := destination.Write(chunk[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
			remaining -= int64(read)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && remaining == 0 {
				return nil
			}
			return readErr
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func validateCandidateSnapshotModuleReplacements(ctx context.Context, snapshotRoot string) error {
	if ctx == nil {
		return errors.New("candidate module replacement context is required")
	}
	path := filepath.Join(snapshotRoot, "go.mod")
	body, err := readRegularFileContext(ctx, path, candidateSourceSnapshotFileBytes)
	if err != nil {
		return fmt.Errorf("read candidate source go.mod: %w", err)
	}
	parsed, err := modfile.Parse(path, body, nil)
	if err != nil {
		return fmt.Errorf("parse candidate source go.mod: %w", err)
	}
	for _, replacement := range parsed.Replace {
		if replacement.New.Version != "" {
			continue
		}
		replacementPath := filepath.Clean(replacement.New.Path)
		resolved := replacementPath
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(snapshotRoot, resolved)
		}
		if contains, comparable := candidatePathContains(snapshotRoot, resolved); !comparable || !contains {
			return fmt.Errorf("candidate local module replacement %q escapes source snapshot", replacement.New.Path)
		}
	}
	return nil
}

func candidateOwnedBuildArguments(binaryPath string) []string {
	return []string{
		"build",
		"-buildvcs=false",
		"-mod=readonly",
		"-ldflags", "-X " + ownedBenchmarkVersionLinkerSymbol + "=" + ownedBenchmarkVersion,
		"-o", binaryPath,
		"./cmd/synapse-sca-bench",
	}
}

func candidateOwnedBuildEnvironment() []string {
	fixed := []string{
		"GOENV=off",
		"GOFLAGS=",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GONOPROXY=*",
		"GONOSUMDB=*",
		"GOOS=" + runtime.GOOS,
		"GOARCH=" + runtime.GOARCH,
		"CGO_ENABLED=0",
	}
	environment := make([]string, 0, len(os.Environ())+len(fixed))
	for _, item := range os.Environ() {
		key, _, found := strings.Cut(item, "=")
		if found && strings.HasPrefix(key, "GO") {
			continue
		}
		environment = append(environment, item)
	}
	return append(environment, fixed...)
}

func (state *runState) buildAndBindCandidateOwnedBinary(ctx context.Context, sourceSnapshotRoot string) (CandidateOwnedBuild, error) {
	if state == nil {
		return CandidateOwnedBuild{}, errors.New("candidate build state is required")
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return CandidateOwnedBuild{}, fmt.Errorf("locate Go toolchain: %w", err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		return CandidateOwnedBuild{}, fmt.Errorf("resolve Go toolchain: %w", err)
	}
	environment := candidateOwnedBuildEnvironment()
	versionCommand := exec.CommandContext(ctx, goBinary, "version")
	versionCommand.Env = environment
	versionCommand.Stderr = io.Discard
	versionBytes, err := versionCommand.Output()
	if err != nil {
		return CandidateOwnedBuild{}, fmt.Errorf("identify candidate Go toolchain: %w", err)
	}
	toolchain := CandidateToolchain{Binary: goBinary, Version: strings.TrimSpace(string(versionBytes))}
	if toolchain.Version == "" {
		return CandidateOwnedBuild{}, errors.New("candidate Go toolchain reported an empty version")
	}
	binaryPath := filepath.Join(state.workRoot, "tools", "synapse-sca-bench")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		return CandidateOwnedBuild{}, fmt.Errorf("create candidate owned binary directory: %w", err)
	}
	arguments := candidateOwnedBuildArguments(binaryPath)
	command := exec.CommandContext(ctx, goBinary, arguments...)
	command.Dir = sourceSnapshotRoot
	command.Env = environment
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return CandidateOwnedBuild{}, fmt.Errorf("build candidate owned benchmark binary: %w", err)
	}
	digest, err := state.bindOwnedBinaryDigest(binaryPath)
	if err != nil {
		return CandidateOwnedBuild{}, err
	}
	return CandidateOwnedBuild{
		Arguments:   append([]string(nil), arguments...),
		Toolchain:   toolchain,
		BuiltBinary: CandidateBuiltBinary{Path: binaryPath, Digest: digest},
	}, nil
}

func loadCandidateCorpus(corpusRoot string) (bench.Catalog, bench.Oracle, bench.Ratchet, cyclePolicy, error) {
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	oracle, err := decodeOracleFile(filepath.Join(corpusRoot, "oracle.json"))
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	if err := validateFixedTargetMatrix(catalog); err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	if err := bench.Validate(catalog, oracle); err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, fmt.Errorf("validate frozen candidate catalog and oracle: %w", err)
	}
	historicalRatchet, err := decodeRatchetFile(filepath.Join(corpusRoot, "ratchet.json"))
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	if historicalRatchet.CatalogRevision != catalog.Revision || historicalRatchet.CatalogDigest != catalogDigest || historicalRatchet.OracleDigest != oracleDigest {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, errors.New("historical ratchet does not bind the frozen candidate corpus")
	}
	policy, err := decodePolicyFile(filepath.Join(corpusRoot, "cycle-policy.json"))
	if err != nil {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, err
	}
	if policy.Repetitions != fixedRepetitions {
		return bench.Catalog{}, bench.Oracle{}, bench.Ratchet{}, cyclePolicy{}, fmt.Errorf("candidate cycle policy repetitions must be %d", fixedRepetitions)
	}
	return catalog, oracle, historicalRatchet, policy, nil
}

func decodeCandidateInputBindingSpec(path string) (bench.TrustedInputBindingSpec, error) {
	body, err := readRegularFileContext(context.Background(), path, bench.MaxTrustedInputArchiveManifestBytes)
	if err != nil {
		return bench.TrustedInputBindingSpec{}, fmt.Errorf("read candidate input binding spec: %w", err)
	}
	spec, err := bench.DecodeTrustedInputBindingSpec(bytes.NewReader(body))
	if err != nil {
		return bench.TrustedInputBindingSpec{}, err
	}
	return spec, nil
}

func digestCandidateInputFile(path string, limit int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect candidate input file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("candidate input must be a regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return "", fmt.Errorf("candidate input file exceeds %d bytes", limit)
	}
	digest, size, err := digestTrustedInputFile(path)
	if err != nil {
		return "", err
	}
	if size > limit {
		return "", fmt.Errorf("candidate input file exceeds %d bytes", limit)
	}
	return digest, nil
}

func bindCandidateOfflineInputs(ctx context.Context, historicalCatalog bench.Catalog, historicalSpec bench.TrustedInputBindingSpec, templates map[string]captureManifestTemplate, offlineRoot string) (bench.Catalog, bench.TrustedInputBindingSpec, map[string]captureManifestTemplate, error) {
	root, err := benchcycle.RealDirectory(offlineRoot)
	if err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("validate offline input root: %w", err)
	}
	catalog := cloneCandidateCatalog(historicalCatalog)
	spec := historicalSpec
	spec.Bindings = append([]bench.TrustedInputPinBinding(nil), historicalSpec.Bindings...)
	candidateTemplates := make(map[string]captureManifestTemplate, len(templates))
	candidatePinDigests := make(map[string]string, len(catalog.Pins))
	for key, template := range templates {
		candidateTemplates[key] = template
	}
	for index := range spec.Bindings {
		if err := ctx.Err(); err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
		binding := &spec.Bindings[index]
		path, err := safeTrustedInputPath(root, binding.Locator)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
		var digest string
		switch binding.Kind {
		case bench.TrustedInputPinFile:
			digest, _, err = digestTrustedInputFile(path)
		case bench.TrustedInputPinTree:
			digest, err = HashTree(path)
		default:
			err = fmt.Errorf("unsupported candidate input binding kind %q", binding.Kind)
		}
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("digest offline input %q: %w", binding.Reference, err)
		}
		binding.PinDigest = digest
		if err := setCandidateCatalogPin(&catalog, candidatePinDigests, binding.Reference, digest); err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
	}
	for targetIndex := range catalog.Targets {
		locator, exists := fixedTrustedSBOMLocators[catalog.Targets[targetIndex].ID]
		if !exists {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("candidate catalog target %q has no fixed SBOM locator", catalog.Targets[targetIndex].ID)
		}
		path, err := belowRoot(root, locator)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("resolve candidate SBOM: %w", err)
		}
		digest, err := digestCandidateInputFile(path, candidateSBOMBytes)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("digest candidate SBOM: %w", err)
		}
		catalog.Targets[targetIndex].SBOMDigest = digest
	}
	attestationPath, err := belowRoot(root, trustedEnvironmentAttestationLocator)
	if err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("resolve candidate environment attestation: %w", err)
	}
	attestationDigest, err := digestCandidateInputFile(attestationPath, candidateAttestationBytes)
	if err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("digest candidate environment attestation: %w", err)
	}
	for key, template := range candidateTemplates {
		if template.EnvironmentAttestation.Reference != trustedEnvironmentAttestationReference {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("candidate template %s has an unknown environment attestation", key)
		}
		template.Environment.ImageDigest = attestationDigest
		if err := setCandidateCatalogPin(&catalog, candidatePinDigests, template.EnvironmentAttestation.Reference, attestationDigest); err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
		environmentJSON, err := canonicalJSON(template.Environment)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("encode candidate environment: %w", err)
		}
		if err := setCandidateCatalogPin(&catalog, candidatePinDigests, template.EnvironmentPinReference, bench.SHA256Digest(environmentJSON)); err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
		profile, _, _, err := buildProfile(template.Engine, template.Database.Format, template.Limits)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("build candidate profile: %w", err)
		}
		profileJSON, err := canonicalJSON(profile)
		if err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("encode candidate profile: %w", err)
		}
		if err := setCandidateCatalogPin(&catalog, candidatePinDigests, template.ProfilePinReference, bench.SHA256Digest(profileJSON)); err != nil {
			return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, err
		}
		if template.Capability != nil {
			for sourceIndex := range template.Capability.Sources {
				source := &template.Capability.Sources[sourceIndex]
				identity, exists := fixedTrustedCapabilitySources[source.Reference]
				if !exists {
					return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("candidate capability source %q is unrecognized", source.Reference)
				}
				digest, exists := catalogPinOptional(catalog, identity.pinReference)
				if !exists {
					return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("candidate catalog omits capability source pin %q", identity.pinReference)
				}
				source.Digest = digest
			}
		}
		candidateTemplates[key] = template
	}
	if err := catalog.Validate(); err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("validate candidate catalog: %w", err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("digest candidate catalog: %w", err)
	}
	spec.CatalogRevision = catalog.Revision
	spec.CatalogDigest = catalogDigest
	if err := spec.Validate(catalog); err != nil {
		return bench.Catalog{}, bench.TrustedInputBindingSpec{}, nil, fmt.Errorf("validate candidate input binding spec: %w", err)
	}
	return catalog, spec, candidateTemplates, nil
}

func bindCandidateSpecCatalog(spec *bench.TrustedInputBindingSpec, catalog bench.Catalog) error {
	if spec == nil {
		return errors.New("candidate input binding spec is required")
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return fmt.Errorf("digest final candidate catalog: %w", err)
	}
	spec.CatalogRevision = catalog.Revision
	spec.CatalogDigest = catalogDigest
	if err := spec.Validate(catalog); err != nil {
		return fmt.Errorf("validate final candidate input binding spec: %w", err)
	}
	return nil
}

func writeCandidateInputBindingSpec(root string, spec bench.TrustedInputBindingSpec) error {
	body, err := bench.CanonicalJSON(spec)
	if err != nil {
		return fmt.Errorf("encode candidate input binding spec: %w", err)
	}
	return replaceCandidateDocument(filepath.Join(root, "trusted-input-bindings.json"), body)
}

func cloneCandidateCatalog(catalog bench.Catalog) bench.Catalog {
	clone := catalog
	clone.Targets = append([]bench.Target(nil), catalog.Targets...)
	clone.Pins = append([]bench.ArtifactPin(nil), catalog.Pins...)
	return clone
}

func setCandidateCatalogPin(catalog *bench.Catalog, materialized map[string]string, reference, digest string) error {
	if catalog == nil {
		return errors.New("candidate catalog is required")
	}
	if previous, exists := materialized[reference]; exists && previous != digest {
		return fmt.Errorf("candidate pin %q has conflicting materialized identities", reference)
	}
	for index := range catalog.Pins {
		if catalog.Pins[index].Reference == reference {
			catalog.Pins[index].Digest = digest
			materialized[reference] = digest
			return nil
		}
	}
	return fmt.Errorf("candidate catalog omits pin %q", reference)
}

func writeCandidateCatalog(root string, catalog bench.Catalog) error {
	body, err := bench.CanonicalJSON(catalog)
	if err != nil {
		return fmt.Errorf("encode candidate catalog: %w", err)
	}
	return replaceCandidateDocument(filepath.Join(root, "catalog.json"), body)
}

func writeCandidateRatchet(root string, ratchet bench.Ratchet) error {
	body, err := bench.CanonicalJSON(ratchet)
	if err != nil {
		return fmt.Errorf("encode candidate ratchet: %w", err)
	}
	return writeNewFile(filepath.Join(root, "candidate-ratchet.json"), body, 0o600)
}

func writeCandidateCorpusRatchet(root string, ratchet bench.Ratchet) error {
	body, err := bench.CanonicalJSON(ratchet)
	if err != nil {
		return fmt.Errorf("encode candidate corpus ratchet: %w", err)
	}
	return replaceCandidateDocument(filepath.Join(root, "ratchet.json"), body)
}

func writeCandidateTemplates(root string, templates map[string]captureManifestTemplate) error {
	directory := filepath.Join(root, "capture-manifests")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read candidate template directory: %w", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("candidate template must be a regular non-symlink file")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove copied candidate template: %w", err)
		}
	}
	for key, template := range templates {
		if !strings.HasPrefix(key, "sca-cell-") || len(key) != len("sca-cell-")+64 {
			return fmt.Errorf("candidate template has an unsafe cell key %q", key)
		}
		body, err := bench.CanonicalJSON(template)
		if err != nil {
			return fmt.Errorf("encode candidate template %s: %w", key, err)
		}
		if err := writeNewFile(filepath.Join(directory, key+".json"), body, 0o600); err != nil {
			return fmt.Errorf("write candidate template %s: %w", key, err)
		}
	}
	return nil
}

func replaceCandidateDocument(path string, body []byte) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return writeNewFile(path, body, 0o600)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("candidate document must replace a regular non-symlink file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return writeNewFile(path, body, 0o600)
}

func bindCandidateRatchet(state *runState) error {
	if state == nil {
		return errors.New("candidate state is required")
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		return err
	}
	floors := make(map[string]*bench.RatchetFloor, len(state.ratchet.Floors))
	for index := range state.ratchet.Floors {
		floor := &state.ratchet.Floors[index]
		key := runCellKey(floor.Expected.TargetID, floor.Expected.Engine)
		if _, exists := floors[key]; exists {
			return fmt.Errorf("candidate ratchet repeats floor %s", key)
		}
		floors[key] = floor
	}
	for key, manifest := range state.manifests {
		floor := floors[key]
		if floor == nil {
			return fmt.Errorf("candidate ratchet omits floor for %s", key)
		}
		target, exists := catalogTarget(state.catalog, manifest.TargetID)
		if !exists {
			return fmt.Errorf("candidate manifest target %q is absent", manifest.TargetID)
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
		expected := bench.ExpectedRunIdentity{
			TargetID: target.ID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest,
			Engine: manifest.Engine, EngineVersion: manifest.EngineVersion, EngineBinaryDigest: binaryDigest,
			DatabaseBuild: manifest.Database.Build, DatabaseDigest: databaseDigest,
			EnvironmentID: manifest.Environment.ID, EnvironmentDigest: environmentDigest, ConfigDigest: configDigest,
		}
		if manifest.Capability != nil {
			body, err := readRegularFile(manifest.Capability.Statement.Path)
			if err != nil {
				return fmt.Errorf("read candidate capability statement for %s: %w", key, err)
			}
			statement, err := decodeCapabilityStatement(body)
			if err != nil {
				return fmt.Errorf("decode candidate capability statement for %s: %w", key, err)
			}
			expected.CapabilityKind = statement.Kind
			expected.CapabilityDigest = manifest.Capability.Statement.Digest
		}
		floor.Expected = expected
	}
	state.ratchet.CatalogRevision = state.catalog.Revision
	state.ratchet.CatalogDigest = catalogDigest
	oracleDigest, err := bench.DigestOracle(state.oracle)
	if err != nil {
		return fmt.Errorf("digest candidate oracle: %w", err)
	}
	state.ratchet.OracleDigest = oracleDigest
	if err := state.ratchet.Validate(); err != nil {
		return fmt.Errorf("validate candidate ratchet: %w", err)
	}
	return state.refreshBoundInputDigests()
}

func writeCandidateManifests(root string, manifests map[string]CaptureManifest) error {
	directory := filepath.Join(root, "manifests")
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create candidate manifest directory: %w", err)
	}
	for key, manifest := range manifests {
		body, err := bench.CanonicalJSON(manifest)
		if err != nil {
			return fmt.Errorf("encode candidate manifest %s: %w", key, err)
		}
		if err := writeNewFile(filepath.Join(directory, key+".json"), body, 0o600); err != nil {
			return fmt.Errorf("write candidate manifest %s: %w", key, err)
		}
	}
	return nil
}

func candidateInputDigests(catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, corpusRoot string) (InputDigests, error) {
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return InputDigests{}, err
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		return InputDigests{}, err
	}
	ratchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return InputDigests{}, err
	}
	policy, err := readRegularFile(filepath.Join(corpusRoot, "cycle-policy.json"))
	if err != nil {
		return InputDigests{}, err
	}
	return InputDigests{Catalog: catalogDigest, Oracle: oracleDigest, Ratchet: ratchetDigest, Policy: sha256Digest(policy)}, nil
}

func candidateSeal(ctx context.Context, evidencePath string, sourceArchive CandidateSourceArchive, ownedBuild CandidateOwnedBuild, archive bench.TrustedInputArchive, catalog bench.Catalog, ratchet bench.Ratchet) (CandidateSeal, error) {
	if ctx == nil {
		return CandidateSeal{}, errors.New("candidate seal context is required")
	}
	if err := benchcycle.ValidateIdentity(sourceArchive.ImplementationCommit, "candidate/source-archive"); err != nil {
		return CandidateSeal{}, err
	}
	if !candidateSourceArchiveHasSelection(sourceArchive.Selection) {
		return CandidateSeal{}, errors.New("candidate source archive records an unexpected selection")
	}
	retainedArchiveDigest, retainedArchiveBytes, err := digestCandidateSourceArchive(ctx, filepath.Join(evidencePath, candidateSourceArchiveFile))
	if err != nil {
		return CandidateSeal{}, fmt.Errorf("digest retained candidate source archive: %w", err)
	}
	if retainedArchiveDigest != sourceArchive.Digest || retainedArchiveBytes != sourceArchive.Bytes {
		return CandidateSeal{}, errors.New("retained candidate source archive does not match its recorded identity")
	}
	frozenCorpusDigest, err := HashTree(filepath.Join(evidencePath, "frozen-corpus"))
	if err != nil {
		return CandidateSeal{}, fmt.Errorf("digest frozen corpus: %w", err)
	}
	candidateCorpusDigest, err := HashTree(filepath.Join(evidencePath, "candidate-corpus"))
	if err != nil {
		return CandidateSeal{}, fmt.Errorf("digest candidate corpus: %w", err)
	}
	candidateCatalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return CandidateSeal{}, err
	}
	candidateRatchetDigest, err := bench.DigestRatchet(ratchet)
	if err != nil {
		return CandidateSeal{}, err
	}
	ownedBinaryDigest, err := digestFile(filepath.Join(evidencePath, "tools", "synapse-sca-bench"))
	if err != nil {
		return CandidateSeal{}, fmt.Errorf("digest candidate owned binary: %w", err)
	}
	if ownedBuild.BuiltBinary.Path != filepath.Join(evidencePath, "tools", "synapse-sca-bench") || ownedBuild.BuiltBinary.Digest != ownedBinaryDigest {
		return CandidateSeal{}, errors.New("candidate owned build does not identify the executed binary")
	}
	manifestDigest, err := HashTree(filepath.Join(evidencePath, "manifests"))
	if err != nil {
		return CandidateSeal{}, fmt.Errorf("digest candidate manifests: %w", err)
	}
	return CandidateSeal{
		ImplementationCommit:   sourceArchive.ImplementationCommit,
		SourceArchive:          sourceArchive,
		FrozenCorpusDigest:     frozenCorpusDigest,
		CandidateCorpusDigest:  candidateCorpusDigest,
		CandidateCatalogDigest: candidateCatalogDigest,
		CandidateRatchetDigest: candidateRatchetDigest,
		InputArchive:           CandidateArchive{CatalogDigest: archive.CatalogDigest, RootManifestDigest: archive.RootManifestDigest},
		OwnedBuild:             ownedBuild,
		OwnedBinaryDigest:      ownedBinaryDigest,
		ManifestDigest:         manifestDigest,
	}, nil
}

func candidateSourceArchiveHasSelection(selection []string) bool {
	expected := candidateSourceArchiveSelection()
	if len(selection) != len(expected) {
		return false
	}
	for index, path := range expected {
		if selection[index] != path {
			return false
		}
	}
	return true
}

func reduceCandidateRepetitions(ctx context.Context, catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, observations [][]bench.Observation) (bench.Result, error) {
	if ctx == nil {
		return bench.Result{}, errors.New("candidate reduction context is required")
	}
	if len(observations) != fixedRepetitions {
		return bench.Result{}, fmt.Errorf("candidate observations contain %d repetitions, want %d", len(observations), fixedRepetitions)
	}
	var expected []byte
	for index, repetition := range observations {
		if err := ctx.Err(); err != nil {
			return bench.Result{}, err
		}
		result, err := bench.Reduce(catalog, oracle, repetition)
		if err != nil {
			return bench.Result{}, fmt.Errorf("reduce candidate repetition %d: %w", index+1, err)
		}
		result, err = bench.ApplyRatchet(result, ratchet)
		if err != nil {
			return bench.Result{}, fmt.Errorf("apply candidate ratchet to repetition %d: %w", index+1, err)
		}
		var encoded bytes.Buffer
		if err := bench.EncodeResult(&encoded, result); err != nil {
			return bench.Result{}, fmt.Errorf("encode candidate repetition %d: %w", index+1, err)
		}
		if index == 0 {
			expected = encoded.Bytes()
			continue
		}
		if !bytes.Equal(expected, encoded.Bytes()) {
			return bench.Result{}, fmt.Errorf("candidate repetition %d reduction differs", index+1)
		}
	}
	result, err := bench.DecodeResult(bytes.NewReader(expected))
	if err != nil {
		return bench.Result{}, fmt.Errorf("decode canonical candidate result: %w", err)
	}
	return result, nil
}

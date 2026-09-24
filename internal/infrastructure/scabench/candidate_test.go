package scabench

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestValidateCandidateInputRejectsExistingEvidenceRun(t *testing.T) {
	evidenceRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(evidenceRoot, "candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(evidenceRoot, "candidate", "attempt"), 0o700); err != nil {
		t.Fatal(err)
	}

	input := candidateValidationInput(t)
	input.EvidenceRoot = evidenceRoot
	input.RunKey = "candidate/attempt"
	err := validateCandidateInput(input)
	if err == nil || !strings.Contains(err.Error(), "candidate evidence path already exists") {
		t.Fatalf("validateCandidateInput() error = %v, want existing evidence rejection", err)
	}
}

func TestValidateCandidateInputRejectsOverlappingEvidenceRoots(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T) CandidateInput
	}{
		{
			name: "evidence nested in corpus",
			setup: func(t *testing.T) CandidateInput {
				source := t.TempDir()
				corpus := filepath.Join(source, "corpus")
				if err := os.Mkdir(corpus, 0o700); err != nil {
					t.Fatal(err)
				}
				evidence := filepath.Join(corpus, "evidence")
				if err := os.Mkdir(evidence, 0o700); err != nil {
					t.Fatal(err)
				}
				return CandidateInput{SourceRoot: source, CorpusRoot: corpus, OfflineInputRoot: t.TempDir(), EvidenceRoot: evidence}
			},
		},
		{
			name: "offline input nested in evidence",
			setup: func(t *testing.T) CandidateInput {
				source := t.TempDir()
				corpus := filepath.Join(source, "corpus")
				if err := os.Mkdir(corpus, 0o700); err != nil {
					t.Fatal(err)
				}
				evidence := t.TempDir()
				offline := filepath.Join(evidence, "offline")
				if err := os.Mkdir(offline, 0o700); err != nil {
					t.Fatal(err)
				}
				return CandidateInput{SourceRoot: source, CorpusRoot: corpus, OfflineInputRoot: offline, EvidenceRoot: evidence}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := test.setup(t)
			input.ImplementationCommit = strings.Repeat("a", 40)
			input.RunKey = "candidate/disjoint"
			err := validateCandidateInput(input)
			if err == nil || !strings.Contains(err.Error(), "evidence root must be disjoint") {
				t.Fatalf("validateCandidateInput() error = %v, want overlapping-root rejection", err)
			}
		})
	}
}

func TestValidateCandidateInputRejectsSymlinkedAncestorAlias(t *testing.T) {
	sourceRoot := t.TempDir()
	corpusRoot := filepath.Join(sourceRoot, "corpus")
	if err := os.Mkdir(corpusRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	inputParent := t.TempDir()
	offlineRoot := filepath.Join(inputParent, "inputs")
	if err := os.Mkdir(offlineRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := t.TempDir()
	alias := filepath.Join(aliasParent, "parent-alias")
	if err := os.Symlink(inputParent, alias); err != nil {
		t.Skipf("creating a directory symlink is unavailable: %v", err)
	}
	input := CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: offlineRoot,
		EvidenceRoot:         filepath.Join(alias, "inputs"),
		ImplementationCommit: strings.Repeat("a", 40), RunKey: "candidate/alias",
	}
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "evidence root must be disjoint") {
		t.Fatalf("validateCandidateInput() error = %v, want physical-root overlap rejection", err)
	}
}

func TestValidateCandidateInputRejectsSharedWritableEvidenceRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX permission bits are required")
	}
	input := candidateValidationInput(t)
	if err := os.Chmod(input.EvidenceRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("validateCandidateInput() error = %v, want protected-root rejection", err)
	}
}

func TestValidateCandidateInputRejectsReviewCaptures(t *testing.T) {
	offlineRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(offlineRoot, "repository", "reviews", "github"), 0o700); err != nil {
		t.Fatal(err)
	}
	input := candidateValidationInput(t)
	input.OfflineInputRoot = offlineRoot
	input.RunKey = "candidate/no-reviews"
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "must not include trusted review") {
		t.Fatalf("validateCandidateInput() error = %v, want review-input rejection", err)
	}
}

func TestValidateCandidateInputRejectsCorpusInsideOfflineInputs(t *testing.T) {
	input := candidateValidationInput(t)
	input.OfflineInputRoot = input.SourceRoot
	input.RunKey = "candidate/disjoint"
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "source, corpus, and offline input roots must be disjoint") {
		t.Fatalf("validateCandidateInput() error = %v, want disjoint-input rejection", err)
	}
}

func TestValidateCandidateBundleAllowsPriorEvidenceAndRequiresNewAttestation(t *testing.T) {
	input := candidateValidationInput(t)
	input.OfflineInputRoot = ""
	input.InputBundleRoot = filepath.Join(input.EvidenceRoot, "candidate", "earlier")
	if err := os.MkdirAll(input.InputBundleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "requires a current host") {
		t.Fatalf("missing attestation error = %v", err)
	}
	input.EnvironmentAttestationPath = filepath.Join(t.TempDir(), "current-attestation.json")
	if err := os.WriteFile(input.EnvironmentAttestationPath, []byte("current host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateInput(input); err != nil {
		t.Fatalf("prior evidence bundle in shared evidence root was rejected: %v", err)
	}
	input.OfflineInputRoot = t.TempDir()
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("conflicting input modes error = %v", err)
	}
}

func TestValidateCandidateBundleRejectsAttestationAliasIntoBundle(t *testing.T) {
	input := candidateValidationInput(t)
	input.OfflineInputRoot = ""
	input.InputBundleRoot = filepath.Join(input.EvidenceRoot, "candidate", "earlier")
	if err := os.MkdirAll(input.InputBundleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input.InputBundleRoot, "archived-attestation.json"), []byte("old host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "bundle-link")
	if err := os.Symlink(input.InputBundleRoot, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	input.EnvironmentAttestationPath = filepath.Join(alias, "archived-attestation.json")
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "path must be a real directory") {
		t.Fatalf("aliased attestation error = %v, want symlinked-parent rejection", err)
	}
}

func TestBindCandidateOfflineInputsRebindsCandidateOnly(t *testing.T) {
	corpusRoot, err := filepath.Abs(filepath.Join("..", "..", "usecase", "scabench", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := runState{input: RunInput{CorpusRoot: corpusRoot}}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, spec)

	historicalCatalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	historicalSpec := spec
	candidateCatalog, candidateSpec, candidateTemplates, err := bindCandidateOfflineInputs(context.Background(), catalog, spec, templates, offlineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bench.DigestCatalog(catalog); err != nil || got != historicalCatalogDigest {
		t.Fatalf("historical catalog digest = %q, %v; want unchanged %q", got, err, historicalCatalogDigest)
	}
	if !reflect.DeepEqual(spec, historicalSpec) {
		t.Fatal("historical binding specification was mutated")
	}
	candidateDigest, err := bench.DigestCatalog(candidateCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if candidateSpec.CatalogDigest != candidateDigest {
		t.Fatalf("candidate binding spec catalog digest = %q, want %q", candidateSpec.CatalogDigest, candidateDigest)
	}
	if err := candidateSpec.Validate(candidateCatalog); err != nil {
		t.Fatalf("candidate binding spec does not bind candidate catalog: %v", err)
	}
	if candidateSpec.Bindings[0].PinDigest == spec.Bindings[0].PinDigest {
		t.Fatal("candidate binding spec retained the historical input pin")
	}
	if candidateTemplates[runCellKey("debian-12-13-slim-amd64", bench.EngineGrype)].Environment.ImageDigest == templates[runCellKey("debian-12-13-slim-amd64", bench.EngineGrype)].Environment.ImageDigest {
		t.Fatal("candidate capture template retained the historical environment identity")
	}
	for _, targetID := range fixedTargetIDs {
		key := runCellKey(targetID, bench.EngineGrype)
		template := candidateTemplates[key]
		currentDigest, err := catalogPin(candidateCatalog, template.Database.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if want := "content-" + currentDigest; template.Database.Build != want {
			t.Fatalf("candidate %s database build = %q, want %q for changed bytes", key, template.Database.Build, want)
		}
	}
	grypeReference := templates[runCellKey(fixedTargetIDs[0], bench.EngineGrype)].Database.Reference
	grypeDigest, err := catalogPin(candidateCatalog, grypeReference)
	if err != nil {
		t.Fatal(err)
	}
	matchingCatalog := cloneCandidateCatalog(catalog)
	for index := range matchingCatalog.Pins {
		if matchingCatalog.Pins[index].Reference == grypeReference {
			matchingCatalog.Pins[index].Digest = grypeDigest
		}
	}
	matchingSpec := spec
	matchingSpec.Bindings = append([]bench.TrustedInputPinBinding(nil), spec.Bindings...)
	for index := range matchingSpec.Bindings {
		if matchingSpec.Bindings[index].Reference == grypeReference {
			matchingSpec.Bindings[index].PinDigest = grypeDigest
		}
	}
	_, _, matchingTemplates, err := bindCandidateOfflineInputs(context.Background(), matchingCatalog, matchingSpec, templates, offlineRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, targetID := range fixedTargetIDs {
		key := runCellKey(targetID, bench.EngineGrype)
		if got, want := matchingTemplates[key].Database.Build, templates[key].Database.Build; got != want {
			t.Fatalf("matching %s database build = %q, want preserved %q", key, got, want)
		}
	}
	candidateCorpus := filepath.Join(t.TempDir(), "candidate-corpus")
	if err := copyCandidateCorpus(context.Background(), corpusRoot, candidateCorpus); err != nil {
		t.Fatal(err)
	}
	if err := writeCandidateCatalog(candidateCorpus, candidateCatalog); err != nil {
		t.Fatal(err)
	}
	if err := writeCandidateTemplates(candidateCorpus, candidateTemplates); err != nil {
		t.Fatal(err)
	}
	if got, err := (&runState{input: RunInput{CorpusRoot: candidateCorpus}}).loadTemplates(); err != nil || len(got) != fixedMatrixCells {
		t.Fatalf("load candidate templates = %d, %v; want %d templates", len(got), err, fixedMatrixCells)
	}
}

func TestBindCandidateOfflineInputsRejectsUnboundDatabase(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := runState{input: RunInput{CorpusRoot: corpusRoot}}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, spec)
	grypeReference := templates[runCellKey(fixedTargetIDs[0], bench.EngineGrype)].Database.Reference
	filtered := spec.Bindings[:0:0]
	for _, binding := range spec.Bindings {
		if binding.Reference != grypeReference {
			filtered = append(filtered, binding)
		}
	}
	spec.Bindings = filtered
	_, _, _, err = bindCandidateOfflineInputs(context.Background(), catalog, spec, templates, offlineRoot)
	if err == nil || !strings.Contains(err.Error(), "has no offline input binding") {
		t.Fatalf("bindCandidateOfflineInputs() error = %v, want missing database binding", err)
	}
}

func TestBindCandidateOfflineInputsRejectsSymlink(t *testing.T) {
	if err := os.Symlink("missing", filepath.Join(t.TempDir(), "probe")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	corpusRoot, err := filepath.Abs(filepath.Join("..", "..", "usecase", "scabench", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := runState{input: RunInput{CorpusRoot: corpusRoot}}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, spec)
	binding := spec.Bindings[0]
	path := filepath.Join(offlineRoot, filepath.FromSlash(binding.Locator))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	_, _, _, err = bindCandidateOfflineInputs(context.Background(), catalog, spec, templates, offlineRoot)
	if err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("bindCandidateOfflineInputs() error = %v, want symlink rejection", err)
	}
}

func TestCandidateArchiveRejectsCorruptCASBeforeCapture(t *testing.T) {
	corpusRoot, err := filepath.Abs(filepath.Join("..", "..", "usecase", "scabench", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := runState{input: RunInput{CorpusRoot: corpusRoot}}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, spec)
	candidateCatalog, candidateSpec, _, err := bindCandidateOfflineInputs(context.Background(), catalog, spec, templates, offlineRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewPinArchiveStore(filepath.Join(t.TempDir(), "cas"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := CollectTrustedInputArchive(context.Background(), candidateCatalog, candidateSpec, offlineRoot, store)
	if err != nil {
		t.Fatal(err)
	}
	var objectDigest string
	for _, entry := range archive.Inventory {
		if entry.Kind == bench.TrustedInputInventoryFile {
			objectDigest = entry.ObjectDigest
			break
		}
	}
	if objectDigest == "" {
		t.Fatal("candidate archive has no file to corrupt")
	}
	path, err := store.blobPath(objectDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "capture-input")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreTrustedInputArchive(context.Background(), candidateCatalog, candidateSpec, archive, destination, store); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("RestoreTrustedInputArchive() error = %v, want corrupt CAS rejection", err)
	}
}

func TestLoadCandidateCorpusRejectsUnboundPreRebindRatchet(t *testing.T) {
	source := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	frozen := filepath.Join(t.TempDir(), "frozen")
	if err := copyCandidateCorpus(context.Background(), source, frozen); err != nil {
		t.Fatal(err)
	}
	ratchetPath := filepath.Join(frozen, "ratchet.json")
	ratchet, err := decodeRatchetFile(ratchetPath)
	if err != nil {
		t.Fatal(err)
	}
	ratchet.CatalogDigest = sha256Digest([]byte("unbound"))
	body, err := bench.CanonicalJSON(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceCandidateDocument(ratchetPath, body); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadCandidateCorpus(frozen); err == nil || !strings.Contains(err.Error(), "pre-rebind ratchet does not bind") {
		t.Fatalf("loadCandidateCorpus() error = %v, want frozen-ratchet mismatch", err)
	}
}

func TestReduceCandidateRepetitionsRetainsNumericAndIdentityFailures(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := decodeOracleFile(filepath.Join(corpusRoot, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := decodeRatchetFile(filepath.Join(corpusRoot, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]bench.Observation, 0, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		expected := floor.Expected
		state := bench.ObservationComplete
		if floor.Mode == bench.FloorGateModeUnsupportedOnly {
			state = bench.ObservationUnsupported
		}
		observations = append(observations, bench.Observation{
			SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: ratchet.CatalogDigest,
			Engine: expected.Engine, EngineVersion: expected.EngineVersion, EngineBinaryDigest: expected.EngineBinaryDigest,
			DatabaseBuild: expected.DatabaseBuild, DatabaseDigest: expected.DatabaseDigest,
			EnvironmentID: expected.EnvironmentID, EnvironmentDigest: expected.EnvironmentDigest,
			TargetID: expected.TargetID, TargetDigest: expected.TargetDigest, SBOMDigest: expected.SBOMDigest,
			State: state, RawOutputDigest: sha256Digest([]byte(expected.TargetID + "\x00" + string(expected.Engine))), ConfigDigest: expected.ConfigDigest,
			CapabilityKind: expected.CapabilityKind, CapabilityDigest: expected.CapabilityDigest,
		})
	}
	passes := [][]bench.Observation{observations, append([]bench.Observation(nil), observations...)}
	candidate, err := reduceCandidateRepetitions(context.Background(), catalog, oracle, ratchet, passes)
	if err != nil || candidate.Gate == nil || candidate.Gate.Passed {
		t.Fatalf("candidate numeric failure = %+v, %v; want retained failed gate", candidate.Gate, err)
	}
	original := ratchet.CatalogDigest
	ratchet.CatalogDigest = sha256Digest([]byte("different catalog"))
	if ratchet.CatalogDigest == original {
		t.Fatal("test ratchet identity did not change")
	}
	historical, err := reduceCandidateRepetitions(context.Background(), catalog, oracle, ratchet, passes)
	if err != nil || historical.Gate == nil || historical.Gate.Passed {
		t.Fatalf("historical identity failure = %+v, %v; want retained failed gate", historical.Gate, err)
	}
	for _, check := range historical.Gate.Checks {
		found := false
		for _, reason := range check.ReasonCodes {
			found = found || reason == bench.GateReasonPinMismatch
		}
		if !found {
			t.Fatalf("historical check %s/%s did not report pin_mismatch: %+v", check.Expected.TargetID, check.Expected.Engine, check)
		}
	}
}

func TestCandidateErrorPreservesEvidencePath(t *testing.T) {
	cause := errors.New("capture failed")
	err := candidateError("/protected/candidate/run", cause)
	var candidateErr *CandidateError
	if !errors.As(err, &candidateErr) {
		t.Fatalf("error %T does not expose CandidateError", err)
	}
	if candidateErr.EvidencePath != "/protected/candidate/run" {
		t.Fatalf("EvidencePath = %q", candidateErr.EvidencePath)
	}
	if !errors.Is(err, cause) {
		t.Fatal("candidate error does not unwrap its cause")
	}
}

func TestRunCandidateRetainsEvidenceOnIncompleteOfflineInput(t *testing.T) {
	sourceRoot, corpusRoot, commit := candidateTestSource(t)
	evidenceRoot := t.TempDir()
	result, err := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: t.TempDir(), EvidenceRoot: evidenceRoot,
		ImplementationCommit: commit, RunKey: "candidate/incomplete",
	}, nil)
	if err == nil {
		t.Fatal("RunCandidate() succeeded with incomplete offline input")
	}
	var candidateErr *CandidateError
	if !errors.As(err, &candidateErr) {
		t.Fatalf("RunCandidate() error %T does not retain candidate evidence", err)
	}
	if result.EvidencePath == "" || result.EvidencePath != candidateErr.EvidencePath {
		t.Fatalf("candidate evidence path = %q, error path = %q", result.EvidencePath, candidateErr.EvidencePath)
	}
	if result.RetentionPolicy != "retain_frozen_inputs_and_raw_bundles" || result.CyclePolicyScope != "inherited_capture_matrix_only" {
		t.Fatalf("candidate result misstates retained evidence policy: %+v", result)
	}
	for _, name := range []string{"candidate-report.json", "frozen-corpus"} {
		if _, statErr := os.Stat(filepath.Join(result.EvidencePath, name)); statErr != nil {
			t.Fatalf("retained %s: %v", name, statErr)
		}
	}
}

func TestRunCandidateRejectsOversizedOfflineSBOMBeforeSourceBuild(t *testing.T) {
	sourceRoot, corpusRoot, commit := candidateTestSource(t)
	offlineRoot := t.TempDir()
	sbom := filepath.Join(offlineRoot, fixedTrustedSBOMLocators[fixedTargetIDs[0]])
	if err := os.MkdirAll(filepath.Dir(sbom), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(sbom, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(candidateSBOMBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: offlineRoot, EvidenceRoot: t.TempDir(),
		ImplementationCommit: commit, RunKey: "candidate/oversized-input",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "candidate offline input bounds") {
		t.Fatalf("RunCandidate() error = %v; want bounded pre-build failure", err)
	}
	if _, err := os.Lstat(filepath.Join(result.EvidencePath, candidateSourceArchiveFile)); !os.IsNotExist(err) {
		t.Fatalf("source build/archive started before offline bounds validation: %v", err)
	}
}

func TestValidateCandidateOfflineInputBoundsRejectsExcessiveTreeDepth(t *testing.T) {
	root := t.TempDir()
	path := root
	for range bench.MaxTrustedInputArchiveDepth + 1 {
		path = filepath.Join(path, "d")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateCandidateOfflineInputBounds(context.Background(), root); err == nil || !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("validateCandidateOfflineInputBounds() error = %v; want depth rejection", err)
	}
}

func TestRunCandidateSealsConsistentCandidateIdentityChain(t *testing.T) {
	sourceRoot, corpusRoot, commit := candidateTestSource(t)
	historicalCatalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	historicalCatalogDigest, err := bench.DigestCatalog(historicalCatalog)
	if err != nil {
		t.Fatal(err)
	}
	historicalSpec, err := decodeCandidateInputBindingSpec(filepath.Join(corpusRoot, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := t.TempDir()
	writeCandidateOfflineInput(t, offlineRoot, historicalSpec)
	repositoryRoot := sourceRoot
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repositoryRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Fatal(err)
		}
	})
	result, runErr := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: offlineRoot, EvidenceRoot: t.TempDir(),
		ImplementationCommit: commit, RunKey: "candidate/identity",
	}, nil)
	if runErr == nil {
		t.Fatal("RunCandidate() unexpectedly completed with synthetic scanner inputs")
	}
	if !result.Sealed || result.Seal == nil {
		t.Fatalf("candidate was not sealed before dispatch failure: %+v (err=%v)", result, runErr)
	}
	if result.Seal.ImplementationCommit != commit || result.Seal.SourceArchive.ImplementationCommit != commit {
		t.Fatalf("candidate seal does not bind selected commit: %+v", result.Seal)
	}
	if !reflect.DeepEqual(result.Seal.SourceArchive.Selection, candidateSourceArchiveSelection()) || result.Seal.SourceArchive.Digest == "" {
		t.Fatalf("candidate seal does not retain source archive selection and digest: %+v", result.Seal.SourceArchive)
	}
	if result.Seal.OwnedBuild.BuiltBinary.Path != filepath.Join(result.EvidencePath, "tools", "synapse-sca-bench") || result.Seal.OwnedBuild.BuiltBinary.Digest != result.Seal.OwnedBinaryDigest {
		t.Fatalf("candidate seal does not bind built binary: %+v", result.Seal.OwnedBuild)
	}
	candidateCorpus := filepath.Join(result.EvidencePath, "candidate-corpus")
	catalog, err := decodeCatalogFile(filepath.Join(candidateCorpus, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if catalogDigest == historicalCatalogDigest {
		t.Fatal("candidate corpus retained historical catalog identity")
	}
	spec, err := decodeCandidateInputBindingSpec(filepath.Join(candidateCorpus, "trusted-input-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(catalog); err != nil {
		t.Fatalf("candidate binding spec does not match final catalog: %v", err)
	}
	archiveBody, err := readRegularFile(filepath.Join(result.EvidencePath, "input-archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := bench.DecodeTrustedInputArchive(bytes.NewReader(archiveBody))
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.ValidateForCatalog(catalog, spec); err != nil {
		t.Fatalf("candidate archive does not match final catalog and binding spec: %v", err)
	}
	ratchet, err := decodeRatchetFile(filepath.Join(candidateCorpus, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ratchet.Validate(); err != nil {
		t.Fatal(err)
	}
	if ratchet.CatalogDigest != catalogDigest {
		t.Fatalf("candidate ratchet catalog digest = %q, want %q", ratchet.CatalogDigest, catalogDigest)
	}
	if result.Seal.CandidateCatalogDigest != catalogDigest || result.Seal.InputArchive.CatalogDigest != catalogDigest {
		t.Fatalf("candidate seal does not bind final catalog: %+v, want %q", result.Seal, catalogDigest)
	}
	sealedCatalog, err := decodeCatalogFile(filepath.Join(result.EvidencePath, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := bench.DigestCatalog(sealedCatalog); err != nil || digest != catalogDigest {
		t.Fatalf("sealed catalog digest = %q, %v; want %q", digest, err, catalogDigest)
	}
	replayed, replayErr := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, InputBundleRoot: result.EvidencePath,
		EnvironmentAttestationPath: filepath.Join(offlineRoot, filepath.FromSlash(trustedEnvironmentAttestationLocator)),
		EvidenceRoot:               t.TempDir(), ImplementationCommit: commit, RunKey: "candidate/replayed-identity",
	}, nil)
	if replayErr == nil || !replayed.Sealed || replayed.Seal == nil {
		t.Fatalf("bundle replay did not reach a sealed candidate before scanner dispatch: result=%+v, error=%v", replayed, replayErr)
	}
	if replayed.Seal.InputArchive.RootManifestDigest != result.Seal.InputArchive.RootManifestDigest {
		t.Fatalf("replayed input manifest = %s, want %s; catalog=%s/%s owned=%s/%s", replayed.Seal.InputArchive.RootManifestDigest, result.Seal.InputArchive.RootManifestDigest,
			replayed.Seal.CandidateCatalogDigest, result.Seal.CandidateCatalogDigest, replayed.Seal.OwnedBinaryDigest, result.Seal.OwnedBinaryDigest)
	}
	newAttestation := filepath.Join(t.TempDir(), "environment-attestation.json")
	newAttestationBody := []byte("different current host attestation")
	if err := os.WriteFile(newAttestation, newAttestationBody, 0o600); err != nil {
		t.Fatal(err)
	}
	rebound, reboundErr := RunCandidate(context.Background(), CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, InputBundleRoot: result.EvidencePath,
		EnvironmentAttestationPath: newAttestation,
		EvidenceRoot:               t.TempDir(), ImplementationCommit: commit, RunKey: "candidate/rebound-attestation",
	}, nil)
	if reboundErr == nil || !rebound.Sealed || rebound.Seal == nil {
		t.Fatalf("attestation replay did not reach a sealed candidate before scanner dispatch: result=%+v, error=%v", rebound, reboundErr)
	}
	if rebound.Seal.InputArchive.RootManifestDigest == result.Seal.InputArchive.RootManifestDigest {
		t.Fatal("changed current-host attestation retained the archived input manifest digest")
	}
	retainedAttestation, err := os.ReadFile(filepath.Join(rebound.EvidencePath, "capture-input", filepath.FromSlash(trustedEnvironmentAttestationLocator)))
	if err != nil || !bytes.Equal(retainedAttestation, newAttestationBody) {
		t.Fatalf("retained current-host attestation = %q, error %v", retainedAttestation, err)
	}
}

func writeCandidateOfflineInput(t *testing.T, root string, spec bench.TrustedInputBindingSpec) {
	t.Helper()
	for _, binding := range spec.Bindings {
		path := filepath.Join(root, filepath.FromSlash(binding.Locator))
		if binding.Kind == bench.TrustedInputPinTree {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "fixture"), []byte(binding.Reference), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(binding.Reference), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for targetID, locator := range fixedTrustedSBOMLocators {
		writeCandidateOfflineFile(t, root, locator, []byte(targetID))
	}
	writeCandidateOfflineFile(t, root, trustedEnvironmentAttestationLocator, []byte("candidate environment attestation"))
}

func writeCandidateOfflineFile(t *testing.T, root, locator string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(locator))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateSourceSnapshotBindsExactCommitAndSelection(t *testing.T) {
	sourceRoot, commit := candidateSnapshotCheckout(t)
	if err := os.WriteFile(filepath.Join(sourceRoot, "go.mod"), []byte("module example.test/dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceRoot := t.TempDir()

	archive, snapshotRoot, err := freezeCandidateSource(context.Background(), sourceRoot, commit, evidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if archive.ImplementationCommit != commit {
		t.Fatalf("archive commit = %q, want %q", archive.ImplementationCommit, commit)
	}
	if !reflect.DeepEqual(archive.Selection, candidateSourceArchiveSelection()) {
		t.Fatalf("archive selection = %#v, want %#v", archive.Selection, candidateSourceArchiveSelection())
	}
	if archive.Digest == "" || archive.Bytes < 1 {
		t.Fatalf("archive identity = %+v, want bounded digest and byte count", archive)
	}
	if digest, err := digestFile(filepath.Join(evidenceRoot, candidateSourceArchiveFile)); err != nil || digest != archive.Digest {
		t.Fatalf("retained source archive digest = %q, %v; want %q", digest, err, archive.Digest)
	}
	wantGoMod, err := exec.Command("git", "-C", sourceRoot, "show", commit+":go.mod").Output()
	if err != nil {
		t.Fatal(err)
	}
	gotGoMod, err := readRegularFile(filepath.Join(snapshotRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotGoMod, wantGoMod) {
		t.Fatalf("source snapshot go.mod digest = %q, want selected Git object digest %q", sha256Digest(gotGoMod), sha256Digest(wantGoMod))
	}
}

func TestCandidateSourceSnapshotRejectsTreeIdentity(t *testing.T) {
	sourceRoot, _ := candidateSnapshotCheckout(t)
	output, err := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD^{tree}").Output()
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot := t.TempDir()
	_, _, err = freezeCandidateSource(context.Background(), sourceRoot, strings.TrimSpace(string(output)), evidenceRoot)
	if err == nil || !strings.Contains(err.Error(), "must reference a Git commit") {
		t.Fatalf("freezeCandidateSource() error = %v; want non-commit rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(evidenceRoot, candidateSourceArchiveFile)); !os.IsNotExist(err) {
		t.Fatalf("non-commit source archive should not be retained: %v", err)
	}
}

func TestExtractCandidateSourceArchiveRejectsUnsafeEntriesAndBounds(t *testing.T) {
	limits := candidateArchiveLimits{MaxBytes: 3, MaxEntries: 2, MaxDepth: 8, MaxFileBytes: 2}
	for _, test := range []struct {
		name    string
		entries []candidateTarEntry
		want    string
	}{
		{
			name:    "path traversal",
			entries: []candidateTarEntry{{name: "../outside.go", typeFlag: tar.TypeReg, body: []byte("x")}},
			want:    "safe relative path",
		},
		{
			name:    "link",
			entries: []candidateTarEntry{{name: "internal/link", typeFlag: tar.TypeSymlink}},
			want:    "directory or regular file",
		},
		{
			name: "duplicate",
			entries: []candidateTarEntry{
				{name: "internal/file.go", typeFlag: tar.TypeReg, body: []byte("x")},
				{name: "internal/file.go", typeFlag: tar.TypeReg, body: []byte("y")},
			},
			want: "duplicate",
		},
		{
			name: "regular file ancestor",
			entries: []candidateTarEntry{
				{name: "internal/file", typeFlag: tar.TypeReg, body: []byte("x")},
				{name: "internal/file/child", typeFlag: tar.TypeReg, body: []byte("y")},
			},
			want: "regular-file ancestor",
		},
		{
			name: "regular file after descendant",
			entries: []candidateTarEntry{
				{name: "internal/file/child", typeFlag: tar.TypeReg, body: []byte("x")},
				{name: "internal/file", typeFlag: tar.TypeReg, body: []byte("y")},
			},
			want: "existing descendant",
		},
		{
			name: "too many entries",
			entries: []candidateTarEntry{
				{name: "internal/one.go", typeFlag: tar.TypeReg, body: []byte("x")},
				{name: "internal/two.go", typeFlag: tar.TypeReg, body: []byte("y")},
				{name: "internal/three.go", typeFlag: tar.TypeReg, body: []byte("z")},
			},
			want: "entry limit",
		},
		{
			name:    "per file bound",
			entries: []candidateTarEntry{{name: "internal/file.go", typeFlag: tar.TypeReg, body: []byte("abc")}},
			want:    "per-file",
		},
		{
			name: "total bound",
			entries: []candidateTarEntry{
				{name: "internal/one.go", typeFlag: tar.TypeReg, body: []byte("ab")},
				{name: "internal/two.go", typeFlag: tar.TypeReg, body: []byte("bc")},
			},
			want: "total",
		},
		{
			name:    "outside selection",
			entries: []candidateTarEntry{{name: "unrelated.txt", typeFlag: tar.TypeReg, body: []byte("x")}},
			want:    "outside the selected source paths",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := candidateTarBytes(t, test.entries)
			destination := filepath.Join(t.TempDir(), "source")
			err := extractCandidateSourceArchiveReader(context.Background(), bytes.NewReader(archive), destination, limits)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("extractCandidateSourceArchiveReader() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCopyCandidateCorpusAllowsOnlyFixedCorpus(t *testing.T) {
	_, corpusRoot, _ := candidateTestSource(t)
	frozen := filepath.Join(t.TempDir(), "frozen")
	if err := copyCandidateCorpus(context.Background(), corpusRoot, frozen); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(frozen, "ratchet-baseline.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(frozen, "unrelated.bin"), []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyCandidateCorpus(context.Background(), frozen, filepath.Join(t.TempDir(), "candidate")); err == nil || !strings.Contains(err.Error(), "unrecognized corpus member") {
		t.Fatalf("copyCandidateCorpus() error = %v, want unrelated-file rejection", err)
	}
}

func TestCopyCandidateCorpusBoundsRootAndTemplateEntries(t *testing.T) {
	_, corpusRoot, _ := candidateTestSource(t)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, corpus string)
		want   string
	}{
		{
			name: "root entry cap",
			mutate: func(t *testing.T, corpus string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(corpus, "unrelated.bin"), []byte("unrelated"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "7-entry limit",
		},
		{
			name: "missing fixed template",
			mutate: func(t *testing.T, corpus string) {
				t.Helper()
				if err := os.Remove(filepath.Join(corpus, "capture-manifests", candidateCorpusTemplateFiles()[0])); err != nil {
					t.Fatal(err)
				}
			},
			want: "missing required member",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyRoot := filepath.Join(t.TempDir(), "corpus")
			if err := copyCandidateCorpus(context.Background(), corpusRoot, copyRoot); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, copyRoot)
			err := copyCandidateCorpus(context.Background(), copyRoot, filepath.Join(t.TempDir(), "candidate"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("copyCandidateCorpus() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateCandidateSnapshotModuleReplacementRejectsEscape(t *testing.T) {
	snapshotRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(snapshotRoot, "go.mod"), []byte("module example.test/benchmark\n\nreplace example.test/dependency => ../outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateSnapshotModuleReplacements(context.Background(), snapshotRoot); err == nil || !strings.Contains(err.Error(), "escapes source snapshot") {
		t.Fatalf("validateCandidateSnapshotModuleReplacements() error = %v, want escape rejection", err)
	}
}

func TestCandidateOwnedBuildControlsFlagsAndEnvironment(t *testing.T) {
	t.Setenv("GOFLAGS", "-overlay=outside.json")
	arguments := candidateOwnedBuildArguments(filepath.Join(t.TempDir(), "synapse-sca-bench"))
	if !containsString(arguments, "-buildvcs=false") || !containsString(arguments, "-trimpath") || !containsString(arguments, "-mod=readonly") {
		t.Fatalf("candidate build arguments = %#v, want controlled VCS, source path, and module flags", arguments)
	}
	environment := candidateOwnedBuildEnvironment()
	for _, expected := range []string{"GOENV=off", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH, "CGO_ENABLED=0"} {
		if !containsString(environment, expected) {
			t.Fatalf("candidate build environment = %#v, missing %q", environment, expected)
		}
	}
	if containsString(environment, "GOFLAGS=-overlay=outside.json") {
		t.Fatalf("candidate build environment retained ambient GOFLAGS: %#v", environment)
	}
}

func TestValidateCandidateInputRejectsCorpusOutsideSourceRoot(t *testing.T) {
	input := candidateValidationInput(t)
	input.CorpusRoot = t.TempDir()
	if err := validateCandidateInput(input); err == nil || !strings.Contains(err.Error(), "corpus root must be inside source root") {
		t.Fatalf("validateCandidateInput() error = %v, want source containment rejection", err)
	}
}

type candidateTarEntry struct {
	name     string
	typeFlag byte
	body     []byte
}

func candidateTarBytes(t *testing.T, entries []candidateTarEntry) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeFlag, Mode: 0o600, Size: int64(len(entry.body))}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func candidateTestSource(t *testing.T) (sourceRoot, corpusRoot, commit string) {
	t.Helper()
	rootOutput, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot = strings.TrimSpace(string(rootOutput))
	commitOutput, err := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	commit = strings.TrimSpace(string(commitOutput))
	corpusRoot = filepath.Join(sourceRoot, "internal", "usecase", "scabench", "corpus")
	return sourceRoot, corpusRoot, commit
}

func candidateSnapshotCheckout(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	for path, body := range map[string][]byte{
		"go.mod":                        []byte("module example.test/benchmark\n\ngo 1.27.0\n"),
		"go.sum":                        []byte{},
		"cmd/synapse-sca-bench/main.go": []byte("package main\n\nfunc main() {}\n"),
		"internal/probe.go":             []byte("package internal\n"),
	} {
		location := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(location), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(location, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arguments := range [][]string{
		{"init"},
		{"config", "user.email", "candidate-test@example.test"},
		{"config", "user.name", "Candidate Test"},
		{"add", "go.mod", "go.sum", "cmd/synapse-sca-bench/main.go", "internal/probe.go"},
		{"commit", "-m", "candidate snapshot fixture"},
	} {
		command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
		}
	}
	output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(output))
}

func candidateValidationInput(t *testing.T) CandidateInput {
	t.Helper()
	sourceRoot := t.TempDir()
	corpusRoot := filepath.Join(sourceRoot, "corpus")
	if err := os.Mkdir(corpusRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return CandidateInput{
		SourceRoot: sourceRoot, CorpusRoot: corpusRoot, OfflineInputRoot: t.TempDir(), EvidenceRoot: t.TempDir(),
		ImplementationCommit: strings.Repeat("a", 40), RunKey: "candidate/validation",
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

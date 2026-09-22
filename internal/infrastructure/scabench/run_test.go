package scabench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestValidateFixedTargetMatrix(t *testing.T) {
	catalog := bench.Catalog{Targets: make([]bench.Target, len(fixedTargetIDs))}
	for index, targetID := range fixedTargetIDs {
		catalog.Targets[index] = bench.Target{ID: targetID}
	}
	if err := validateFixedTargetMatrix(catalog); err != nil {
		t.Fatalf("validate fixed matrix: %v", err)
	}
	catalog.Targets = catalog.Targets[:1]
	if err := validateFixedTargetMatrix(catalog); err == nil {
		t.Fatal("catalog missing a fixed benchmark target was accepted")
	}
}

func TestThreeTargetPublicationAcceptsExactArtifactSet(t *testing.T) {
	catalog, files := completePublicationArtifacts()
	if got, want := len(files), expectedPublicationFileCount(); got != want {
		t.Fatalf("publication artifact count = %d, want %d", got, want)
	}
	if err := validateStagedArtifactSet(catalog, files); err != nil {
		t.Fatalf("complete fixed publication artifact set rejected: %v", err)
	}

	state := testPublicationState(t)
	state.runtimeCleanup = func(context.Context) error { return nil }
	state.stageVerifier = func(ctx context.Context, stage string, identities []benchcycle.FileIdentity) error {
		staged, err := publicationStageFiles(ctx, stage, identities)
		if err != nil {
			return err
		}
		return validateStagedArtifactSet(catalog, staged)
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range files {
		if _, err := publication.WriteBytes(context.Background(), path, body); err != nil {
			t.Fatalf("stage publication artifact %q: %v", path, err)
		}
	}
	if err := publication.Commit(context.Background()); err != nil {
		t.Fatalf("publish complete three-target artifact set: %v", err)
	}
}

func TestThreeTargetPublicationRejectsMissingAndUnexpectedArtifacts(t *testing.T) {
	catalog, complete := completePublicationArtifacts()
	for _, test := range []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{
			name: "missing fixed artifact",
			mutate: func(files map[string][]byte) {
				delete(files, "result.json")
			},
		},
		{
			name: "unexpected artifact",
			mutate: func(files map[string][]byte) {
				files["extra.json"] = []byte("extra")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := make(map[string][]byte, len(complete))
			for path, body := range complete {
				files[path] = body
			}
			test.mutate(files)
			if err := validateStagedArtifactSet(catalog, files); err == nil {
				t.Fatal("incomplete or unexpected publication artifact set was accepted")
			}
		})
	}
}

func TestRequireTrustedCycleResultRejectsMissingOrFailedAbsoluteGate(t *testing.T) {
	for _, result := range []bench.Result{
		{},
		{Gate: &bench.Gate{Passed: false}},
	} {
		if err := requireTrustedCycleResult(result); err == nil {
			t.Fatal("result without a passed absolute gate was accepted")
		}
	}
}

func TestRequireTrustedCycleResultRejectsMeasuredComparatorRecallBreach(t *testing.T) {
	result := measuredCycleResult(0.5)
	if err := requireTrustedCycleResult(result); err == nil {
		t.Fatal("result with a comparator recall above owned recall was accepted")
	}
}

func TestCanonicalCapabilityComponentsUsesBenchmarkIdentityOrder(t *testing.T) {
	version := "4.4-150400.25.22"
	components, err := canonicalCapabilityComponents(bench.CapabilityKindOSVScannerSUSERPM, []bench.Component{
		{PURL: "pkg:rpm/sles/bash-sh@" + version, Version: version},
		{PURL: "pkg:rpm/sles/bash@" + version, Version: version},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 2 || components[0].PURL != "pkg:rpm/sles/bash@"+version || components[1].PURL != "pkg:rpm/sles/bash-sh@"+version {
		t.Fatalf("capability component order = %+v", components)
	}
}

func TestCanonicalCapabilityComponentsFiltersNonApplicableEcosystems(t *testing.T) {
	version := "1.2.3-4.el9"
	components, err := canonicalCapabilityComponents(bench.CapabilityKindOSVScannerRedHatEnterpriseLinuxRPM, []bench.Component{
		{PURL: "pkg:pypi/example@1.2.3", Version: "1.2.3"},
		{PURL: "pkg:rpm/redhat/example@" + version, Version: version},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].PURL != "pkg:rpm/redhat/example@"+version {
		t.Fatalf("capability components = %+v", components)
	}
}

func TestValidateReviewEvidenceRequiresReviewOfImplementationCommit(t *testing.T) {
	const implementationCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const reviewedCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const timestamp = "2026-09-21T00:00:00Z"
	review := reviewCapture{
		SchemaVersion: "review-v1",
		ID:            "review-1",
		URL:           "https://example.invalid/review/1",
		Login:         "reviewer",
		State:         "COMMENTED",
		SubmittedAt:   timestamp,
		CommitID:      reviewedCommit,
		Body:          "reviewed",
	}
	disposition := dispositionCapture{
		SchemaVersion:        "disposition-v1",
		ID:                   "disposition-1",
		URL:                  "https://example.invalid/disposition/1",
		Login:                "maintainer",
		CreatedAt:            timestamp,
		UpdatedAt:            timestamp,
		ReviewID:             review.ID,
		ReviewedCommit:       reviewedCommit,
		ImplementationCommit: implementationCommit,
		Decision:             "approved",
		Body:                 "accepted",
	}
	reviewBody, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	dispositionBody, err := json.Marshal(disposition)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReviewEvidence(reviewBody, dispositionBody, implementationCommit); err == nil {
		t.Fatal("review evidence accepted a review for a different implementation commit")
	}

	review.CommitID = implementationCommit
	disposition.ReviewedCommit = implementationCommit
	reviewBody, err = json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	dispositionBody, err = json.Marshal(disposition)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReviewEvidence(reviewBody, dispositionBody, implementationCommit); err != nil {
		t.Fatalf("matching review evidence rejected: %v", err)
	}
}

func TestOwnedBuildInjectsStableBenchmarkVersion(t *testing.T) {
	_, source := testFixture(t, bench.EngineOwned)
	binaryName := "synapse-sca-bench"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", ownedBuildArguments(binaryPath)...)
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build owned benchmark helper: %v\n%s", err, output)
	}
	run := exec.Command(
		binaryPath,
		"--owned-helper",
		"-database", source.Database.Path,
		"-database-format", string(source.Database.Format),
		"-sbom", source.SBOMPath,
	)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run owned benchmark helper: %v\n%s", err, output)
	}
	var wire ownedWire
	if err := json.Unmarshal(output, &wire); err != nil {
		t.Fatalf("decode owned benchmark output: %v", err)
	}
	if wire.EngineVersion != ownedBenchmarkVersion {
		t.Fatalf("owned engine version = %q, want %q", wire.EngineVersion, ownedBenchmarkVersion)
	}
}

func TestReduceRepetitionsRejectsFailedAbsoluteGate(t *testing.T) {
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
	if _, _, _, err := reduceRepetitions(catalog, oracle, ratchet, [][]bench.Observation{observations, append([]bench.Observation(nil), observations...)}); err == nil {
		t.Fatal("trusted cycle accepted observations with a failed absolute ratchet gate")
	}
}

func TestMaterializeManifestPreservesPinnedCompetitorPathsAndRebindsOwnedBinary(t *testing.T) {
	for _, engine := range []bench.Engine{bench.EngineGrype, bench.EngineOwned} {
		t.Run(string(engine), func(t *testing.T) {
			catalog, source := testFixture(t, engine)
			workRoot := t.TempDir()
			if engine == bench.EngineOwned {
				body, err := os.ReadFile(source.Binary.Path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(workRoot, "tools"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(workRoot, "tools", "synapse-sca-bench"), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			catalogDigest, err := bench.DigestCatalog(catalog)
			if err != nil {
				t.Fatal(err)
			}
			state := runState{
				input:          RunInput{TrustedInputRoot: t.TempDir()},
				catalog:        catalog,
				workRoot:       workRoot,
				expectedStates: map[string]bench.ObservationState{runCellKey(source.TargetID, engine): bench.ObservationComplete},
			}
			template := captureManifestTemplate{
				SchemaVersion: CaptureManifestSchemaVersion, TargetID: source.TargetID, Engine: engine, EngineVersion: source.EngineVersion,
				Binary: source.Binary, Database: source.Database, Environment: source.Environment, EnvironmentAttestation: source.EnvironmentAttestation,
				EnvironmentPinReference: source.EnvironmentPinReference, ProfilePinReference: source.ProfilePinReference, Limits: source.Limits,
			}
			materialized, err := state.materializeManifest(catalogDigest, sourceTarget(t, catalog), template)
			if err != nil {
				t.Fatal(err)
			}
			if materialized.Database.Path != source.Database.Path || materialized.EnvironmentAttestation.Path != source.EnvironmentAttestation.Path {
				t.Fatal("materialization rewrote template-pinned database or environment paths")
			}
			if engine == bench.EngineOwned {
				if materialized.Binary.Path != filepath.Join(workRoot, "tools", "synapse-sca-bench") {
					t.Fatal("owned binary was not rebound into the work root")
				}
				return
			}
			if materialized.Binary.Path != source.Binary.Path {
				t.Fatal("competitor binary path was not preserved from the template")
			}
		})
	}
}

func TestBoundInputDigestsRefreshRuntimeBindingsAndExternalEvidence(t *testing.T) {
	catalog, _ := testFixture(t, bench.EngineGrype)
	state := runState{catalog: catalog, ratchet: bench.Ratchet{}, inputDigests: InputDigests{Catalog: "stale", Ratchet: "stale"}}
	state.bindReviewEvidence([]byte("review bytes"), []byte("disposition bytes"))
	if state.inputDigests.Review != sha256Digest(state.review) || state.inputDigests.Disposition != sha256Digest(state.disposition) {
		t.Fatal("review evidence digests do not bind the exact validated bytes")
	}
	if err := state.refreshBoundInputDigests(); err != nil {
		t.Fatal(err)
	}
	firstCatalog, firstRatchet := state.inputDigests.Catalog, state.inputDigests.Ratchet
	state.catalog.Revision = "runtime-rebound"
	state.ratchet.CatalogRevision = "runtime-rebound"
	if err := state.refreshBoundInputDigests(); err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		t.Fatal(err)
	}
	ratchetDigest, err := bench.DigestRatchet(state.ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if state.inputDigests.Catalog != catalogDigest || state.inputDigests.Ratchet != ratchetDigest || state.inputDigests.Catalog == firstCatalog || state.inputDigests.Ratchet == firstRatchet {
		t.Fatal("published input digests were not refreshed for runtime bindings")
	}
}

func TestCyclePlanUsesStableOpaqueKeysAndCanonicalPairs(t *testing.T) {
	catalog := bench.Catalog{Targets: []bench.Target{{ID: "target-a"}, {ID: "target-b"}}}
	state := runState{
		catalog:        catalog,
		manifests:      make(map[string]CaptureManifest),
		expectedStates: make(map[string]bench.ObservationState),
	}
	for _, target := range catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			state.manifests[key] = CaptureManifest{TargetID: target.ID, Engine: engine}
			state.expectedStates[key] = bench.ObservationComplete
		}
	}
	plan := state.cyclePlan()
	if len(plan) != len(catalog.Targets)*len(bench.Engines()) {
		t.Fatalf("plan cells = %d", len(plan))
	}
	for index, cell := range plan {
		target := catalog.Targets[index/len(bench.Engines())]
		engine := bench.Engines()[index%len(bench.Engines())]
		if want := runCellKey(target.ID, engine); cell.Key != want || cell.Cell.key != want || cell.Cell.manifest.TargetID != target.ID || cell.Cell.manifest.Engine != engine {
			t.Fatalf("plan[%d] = %#v, want target=%q engine=%q key=%q", index, cell, target.ID, engine, want)
		}
		if err := benchcycle.ValidateTwoPassCellKey(cell.Key); err != nil {
			t.Fatalf("plan[%d] key is not an opaque two-pass key: %v", index, err)
		}
	}
	pairs, err := benchcycle.ExecuteTwoPass(context.Background(), benchcycle.TwoPassPlan[cycleCell]{Cells: plan},
		func(_ context.Context, attempt benchcycle.Attempt[cycleCell]) (benchcycle.AttemptOutcome[struct{}], error) {
			return benchcycle.AttemptOutcome[struct{}]{Address: attempt.Address}, nil
		}, nil)
	if err != nil {
		t.Fatalf("execute keyed cycle plan: %v", err)
	}
	for index, pair := range pairs {
		if pair.Cell.Key != plan[index].Key || pair.Outcomes[0].Address != (benchcycle.AttemptAddress{CellKey: plan[index].Key, Repetition: 1}) || pair.Outcomes[1].Address != (benchcycle.AttemptAddress{CellKey: plan[index].Key, Repetition: 2}) {
			t.Fatalf("pair[%d] = %#v", index, pair)
		}
	}
}

func TestStoredCaptureBundlePreservesExactArtifactBytesAndCancellation(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	captured, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	state := runState{rawRunRoot: t.TempDir()}
	store, err := state.newEvidenceStore()
	if err != nil {
		t.Fatal(err)
	}
	path, err := state.storeBundle(context.Background(), store, benchcycle.AttemptAddress{CellKey: runCellKey(manifest.TargetID, manifest.Engine), Repetition: 1}, captured)
	if err != nil {
		t.Fatalf("store capture bundle: %v", err)
	}
	wantPath := filepath.Join(t.TempDir(), "direct")
	if err := WriteBundle(wantPath, captured); err != nil {
		t.Fatal(err)
	}
	got, err := bundleFileMapContext(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := bundleFileMapContext(context.Background(), wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("stored artifact count = %d, want %d", len(got), len(want))
	}
	for name, body := range want {
		if !bytes.Equal(got[name], body) {
			t.Fatalf("stored artifact %q differs from WriteBundle bytes", name)
		}
	}

	cancelledState := runState{rawRunRoot: t.TempDir()}
	cancelledStore, err := cancelledState.newEvidenceStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cancelledState.storeBundle(ctx, cancelledStore, benchcycle.AttemptAddress{CellKey: runCellKey(manifest.TargetID, manifest.Engine), Repetition: 1}, captured); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled bundle storage error = %v, want context cancellation", err)
	}
	entries, err := os.ReadDir(cancelledState.rawRunRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled storage left raw artifacts: %v, %v", entries, err)
	}
}

func TestReadBoundedContextStopsDuringMultiChunkRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancellingChunkReader{cancel: cancel}
	_, _, err := readBoundedContext(ctx, reader, 2*bundleReadBufferSize, 2*bundleReadBufferSize)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("bounded read error = %v, want context cancellation", err)
	}
	if reader.reads != 1 {
		t.Fatalf("bounded reader reads = %d, want cancellation before the second chunk", reader.reads)
	}
}

type cancellingChunkReader struct {
	cancel context.CancelFunc
	reads  int
}

func (reader *cancellingChunkReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.reads > 1 {
		return 0, io.EOF
	}
	for index := range buffer {
		buffer[index] = 'x'
	}
	reader.cancel()
	return len(buffer), nil
}

func TestEvidenceStoreLimitsMatchFixedBundleShape(t *testing.T) {
	if len(capabilitySourceReferences) != fixedCapabilitySourceArtifacts {
		t.Fatalf("capability source count = %d, want %d", len(capabilitySourceReferences), fixedCapabilitySourceArtifacts)
	}
	limits := evidenceStoreLimits()
	maxCaptureBytes := maxBundleArtifactBytes + int64(maxRawBundleArtifacts-1)*maxManifestBytes
	if limits.MaxArtifactBytes != maxBundleArtifactBytes {
		t.Fatalf("artifact limit = %d, want %d", limits.MaxArtifactBytes, maxBundleArtifactBytes)
	}
	if limits.MaxTotalBytes != int64(fixedMatrixCells*fixedRepetitions)*maxCaptureBytes {
		t.Fatalf("aggregate limit = %d, want %d", limits.MaxTotalBytes, int64(fixedMatrixCells*fixedRepetitions)*maxCaptureBytes)
	}
	if limits.MaxFiles != fixedMatrixCells*fixedRepetitions*maxRawBundleArtifacts {
		t.Fatalf("file limit = %d, want %d", limits.MaxFiles, fixedMatrixCells*fixedRepetitions*maxRawBundleArtifacts)
	}
}

func TestCyclePublicationCleansBeforeStageVerificationAndDoesNotOverwrite(t *testing.T) {
	state := testPublicationState(t)
	cleanupCalls := 0
	verified := false
	state.runtimeCleanup = func(context.Context) error {
		cleanupCalls++
		for _, path := range []string{state.workspace.RawRunRoot(), state.workspace.WorkRoot()} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return fmt.Errorf("private state %q remains during runtime cleanup: %v", path, err)
			}
		}
		return nil
	}
	state.stageVerifier = func(_ context.Context, stage string, _ []benchcycle.FileIdentity) error {
		if !state.cleanup.RawRunRemoved || !state.cleanup.DockerCleaned {
			return errors.New("stage verification ran before cleanup")
		}
		if stage == state.input.OutputRoot {
			return errors.New("stage verification read the destination")
		}
		verified = true
		return nil
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state.input.OutputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state.input.OutputRoot, "existing.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("publication overwrote an existing destination")
	}
	if !verified || cleanupCalls != 1 {
		t.Fatalf("verified=%t cleanup calls=%d, want true and one", verified, cleanupCalls)
	}
	body, err := os.ReadFile(filepath.Join(state.input.OutputRoot, "existing.json"))
	if err != nil || string(body) != "existing" {
		t.Fatalf("existing destination = %q, %v", body, err)
	}
}

func TestCyclePublicationFailureCleansPrivateStateOnce(t *testing.T) {
	state := testPublicationState(t)
	cleanupCalls := 0
	state.runtimeCleanup = func(context.Context) error {
		cleanupCalls++
		return errors.New("runtime cleanup failed")
	}
	state.stageVerifier = func(context.Context, string, []benchcycle.FileIdentity) error {
		t.Fatal("stage verifier ran after cleanup failure")
		return nil
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("publication succeeded after cleanup failure")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	for _, path := range []string{state.workspace.RawRunRoot(), state.workspace.WorkRoot(), state.input.OutputRoot} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("path %q remains after failed publication: %v", path, err)
		}
	}
}

func testPublicationState(t *testing.T) runState {
	t.Helper()
	rawRoot := t.TempDir()
	workspace, err := benchcycle.PrepareWorkspace(rawRoot, "run/attempt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(workspace.RawRunRoot()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspace.RawRunRoot(), []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	return runState{
		input:           RunInput{OutputRoot: filepath.Join(t.TempDir(), "output")},
		workspace:       workspace,
		cleanupRequired: true,
	}
}

func completePublicationArtifacts() (bench.Catalog, map[string][]byte) {
	catalog := bench.Catalog{Targets: make([]bench.Target, 0, len(fixedTargetIDs))}
	files := make(map[string][]byte, expectedPublicationFileCount())
	for _, path := range fixedPublicationArtifactPaths {
		files[path] = []byte(path)
	}
	for _, targetID := range fixedTargetIDs {
		body := []byte("SBOM for " + targetID)
		catalog.Targets = append(catalog.Targets, bench.Target{
			ID:         targetID,
			SBOMDigest: bench.SHA256Digest(body),
		})
		files["sboms/"+targetID+".cdx.json"] = body
	}
	return catalog, files
}

func measuredCycleResult(ownedRecall float64) bench.Result {
	metrics := make([]bench.RunMetric, 0, len(fixedTargetIDs)*len(bench.Engines()))
	for _, targetID := range fixedTargetIDs {
		for _, engine := range bench.Engines() {
			recall := 1.0
			if engine == bench.EngineOwned {
				recall = ownedRecall
			}
			metrics = append(metrics, measuredCycleMetric(targetID, engine, recall))
		}
	}
	return bench.Result{
		Gate:       &bench.Gate{Passed: true},
		RunMetrics: metrics,
	}
}

func measuredCycleMetric(targetID string, engine bench.Engine, recall float64) bench.RunMetric {
	truePositives := 1
	falseNegatives := 0
	if recall < 1 {
		falseNegatives = 1
	}
	precision := 1.0
	return bench.RunMetric{
		Run: bench.RunIdentity{
			TargetID: targetID,
			Engine:   engine,
			State:    bench.ObservationComplete,
		},
		Metrics: bench.EngineResult{
			Engine:            engine,
			Covered:           truePositives + falseNegatives + 1,
			AffectedRelations: truePositives + falseNegatives,
			NegativeRelations: 1,
			TruePositives:     truePositives,
			FalseNegatives:    falseNegatives,
			MetricsComplete:   true,
			Precision:         &precision,
			Recall:            &recall,
		},
	}
}

func sourceTarget(t *testing.T, catalog bench.Catalog) bench.Target {
	t.Helper()
	if len(catalog.Targets) != 1 {
		t.Fatal("fixture catalog must contain exactly one target")
	}
	return catalog.Targets[0]
}

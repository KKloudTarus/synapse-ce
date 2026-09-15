package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestManifestSetDerivesCapabilityAndRatchetBindings(t *testing.T) {
	corpus := corpusPath(t)
	output := t.TempDir()
	freezePath := filepath.Join(output, "source-freeze.json")
	writeManifestSourceFreeze(t, corpus, freezePath)
	option := options{
		repositoryRoot: "/trusted/repository", sourceFreezeOutput: freezePath,
		catalog: optionPath(corpus, "catalog.json"), oracle: optionPath(corpus, "oracle.json"), ratchet: optionPath(corpus, "ratchet.json"),
		manifestTemplateDir: optionPath(corpus, "capture-manifests"), manifestOutputDir: filepath.Join(output, "manifests"),
		capabilityOutputDir: filepath.Join(output, "capabilities"), sbomRoot: "/trusted/sboms",
	}
	if err := materializeManifestSet(option); err != nil {
		t.Fatal(err)
	}
	manifests, err := filepath.Glob(filepath.Join(option.manifestOutputDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 8 {
		t.Fatalf("manifest count = %d, want 8", len(manifests))
	}
	statementPath := filepath.Join(option.capabilityOutputDir, "sles-15-6-bci-base-45-31-amd64--osv-scanner.json")
	body, err := os.ReadFile(statementPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != "sha256:bb707e0268663844c464d6d658f0213a46d2619879b13e53b25e3da0566eb4c6" {
		t.Fatalf("capability digest = %s", got)
	}
	manifest, err := decodeCaptureManifest(filepath.Join(option.manifestOutputDir, "sles-15-6-bci-base-45-31-amd64--osv-scanner.json"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Capability == nil || manifest.Capability.Statement.Digest != "sha256:bb707e0268663844c464d6d658f0213a46d2619879b13e53b25e3da0566eb4c6" {
		t.Fatalf("manifest capability = %+v", manifest.Capability)
	}
	freeze, err := decodeSourceFreeze(freezePath)
	if err != nil {
		t.Fatal(err)
	}
	for index := range freeze.Assets {
		if strings.HasPrefix(freeze.Assets[index].Locator, "capability/") {
			freeze.Assets[index].Digest = testDigest('f')
			break
		}
	}
	freeze.ContentDigest, err = bench.DigestContentReferences(freeze.Assets)
	if err != nil {
		t.Fatal(err)
	}
	badFreeze := filepath.Join(output, "bad-source-freeze.json")
	writeTestJSON(t, badFreeze, freeze)
	option.sourceFreezeOutput = badFreeze
	option.manifestOutputDir = filepath.Join(output, "bad-manifests")
	option.capabilityOutputDir = filepath.Join(output, "bad-capabilities")
	if err := materializeManifestSet(option); err == nil || !strings.Contains(err.Error(), "does not match the source freeze") {
		t.Fatalf("capability source freeze mismatch error = %v", err)
	}
}

func TestCorpusDerivesCompleteMatrixWithoutManualCellList(t *testing.T) {
	corpus := corpusPath(t)
	catalog, err := decodeCatalog(optionPath(corpus, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := decodeOracle(optionPath(corpus, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := decodeRatchet(optionPath(corpus, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy cyclePolicy
	if err := decodeJSONFile(optionPath(corpus, "cycle-policy.json"), &policy); err != nil {
		t.Fatal(err)
	}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	invalidPolicy := policy
	invalidPolicy.Repetitions++
	if err := invalidPolicy.validate(); err == nil || !strings.Contains(err.Error(), "exactly two") {
		t.Fatalf("invalid repetition policy error = %v", err)
	}
	states, err := expectedCellStates(catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRatchetPlanBindings(catalog, catalogDigest, oracleDigest, states, ratchet); err != nil {
		t.Fatal(err)
	}
	cells := make([]bench.CycleCell, 0, len(states))
	for key, state := range states {
		targetID, engine, err := splitCellKey(key)
		if err != nil {
			t.Fatal(err)
		}
		dispatches := 1
		if state == bench.ObservationUnsupported {
			dispatches = 0
		}
		cells = append(cells, bench.CycleCell{TargetID: targetID, Engine: engine, ExpectedState: state, ScannerDispatches: dispatches})
	}
	plan := bench.CyclePlan{Repetitions: policy.Repetitions, Cells: canonicalCells(cells)}
	counts := countsForPlan(plan)
	if counts != (matrixCounts{Repetitions: 2, Cells: 8, PlannedSlots: 16, ScannerDispatches: 14, Unsupported: 2}) {
		t.Fatalf("matrix counts = %+v", counts)
	}
	state, exists := states[cellKey("sles-15-6-bci-base-45-31-amd64", bench.EngineOSVScanner)]
	if !exists || state != bench.ObservationUnsupported {
		t.Fatalf("SLES OSV state = %q, exists=%v", state, exists)
	}
}

func TestCorpusContainsOnlyReviewedRootInputs(t *testing.T) {
	corpus := corpusPath(t)
	expected := map[string]struct{}{
		"catalog.json": {}, "oracle.json": {}, "ratchet.json": {}, "source-freeze.template.json": {},
		"source-evidence-plan.template.json": {}, "cycle-policy.json": {}, "falsifier-spec.json": {},
	}
	for _, target := range []string{"debian-12-13-slim-amd64", "sles-15-6-bci-base-45-31-amd64"} {
		for _, engine := range bench.Engines() {
			expected[filepath.ToSlash(filepath.Join("capture-manifests", target+"--"+string(engine)+".json"))] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(corpus, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(corpus, path)
		if err != nil {
			return err
		}
		locator := filepath.ToSlash(relative)
		if _, allowed := expected[locator]; !allowed {
			t.Errorf("corpus contains generated or unreviewed file %q", locator)
		}
		seen[locator] = struct{}{}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{"BEGIN PRIVATE KEY", "AKIA", "ASIA", "secret_access_key", "github_pat_", "ghp_", "Bearer ", `C:\\Users\\`, "/Users/", "/home/", "result.json", "report.md", "observation.json", "raw-output"} {
			if strings.Contains(string(body), forbidden) {
				t.Errorf("corpus file %q contains forbidden generated or sensitive marker %q", locator, forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for locator := range expected {
		if _, exists := seen[locator]; !exists {
			t.Errorf("reviewed corpus input %q is missing", locator)
		}
	}
}

func TestSourceFreezeMaterializationRehashesAssetsAndRebindsPlan(t *testing.T) {
	corpus := corpusPath(t)
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.MkdirAll(filepath.Join(repository, "vendor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "vendor", "debian-bookworm-oval.xml.bz2"), []byte("debian\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "vendor", "sles-15-affected-oval.xml.gz"), []byte("sles\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	capabilityRoot := filepath.Join(repository, "capability", "osv-scanner-v2.5.1")
	if err := os.MkdirAll(capabilityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"purl_to_package.go", "ecosystem.go"} {
		if err := os.WriteFile(filepath.Join(capabilityRoot, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := t.TempDir()
	option := options{
		repositoryRoot: repository, sourceFreezeTemplate: optionPath(corpus, "source-freeze.template.json"), sourcePlanTemplate: optionPath(corpus, "source-evidence-plan.template.json"),
		sourceFreezeOutput: filepath.Join(output, "source-freeze.json"), sourcePlanOutput: filepath.Join(output, "source-plan.json"),
	}
	if err := materializeSourceFreeze(option); err != nil {
		t.Fatal(err)
	}
	freeze, err := decodeSourceFreeze(option.sourceFreezeOutput)
	if err != nil {
		t.Fatal(err)
	}
	var plan bench.SourceEvidencePlan
	if err := decodeJSONFile(option.sourcePlanOutput, &plan); err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceFreezeDigest != freezeDigest {
		t.Fatalf("source plan digest = %s, want %s", plan.SourceFreezeDigest, freezeDigest)
	}
	second := t.TempDir()
	option.sourceFreezeOutput = filepath.Join(second, "source-freeze.json")
	option.sourcePlanOutput = filepath.Join(second, "source-plan.json")
	if err := materializeSourceFreeze(option); err != nil {
		t.Fatal(err)
	}
	assertSameFile(t, filepath.Join(output, "source-freeze.json"), option.sourceFreezeOutput)
	assertSameFile(t, filepath.Join(output, "source-plan.json"), option.sourcePlanOutput)
}

func TestBinaryPinMaterializationRebindsCatalogAndRatchet(t *testing.T) {
	corpus := corpusPath(t)
	output := t.TempDir()
	binaryPath := filepath.Join(output, "synapse-sca-bench")
	binaryBody := []byte("reproducible benchmark binary")
	if err := os.WriteFile(binaryPath, binaryBody, 0o700); err != nil {
		t.Fatal(err)
	}
	catalogOutput := filepath.Join(output, "catalog.json")
	ratchetOutput := filepath.Join(output, "ratchet.json")
	sourceRatchet, err := decodeRatchet(optionPath(corpus, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalBinaryDigests := make(map[string]string, len(sourceRatchet.Floors))
	for _, floor := range sourceRatchet.Floors {
		originalBinaryDigests[cellKey(floor.Expected.TargetID, floor.Expected.Engine)] = floor.Expected.EngineBinaryDigest
	}
	if err := run([]string{
		"-mode", "binary-pin",
		"-catalog", optionPath(corpus, "catalog.json"),
		"-ratchet", optionPath(corpus, "ratchet.json"),
		"-binary-reference", "binary:synapse-sca-bench:reproducible-v1",
		"-binary-path", binaryPath,
		"-engine", string(bench.EngineOwned),
		"-catalog-output", catalogOutput,
		"-ratchet-output", ratchetOutput,
	}); err != nil {
		t.Fatalf("materialize binary pin: %v", err)
	}

	catalog, err := decodeCatalog(catalogOutput)
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := decodeRatchet(ratchetOutput)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binaryBody)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	found := false
	for _, pin := range catalog.Pins {
		if pin.Reference == "binary:synapse-sca-bench:reproducible-v1" {
			found = true
			if pin.Digest != wantDigest {
				t.Fatalf("binary pin = %s, want %s", pin.Digest, wantDigest)
			}
		}
	}
	if !found {
		t.Fatal("materialized catalog omitted the benchmark binary pin")
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if ratchet.CatalogDigest != catalogDigest {
		t.Fatalf("ratchet catalog digest = %s, want %s", ratchet.CatalogDigest, catalogDigest)
	}
	updatedFloors := 0
	for _, floor := range ratchet.Floors {
		if floor.Expected.Engine != bench.EngineOwned {
			key := cellKey(floor.Expected.TargetID, floor.Expected.Engine)
			if floor.Expected.EngineBinaryDigest != originalBinaryDigests[key] {
				t.Fatalf("unrelated floor %s binary digest changed", key)
			}
			continue
		}
		updatedFloors++
		if floor.Expected.EngineBinaryDigest != wantDigest {
			t.Fatalf("owned floor binary digest = %s, want %s", floor.Expected.EngineBinaryDigest, wantDigest)
		}
	}
	if updatedFloors != 2 {
		t.Fatalf("updated %d owned floors, want 2", updatedFloors)
	}
}

func TestBinaryPinMaterializationRejectsMixedRatchetBinding(t *testing.T) {
	corpus := corpusPath(t)
	output := t.TempDir()
	ratchet, err := decodeRatchet(optionPath(corpus, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	for index := range ratchet.Floors {
		if ratchet.Floors[index].Expected.Engine == bench.EngineOwned {
			ratchet.Floors[index].Expected.EngineBinaryDigest = testDigest('f')
			break
		}
	}
	ratchetPath := filepath.Join(output, "mixed-ratchet.json")
	writeTestJSON(t, ratchetPath, ratchet)
	binaryPath := filepath.Join(output, "synapse-sca-bench")
	if err := os.WriteFile(binaryPath, []byte("reproducible benchmark binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	catalogOutput := filepath.Join(output, "catalog-output.json")
	ratchetOutput := filepath.Join(output, "ratchet-output.json")
	err = run([]string{
		"-mode", "binary-pin",
		"-catalog", optionPath(corpus, "catalog.json"),
		"-ratchet", ratchetPath,
		"-binary-reference", "binary:synapse-sca-bench:reproducible-v1",
		"-binary-path", binaryPath,
		"-engine", string(bench.EngineOwned),
		"-catalog-output", catalogOutput,
		"-ratchet-output", ratchetOutput,
	})
	if err == nil || !strings.Contains(err.Error(), "does not bind catalog binary") {
		t.Fatalf("mixed ratchet binding error = %v", err)
	}
	for _, path := range []string{catalogOutput, ratchetOutput} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("failed materialization left output %s", path)
		}
	}
}

func TestNonRegressionFloorPreservesUndefinedPrecisionAndUnsupportedCapability(t *testing.T) {
	zero := 0
	maximum := 99
	minimum := 1
	metricZero := 0.0
	recall := 0.0
	accuracyPilot := bench.RatchetFloor{
		Expected: bench.ExpectedRunIdentity{TargetID: "target", Engine: bench.EngineOwned}, Mode: bench.FloorGateModeAccuracy,
		MinimumCovered: &minimum, MinimumAffectedRelations: &minimum, MinimumNegativeRelations: &minimum, MinimumPrecision: &metricZero, MinimumRecall: &metricZero,
		MaximumFalsePositives: &maximum, MaximumFalseNegatives: &maximum, MaximumUnknown: &maximum, MaximumIncomplete: &zero, MaximumUnsupported: &zero,
	}
	accuracyMetric := bench.RunMetric{Metrics: bench.EngineResult{Covered: 10, AffectedRelations: 2, NegativeRelations: 8, FalseNegatives: 2, Recall: &recall}}
	floor, err := nonRegressionFloor(accuracyPilot, accuracyMetric)
	if err != nil {
		t.Fatal(err)
	}
	if !floor.AllowUndefinedPrecision || *floor.MinimumPrecision != 0 || *floor.MinimumRecall != 0 || *floor.MaximumFalseNegatives != 2 {
		t.Fatalf("accuracy floor = %+v", floor)
	}
	unsupportedPilot := accuracyPilot
	unsupportedPilot.Mode = bench.FloorGateModeUnsupportedOnly
	unsupportedPilot.Expected.CapabilityKind = bench.CapabilityKindOSVScannerSUSERPM
	unsupportedPilot.Expected.CapabilityDigest = testDigest('a')
	unsupportedMetric := bench.RunMetric{Metrics: bench.EngineResult{Unsupported: 35}}
	unsupported, err := nonRegressionFloor(unsupportedPilot, unsupportedMetric)
	if err != nil {
		t.Fatal(err)
	}
	if unsupported.Mode != bench.FloorGateModeUnsupportedOnly || *unsupported.MaximumUnsupported != 35 || *unsupported.MinimumCovered != 0 {
		t.Fatalf("unsupported floor = %+v", unsupported)
	}
}

func TestAccountableReviewMaterializationBindsCaptureOracleAndCommit(t *testing.T) {
	corpus := corpusPath(t)
	repository := t.TempDir()
	capturePath := filepath.Join(repository, "reviews", "github", "123.json")
	if err := os.MkdirAll(filepath.Dir(capturePath), 0o700); err != nil {
		t.Fatal(err)
	}
	capture := bench.GitHubReviewCapture{
		SchemaVersion: bench.GitHubReviewCaptureSchemaVersion, ID: "123", URL: "https://github.com/example/project/pull/7#pullrequestreview-123",
		Login: "reviewer", State: "APPROVED", SubmittedAt: "2026-09-15T12:00:00Z", CommitID: "0123456789abcdef0123456789abcdef01234567", Body: "decision: approved",
	}
	writeTestJSON(t, capturePath, capture)
	adjudicationPath := filepath.Join(t.TempDir(), "adjudication.json")
	adjudication := bench.AdjudicationRecord{SchemaVersion: bench.AdjudicationSchemaVersion, CycleID: "same-sbom-linux-20260915", OracleCandidateDigest: testDigest('1'), CrossCheckDigest: testDigest('2'), ResolutionDigest: testDigest('3'), Status: "resolved"}
	writeTestJSON(t, adjudicationPath, adjudication)
	outputRoot := t.TempDir()
	output := filepath.Join(outputRoot, "accountable-review.json")
	captureOutput := filepath.Join(outputRoot, "review-capture.json")
	if err := materializeAccountableReview(options{repositoryRoot: repository, reviewCaptureLocator: "reviews/github/123.json", reviewCaptureOutput: captureOutput, adjudication: adjudicationPath, oracle: optionPath(corpus, "oracle.json"), reviewOutput: output}); err != nil {
		t.Fatal(err)
	}
	originalCapture, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	retainedCapture, err := os.ReadFile(captureOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalCapture, retainedCapture) {
		t.Fatal("retained review capture differs from the reviewed bytes")
	}
	review, err := decodeReview(output)
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := decodeOracle(optionPath(corpus, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracleDigest, err := bench.DigestOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if review.FinalOracleDigest != oracleDigest || review.ReviewedCommit != capture.CommitID || review.ReviewerIdentity != "github:reviewer" || review.DecisionDigest != review.ReviewCapture.Digest {
		t.Fatalf("review = %+v", review)
	}
}

func TestDecodeJSONFileRejectsDuplicateKeysAndOversizedInputs(t *testing.T) {
	duplicatePath := filepath.Join(t.TempDir(), "duplicate.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"schema_version":"test","nested":{"value":1,"value":2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Nested        struct {
			Value int `json:"value"`
		} `json:"nested"`
	}
	if err := decodeJSONFile(duplicatePath, &decoded); err == nil || !strings.Contains(err.Error(), `duplicate JSON key "value"`) {
		t.Fatalf("duplicate-key error = %v", err)
	}

	caseVariantPath := filepath.Join(t.TempDir(), "case-variant.json")
	if err := os.WriteFile(caseVariantPath, []byte(`{"Schema_Version":"test","nested":{"value":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeJSONFile(caseVariantPath, &decoded); err == nil || !strings.Contains(err.Error(), `unknown JSON field "Schema_Version"`) {
		t.Fatalf("case-variant-key error = %v", err)
	}

	oversizedPath := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat(" ", int(bench.MaxJSONBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeJSONFile(oversizedPath, &decoded); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized-input error = %v", err)
	}
}

func TestPublicationControlDerivesInventoryFromCandidateFiles(t *testing.T) {
	corpus := corpusPath(t)
	candidateRoot := t.TempDir()
	controlRoot := filepath.Join(candidateRoot, "control")
	manifestRoot := filepath.Join(controlRoot, "capture-manifests")
	capabilityRoot := filepath.Join(controlRoot, "capability-statements")
	sbomRoot := filepath.Join(controlRoot, "sboms")
	observationRoot := filepath.Join(controlRoot, "observations")
	recordRoot := filepath.Join(candidateRoot, "records")
	publicationRoot := filepath.Join(candidateRoot, "publication")
	for _, directory := range []string{sbomRoot, observationRoot, recordRoot, publicationRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	repositoryRoot, templateRoot := preparePublicationSources(t, corpus, controlRoot)
	catalog, err := decodeCatalog(optionPath(corpus, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	sbomBody := []byte("{}\n")
	for index := range catalog.Targets {
		catalog.Targets[index].SBOMDigest = bench.SHA256Digest(sbomBody)
	}
	oracle, err := decodeOracle(optionPath(corpus, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	states, err := expectedCellStates(catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]bench.CycleCell, 0, len(states))
	for key, state := range states {
		targetID, engine, splitErr := splitCellKey(key)
		if splitErr != nil {
			t.Fatal(splitErr)
		}
		dispatches := 1
		if state == bench.ObservationUnsupported {
			dispatches = 0
		}
		cells = append(cells, bench.CycleCell{TargetID: targetID, Engine: engine, ExpectedState: state, ScannerDispatches: dispatches})
	}
	plan := bench.CyclePlan{
		SchemaVersion: bench.CyclePlanSchemaVersion, CycleID: "same-sbom-linux-20260915",
		SourceFreezeDigest: testDigest('1'), OracleCandidateDigest: testDigest('2'), CrossCheckDigest: testDigest('3'),
		AdjudicationDigest: testDigest('4'), AccountableReviewDigest: testDigest('5'), FinalOracleDigest: testDigest('6'),
		Repetitions: 2, Cells: canonicalCells(cells),
	}
	planPath := filepath.Join(controlRoot, "plan.json")
	writeTestJSON(t, planPath, plan)
	writeTestJSON(t, filepath.Join(controlRoot, "catalog.json"), catalog)
	for _, path := range []string{
		filepath.Join(controlRoot, "oracle.json"), filepath.Join(controlRoot, "falsifier-spec.json"),
		filepath.Join(controlRoot, "ratchet.json"), filepath.Join(publicationRoot, "native-evidence.json"),
	} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cyclePolicyBody, err := os.ReadFile(optionPath(corpus, "cycle-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controlRoot, "cycle-policy.json"), cyclePolicyBody, 0o600); err != nil {
		t.Fatal(err)
	}
	reviewCapturePath := filepath.Join(controlRoot, "review-capture.json")
	writeTestJSON(t, reviewCapturePath, bench.GitHubReviewCapture{
		SchemaVersion: bench.GitHubReviewCaptureSchemaVersion, ID: "123", URL: "https://github.com/example/project/pull/7#pullrequestreview-123",
		Login: "reviewer", State: "APPROVED", SubmittedAt: "2026-09-15T12:00:00Z", CommitID: "0123456789abcdef0123456789abcdef01234567", Body: "decision: approved",
	})
	reviewCaptureReference, err := contentReference(reviewCapturePath, "reviews/github/123.json")
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, filepath.Join(controlRoot, "accountable-review.json"), bench.AccountableReview{
		SchemaVersion: bench.AccountableReviewSchemaVersion, CycleID: plan.CycleID,
		AdjudicationDigest: testDigest('4'), FinalOracleDigest: plan.FinalOracleDigest,
		ReviewerIdentity: "github:reviewer", SubmittedAt: "2026-09-15T12:00:00Z", ReviewedCommit: "0123456789abcdef0123456789abcdef01234567",
		GitHubReviewID: "123", GitHubReviewURL: "https://github.com/example/project/pull/7#pullrequestreview-123",
		ReviewCapture: reviewCaptureReference, Decision: "approved", DecisionDigest: reviewCaptureReference.Digest,
	})
	for _, target := range catalog.Targets {
		if err := os.WriteFile(filepath.Join(sbomRoot, target.ID+".cdx.json"), sbomBody, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := materializeManifestSet(options{
		repositoryRoot: repositoryRoot, sourceFreezeOutput: filepath.Join(controlRoot, "source-freeze.json"),
		catalog: filepath.Join(controlRoot, "catalog.json"), oracle: optionPath(corpus, "oracle.json"),
		manifestTemplateDir: templateRoot, manifestOutputDir: manifestRoot,
		capabilityOutputDir: capabilityRoot, sbomRoot: sbomRoot,
	}); err != nil {
		t.Fatal(err)
	}
	captures := make([]capture.CycleCellCapture, 0, plan.Repetitions*len(plan.Cells))
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		repetitionRoot := filepath.Join(observationRoot, fmt.Sprintf("%d", repetition))
		if err := os.MkdirAll(repetitionRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		for index, cell := range plan.Cells {
			manifest, decodeErr := decodeCaptureManifest(filepath.Join(manifestRoot, cell.TargetID+"--"+string(cell.Engine)+".json"))
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			target, exists := targetByID(catalog, cell.TargetID)
			if !exists {
				t.Fatalf("target %q is missing", cell.TargetID)
			}
			binaryDigest, digestErr := catalogPin(catalog, manifest.Binary.Reference)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			databaseDigest, digestErr := catalogPin(catalog, manifest.Database.Reference)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			environmentDigest, digestErr := catalogPin(catalog, manifest.EnvironmentPinReference)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			configDigest, digestErr := catalogPin(catalog, manifest.ProfilePinReference)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			observation := bench.Observation{
				SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest,
				Engine: cell.Engine, EngineVersion: manifest.EngineVersion, EngineBinaryDigest: binaryDigest,
				DatabaseBuild: manifest.Database.Build, DatabaseDigest: databaseDigest,
				EnvironmentID: manifest.Environment.ID, EnvironmentDigest: environmentDigest,
				TargetID: cell.TargetID, TargetDigest: target.Digest, SBOMDigest: target.SBOMDigest, State: cell.ExpectedState,
				RawOutputDigest: testDigest('7'), ConfigDigest: configDigest,
			}
			if manifest.Capability != nil {
				observation.CapabilityKind = bench.CapabilityKindOSVScannerSUSERPM
				observation.CapabilityDigest = manifest.Capability.Statement.Digest
			}
			writeTestJSON(t, filepath.Join(repetitionRoot, cell.TargetID+"--"+string(cell.Engine)+".json"), observation)
			packageFamily := "deb"
			method := "target-native-dpkg"
			if strings.HasPrefix(target.Components[0].PURL, "pkg:rpm/") {
				packageFamily = "rpm"
				method = "target-native-rpm"
			}
			native := bench.NativeTargetEvidence{
				TargetID: target.ID, TargetDigest: target.Digest, PackageFamily: packageFamily,
				Comparisons: []bench.NativeComparisonRecord{{
					SchemaVersion: bench.NativeComparisonSchemaVersion, ID: fmt.Sprintf("comparison-%d-%d", repetition, index),
					TargetID: target.ID, TargetDigest: target.Digest, PackageFamily: packageFamily,
					PackageIdentity: "binary:fixture", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: method, ExecutionDigest: testDigest('8'),
				}},
			}
			nativeDigest, digestErr := bench.DigestNativeTargetEvidence(native)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			rootDigest := bench.SHA256Digest([]byte(fmt.Sprintf("%d/%s/%s", repetition, cell.TargetID, cell.Engine)))
			evidence := &bench.BundleEvidenceIdentity{
				TargetID: cell.TargetID, Engine: cell.Engine, BundleManifestDigest: testDigest('9'), BundleRootDigest: rootDigest,
				RawOutputDigest: testDigest('a'), NormalizedObservationDigest: testDigest('b'), SBOMDigest: target.SBOMDigest,
				NativeComparisonDigest: nativeDigest, ProcessEvidenceDigest: testDigest('c'), EnvironmentDigest: testDigest('d'),
			}
			record := capture.CycleCellCapture{
				Repetition: repetition, TargetID: cell.TargetID, Engine: cell.Engine, Outcome: bench.CycleAttemptAccepted,
				ObservationState: cell.ExpectedState, ScannerDispatches: cell.ScannerDispatches,
				Bundle:           bench.ProtectedBundleReference{Locator: fmt.Sprintf("protected://fixture/%d/%s/%s", repetition, cell.TargetID, cell.Engine), Digest: rootDigest, Retention: "delete_after_verification"},
				Identity:         capture.BundleIdentity{TargetID: cell.TargetID, Engine: cell.Engine, RootDigest: rootDigest},
				EvidenceIdentity: evidence, NativeEvidence: native,
			}
			writeTestJSON(t, filepath.Join(recordRoot, fmt.Sprintf("%d-%s--%s-attempt-1.json", repetition, cell.TargetID, cell.Engine)), record)
			captures = append(captures, record)
		}
	}
	ledger, err := capture.BuildCycleLedger(plan, captures)
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, filepath.Join(controlRoot, "cycle-ledger.json"), ledger)
	outputPath := filepath.Join(controlRoot, "publication-control.json")
	commit := "0123456789abcdef0123456789abcdef01234567"
	if err := materializePublicationControl(options{candidateRoot: candidateRoot, implementationCommit: commit, planOutput: planPath, publicationControlOutput: outputPath}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	publicationControl, err := bench.DecodePublicationControl(file)
	if err != nil {
		t.Fatal(err)
	}
	if publicationControl.ImplementationCommit != commit || len(publicationControl.Artifacts) != 7 {
		t.Fatalf("publication control commit/indexes = %s/%d", publicationControl.ImplementationCommit, len(publicationControl.Artifacts))
	}
	indexedFiles := 0
	for _, artifact := range publicationControl.Artifacts {
		var index publicationArtifactIndex
		if err := decodeJSONFile(filepath.Join(candidateRoot, filepath.FromSlash(artifact.Reference.Locator)), &index); err != nil {
			t.Fatal(err)
		}
		if err := index.validate(); err != nil {
			t.Fatal(err)
		}
		if index.Kind != artifact.Kind {
			t.Fatalf("publication index kind = %q, want %q", index.Kind, artifact.Kind)
		}
		indexedFiles += len(index.Files)
	}
	if indexedFiles != 57 {
		t.Fatalf("indexed files = %d, want 57", indexedFiles)
	}
	firstObservation := filepath.Join(observationRoot, "1", plan.Cells[0].TargetID+"--"+string(plan.Cells[0].Engine)+".json")
	secondObservation := filepath.Join(observationRoot, "1", plan.Cells[1].TargetID+"--"+string(plan.Cells[1].Engine)+".json")
	firstObservationBody, err := os.ReadFile(firstObservation)
	if err != nil {
		t.Fatal(err)
	}
	secondObservationBody, err := os.ReadFile(secondObservation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstObservation, secondObservationBody, 0o600); err != nil {
		t.Fatal(err)
	}
	swappedOutput := filepath.Join(candidateRoot, "swapped", "publication-control.json")
	if err := materializePublicationControl(options{candidateRoot: candidateRoot, implementationCommit: commit, planOutput: planPath, publicationControlOutput: swappedOutput}); err == nil || !strings.Contains(err.Error(), "does not match its planned slot") {
		t.Fatalf("swapped observation error = %v", err)
	}
	if err := os.WriteFile(firstObservation, firstObservationBody, 0o600); err != nil {
		t.Fatal(err)
	}
	firstRecord := filepath.Join(recordRoot, fmt.Sprintf("1-%s--%s-attempt-1.json", plan.Cells[0].TargetID, plan.Cells[0].Engine))
	gappedRecord := filepath.Join(recordRoot, fmt.Sprintf("1-%s--%s-attempt-2.json", plan.Cells[0].TargetID, plan.Cells[0].Engine))
	if err := os.Rename(firstRecord, gappedRecord); err != nil {
		t.Fatal(err)
	}
	gappedOutput := filepath.Join(candidateRoot, "gapped", "publication-control.json")
	if err := materializePublicationControl(options{candidateRoot: candidateRoot, implementationCommit: commit, planOutput: planPath, publicationControlOutput: gappedOutput}); err == nil || !strings.Contains(err.Error(), "contiguous attempt sequence") {
		t.Fatalf("gapped process records error = %v", err)
	}
	if err := os.Rename(gappedRecord, firstRecord); err != nil {
		t.Fatal(err)
	}
	overflowRecord := filepath.Join(recordRoot, fmt.Sprintf("1-%s--%s-attempt-4.json", plan.Cells[0].TargetID, plan.Cells[0].Engine))
	if err := os.Rename(firstRecord, overflowRecord); err != nil {
		t.Fatal(err)
	}
	overflowOutput := filepath.Join(candidateRoot, "overflow", "publication-control.json")
	if err := materializePublicationControl(options{candidateRoot: candidateRoot, implementationCommit: commit, planOutput: planPath, publicationControlOutput: overflowOutput}); err == nil || !strings.Contains(err.Error(), "attempt outside policy") {
		t.Fatalf("out-of-policy process record error = %v", err)
	}
	if err := os.Rename(overflowRecord, firstRecord); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controlRoot, "source-freeze.json"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range publicationControl.Artifacts {
		if artifact.Kind != "source_snapshot" {
			continue
		}
		_, err := verifyPublicationIndex(candidateRoot, artifact.Kind, filepath.Join(candidateRoot, filepath.FromSlash(artifact.Reference.Locator)))
		if err == nil || !strings.Contains(err.Error(), "digest or size changed") {
			t.Fatalf("tampered indexed input error = %v", err)
		}
	}
}

func TestCleanupRejectsEscapingRunIdentityBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cleanupRunnerState(options{
		rawRetentionRoot: root, runID: "..", runAttempt: "1", cleanupOutput: filepath.Join(root, "receipt.json"), dockerBinary: "unused",
	})
	if err == nil || !strings.Contains(err.Error(), "portable path segments") {
		t.Fatalf("cleanup path error = %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel changed: %v", err)
	}
}

func TestCandidateReceiptRequiresExactImplementationCommit(t *testing.T) {
	err := materializeCandidateReceipt(options{candidateRoot: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "implementation commit is required") {
		t.Fatalf("missing-commit error = %v", err)
	}
}

func TestCandidateInventoryRejectsUnexpectedAndRawFiles(t *testing.T) {
	safe := bench.ContentReference{Locator: "publication/result.json"}
	allowed := map[string]struct{}{safe.Locator: {}}
	if err := validateCandidateInventory([]bench.ContentReference{safe}, allowed); err != nil {
		t.Fatal(err)
	}
	unexpected := bench.ContentReference{Locator: "captures/scanner-output.json"}
	if err := validateCandidateInventory([]bench.ContentReference{unexpected}, allowed); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("unexpected candidate file error = %v", err)
	}
	raw := bench.ContentReference{Locator: "publication/raw-output.json"}
	if err := validateCandidateInventory([]bench.ContentReference{raw}, map[string]struct{}{raw.Locator: {}}); err == nil || !strings.Contains(err.Error(), "raw scanner material") {
		t.Fatalf("raw candidate file error = %v", err)
	}
}

func corpusPath(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "internal", "usecase", "scabench", "corpus"))
}

func optionPath(root, name string) string { return filepath.Join(root, filepath.FromSlash(name)) }

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := bench.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyTestFile(t *testing.T, source, destination string) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeManifestSourceFreeze(t *testing.T, corpus, output string) {
	t.Helper()
	var freezeTemplate sourceFreezeTemplate
	if err := decodeJSONFile(optionPath(corpus, "source-freeze.template.json"), &freezeTemplate); err != nil {
		t.Fatal(err)
	}
	var manifestTemplate captureManifestTemplate
	if err := decodeJSONFile(optionPath(corpus, "capture-manifests/sles-15-6-bci-base-45-31-amd64--osv-scanner.json"), &manifestTemplate); err != nil {
		t.Fatal(err)
	}
	capabilityDigests := make(map[string]string, len(manifestTemplate.Capability.Sources))
	for _, source := range manifestTemplate.Capability.Sources {
		capabilityDigests[source.Locator] = source.Digest
	}
	assets := make([]bench.ContentReference, 0, len(freezeTemplate.Assets))
	for index, asset := range freezeTemplate.Assets {
		digest, exists := capabilityDigests[asset.Locator]
		if !exists {
			digest = testDigest(byte('a' + index))
		}
		assets = append(assets, bench.ContentReference{Locator: asset.Locator, Digest: digest, Size: 1})
	}
	sort.Slice(assets, func(left, right int) bool { return assets[left].Locator < assets[right].Locator })
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, output, bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: freezeTemplate.CycleID, Assets: assets, ContentDigest: contentDigest})
}

func preparePublicationSources(t *testing.T, corpus, controlRoot string) (string, string) {
	t.Helper()
	var freezeTemplate sourceFreezeTemplate
	if err := decodeJSONFile(optionPath(corpus, "source-freeze.template.json"), &freezeTemplate); err != nil {
		t.Fatal(err)
	}
	repositoryRoot := t.TempDir()
	for _, asset := range freezeTemplate.Assets {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(asset.Locator))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture:"+asset.Locator+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	templateRoot := filepath.Join(t.TempDir(), "capture-manifests")
	if err := os.MkdirAll(templateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(optionPath(corpus, "capture-manifests"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		sourcePath := optionPath(corpus, "capture-manifests/"+entry.Name())
		destinationPath := filepath.Join(templateRoot, entry.Name())
		if entry.Name() != "sles-15-6-bci-base-45-31-amd64--osv-scanner.json" {
			copyTestFile(t, sourcePath, destinationPath)
			continue
		}
		var template captureManifestTemplate
		if err := decodeJSONFile(sourcePath, &template); err != nil {
			t.Fatal(err)
		}
		for index := range template.Capability.Sources {
			path := filepath.Join(repositoryRoot, filepath.FromSlash(template.Capability.Sources[index].Locator))
			reference, err := contentReference(path, template.Capability.Sources[index].Locator)
			if err != nil {
				t.Fatal(err)
			}
			template.Capability.Sources[index].Digest = reference.Digest
		}
		writeTestJSON(t, destinationPath, template)
	}
	freezePath := filepath.Join(controlRoot, "source-freeze.json")
	sourcePlanPath := filepath.Join(controlRoot, "source-evidence-plan.json")
	if err := materializeSourceFreeze(options{
		repositoryRoot: repositoryRoot, sourceFreezeTemplate: optionPath(corpus, "source-freeze.template.json"),
		sourcePlanTemplate: optionPath(corpus, "source-evidence-plan.template.json"), sourceFreezeOutput: freezePath, sourcePlanOutput: sourcePlanPath,
	}); err != nil {
		t.Fatal(err)
	}
	freeze, err := decodeSourceFreeze(freezePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range freeze.Assets {
		sourcePath := filepath.Join(repositoryRoot, filepath.FromSlash(asset.Locator))
		destinationPath := filepath.Join(controlRoot, "source-assets", filepath.FromSlash(asset.Locator))
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
			t.Fatal(err)
		}
		copyTestFile(t, sourcePath, destinationPath)
	}
	return repositoryRoot, templateRoot
}

func assertSameFile(t *testing.T, left, right string) {
	t.Helper()
	leftBody, err := os.ReadFile(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBody, err := os.ReadFile(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftBody) != string(rightBody) {
		t.Fatalf("files differ: %s and %s", left, right)
	}
}

func testDigest(character byte) string { return "sha256:" + repeatByte(character, 64) }

func repeatByte(character byte, count int) string {
	body := make([]byte, count)
	for index := range body {
		body[index] = character
	}
	return string(body)
}

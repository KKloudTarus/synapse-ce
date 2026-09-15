package scabench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	publishedBenchmarkComparisonSHA256 = "3183de973f6a00c04896216262da44b6435e66584128b49253ce775513648948"
	publishedBenchmarkResultSHA256     = "eac69db59c23b0a5efe6fe694375c180e7d82b123b8e1a105eb9d643b0eecd2c"
)

type publishedBenchmarkContentIdentity struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

var publishedBenchmarkFixtureFiles = map[string]publishedBenchmarkContentIdentity{
	"catalog.json": {
		SHA256: "af72418b62bc0da9e0d17b9431ff55fe92af3ddad484a4411b3fdafad6d96513",
		Size:   49314,
	},
	"comparison.json": {
		SHA256: publishedBenchmarkComparisonSHA256,
		Size:   17740,
	},
	"observations/debian-12-13-slim-amd64--grype.json": {
		SHA256: "7265d39ed49a2c06b5f73f54d7ca468f3d84317b74f9cc2eba387ed280d7b444",
		Size:   47099,
	},
	"observations/debian-12-13-slim-amd64--osv-scanner.json": {
		SHA256: "174b91f196776abbf43c2be13e386af1ce9392f5574e69491a5138e9cfae65a8",
		Size:   6220,
	},
	"observations/debian-12-13-slim-amd64--owned.json": {
		SHA256: "1fb40eb6b1eef969801f3af546349f06b57dcc0eaaba98ab09bbac6c492d7b7f",
		Size:   9331,
	},
	"observations/debian-12-13-slim-amd64--trivy.json": {
		SHA256: "e3043c1205cbf661ad7b830a6fbbf5899c04312f55496779fc47a8109885b046",
		Size:   6559,
	},
	"observations/sles-15-6-bci-base-amd64--grype.json": {
		SHA256: "2c9395aa8ee15f620702f57a29d12bcd0e949ccdef259a20a28524897ee321fa",
		Size:   53463,
	},
	"observations/sles-15-6-bci-base-amd64--osv-scanner-unsupported.json": {
		SHA256: "f2fad9e99256d013822f010828058a3f0f6b11183f587ef8ffc8d446296f2d1b",
		Size:   1456,
	},
	"observations/sles-15-6-bci-base-amd64--owned.json": {
		SHA256: "8b1888a4b48bab51c9e07780702aacb361a285c8b58c273d16d84ba1952816ce",
		Size:   53478,
	},
	"observations/sles-15-6-bci-base-amd64--trivy.json": {
		SHA256: "213dd97830fcdefc65081adb62b631e96b6d64c0e13c991bc8cd38d820bd1973",
		Size:   1280,
	},
	"oracle.json": {
		SHA256: "c6e7ad9e96f7fd2bb45433804e584654736d8aadecb3013c6864cd3a490e0d90",
		Size:   1275497,
	},
	"provenance.json": {
		SHA256: "4515b54326b5687fcdaddf8d2a046272c668588d7c9ef4268c363617ad97da0b",
		Size:   8422,
	},
	"ratchet.json": {
		SHA256: "9474093eda3f179d1a99dae108119ee2353d96a75acc4693db3080940c29f4eb",
		Size:   8817,
	},
	"result.json": {
		SHA256: publishedBenchmarkResultSHA256,
		Size:   127331,
	},
	"sboms/debian-12-13-slim-amd64.json": {
		SHA256: "7ce61382f20b13bc49a843112f3fd83a8bcb215c2c01bd77263735f0093b6d39",
		Size:   1015852,
	},
	"sboms/sles-15-6-bci-base-amd64.json": {
		SHA256: "c858309e5c5df2ce920343bc104c8011e99fc26ea5337aa7c1fb35c8d2dfc870",
		Size:   899649,
	},
}

type publishedBenchmarkComparison struct {
	Schema           string `json:"schema"`
	ComparisonPolicy string `json:"comparison_policy"`
	ClaimScope       string `json:"claim_scope"`
	BundleCounts     struct {
		Exact    int `json:"exact"`
		Semantic int `json:"semantic"`
		Total    int `json:"total"`
	} `json:"bundle_counts"`
	ExactBundles                []json.RawMessage `json:"exact_bundles"`
	SemanticBundles             []json.RawMessage `json:"semantic_bundles"`
	FalsifierCount              int               `json:"falsifier_count"`
	Falsifiers                  map[string]bool   `json:"falsifiers"`
	ReducedResultSHA256         string            `json:"reduced_result_sha256"`
	ReducedResultsByteIdentical bool              `json:"reduced_results_byte_identical"`
	SemanticReproducibility     bool              `json:"semantic_reproducibility"`
	RawEvidencePreserved        bool              `json:"raw_evidence_preserved"`
}

type publishedBenchmarkProvenance struct {
	Schema    string `json:"schema"`
	Benchmark struct {
		CatalogDigest            string `json:"catalog_digest"`
		CatalogRevision          string `json:"catalog_revision"`
		DiagnosticCount          int    `json:"diagnostic_count"`
		GateCheckCount           int    `json:"gate_check_count"`
		GatePassed               bool   `json:"gate_passed"`
		OracleDigest             string `json:"oracle_digest"`
		ResultID                 string `json:"result_id"`
		ScoringObservationDigest string `json:"scoring_observation_digest"`
	} `json:"benchmark"`
	Targets []struct {
		ID         string `json:"id"`
		SBOMSHA256 string `json:"sbom_sha256"`
		SBOMSize   int64  `json:"sbom_size"`
	} `json:"targets"`
	Execution struct {
		Matrix []struct {
			Engine string `json:"engine"`
			Mode   string `json:"mode"`
			Target string `json:"target"`
		} `json:"matrix"`
		SameCanonicalSBOMBytesForAllEngines bool `json:"same_canonical_sbom_bytes_for_all_engines"`
		ScannerDatabasesUnchanged           bool `json:"scanner_databases_unchanged_across_repetitions"`
	} `json:"execution"`
	Truth struct {
		CaseCount                              int  `json:"case_count"`
		IndependentScannerFreeLabeling         bool `json:"independent_scanner_free_labeling"`
		ScannerOutputUsedToCreateOrReviseLabel bool `json:"scanner_output_used_to_create_or_revise_labels"`
	} `json:"truth"`
	SemanticReproducibility struct {
		AllFalsifiersPassed                  bool                              `json:"all_falsifiers_passed"`
		ClaimScope                           string                            `json:"claim_scope"`
		Comparison                           publishedBenchmarkContentIdentity `json:"comparison"`
		ExactBundleCount                     int                               `json:"exact_bundle_count"`
		FalsifierCount                       int                               `json:"falsifier_count"`
		Policy                               string                            `json:"policy"`
		RawEvidencePreservedDuringComparison bool                              `json:"raw_evidence_preserved_during_comparison"`
		SemanticBundleCount                  int                               `json:"semantic_bundle_count"`
		TotalBundleCount                     int                               `json:"total_bundle_count"`
		TwoComparisonOutputsByteIdentical    bool                              `json:"two_comparison_outputs_byte_identical"`
	} `json:"semantic_reproducibility"`
	AcceptedRepetitions struct {
		Count       int `json:"count"`
		Repetitions []struct {
			RepetitionID                     int `json:"repetition_id"`
			CellCount                        int `json:"cell_count"`
			ScannerDispatchCount             int `json:"scanner_dispatch_count"`
			UnsupportedOnlyZeroDispatchCount int `json:"unsupported_only_zero_dispatch_count"`
		} `json:"repetitions"`
	} `json:"accepted_repetitions"`
	FixtureFiles map[string]publishedBenchmarkContentIdentity `json:"fixture_files"`
}

func TestPublishedBenchmarkFixtureContract(t *testing.T) {
	root := publishedBenchmarkFixtureRoot(t)
	publishedBenchmarkVerifyInventoryAndContent(t, root)

	catalog, err := DecodeCatalog(bytes.NewReader(publishedBenchmarkReadFile(t, root, "catalog.json")))
	if err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	oracle, err := DecodeOracle(bytes.NewReader(publishedBenchmarkReadFile(t, root, "oracle.json")))
	if err != nil {
		t.Fatalf("decode oracle: %v", err)
	}
	ratchet, err := DecodeRatchet(bytes.NewReader(publishedBenchmarkReadFile(t, root, "ratchet.json")))
	if err != nil {
		t.Fatalf("decode ratchet: %v", err)
	}
	result, err := DecodeResult(bytes.NewReader(publishedBenchmarkReadFile(t, root, "result.json")))
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if err := Validate(catalog, oracle); err != nil {
		t.Fatalf("validate catalog and oracle: %v", err)
	}

	for _, name := range publishedBenchmarkObservationFiles() {
		set, err := DecodeObservationSet(bytes.NewReader(publishedBenchmarkReadFile(t, root, name)))
		if err != nil {
			t.Fatalf("decode observation %q: %v", name, err)
		}
		if len(set.Observations) != 1 {
			t.Fatalf("observation set %q count = %d, want 1", name, len(set.Observations))
		}
	}

	if len(catalog.Targets) != 2 || len(result.Targets) != 2 {
		t.Fatalf("target count catalog/result = %d/%d, want 2/2", len(catalog.Targets), len(result.Targets))
	}
	if len(oracle.Cases) != 628 {
		t.Fatalf("oracle case count = %d, want 628", len(oracle.Cases))
	}
	if len(ratchet.Floors) != 8 || len(result.Runs) != 8 || len(result.RunMetrics) != 8 {
		t.Fatalf("ratchet/runs/run metrics = %d/%d/%d, want 8/8/8", len(ratchet.Floors), len(result.Runs), len(result.RunMetrics))
	}
	if result.Gate == nil || !result.Gate.Passed || len(result.Gate.Checks) != 8 {
		t.Fatalf("gate = %+v, want passed with 8 checks", result.Gate)
	}
	if len(result.Diagnostics) != 348 {
		t.Fatalf("diagnostic count = %d, want 348", len(result.Diagnostics))
	}
	publishedBenchmarkRequireRunMetric(t, result, "debian-12-13-slim-amd64", EngineTrivy, ObservationComplete, 5, 0, 0)
	publishedBenchmarkRequireRunMetric(t, result, "sles-15-6-bci-base-amd64", EngineTrivy, ObservationComplete, 0, 239, 0)
	publishedBenchmarkRequireRunMetric(t, result, "sles-15-6-bci-base-amd64", EngineOSVScanner, ObservationUnsupported, 0, 0, 507)
	const capabilityKind = CapabilityKindOSVScannerSUSERPM
	const capabilityDigest = "sha256:426d839d8e21d9293851730acb892755d8ec2811ef5f6f26326ad78faa569b7a"
	for _, floor := range ratchet.Floors {
		unsupported := floor.Expected.Engine == EngineOSVScanner && floor.Expected.TargetID == "sles-15-6-bci-base-amd64"
		if unsupported && (floor.Expected.CapabilityKind != capabilityKind || floor.Expected.CapabilityDigest != capabilityDigest) {
			t.Fatalf("unsupported-only ratchet capability identity = %+v", floor.Expected)
		}
		if !unsupported && (floor.Expected.CapabilityKind != "" || floor.Expected.CapabilityDigest != "") {
			t.Fatalf("accuracy ratchet carried a capability identity: %+v", floor.Expected)
		}
	}
	for _, run := range result.Runs {
		unsupported := run.Engine == EngineOSVScanner && run.TargetID == "sles-15-6-bci-base-amd64"
		if unsupported && (run.CapabilityKind != capabilityKind || run.CapabilityDigest != capabilityDigest) {
			t.Fatalf("unsupported run capability identity = %+v", run)
		}
		if !unsupported && (run.CapabilityKind != "" || run.CapabilityDigest != "") {
			t.Fatalf("non-unsupported run carried a capability identity: %+v", run)
		}
	}

	comparisonRaw, _ := publishedBenchmarkStrictJSONObjectWithRequiredNames(t, root, "comparison.json", []string{
		"bundle_counts", "bundle_file_sets_identical", "claim_scope", "comparison_policy", "exact_bundles",
		"falsifier_count", "falsifiers", "grype_policy", "observation_envelope_allowed_difference_paths",
		"osv_pointer_and_timing_policy", "raw_evidence_preserved", "reduced_result_sha256",
		"reduced_results_byte_identical", "schema", "semantic_bundles", "semantic_reproducibility", "trivy_policy",
	})
	var comparison publishedBenchmarkComparison
	if err := json.Unmarshal(comparisonRaw, &comparison); err != nil {
		t.Fatalf("decode comparison contract: %v", err)
	}
	schemaRevision, schemaVersioned := publishedBenchmarkVersionedFamily(comparison.Schema)
	policyRevision, policyVersioned := publishedBenchmarkVersionedFamily(comparison.ComparisonPolicy)
	if !schemaVersioned || !policyVersioned || schemaRevision != policyRevision {
		t.Fatalf("comparison schema/policy must be non-empty, versioned, and use the same revision: %q/%q", comparison.Schema, comparison.ComparisonPolicy)
	}
	if comparison.BundleCounts.Exact != 3 || comparison.BundleCounts.Semantic != 5 || comparison.BundleCounts.Total != 8 || len(comparison.ExactBundles) != 3 || len(comparison.SemanticBundles) != 5 {
		t.Fatalf("comparison bundles = %+v (exact=%d semantic=%d), want 3 exact and 5 semantic", comparison.BundleCounts, len(comparison.ExactBundles), len(comparison.SemanticBundles))
	}
	if comparison.FalsifierCount != 41 || len(comparison.Falsifiers) != 41 {
		t.Fatalf("comparison falsifiers = %d/%d, want 41/41", comparison.FalsifierCount, len(comparison.Falsifiers))
	}
	for name, passed := range comparison.Falsifiers {
		if !passed {
			t.Fatalf("comparison falsifier %q did not pass", name)
		}
	}
	if comparison.ClaimScope != "semantic reproducibility only; does not attest raw-byte reproducibility, vulnerability accuracy, or fingerprint stability" {
		t.Fatalf("comparison claim scope = %q", comparison.ClaimScope)
	}
	if comparison.ReducedResultSHA256 != "sha256:"+publishedBenchmarkResultSHA256 || !comparison.ReducedResultsByteIdentical || !comparison.SemanticReproducibility || !comparison.RawEvidencePreserved {
		t.Fatalf("comparison reproducibility evidence = %+v", comparison)
	}

	provenanceRaw, _ := publishedBenchmarkStrictJSONObject(t, root, "provenance.json", []string{
		"accepted_repetitions", "benchmark", "execution", "fixture_files", "pins", "repository_reconciliation",
		"result_metrics", "sanitization", "schema", "semantic_reproducibility", "targets", "truth",
	})
	var provenance publishedBenchmarkProvenance
	if err := json.Unmarshal(provenanceRaw, &provenance); err != nil {
		t.Fatalf("decode provenance contract: %v", err)
	}
	if provenance.Schema != "synapse-sca-benchmark-provenance/v1" {
		t.Fatalf("provenance schema = %q", provenance.Schema)
	}
	if provenance.Truth.CaseCount != 628 || !provenance.Truth.IndependentScannerFreeLabeling || provenance.Truth.ScannerOutputUsedToCreateOrReviseLabel {
		t.Fatalf("truth provenance = %+v", provenance.Truth)
	}
	if len(provenance.Execution.Matrix) != 8 || !provenance.Execution.SameCanonicalSBOMBytesForAllEngines || !provenance.Execution.ScannerDatabasesUnchanged {
		t.Fatalf("execution provenance = %+v", provenance.Execution)
	}
	if provenance.AcceptedRepetitions.Count != 2 || len(provenance.AcceptedRepetitions.Repetitions) != 2 {
		t.Fatalf("accepted repetitions = %+v, want exactly 2", provenance.AcceptedRepetitions)
	}
	for _, repetition := range provenance.AcceptedRepetitions.Repetitions {
		if repetition.CellCount != 8 || repetition.ScannerDispatchCount != 7 || repetition.UnsupportedOnlyZeroDispatchCount != 1 {
			t.Fatalf("repetition %d = %+v, want 8 cells, 7 dispatches, and one zero-dispatch unsupported-only cell", repetition.RepetitionID, repetition)
		}
	}
	if provenance.Benchmark.DiagnosticCount != 348 || provenance.Benchmark.GateCheckCount != 8 || !provenance.Benchmark.GatePassed || provenance.Benchmark.ResultID != result.ID {
		t.Fatalf("benchmark provenance = %+v", provenance.Benchmark)
	}
	if !provenance.SemanticReproducibility.AllFalsifiersPassed || provenance.SemanticReproducibility.Policy != comparison.ComparisonPolicy || provenance.SemanticReproducibility.ExactBundleCount != 3 || provenance.SemanticReproducibility.SemanticBundleCount != 5 || provenance.SemanticReproducibility.TotalBundleCount != 8 || provenance.SemanticReproducibility.FalsifierCount != 41 || !provenance.SemanticReproducibility.TwoComparisonOutputsByteIdentical {
		t.Fatalf("semantic reproducibility provenance = %+v", provenance.SemanticReproducibility)
	}
	if provenance.SemanticReproducibility.Comparison != (publishedBenchmarkContentIdentity{SHA256: "sha256:" + publishedBenchmarkComparisonSHA256, Size: 17740}) {
		t.Fatalf("comparison identity in provenance = %+v", provenance.SemanticReproducibility.Comparison)
	}
	publishedBenchmarkVerifyProvenanceFileIdentities(t, provenance.FixtureFiles)
	publishedBenchmarkVerifyProvenanceSBOMIdentities(t, provenance.Targets)
}

func TestPublishedBenchmarkFixtureHygiene(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "credential assignment", content: `{"aws_access_key_id":"fixture-secret"}`, want: "credential assignment"},
		{name: "PEM private key", content: "-----BEGIN PRIVATE KEY-----", want: "PEM private key"},
		{name: "Windows user home", content: `C:\\Users\\fixture-user\\secret.txt`, want: "Windows user-home path"},
		{name: "POSIX user home", content: "/home/fixture-user/secret.txt", want: "POSIX user-home path"},
		{name: "AWS account ID", content: "123456789012", want: "AWS account or physical resource ID"},
		{name: "AWS physical resource ID", content: "i-0123456789abcdef0", want: "AWS account or physical resource ID"},
		{name: "credential-bearing URL", content: "https://fixture:secret@example.test/path", want: "credential-bearing URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !publishedBenchmarkContainsHygieneFinding(publishedBenchmarkHygieneFindings(test.content), test.want) {
				t.Fatalf("hygiene scanner did not reject %q: %v", test.content, publishedBenchmarkHygieneFindings(test.content))
			}
		})
	}
	for _, allowed := range []string{
		`{"description":"This package accepts a password in an application-specific configuration."}`,
	} {
		if findings := publishedBenchmarkHygieneFindings(allowed); len(findings) != 0 {
			t.Fatalf("hygiene scanner rejected an allowed description %q: %v", allowed, findings)
		}
	}

	root := publishedBenchmarkFixtureRoot(t)
	for _, name := range publishedBenchmarkSortedFixtureNames() {
		raw := publishedBenchmarkReadFile(t, root, name)
		content := string(raw)
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("decode %q for hygiene: %v", name, err)
		}
		content += "\n" + strings.Join(publishedBenchmarkStringValues(value), "\n")
		if findings := publishedBenchmarkHygieneFindings(content); len(findings) != 0 {
			t.Errorf("fixture %q has forbidden hygiene content: %s", name, strings.Join(findings, ", "))
		}
	}

	oracle, err := DecodeOracle(bytes.NewReader(publishedBenchmarkReadFile(t, root, "oracle.json")))
	if err != nil {
		t.Fatal(err)
	}
	fileReferences := make([]string, 0)
	for _, oracleCase := range oracle.Cases {
		for _, citation := range oracleCase.Citations {
			if strings.HasPrefix(citation.Reference, "file://") {
				fileReferences = append(fileReferences, citation.Reference)
			}
		}
	}
	citationRoot, err := publishedBenchmarkCitationRoot(fileReferences)
	if err != nil {
		t.Fatalf("validate fixture file citations: %v", err)
	}
	if findings := publishedBenchmarkHygieneFindings(citationRoot + "independent-review/case-001.json"); len(findings) != 0 {
		t.Fatalf("hygiene scanner rejected a stable citation root %q: %v", citationRoot, findings)
	}
}

func publishedBenchmarkCitationRoot(references []string) (string, error) {
	var root string
	for _, reference := range references {
		parsed, err := url.ParseRequestURI(reference)
		if err != nil {
			return "", fmt.Errorf("parse file citation %q: %w", reference, err)
		}
		if parsed.Scheme != "file" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", fmt.Errorf("file citation must be an authority-free path without query or fragment: %q", reference)
		}
		pathSegments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(pathSegments) < 3 || pathSegments[0] != "opt" {
			return "", fmt.Errorf("file citation must have file:///opt/<capture-root>/... form: %q", reference)
		}
		for _, segment := range pathSegments {
			if segment == "" || segment == "." || segment == ".." {
				return "", fmt.Errorf("file citation has an invalid path segment: %q", reference)
			}
		}
		candidate := "file:///opt/" + url.PathEscape(pathSegments[1]) + "/"
		if !strings.HasPrefix(reference, candidate) {
			return "", fmt.Errorf("file citation is not canonically rooted: %q", reference)
		}
		if root == "" {
			root = candidate
		} else if root != candidate {
			return "", fmt.Errorf("file citation root %q differs from %q", candidate, root)
		}
	}
	if root == "" {
		return "", fmt.Errorf("fixture has no file citations")
	}
	return root, nil
}

func publishedBenchmarkFixtureRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve published benchmark fixture root from runtime caller")
	}
	return filepath.Join(filepath.Dir(sourceFile), "testdata", "reference")
}

func publishedBenchmarkVerifyInventoryAndContent(t *testing.T, root string) {
	t.Helper()
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("lstat fixture root: %v", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		t.Fatalf("fixture root must be a real directory, mode=%v", rootInfo.Mode())
	}

	files := make(map[string]struct{})
	directories := make(map[string]struct{})
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is forbidden: %s", relative)
		}
		if entry.IsDir() {
			directories[relative] = struct{}{}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular fixture entry: %s (%v)", relative, info.Mode())
		}
		files[relative] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixture root: %v", err)
	}
	publishedBenchmarkRequireExactNames(t, "fixture files", publishedBenchmarkSortedMapKeys(files), publishedBenchmarkSortedFixtureNames())
	publishedBenchmarkRequireExactNames(t, "fixture directories", publishedBenchmarkSortedMapKeys(directories), []string{".", "observations", "sboms"})

	for name, expected := range publishedBenchmarkFixtureFiles {
		content := publishedBenchmarkReadFile(t, root, name)
		actual := publishedBenchmarkContentIdentity{SHA256: publishedBenchmarkSHA256(content), Size: int64(len(content))}
		if actual != expected {
			t.Errorf("fixture %q identity = %+v, want %+v", name, actual, expected)
		}
	}
}

func publishedBenchmarkVerifyProvenanceFileIdentities(t *testing.T, actual map[string]publishedBenchmarkContentIdentity) {
	t.Helper()
	expected := make(map[string]publishedBenchmarkContentIdentity, len(publishedBenchmarkFixtureFiles)-2)
	for name, identity := range publishedBenchmarkFixtureFiles {
		if name != "comparison.json" && name != "provenance.json" {
			expected[name] = publishedBenchmarkContentIdentity{SHA256: "sha256:" + identity.SHA256, Size: identity.Size}
		}
	}
	publishedBenchmarkRequireExactNames(t, "provenance fixture files", publishedBenchmarkSortedMapKeys(actual), publishedBenchmarkSortedMapKeys(expected))
	for name, expectedIdentity := range expected {
		if actual[name] != expectedIdentity {
			t.Errorf("provenance identity %q = %+v, want %+v", name, actual[name], expectedIdentity)
		}
	}
}

func publishedBenchmarkVerifyProvenanceSBOMIdentities(t *testing.T, targets []struct {
	ID         string `json:"id"`
	SBOMSHA256 string `json:"sbom_sha256"`
	SBOMSize   int64  `json:"sbom_size"`
}) {
	t.Helper()
	expected := map[string]publishedBenchmarkContentIdentity{
		"debian-12-13-slim-amd64": {
			SHA256: "sha256:" + publishedBenchmarkFixtureFiles["sboms/debian-12-13-slim-amd64.json"].SHA256,
			Size:   publishedBenchmarkFixtureFiles["sboms/debian-12-13-slim-amd64.json"].Size,
		},
		"sles-15-6-bci-base-amd64": {
			SHA256: "sha256:" + publishedBenchmarkFixtureFiles["sboms/sles-15-6-bci-base-amd64.json"].SHA256,
			Size:   publishedBenchmarkFixtureFiles["sboms/sles-15-6-bci-base-amd64.json"].Size,
		},
	}
	actual := make(map[string]publishedBenchmarkContentIdentity, len(targets))
	for _, target := range targets {
		actual[target.ID] = publishedBenchmarkContentIdentity{SHA256: target.SBOMSHA256, Size: target.SBOMSize}
	}
	publishedBenchmarkRequireExactNames(t, "provenance target identities", publishedBenchmarkSortedMapKeys(actual), publishedBenchmarkSortedMapKeys(expected))
	for target, expectedIdentity := range expected {
		if actual[target] != expectedIdentity {
			t.Errorf("SBOM identity %q = %+v, want %+v", target, actual[target], expectedIdentity)
		}
	}
}

func publishedBenchmarkRequireRunMetric(t *testing.T, result Result, targetID string, engine Engine, state ObservationState, truePositives, falseNegatives, unsupported int) {
	t.Helper()
	for _, runMetric := range result.RunMetrics {
		if runMetric.Run.TargetID == targetID && runMetric.Run.Engine == engine {
			if runMetric.Run.State != state || runMetric.Metrics.TruePositives != truePositives || runMetric.Metrics.FalseNegatives != falseNegatives || runMetric.Metrics.Unsupported != unsupported {
				t.Errorf("run metric %s/%s = run=%+v metrics=%+v", targetID, engine, runMetric.Run, runMetric.Metrics)
			}
			return
		}
	}
	t.Errorf("result has no run metric for %s/%s", targetID, engine)
}

func publishedBenchmarkStrictJSONObject(t *testing.T, root, name string, expectedKeys []string) ([]byte, map[string]json.RawMessage) {
	raw, fields := publishedBenchmarkStrictJSONObjectFields(t, root, name)
	publishedBenchmarkRequireExactNames(t, name+" keys", publishedBenchmarkSortedMapKeys(fields), expectedKeys)
	return raw, fields
}

func publishedBenchmarkStrictJSONObjectWithRequiredNames(t *testing.T, root, name string, requiredKeys []string) ([]byte, map[string]json.RawMessage) {
	raw, fields := publishedBenchmarkStrictJSONObjectFields(t, root, name)
	publishedBenchmarkRequireRequiredNames(t, name+" keys", fields, requiredKeys)
	return raw, fields
}

func publishedBenchmarkStrictJSONObjectFields(t *testing.T, root, name string) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	raw := publishedBenchmarkReadFile(t, root, name)
	if !utf8.Valid(raw) {
		t.Fatalf("%q is not valid UTF-8", name)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		t.Fatalf("%q fails duplicate-key validation: %v", name, err)
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil {
		t.Fatalf("decode %q object: %v", name, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatalf("%q has trailing JSON: %v", name, err)
	}
	return raw, fields
}

func publishedBenchmarkRequireRequiredNames(t *testing.T, label string, actual map[string]json.RawMessage, required []string) {
	t.Helper()
	for _, want := range required {
		if _, ok := actual[want]; ok {
			continue
		}
		for got := range actual {
			if strings.EqualFold(got, want) {
				t.Errorf("%s has case-variant key %q, want %q", label, got, want)
				break
			}
		}
		t.Errorf("%s is missing required key %q", label, want)
	}
}

func publishedBenchmarkVersionedFamily(value string) (string, bool) {
	separator := strings.LastIndex(value, "/")
	if separator <= 0 || separator == len(value)-1 || strings.TrimSpace(value) != value {
		return "", false
	}
	version := value[separator+1:]
	if len(version) < 2 || version[0] != 'v' {
		return "", false
	}
	for _, digit := range version[1:] {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	return version, true
}

func publishedBenchmarkRequireExactNames(t *testing.T, label string, actual, expected []string) {
	t.Helper()
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Errorf("%s count = %d, want %d; got %v", label, len(actual), len(expected), actual)
		return
	}
	for i := range expected {
		if actual[i] != expected[i] {
			if strings.EqualFold(actual[i], expected[i]) {
				t.Errorf("%s has case-variant key or path %q, want %q", label, actual[i], expected[i])
			} else {
				t.Errorf("%s[%d] = %q, want %q", label, i, actual[i], expected[i])
			}
		}
	}
}

func publishedBenchmarkObservationFiles() []string {
	return []string{
		"observations/debian-12-13-slim-amd64--grype.json",
		"observations/debian-12-13-slim-amd64--osv-scanner.json",
		"observations/debian-12-13-slim-amd64--owned.json",
		"observations/debian-12-13-slim-amd64--trivy.json",
		"observations/sles-15-6-bci-base-amd64--grype.json",
		"observations/sles-15-6-bci-base-amd64--osv-scanner-unsupported.json",
		"observations/sles-15-6-bci-base-amd64--owned.json",
		"observations/sles-15-6-bci-base-amd64--trivy.json",
	}
}

func publishedBenchmarkSortedFixtureNames() []string {
	return publishedBenchmarkSortedMapKeys(publishedBenchmarkFixtureFiles)
}

func publishedBenchmarkSortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func publishedBenchmarkReadFile(t *testing.T, root, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return content
}

func publishedBenchmarkSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

var publishedBenchmarkHygienePatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{name: "credential assignment", pattern: regexp.MustCompile(`(?i)(?:^|[,{[:space:]])["']?(?:aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|session[_-]?token)|api[_-]?key|access[_-]?token|client[_-]?secret|password)["']?\s*[:=]\s*["']?[^\s,"'}]{4,}`)},
	{name: "PEM private key", pattern: regexp.MustCompile(`-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----`)},
	{name: "Windows user-home path", pattern: regexp.MustCompile(`(?i)\b[a-z]:(?:\\{1,2}|/)+users(?:\\{1,2}|/)+[^\\/\s"']+`)},
	{name: "POSIX user-home path", pattern: regexp.MustCompile(`(?i)/home/[^/\s"']+`)},
	{name: "AWS account or physical resource ID", pattern: regexp.MustCompile(`(?i)(?:^|[^0-9a-f])[0-9]{12}(?:$|[^0-9a-f])|\b(?:i|vol|eni|subnet|vpc|sg|igw|rtb|nat|vpce|eipalloc|ami|snap)-[0-9a-f]{8,17}\b|arn:aws(?:-[a-z]+)?:[^:\s]+:[^:\s]*:[0-9]{12}:`)},
	{name: "credential-bearing URL", pattern: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s@]+@`)},
}

func publishedBenchmarkHygieneFindings(content string) []string {
	findings := make([]string, 0, len(publishedBenchmarkHygienePatterns))
	for _, check := range publishedBenchmarkHygienePatterns {
		if check.pattern.MatchString(content) {
			findings = append(findings, check.name)
		}
	}
	return findings
}

func publishedBenchmarkContainsHygieneFinding(findings []string, want string) bool {
	for _, finding := range findings {
		if finding == want {
			return true
		}
	}
	return false
}

func publishedBenchmarkStringValues(value any) []string {
	var values []string
	var collect func(any)
	collect = func(current any) {
		switch typed := current.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, item := range typed {
				collect(item)
			}
		case map[string]any:
			for key, item := range typed {
				values = append(values, key)
				collect(item)
			}
		}
	}
	collect(value)
	return values
}

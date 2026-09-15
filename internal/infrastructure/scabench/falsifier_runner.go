package scabench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// FalsifierResult records the actual generated inputs and outcome. No stored
// pass boolean is accepted: every outcome comes from the full bundle validator
// and semantic comparator operating on a temporary generated tree.
type FalsifierResult struct {
	ID              string       `json:"id"`
	Capability      string       `json:"capability"`
	Engine          bench.Engine `json:"engine"`
	Baseline        string       `json:"baseline"`
	Mutation        string       `json:"mutation"`
	Operation       string       `json:"operation"`
	ExpectedOutcome string       `json:"expected_outcome"`
	ObservedOutcome string       `json:"observed_outcome"`
	BaselineDigest  string       `json:"baseline_digest"`
	MutationDigest  string       `json:"mutation_digest"`
	ReasonCode      string       `json:"reason_code"`
	Reason          string       `json:"reason,omitempty"`
}

type falsifierRecipe struct {
	Engine          bench.Engine
	Baseline        string
	Mutation        string
	ExpectedOutcome string
}

// RunFalsifierSpec materializes each of the 41 historical capability recipes
// from a canonical synthetic base. Temporary trees are deliberately discarded;
// their immutable roots and result records are the retained proof.
func RunFalsifierSpec(spec bench.FalsifierSpec) ([]FalsifierResult, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := validateExecutableFalsifierSpec(spec); err != nil {
		return nil, err
	}
	results := make([]FalsifierResult, 0, len(spec.Entries))
	for _, entry := range spec.Entries {
		baseline, mutated, err := materializeFalsifierBundles(entry)
		if err != nil {
			return results, fmt.Errorf("materialize falsifier %q: %w", entry.ID, err)
		}
		defer func(path string) { _ = os.RemoveAll(path) }(filepath.Dir(baseline))
		baselineDigest, err := digestSyntheticTree(baseline)
		if err != nil {
			return results, fmt.Errorf("digest falsifier %q baseline: %w", entry.ID, err)
		}
		mutationDigest, err := digestSyntheticTree(mutated)
		if err != nil {
			return results, fmt.Errorf("digest falsifier %q mutation: %w", entry.ID, err)
		}
		if baselineDigest == mutationDigest {
			return results, fmt.Errorf("falsifier %q mutation did not change the generated bundle", entry.ID)
		}
		_, compareErr := CompareBundles(baseline, mutated, entry.Engine)
		observed := "accepted"
		reasonCode, reason := "semantic_bundle_accepted", ""
		if compareErr != nil {
			observed = "rejected"
			reasonCode, reason = stableFalsifierRejection(compareErr)
		}
		result := FalsifierResult{
			ID: entry.ID, Capability: entry.Capability, Engine: entry.Engine, Baseline: entry.Baseline, Mutation: entry.Mutation,
			Operation: entry.Operation, ExpectedOutcome: entry.ExpectedOutcome, ObservedOutcome: observed,
			BaselineDigest: baselineDigest, MutationDigest: mutationDigest, ReasonCode: reasonCode, Reason: reason,
		}
		results = append(results, result)
		if observed != entry.ExpectedOutcome {
			return results, fmt.Errorf("falsifier %q observed %s, want %s (%s)", entry.ID, observed, entry.ExpectedOutcome, reasonCode)
		}
	}
	sort.Slice(results, func(left, right int) bool { return results[left].ID < results[right].ID })
	return results, nil
}

func stableFalsifierRejection(err error) (string, string) {
	message := err.Error()
	switch {
	case strings.Contains(message, "validate left bundle") || strings.Contains(message, "validate right bundle"):
		return "bundle_validation_rejected", "generated bundle failed strict validation"
	case strings.Contains(message, "unclassified differences"):
		return "unclassified_semantic_difference", "generated raw output differs outside the selected policy"
	default:
		return "semantic_operation_rejected", "generated comparator operation rejected the mutation"
	}
}

func validateExecutableFalsifierSpec(spec bench.FalsifierSpec) error {
	if len(spec.Entries) != len(historicalFalsifierRecipes) {
		return fmt.Errorf("falsifier spec has %d entries, want %d historical recipes", len(spec.Entries), len(historicalFalsifierRecipes))
	}
	seen := make(map[string]struct{}, len(spec.Entries))
	for _, entry := range spec.Entries {
		recipe, exists := historicalFalsifierRecipes[entry.ID]
		if !exists {
			return fmt.Errorf("falsifier %q is not a historical executable recipe", entry.ID)
		}
		if entry.Capability != "semantic-full-bundle-comparator" || entry.Operation != "semantic_bundle_comparator" || entry.Engine != recipe.Engine || entry.Baseline != recipe.Baseline || entry.Mutation != recipe.Mutation || entry.ExpectedOutcome != recipe.ExpectedOutcome {
			return fmt.Errorf("falsifier %q does not match its executable recipe", entry.ID)
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return fmt.Errorf("falsifier %q is duplicated", entry.ID)
		}
		seen[entry.ID] = struct{}{}
	}
	return nil
}

func materializeFalsifierBundles(entry bench.FalsifierEntry) (string, string, error) {
	baseStdout, baseStderr, mutatedStdout, mutatedStderr, err := falsifierRawMutation(entry)
	if err != nil {
		return "", "", err
	}
	root, err := os.MkdirTemp("", "synapse-sca-falsifier-")
	if err != nil {
		return "", "", err
	}
	defer func() { _ = os.RemoveAll(root) }()
	baseline, err := writeSyntheticFalsifierBundle(filepath.Join(root, "baseline"), entry.Engine, baseStdout, baseStderr)
	if err != nil {
		return "", "", err
	}
	mutated, err := writeSyntheticFalsifierBundle(filepath.Join(root, "mutation"), entry.Engine, mutatedStdout, mutatedStderr)
	if err == nil {
		stableRoot, err := os.MkdirTemp("", "synapse-sca-falsifier-result-")
		if err != nil {
			return "", "", err
		}
		left := filepath.Join(stableRoot, "baseline")
		right := filepath.Join(stableRoot, "mutation")
		if err := copyTree(baseline, left); err != nil {
			return "", "", err
		}
		if err := copyTree(mutated, right); err != nil {
			return "", "", err
		}
		return left, right, nil
	}
	// Deliberately malformed raw JSON cannot pass capture parsing. Start from a
	// valid complete bundle, then replace only its retained raw process evidence;
	// CompareBundles must reject it through the real validation/decoder boundary.
	stableRoot, rootErr := os.MkdirTemp("", "synapse-sca-falsifier-result-")
	if rootErr != nil {
		return "", "", rootErr
	}
	left := filepath.Join(stableRoot, "baseline")
	right := filepath.Join(stableRoot, "mutation")
	if rootErr = copyTree(baseline, left); rootErr != nil {
		return "", "", rootErr
	}
	if rootErr = copyTree(baseline, right); rootErr != nil {
		return "", "", rootErr
	}
	if rootErr = replaceBundleScanRaw(right, mutatedStdout, mutatedStderr); rootErr != nil {
		return "", "", rootErr
	}
	return left, right, nil
}

func writeSyntheticFalsifierBundle(root string, engine bench.Engine, stdout, stderr []byte) (string, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	catalog, manifest, err := syntheticFalsifierCaptureFixture(root, engine)
	if err != nil {
		return "", err
	}
	runner := &syntheticFalsifierRunner{engine: engine, scan: ports.ToolResult{Stdout: stdout, Stderr: stderr}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		return "", err
	}
	bundle := filepath.Join(root, "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		return "", err
	}
	return bundle, nil
}

type syntheticFalsifierRunner struct {
	engine bench.Engine
	scan   ports.ToolResult
}

func (runner *syntheticFalsifierRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if runner.engine == bench.EngineOSVScanner && len(spec.Args) == 1 && spec.Args[0] == "--version" {
		return ports.ToolResult{Stdout: []byte("osv-scanner version: v1.2.3\nosv-scalibr version: 0.0.0\ncommit: synthetic\nbuilt at: 2026-01-01T00:00:00Z\n")}, nil
	}
	return runner.scan, nil
}

func syntheticFalsifierCaptureFixture(root string, engine bench.Engine) (bench.Catalog, CaptureManifest, error) {
	binary := filepath.Join(root, "engine")
	sbom := filepath.Join(root, "input.json")
	database := filepath.Join(root, "database")
	attestation := filepath.Join(root, "environment-attestation.json")
	if err := os.WriteFile(binary, []byte("synthetic scanner binary"), 0o600); err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	const sbomJSON = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}]}`
	if err := os.WriteFile(sbom, []byte(sbomJSON), 0o600); err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	if err := os.Mkdir(database, 0o700); err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	if err := os.WriteFile(filepath.Join(database, "advisory.json"), []byte(`{"id":"CVE-2026-0001"}`), 0o600); err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	attestationData := []byte(`{"kind":"synthetic-environment","subject":"falsifier"}`)
	if err := os.WriteFile(attestation, attestationData, 0o600); err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	_, binaryDigest, err := verifyRegularFile(binary)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	_, databaseDigest, err := verifyDatabasePath(database)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	format, err := syntheticFalsifierDatabaseFormat(engine)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	limits := RuntimeLimits{TimeoutSeconds: 5, MaxOutputBytes: 1 << 20, MemoryBytes: 64 << 20, PIDsMax: 32}
	profile, _, _, err := buildProfile(engine, format, limits)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	profileData, err := canonicalJSON(profile)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	environment := EnvironmentDescriptor{ID: "synthetic", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: bench.SHA256Digest(attestationData), SandboxIdentity: SandboxIdentityBubblewrapSeccompCgroupV2}
	environmentData, err := canonicalJSON(environment)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	catalog := bench.Catalog{SchemaVersion: bench.CatalogSchemaVersion, Revision: "synthetic-falsifier-r1", Targets: []bench.Target{{ID: "synthetic-target", OCIRef: "registry.example/synthetic@" + syntheticDigest('a'), Digest: syntheticDigest('a'), SBOMDigest: bench.SHA256Digest([]byte(sbomJSON)), Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}}, Pins: []bench.ArtifactPin{{Reference: "binary", Digest: binaryDigest}, {Reference: "database", Digest: databaseDigest}, {Reference: "environment", Digest: bench.SHA256Digest(environmentData)}, {Reference: "environment-attestation", Digest: bench.SHA256Digest(attestationData)}, {Reference: "profile", Digest: bench.SHA256Digest(profileData)}}}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		return bench.Catalog{}, CaptureManifest{}, err
	}
	version := "1.2.3"
	if engine == bench.EngineOSVScanner {
		version = "v1.2.3"
	}
	manifest := CaptureManifest{SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "synthetic-target", SBOMPath: sbom, Engine: engine, EngineVersion: version, Binary: Artifact{Reference: "binary", Path: binary}, Database: DatabaseArtifact{Reference: "database", Path: database, Build: "synthetic-db", Format: format}, Environment: environment, EnvironmentAttestation: Artifact{Reference: "environment-attestation", Path: attestation}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: limits}
	return catalog, manifest, nil
}

func syntheticFalsifierDatabaseFormat(engine bench.Engine) (DatabaseFormat, error) {
	switch engine {
	case bench.EngineGrype:
		return DatabaseFormatGrypeDBV6, nil
	case bench.EngineTrivy:
		return DatabaseFormatTrivyDBV2, nil
	case bench.EngineOSVScanner:
		return DatabaseFormatOSVScannerOffline, nil
	default:
		return "", fmt.Errorf("unsupported synthetic falsifier engine %q", engine)
	}
}

func replaceBundleScanRaw(path string, stdout, stderr []byte) error {
	body, err := os.ReadFile(filepath.Join(path, "evidence.json"))
	if err != nil {
		return err
	}
	var evidence Evidence
	if err := json.Unmarshal(body, &evidence); err != nil {
		return err
	}
	if evidence.Scan == nil {
		return fmt.Errorf("synthetic bundle lacks scan evidence")
	}
	evidence.Scan.Stdout = append([]byte(nil), stdout...)
	evidence.Scan.Stderr = append([]byte(nil), stderr...)
	body, err = canonicalJSON(evidence)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, "evidence.json"), body, 0o600)
}

func copyTree(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("synthetic bundle has a non-regular artifact")
		}
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func digestSyntheticTree(path string) (string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return "", fmt.Errorf("generated tree contains a non-regular artifact")
		}
		body, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return "", err
		}
		parts = append(parts, entry.Name()+"\x00"+bench.SHA256Digest(body))
	}
	sort.Strings(parts)
	return bench.SHA256Digest([]byte(strings.Join(parts, "\n"))), nil
}

func syntheticDigest(marker byte) string {
	return "sha256:" + strings.Repeat(string(marker), 64)
}

func falsifierRawMutation(entry bench.FalsifierEntry) ([]byte, []byte, []byte, []byte, error) {
	switch entry.Engine {
	case bench.EngineGrype:
		base := `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"one"},"matches":[]}`
		mutated := base
		switch entry.Mutation {
		case "descriptor-timestamp-change":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"two"},"matches":[]}`
		case "duplicate-json-key":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"two","timestamp":"three"},"matches":[]}`
		case "extra-json-field":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"one","unexpected":true},"matches":[]}`
		case "finding-change":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"one"},"matches":[{"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"},"vulnerability":{"id":"CVE-2026-0001"}}]}`
		case "remove-allowed-field":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`
		case "nested-timestamp-change":
			mutated = `{"descriptor":{"name":"grype","version":"1.2.3","timestamp":"one"},"metadata":{"timestamp":"two"},"matches":[]}`
		case "trailing-json":
			mutated = base + ` {}`
		default:
			return nil, nil, nil, nil, fmt.Errorf("unsupported grype mutation %q", entry.Mutation)
		}
		return []byte(base), nil, []byte(mutated), nil, nil
	case bench.EngineTrivy:
		base := trivyRaw("one", "one", "one", "2.0.0", 1, 1)
		mutated := base
		switch entry.Mutation {
		case "added-field":
			mutated = strings.Replace(base, `"ReportID":"one"`, `"ReportID":"one","unexpected":true`, 1)
		case "created-at-and-report-id-change":
			mutated = trivyRaw("two", "two", "one", "2.0.0", 1, 1)
		case "direct-fingerprint-change":
			mutated = trivyRaw("one", "one", "two", "2.0.0", 1, 1)
		case "debian-field-addition":
			mutated = strings.Replace(base, `"FixedVersion":"2.0.0"`, `"FixedVersion":"2.0.0","Added":"x"`, 1)
		case "debian-field-removal":
			mutated = strings.Replace(base, `,"FixedVersion":"2.0.0"`, "", 1)
		case "fixed-version-change":
			mutated = trivyRaw("one", "one", "one", "3.0.0", 1, 1)
		case "malformed-fingerprint":
			mutated = strings.Replace(base, `"Fingerprint":"one1"`, `"Fingerprint":""`, 1)
		case "missing-fingerprint":
			mutated = strings.Replace(base, `,"Fingerprint":"one1"`, "", 1)
		case "nested-fingerprint-change":
			mutated = strings.Replace(base, `"Fingerprint":"one1"`, `"Fingerprint":"one1","Nested":{"Fingerprint":"two"}`, 1)
		case "null-fingerprint":
			mutated = strings.Replace(base, `"Fingerprint":"one1"`, `"Fingerprint":null`, 1)
		case "reordered-vulnerabilities":
			base, mutated = trivyRaw("one", "one", "one", "2.0.0", 1, 2), trivyRaw("one", "one", "one", "2.0.0", 2, 2)
		case "wrong-result-count":
			mutated = trivyRaw("one", "one", "one", "2.0.0", 2, 1)
		case "wrong-vulnerability-count":
			mutated = trivyRaw("one", "one", "one", "2.0.0", 1, 2)
		case "wrong-fingerprint-type":
			mutated = strings.Replace(base, `"Fingerprint":"one1"`, `"Fingerprint":1`, 1)
		case "nested-field-change":
			mutated = strings.Replace(base, `"PkgIdentifier":{"PURL":"pkg:npm/a@1.0.0"}`, `"PkgIdentifier":{"PURL":"pkg:npm/a@1.0.0","Nested":"two"}`, 1)
		default:
			return nil, nil, nil, nil, fmt.Errorf("unsupported trivy mutation %q", entry.Mutation)
		}
		return []byte(base), nil, []byte(mutated), nil, nil
	case bench.EngineOSVScanner:
		baseStderr := osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		mutated := baseStderr
		switch entry.Mutation {
		case "allowed-pointer-change":
			mutated = osvRaw("Hashes", `["two"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "allowed-timing-change":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 3ms elapsed, 4ms wall time")
		case "field-name-change":
			mutated = osvRaw("Hashz", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "line-add":
			mutated = strings.Replace(baseStderr, "\nEnd status", "\nextra diagnostic\nEnd status", 1)
		case "line-remove":
			mutated = "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n"
		case "line-reorder":
			mutated = "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n" + strings.Split(baseStderr, "\n")[0] + "\n"
		case "non-pointer-diagnostic-change":
			mutated = strings.Replace(baseStderr, `"Name":"a"`, `"Name":"b"`, 1)
		case "outside-diagnostic-change":
			mutated = strings.Replace(baseStderr, `"Name":"a"`, `"Name":"a","Outside":"two"`, 1)
		case "pointer-like-package-content":
			mutated = strings.Replace(baseStderr, `"Name":"a"`, `"Name":"a","Package":{"Name":"two"}`, 1)
		case "pointer-versus-nil":
			mutated = osvRaw("Hashes", `null`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "timing-counter-change":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 1 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "timing-duplicate":
			mutated = baseStderr + "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n"
		case "timing-label-change":
			mutated = osvRaw("Hashes", `["one"]`, "End state: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "timing-malformed":
			mutated = osvRaw("Hashes", `["one"]`, "End status: malformed")
		case "timing-misplaced":
			mutated = "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time\n" + strings.Split(baseStderr, "\n")[0] + "\n"
		case "timing-punctuation-change":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited; 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time")
		case "timing-unit-change":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1s elapsed, 2ms wall time")
		case "timing-whitespace-change":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 1ms elapsed, 2ms wall time ")
		case "timing-zero":
			mutated = osvRaw("Hashes", `["one"]`, "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, 0ms elapsed, 2ms wall time")
		default:
			return nil, nil, nil, nil, fmt.Errorf("unsupported OSV mutation %q", entry.Mutation)
		}
		return []byte(`{"results":[]}`), []byte(baseStderr), []byte(`{"results":[]}`), []byte(mutated), nil
	default:
		return nil, nil, nil, nil, fmt.Errorf("unsupported falsifier engine %q", entry.Engine)
	}
}

func trivyRaw(createdAt, reportID, fingerprint, fixed string, resultOrder, vulnerabilities int) string {
	vulnerabilitiesJSON := make([]string, 0, vulnerabilities)
	for index := 0; index < vulnerabilities; index++ {
		value := fmt.Sprintf(`{"VulnerabilityID":"CVE-2026-000%d","PkgIdentifier":{"PURL":"pkg:npm/a@1.0.0"},"InstalledVersion":"1.0.0","FixedVersion":"%s","Fingerprint":"%s%d"}`, index+1, fixed, fingerprint, index+1)
		vulnerabilitiesJSON = append(vulnerabilitiesJSON, value)
	}
	if resultOrder == 2 && len(vulnerabilitiesJSON) > 1 {
		vulnerabilitiesJSON[0], vulnerabilitiesJSON[1] = vulnerabilitiesJSON[1], vulnerabilitiesJSON[0]
	}
	result := `{"Vulnerabilities":[` + strings.Join(vulnerabilitiesJSON, ",") + `]}`
	results := []string{result}
	if resultOrder == 2 && vulnerabilities == 1 {
		results = append(results, `{"Vulnerabilities":[]}`)
	}
	return `{"SchemaVersion":2,"Trivy":{"Version":"1.2.3"},"CreatedAt":"` + createdAt + `","ReportID":"` + reportID + `","Results":[` + strings.Join(results, ",") + `]}`
}

func osvRaw(field, value, timing string) string {
	return `Neither CPE nor PURL found for package: {"Name":"a","` + field + `":` + value + `}` + "\n" + timing + "\n"
}

var historicalFalsifierRecipes = map[string]falsifierRecipe{
	"grype_allowed_metadata_change_accepted":          {bench.EngineGrype, "synthetic-grype-bundle", "descriptor-timestamp-change", "accepted"},
	"grype_duplicate_json_key_rejected":               {bench.EngineGrype, "synthetic-grype-bundle", "duplicate-json-key", "rejected"},
	"grype_extra_json_field_rejected":                 {bench.EngineGrype, "synthetic-grype-bundle", "extra-json-field", "rejected"},
	"grype_finding_change_rejected":                   {bench.EngineGrype, "synthetic-grype-bundle", "finding-change", "rejected"},
	"grype_missing_allowed_field_rejected":            {bench.EngineGrype, "synthetic-grype-bundle", "remove-allowed-field", "rejected"},
	"grype_nested_timestamp_change_rejected":          {bench.EngineGrype, "synthetic-grype-bundle", "nested-timestamp-change", "rejected"},
	"grype_trailing_json_rejected":                    {bench.EngineGrype, "synthetic-grype-bundle", "trailing-json", "rejected"},
	"osv_allowed_pointer_change_accepted":             {bench.EngineOSVScanner, "synthetic-osv-bundle", "allowed-pointer-change", "accepted"},
	"osv_allowed_timing_change_accepted":              {bench.EngineOSVScanner, "synthetic-osv-bundle", "allowed-timing-change", "accepted"},
	"osv_field_name_change_rejected":                  {bench.EngineOSVScanner, "synthetic-osv-bundle", "field-name-change", "rejected"},
	"osv_line_add_rejected":                           {bench.EngineOSVScanner, "synthetic-osv-bundle", "line-add", "rejected"},
	"osv_line_remove_rejected":                        {bench.EngineOSVScanner, "synthetic-osv-bundle", "line-remove", "rejected"},
	"osv_line_reorder_rejected":                       {bench.EngineOSVScanner, "synthetic-osv-bundle", "line-reorder", "rejected"},
	"osv_non_pointer_diagnostic_change_rejected":      {bench.EngineOSVScanner, "synthetic-osv-bundle", "non-pointer-diagnostic-change", "rejected"},
	"osv_outside_diagnostic_change_rejected":          {bench.EngineOSVScanner, "synthetic-osv-bundle", "outside-diagnostic-change", "rejected"},
	"osv_pointer_like_package_content_rejected":       {bench.EngineOSVScanner, "synthetic-osv-bundle", "pointer-like-package-content", "rejected"},
	"osv_pointer_vs_nil_rejected":                     {bench.EngineOSVScanner, "synthetic-osv-bundle", "pointer-versus-nil", "rejected"},
	"osv_timing_counter_rejected":                     {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-counter-change", "rejected"},
	"osv_timing_duplicate_rejected":                   {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-duplicate", "rejected"},
	"osv_timing_label_rejected":                       {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-label-change", "rejected"},
	"osv_timing_malformed_rejected":                   {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-malformed", "rejected"},
	"osv_timing_misplaced_rejected":                   {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-misplaced", "rejected"},
	"osv_timing_punctuation_rejected":                 {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-punctuation-change", "rejected"},
	"osv_timing_unit_rejected":                        {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-unit-change", "rejected"},
	"osv_timing_whitespace_rejected":                  {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-whitespace-change", "rejected"},
	"osv_timing_zero_rejected":                        {bench.EngineOSVScanner, "synthetic-osv-bundle", "timing-zero", "rejected"},
	"trivy_added_field_rejected":                      {bench.EngineTrivy, "synthetic-trivy-bundle", "added-field", "rejected"},
	"trivy_allowed_values_accepted":                   {bench.EngineTrivy, "synthetic-trivy-bundle", "created-at-and-report-id-change", "accepted"},
	"trivy_debian_direct_fingerprint_change_accepted": {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "direct-fingerprint-change", "accepted"},
	"trivy_debian_field_addition_rejected":            {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "debian-field-addition", "rejected"},
	"trivy_debian_field_removal_rejected":             {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "debian-field-removal", "rejected"},
	"trivy_debian_fixed_version_change_rejected":      {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "fixed-version-change", "rejected"},
	"trivy_debian_malformed_fingerprint_rejected":     {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "malformed-fingerprint", "rejected"},
	"trivy_debian_missing_fingerprint_rejected":       {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "missing-fingerprint", "rejected"},
	"trivy_debian_nested_fingerprint_change_rejected": {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "nested-fingerprint-change", "rejected"},
	"trivy_debian_null_fingerprint_rejected":          {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "null-fingerprint", "rejected"},
	"trivy_debian_reordered_vulnerabilities_rejected": {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "reordered-vulnerabilities", "rejected"},
	"trivy_debian_wrong_result_count_rejected":        {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "wrong-result-count", "rejected"},
	"trivy_debian_wrong_type_fingerprint_rejected":    {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "wrong-fingerprint-type", "rejected"},
	"trivy_debian_wrong_vulnerability_count_rejected": {bench.EngineTrivy, "synthetic-trivy-debian-bundle", "wrong-vulnerability-count", "rejected"},
	"trivy_nested_field_change_rejected":              {bench.EngineTrivy, "synthetic-trivy-bundle", "nested-field-change", "rejected"},
}

// BundleComparisonPair is one repetition-to-repetition full bundle comparison.
type BundleComparisonPair struct {
	Engine    bench.Engine
	LeftPath  string
	RightPath string
}

func CompareCycleBundles(pairs []BundleComparisonPair) ([]SemanticBundleComparison, error) {
	if len(pairs) == 0 {
		return nil, fmt.Errorf("cycle requires bundle comparisons")
	}
	reports := make([]SemanticBundleComparison, 0, len(pairs))
	for _, pair := range pairs {
		if pair.LeftPath == "" || pair.RightPath == "" {
			return nil, fmt.Errorf("cycle comparison pair is incomplete")
		}
		report, err := CompareBundles(pair.LeftPath, pair.RightPath, pair.Engine)
		if err != nil {
			return append(reports, report), err
		}
		reports = append(reports, report)
	}
	sort.Slice(reports, func(left, right int) bool { return reports[left].Engine < reports[right].Engine })
	return reports, nil
}

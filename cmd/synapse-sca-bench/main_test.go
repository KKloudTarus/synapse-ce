package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type commandRunner struct{ result ports.ToolResult }

func (r commandRunner) Run(_ context.Context, _ ports.ToolSpec) (ports.ToolResult, error) {
	return r.result, nil
}

type cancelAfterDispatchRunner struct {
	cancel context.CancelFunc
	calls  *int
}

func (r cancelAfterDispatchRunner) Run(_ context.Context, _ ports.ToolSpec) (ports.ToolResult, error) {
	*r.calls++
	r.cancel()
	return ports.ToolResult{
		ExitCode: 19,
		Stdout:   []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`),
	}, nil
}

func TestCLIChildExitCodesWithoutGoRun(t *testing.T) {
	if encoded := os.Getenv("SYNAPSE_SCA_BENCH_CHILD_ARGS"); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			os.Exit(99)
		}
		os.Exit(executeCLI(args, os.Stdout, os.Stderr))
	}
	runChild := func(args []string) int {
		encoded, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestCLIChildExitCodesWithoutGoRun$")
		command.Env = append(os.Environ(), "SYNAPSE_SCA_BENCH_CHILD_ARGS="+string(encoded))
		if err := command.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	if code := runChild([]string{"-h"}); code != 0 {
		t.Fatalf("help child exit = %d", code)
	}
	if code := runChild([]string{"-unknown"}); code != 1 {
		t.Fatalf("invalid flag child exit = %d", code)
	}
}

func TestExecuteCLIHelpAndInputErrors(t *testing.T) {
	if code := executeCLI([]string{"-h"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if code := executeCLI([]string{"-unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("invalid flag exit = %d", code)
	}
	if code := executeCLI([]string{"-catalog", "catalog"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("missing flag exit = %d", code)
	}
}

func TestExecuteOwnedHelperEmitsOwnedWireForPinnedLocalInputs(t *testing.T) {
	directory := t.TempDir()
	database := filepath.Join(directory, "database")
	if err := os.Mkdir(database, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(database, "advisory.json"), []byte(`{"id":"GHSA-AAAA-BBBB-CCCC","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(directory, "input.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := executeOwnedHelper([]string{"--database", database, "--database-format", string(capture.DatabaseFormatOSVJSON), "--sbom", sbomPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("helper exit=%d stderr=%q", code, stderr.String())
	}
	var wire struct {
		SchemaVersion      string     `json:"schema_version"`
		EngineVersion      string     `json:"engine_version"`
		AdvisoriesIngested int        `json:"advisories_ingested"`
		AdvisoriesSkipped  int        `json:"advisories_skipped"`
		Findings           []struct{} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil || wire.SchemaVersion != "synapse-sca-benchmark-owned-wire-v2" || wire.EngineVersion != buildinfo.App() || wire.AdvisoriesIngested != 1 || wire.AdvisoriesSkipped != 0 {
		t.Fatalf("owned wire=%s err=%v", stdout.Bytes(), err)
	}
}

func TestExecuteCLICapturesCapabilityWithoutRunner(t *testing.T) {
	catalog, manifest := commandCapabilityFixture(t)
	catalogPath, manifestPath := writeFixtureFiles(t, catalog, manifest)
	output := filepath.Join(t.TempDir(), "capability")
	calls := 0
	factory := func(capture.RuntimeLimits) (ports.ToolRunner, error) {
		calls++
		return commandRunner{}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := executeCLIWithDeps([]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", output}, &stdout, &stderr, factory); code != 0 {
		t.Fatalf("capability exit=%d stderr=%q", code, stderr.String())
	}
	if calls != 0 {
		t.Fatalf("capability path constructed a runner %d times", calls)
	}
	if !strings.Contains(stdout.String(), "capability unsupported") {
		t.Fatalf("capability stdout=%q", stdout.String())
	}
	if err := capture.ValidateBundle(output); err != nil {
		t.Fatal(err)
	}
	assertEnvironmentBundleArtifacts(t, output, manifest)

	catalog, manifest = commandCapabilityFixture(t)
	manifest.Capability.Statement.Digest = digest('f')
	catalogPath, manifestPath = writeFixtureFiles(t, catalog, manifest)
	failedOutput := filepath.Join(t.TempDir(), "failed")
	calls = 0
	if code := executeCLIWithDeps([]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", failedOutput}, &bytes.Buffer{}, &bytes.Buffer{}, factory); code != 1 {
		t.Fatalf("invalid capability exit=%d", code)
	}
	if calls != 0 {
		t.Fatalf("invalid capability constructed a runner %d times", calls)
	}
	if _, err := os.Lstat(failedOutput); !os.IsNotExist(err) {
		t.Fatalf("invalid capability wrote output: %v", err)
	}
}

func TestExecuteCLIWritesCompleteAndIncompleteBundles(t *testing.T) {
	catalog, manifest := commandFixture(t)
	catalogPath, manifestPath := writeFixtureFiles(t, catalog, manifest)
	completeFactory := func(capture.RuntimeLimits) (ports.ToolRunner, error) {
		return commandRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}, nil
	}
	complete := filepath.Join(t.TempDir(), "complete")
	if code := executeCLIWithDeps([]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", complete}, &bytes.Buffer{}, &bytes.Buffer{}, completeFactory); code != 0 {
		t.Fatalf("complete exit = %d", code)
	}
	if _, err := os.Stat(filepath.Join(complete, "observation.json")); err != nil {
		t.Fatal(err)
	}
	assertEnvironmentBundleArtifacts(t, complete, manifest)

	incompleteFactory := func(capture.RuntimeLimits) (ports.ToolRunner, error) {
		return commandRunner{result: ports.ToolResult{ExitCode: 19}}, nil
	}
	incomplete := filepath.Join(t.TempDir(), "incomplete")
	if code := executeCLIWithDeps([]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", incomplete}, &bytes.Buffer{}, &bytes.Buffer{}, incompleteFactory); code != 2 {
		t.Fatalf("incomplete exit = %d", code)
	}
	assertEnvironmentBundleArtifacts(t, incomplete, manifest)
}

func TestExecuteCLIWithContextCancellationAfterDispatchWritesIncompleteBundle(t *testing.T) {
	catalog, manifest := commandFixture(t)
	catalogPath, manifestPath := writeFixtureFiles(t, catalog, manifest)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	factory := func(capture.RuntimeLimits) (ports.ToolRunner, error) {
		return cancelAfterDispatchRunner{cancel: cancel, calls: &calls}, nil
	}
	output := filepath.Join(t.TempDir(), "cancelled")
	if code := executeCLIWithContext([]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", output}, &bytes.Buffer{}, &bytes.Buffer{}, ctx, factory); code != 2 {
		t.Fatalf("cancelled exit = %d, want 2", code)
	}
	if calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
	observationJSON, err := os.ReadFile(filepath.Join(output, "observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	observations, err := bench.DecodeObservationSet(bytes.NewReader(observationJSON))
	if err != nil {
		t.Fatalf("decode observation bundle: %v", err)
	}
	if len(observations.Observations) != 1 || observations.Observations[0].State != bench.ObservationIncomplete {
		t.Fatalf("observations = %+v, want one incomplete observation", observations.Observations)
	}
	evidenceJSON, err := os.ReadFile(filepath.Join(output, "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence capture.Evidence
	if err := json.Unmarshal(evidenceJSON, &evidence); err != nil {
		t.Fatalf("decode evidence bundle: %v", err)
	}
	if evidence.FailureCode != capture.FailureCancelled {
		t.Fatalf("failure code = %q, want %q", evidence.FailureCode, capture.FailureCancelled)
	}
	if evidence.Scan == nil || !evidence.Scan.Cancelled || evidence.Scan.ExitKnown || evidence.Scan.ExitCode != 0 {
		t.Fatalf("scan evidence = %+v, want cancelled with unknown zero exit", evidence.Scan)
	}
}

func TestExecuteCLICleansPreparedSnapshotWhenRunnerCreationFails(t *testing.T) {
	catalog, manifest := commandFixture(t)
	catalogPath, manifestPath := writeFixtureFiles(t, catalog, manifest)
	temporaryRoot := t.TempDir()
	for _, name := range []string{"TMP", "TEMP", "TMPDIR"} {
		t.Setenv(name, temporaryRoot)
	}
	factory := func(capture.RuntimeLimits) (ports.ToolRunner, error) {
		return nil, errors.New("sandbox unavailable")
	}
	code := executeCLIWithDeps(
		[]string{"-catalog", catalogPath, "-manifest", manifestPath, "-output", filepath.Join(t.TempDir(), "bundle")},
		&bytes.Buffer{}, &bytes.Buffer{}, factory,
	)
	if code != 1 {
		t.Fatalf("runner-factory failure exit = %d", code)
	}
	entries, err := os.ReadDir(temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "synapse-sca-bench-snapshot-") {
			t.Fatalf("runner-factory failure leaked prepared snapshot %q", entry.Name())
		}
	}
}

func TestProductionRunnerFailsClosedOutsideLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := productionRunner(capture.RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}); err == nil {
			t.Fatal("production runner unexpectedly fell back outside Linux")
		}
	}
}

func commandFixture(t *testing.T) (bench.Catalog, capture.CaptureManifest) {
	t.Helper()
	root := t.TempDir()
	binaryPath := filepath.Join(root, "scanner")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}]}`)
	sbomPath := filepath.Join(root, "input.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(root, "database")
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(databasePath, "db"), []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryDigest := bench.SHA256Digest([]byte("binary"))
	databaseDigest, err := capture.HashTree(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	limits := capture.RuntimeLimits{TimeoutSeconds: 5, MaxOutputBytes: 1024, MemoryBytes: 1024 * 1024, PIDsMax: 8}
	environmentAttestation := []byte("{\n  \"kind\": \"environment\",\n  \"subject\": \"command-test\"\n}\n")
	environmentAttestationPath := filepath.Join(root, "environment-attestation.json")
	if err := os.WriteFile(environmentAttestationPath, environmentAttestation, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := capture.EnvironmentDescriptor{ID: "command-test", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: bench.SHA256Digest(environmentAttestation), SandboxIdentity: capture.SandboxIdentityBubblewrapSeccompCgroupV2}
	environmentBytes, err := json.Marshal(environment)
	if err != nil {
		t.Fatal(err)
	}
	profile := capture.ExecutionProfile{SchemaVersion: capture.ProfileSchemaVersion, Engine: bench.EngineGrype, DatabaseFormat: capture.DatabaseFormatGrypeDBV6, ExecutionMode: "external", ArgvTemplate: []string{"sbom:{sbom}", "-o", "json", "-q", "--config", "{config}"}, EnvironmentTemplate: []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_CACHE_DIR={db}", "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false", "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true"}, OutputFormat: "grype-json", NoNetwork: true, AutoUpdateDisabled: true, Limits: limits, ConfigContentDigest: bench.SHA256Digest(nil), IgnoreContentDigest: bench.SHA256Digest(nil)}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	catalog := bench.Catalog{SchemaVersion: bench.CatalogSchemaVersion, Revision: "command-r1", Targets: []bench.Target{{ID: "target", OCIRef: "registry.example/target@" + digest('a'), Digest: digest('a'), SBOMDigest: bench.SHA256Digest(sbomBytes), Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}}, Pins: []bench.ArtifactPin{{Reference: "binary", Digest: binaryDigest}, {Reference: "database", Digest: databaseDigest}, {Reference: "environment", Digest: bench.SHA256Digest(environmentBytes)}, {Reference: "environment-attestation", Digest: bench.SHA256Digest(environmentAttestation)}, {Reference: "profile", Digest: bench.SHA256Digest(profileBytes)}}}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, capture.CaptureManifest{SchemaVersion: capture.CaptureManifestSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", SBOMPath: sbomPath, Engine: bench.EngineGrype, EngineVersion: "1.2.3", Binary: capture.Artifact{Reference: "binary", Path: binaryPath}, Database: capture.DatabaseArtifact{Reference: "database", Path: databasePath, Build: "test", Format: capture.DatabaseFormatGrypeDBV6}, Environment: environment, EnvironmentAttestation: capture.Artifact{Reference: "environment-attestation", Path: environmentAttestationPath}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: limits}
}

func commandCapabilityFixture(t *testing.T) (bench.Catalog, capture.CaptureManifest) {
	t.Helper()
	root := t.TempDir()
	binaryPath := filepath.Join(root, "osv-scanner")
	if err := os.WriteFile(binaryPath, []byte("osv-scanner-v2.5.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bash","version":"5.1","purl":"pkg:rpm/sles/bash@5.1"},{"name":"image-spec","version":"v1.1.1","purl":"pkg:golang/github.com/opencontainers/image-spec@v1.1.1"},{"name":"stdlib","version":"go1.24.11","purl":"pkg:golang/stdlib@1.24.11"}]}`)
	sbomPath := filepath.Join(root, "input.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(root, "database")
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(databasePath, "offline.zip"), []byte("offline database"), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryDigest := bench.SHA256Digest([]byte("osv-scanner-v2.5.1"))
	databaseDigest, err := capture.HashTree(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	limits := capture.RuntimeLimits{TimeoutSeconds: 5, MaxOutputBytes: 1024, MemoryBytes: 1024 * 1024, PIDsMax: 8}
	environmentAttestation := []byte("{\n  \"kind\": \"environment\",\n  \"subject\": \"command-capability\"\n}\n")
	environmentAttestationPath := filepath.Join(root, "environment-attestation.json")
	if err := os.WriteFile(environmentAttestationPath, environmentAttestation, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := capture.EnvironmentDescriptor{ID: "command-capability", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: bench.SHA256Digest(environmentAttestation), SandboxIdentity: capture.SandboxIdentityBubblewrapSeccompCgroupV2}
	environmentBytes, err := json.Marshal(environment)
	if err != nil {
		t.Fatal(err)
	}
	profile := capture.ExecutionProfile{SchemaVersion: capture.ProfileSchemaVersion, Engine: bench.EngineOSVScanner, DatabaseFormat: capture.DatabaseFormatOSVScannerOffline, ExecutionMode: "external", ArgvTemplate: []string{"scan", "source", "--offline", "--offline-vulnerabilities", "--experimental-no-default-plugins", "--experimental-plugins=lockfile", "--experimental-plugins=sbom", "--format", "json", "--config={config}", "--lockfile={sbom}"}, VersionProbeArgvTemplate: []string{"--version"}, EnvironmentTemplate: []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={db}"}, OutputFormat: "osv-scanner-v2-json", NoNetwork: true, AutoUpdateDisabled: true, Limits: limits, ConfigContentDigest: bench.SHA256Digest(nil), IgnoreContentDigest: bench.SHA256Digest(nil)}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	catalog := bench.Catalog{SchemaVersion: bench.CatalogSchemaVersion, Revision: "command-capability-r1", Targets: []bench.Target{{ID: "target", OCIRef: "registry.example/target@" + digest('a'), Digest: digest('a'), SBOMDigest: bench.SHA256Digest(sbomBytes), Components: []bench.Component{{PURL: "pkg:rpm/sles/bash@5.1", Version: "5.1"}}}}, Pins: []bench.ArtifactPin{{Reference: "binary", Digest: binaryDigest}, {Reference: "database", Digest: databaseDigest}, {Reference: "environment", Digest: bench.SHA256Digest(environmentBytes)}, {Reference: "environment-attestation", Digest: bench.SHA256Digest(environmentAttestation)}, {Reference: "profile", Digest: bench.SHA256Digest(profileBytes)}}}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	sourceReferences := []string{
		"https://github.com/google/osv-scanner/blob/c84fa4568f2526d0333e9a914ea8a0a5f74ad68b/internal/utility/purl/purl_to_package.go",
		"https://github.com/google/osv-scalibr/blob/23fa66ca68dd17bfdbe0b8b3536d1887a3a940da/purl/ecosystem/ecosystem.go",
	}
	sources := make([]capture.CapabilityArtifact, len(sourceReferences))
	statementSources := make([]capture.CapabilityStatementSource, len(sourceReferences))
	for i, reference := range sourceReferences {
		path := filepath.Join(root, "source-"+string(rune('0'+i)))
		data := []byte("source-" + string(rune('0'+i)))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := bench.SHA256Digest(data)
		sources[i] = capture.CapabilityArtifact{Reference: reference, Path: path, Digest: digest}
		statementSources[i] = capture.CapabilityStatementSource{Reference: reference, Digest: digest}
	}
	statement := capture.CapabilityStatement{SchemaVersion: capture.CapabilityStatementSchemaVersion, Kind: bench.CapabilityKindOSVScannerSUSERPM, DecisionRuleRevision: capture.CapabilityDecisionRuleRevision, Scope: capture.CapabilityScopeSameSBOMOSPackageMatching, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", TargetDigest: catalog.Targets[0].Digest, SBOMDigest: catalog.Targets[0].SBOMDigest, Engine: bench.EngineOSVScanner, EngineVersion: "v2.5.1", EngineBinaryDigest: binaryDigest, DatabaseBuild: "offline-2026-09-13", DatabaseDigest: databaseDigest, EnvironmentID: environment.ID, EnvironmentDigest: bench.SHA256Digest(environmentBytes), ConfigDigest: bench.SHA256Digest(profileBytes), Components: append([]bench.Component(nil), catalog.Targets[0].Components...), Sources: statementSources}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	statementPath := filepath.Join(root, "statement.json")
	if err := os.WriteFile(statementPath, statementBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return catalog, capture.CaptureManifest{SchemaVersion: capture.CaptureManifestSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", SBOMPath: sbomPath, Engine: bench.EngineOSVScanner, EngineVersion: "v2.5.1", Binary: capture.Artifact{Reference: "binary", Path: binaryPath}, Database: capture.DatabaseArtifact{Reference: "database", Path: databasePath, Build: "offline-2026-09-13", Format: capture.DatabaseFormatOSVScannerOffline}, Environment: environment, EnvironmentAttestation: capture.Artifact{Reference: "environment-attestation", Path: environmentAttestationPath}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: limits, Capability: &capture.CapabilityManifest{Statement: capture.CapabilityArtifact{Reference: "capability-statement", Path: statementPath, Digest: bench.SHA256Digest(statementBytes)}, Sources: sources}}
}

func writeFixtureFiles(t *testing.T, catalog bench.Catalog, manifest capture.CaptureManifest) (string, string) {
	t.Helper()
	dir := t.TempDir()
	catalogBytes, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "catalog.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(catalogPath, catalogBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return catalogPath, manifestPath
}

func assertEnvironmentBundleArtifacts(t *testing.T, bundle string, manifest capture.CaptureManifest) {
	t.Helper()
	environmentJSON, err := json.Marshal(manifest.Environment)
	if err != nil {
		t.Fatal(err)
	}
	attestationJSON, err := os.ReadFile(manifest.EnvironmentAttestation.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct {
		name string
		data []byte
	}{
		{name: "environment.json", data: environmentJSON},
		{name: "environment-attestation.json", data: attestationJSON},
	} {
		data, err := os.ReadFile(filepath.Join(bundle, artifact.name))
		if err != nil || !bytes.Equal(data, artifact.data) {
			t.Fatalf("bundle %s does not retain exact bytes: data=%q err=%v", artifact.name, data, err)
		}
	}
}

func digest(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }

package scabench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type fakeRunner struct {
	result        ports.ToolResult
	err           error
	results       []ports.ToolResult
	errs          []error
	spec          ports.ToolSpec
	specs         []ports.ToolSpec
	calls         int
	mutate        func()
	mutateSpec    func(ports.ToolSpec)
	resultForSpec func(ports.ToolSpec) ports.ToolResult
}

type mutationWriter struct {
	path    string
	mutated bool
}

func (w *mutationWriter) Write(data []byte) (int, error) {
	if !w.mutated {
		file, err := os.OpenFile(w.path, os.O_WRONLY, 0)
		if err != nil {
			return 0, err
		}
		_, err = file.WriteAt([]byte("x"), 0)
		closeErr := file.Close()
		if err != nil {
			return 0, err
		}
		if closeErr != nil {
			return 0, closeErr
		}
		info, err := os.Stat(w.path)
		if err != nil {
			return 0, err
		}
		if err := os.Chtimes(w.path, info.ModTime(), info.ModTime().Add(2*time.Second)); err != nil {
			return 0, err
		}
		w.mutated = true
	}
	return len(data), nil
}

func (f *fakeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	f.spec = spec
	f.specs = append(f.specs, spec)
	call := f.calls
	f.calls++
	if f.mutate != nil {
		f.mutate()
	}
	if f.mutateSpec != nil {
		f.mutateSpec(spec)
	}
	if f.resultForSpec != nil {
		return f.resultForSpec(spec), f.err
	}
	if call < len(f.results) {
		var err error
		if call < len(f.errs) {
			err = f.errs[call]
		}
		return f.results[call], err
	}
	return f.result, f.err
}

func evidenceForTest(t *testing.T, result CaptureResult) Evidence {
	t.Helper()
	var evidence Evidence
	if err := json.Unmarshal(result.EvidenceJSON(), &evidence); err != nil {
		t.Fatalf("decode result evidence: %v", err)
	}
	return evidence
}

func TestParseOSVVersionRequiresOfficialFirstLine(t *testing.T) {
	output := []byte("osv-scanner version: 2.5.1\nosv-scalibr version: 0.0.0\ncommit: test\nbuilt at: 2026-09-13T00:00:00Z\n")
	original := append([]byte(nil), output...)
	version, err := parseOSVVersion(output)
	if err != nil || version != "v2.5.1" {
		t.Fatalf("parseOSVVersion() = %q, %v", version, err)
	}
	if !bytes.Equal(output, original) {
		t.Fatalf("parseOSVVersion modified version probe output: %q", output)
	}
	if version, err := parseOSVVersion([]byte("osv-scanner version: v2.5.1\n")); err != nil || version != "v2.5.1" {
		t.Fatalf("parseOSVVersion() with canonical token = %q, %v", version, err)
	}
	for _, test := range []struct {
		name   string
		output []byte
	}{
		{name: "legacy prefix", output: []byte("osv-scanner 2.5.1\n")},
		{name: "wrong capitalization", output: []byte("OSV-Scanner version: 2.5.1\n")},
		{name: "missing version", output: []byte("osv-scanner version: \n")},
		{name: "multiple tokens", output: []byte("osv-scanner version: 2.5.1 extra\n")},
		{name: "carriage return in token", output: []byte("osv-scanner version: 2.5.1\r\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if version, err := parseOSVVersion(test.output); err == nil || version != "" {
				t.Fatalf("parseOSVVersion(%q) = %q, %v, want version mismatch", test.output, version, err)
			}
		})
	}
}

func TestDecodeCaptureManifestRejectsStrictJSONViolations(t *testing.T) {
	manifest := testManifestSkeleton()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
	}{
		{name: "unknown", data: append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)},
		{name: "unknown environment attestation field", data: bytes.Replace(encoded, []byte(`"environment_attestation":{"reference":"environment-attestation","path":"attestation"}`), []byte(`"environment_attestation":{"reference":"environment-attestation","path":"attestation","unexpected":true}`), 1)},
		{name: "duplicate nested", data: []byte(`{"schema_version":"synapse-sca-benchmark-capture-manifest-v1","catalog_revision":"r","catalog_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_id":"t","sbom_path":"s","engine":"grype","engine_version":"v","binary":{"reference":"x","reference":"y","path":"p"},"database":{"reference":"db","path":"d","build":"b"},"environment":{"id":"e","goos":"` + runtime.GOOS + `","goarch":"` + runtime.GOARCH + `","image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_identity":"s"},"environment_pin_reference":"env","profile_pin_reference":"p","limits":{"timeout_seconds":1,"max_output_bytes":1,"memory_bytes":1,"pids_max":1}}`)},
		{name: "case variant", data: bytes.Replace(encoded, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)},
		{name: "trailing", data: append(encoded, []byte(` {}`)...)},
		{name: "invalid utf8", data: []byte{0xff}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeCaptureManifest(bytes.NewReader(test.data)); err == nil {
				t.Fatal("DecodeCaptureManifest succeeded")
			}
		})
	}
}

func TestManifestRequiresCompatibleDatabaseFormatAndProfilesBindIt(t *testing.T) {
	manifest := testManifestSkeleton()
	manifest.Database.Format = ""
	if err := manifest.Validate(); err == nil {
		t.Fatal("manifest accepted a missing database format")
	}
	manifest.Database.Format = DatabaseFormatTrivyDBV2
	if err := manifest.Validate(); err == nil {
		t.Fatal("manifest accepted an incompatible database format")
	}
	manifest = testManifestSkeleton()
	manifest.Environment.SandboxIdentity = "unattested-sandbox"
	if err := manifest.Validate(); err == nil {
		t.Fatal("manifest accepted an arbitrary sandbox identity")
	}
	limits := RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}
	first, _, _, err := buildProfile(bench.EngineOwned, DatabaseFormatOSVJSON, limits)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := buildProfile(bench.EngineOwned, DatabaseFormatOVAL, limits)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := canonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := canonicalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstJSON, secondJSON) || bench.SHA256Digest(firstJSON) == bench.SHA256Digest(secondJSON) {
		t.Fatal("changing only database format did not change the pinned profile digest")
	}
}

func TestHashTreeIsDeterministicAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := HashTree(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashTree(root)
	if err != nil || first != second {
		t.Fatalf("tree hashes = %q, %q, err=%v", first, second, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "a"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := HashTree(root); err == nil {
		t.Fatal("HashTree accepted symlink")
	}
}

func TestStableFileHashStreamsLargeFileAndRejectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.db")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte("a"), 64<<10)
	for written := 0; written < 8<<20; written += len(block) {
		if _, err := file.Write(block); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyRegularFile(path); err != nil {
		t.Fatalf("streaming large regular file verification failed: %v", err)
	}
	if _, err := streamStableRegularFile(path, nil, &mutationWriter{path: path}); err == nil {
		t.Fatal("streaming file hash accepted content mutation during read")
	}
}

func TestCapturePreflightRejectsPinSBOMAndComponentMismatch(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	cases := []struct {
		name   string
		change func(*bench.Catalog, *CaptureManifest)
	}{
		{name: "binary pin", change: func(c *bench.Catalog, _ *CaptureManifest) { c.Pins[0].Digest = digestByte('f') }},
		{name: "sbom", change: func(_ *bench.Catalog, m *CaptureManifest) {
			m.SBOMPath = writeFile(t, t.TempDir(), "bad.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}]}`))
		}},
		{name: "component", change: func(c *bench.Catalog, _ *CaptureManifest) { c.Targets[0].Components[0].PURL = "pkg:npm/missing@1.0.0" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c, m := catalog, manifest
			test.change(&c, &m)
			runner := &fakeRunner{}
			if _, err := NewCapturer(runner).Capture(context.Background(), c, m); err == nil {
				t.Fatal("Capture accepted invalid preflight")
			}
			if runner.calls != 0 {
				t.Fatalf("preflight failure dispatched %d scanner calls", runner.calls)
			}
		})
	}
}

func TestCapturePreflightRejectsInvalidEnvironmentAttestationBeforeDispatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, catalog *bench.Catalog, manifest *CaptureManifest)
	}{
		{
			name: "missing",
			mutate: func(_ *testing.T, _ *bench.Catalog, manifest *CaptureManifest) {
				manifest.EnvironmentAttestation = Artifact{}
			},
		},
		{
			name: "empty",
			mutate: func(t *testing.T, _ *bench.Catalog, manifest *CaptureManifest) {
				if err := os.WriteFile(manifest.EnvironmentAttestation.Path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			mutate: func(t *testing.T, _ *bench.Catalog, manifest *CaptureManifest) {
				if err := os.WriteFile(manifest.EnvironmentAttestation.Path, bytes.Repeat([]byte("a"), int(maxManifestBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "image digest mismatch",
			mutate: func(t *testing.T, _ *bench.Catalog, manifest *CaptureManifest) {
				if err := os.WriteFile(manifest.EnvironmentAttestation.Path, []byte("different exact attestation bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "catalog pin mismatch",
			mutate: func(t *testing.T, catalog *bench.Catalog, manifest *CaptureManifest) {
				for index := range catalog.Pins {
					if catalog.Pins[index].Reference == manifest.EnvironmentAttestation.Reference {
						catalog.Pins[index].Digest = digestByte('f')
						break
					}
				}
				rebindFixtureCatalog(t, catalog, manifest)
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineGrype)
			test.mutate(t, &catalog, &manifest)
			runner := &fakeRunner{}
			if _, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest); err == nil {
				t.Fatal("Capture accepted invalid environment attestation")
			}
			if runner.calls != 0 {
				t.Fatalf("environment attestation preflight failure dispatched %d scanner calls", runner.calls)
			}
		})
	}
}

func TestPrepareRejectsEmptyAndNonDirectoryDatabasesForEveryEngine(t *testing.T) {
	for _, engine := range bench.Engines() {
		for _, test := range []struct {
			name   string
			mutate func(*CaptureManifest)
		}{
			{name: "empty", mutate: func(manifest *CaptureManifest) {
				if err := os.Remove(filepath.Join(manifest.Database.Path, "advisory.json")); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "file", mutate: func(manifest *CaptureManifest) {
				file := writeFile(t, t.TempDir(), "database.json", []byte(`{}`))
				manifest.Database.Path = file
			}},
		} {
			t.Run(string(engine)+"/"+test.name, func(t *testing.T) {
				catalog, manifest := testFixture(t, engine)
				test.mutate(&manifest)
				if _, err := Prepare(catalog, manifest); err == nil {
					t.Fatal("Prepare accepted an empty or non-directory database")
				}
			})
		}
	}
}

func TestPreflightBindsComponentsByStructuralIdentity(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	catalog.Targets[0].Components[0] = bench.Component{PURL: "pkg:npm/a@1.0.0?repository_url=https%3A%2F%2Fexample.test#ignored", Version: ""}
	digest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = digest
	if err := Preflight(catalog, manifest); err != nil {
		t.Fatalf("preflight rejected component version in PURL or qualifier-order-insensitive identity: %v", err)
	}

	catalog, manifest = testFixture(t, bench.EngineGrype)
	ambiguous := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a@1.0.0?x=1&y=2"},{"name":"a","purl":"pkg:npm/a@1.0.0?y=2&x=1"}]}`)
	manifest.SBOMPath = writeFile(t, t.TempDir(), "ambiguous.json", ambiguous)
	catalog.Targets[0].SBOMDigest = bench.SHA256Digest(ambiguous)
	digest, err = bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = digest
	if err := Preflight(catalog, manifest); err == nil {
		t.Fatal("preflight accepted ambiguous structural SBOM components")
	}
}

func TestPreflightHandlesSyftMetadataContainerWithoutPURL(t *testing.T) {
	const osPURL = "pkg:deb/debian/bash@5.2.15-2%2Bdeb12u1?arch=amd64&distro=debian-12"

	for _, test := range []struct {
		name         string
		metadataPURL string
		wantErr      bool
	}{
		{
			name: "metadata container without PURL does not block OS package match",
		},
		{
			name:         "metadata container with whitespace PURL does not block OS package match",
			metadataPURL: " \\t\\u00a0\\n",
		},
		{
			name:         "malformed metadata PURL remains rejected",
			metadataPURL: "not-a-purl",
			wantErr:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineGrype)
			sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","name":"docker.io/library/debian","version":"12","purl":"` + test.metadataPURL + `"}},"components":[{"type":"operating-system","name":"bash","version":"5.2.15-2+deb12u1","purl":"` + osPURL + `"}]}`)
			manifest.SBOMPath = writeFile(t, t.TempDir(), "syft-shape.json", sbom)
			catalog.Targets[0].SBOMDigest = bench.SHA256Digest(sbom)
			catalog.Targets[0].Components = []bench.Component{{PURL: osPURL, Version: "5.2.15-2+deb12u1"}}
			digest, err := bench.DigestCatalog(catalog)
			if err != nil {
				t.Fatal(err)
			}
			manifest.CatalogDigest = digest

			err = Preflight(catalog, manifest)
			if test.wantErr && err == nil {
				t.Fatal("preflight accepted a metadata component with a malformed nonblank PURL")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("preflight rejected Syft metadata container without PURL: %v", err)
			}
		})
	}
}

func TestExternalProfileUsesExactGrypeSpecAndArgvElements(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	weirdDir := filepath.Join(t.TempDir(), "path;$(not-a-command){literal}")
	if err := os.Mkdir(weirdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest.SBOMPath = writeFile(t, weirdDir, "input.json", canonicalSBOM())
	catalog.Targets[0].SBOMDigest = bench.SHA256Digest(canonicalSBOM())
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = catalogDigest
	runner := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}]}`)}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation().State != bench.ObservationComplete {
		t.Fatalf("state = %q", result.Observation().State)
	}
	if len(runner.spec.ReadOnlyPaths) != 5 || runner.spec.Name != runner.spec.ReadOnlyPaths[0] {
		t.Fatalf("snapshot ToolSpec identity = %#v", runner.spec)
	}
	wantArgs := []string{"sbom:" + runner.spec.ReadOnlyPaths[1], "-o", "json", "-q", "--config"}
	if len(runner.spec.Args) != len(wantArgs)+1 {
		t.Fatalf("args = %#v", runner.spec.Args)
	}
	for i, want := range wantArgs {
		if runner.spec.Args[i] != want {
			t.Fatalf("arg %d = %q, want %q", i, runner.spec.Args[i], want)
		}
	}
	if strings.Contains(strings.Join(runner.spec.Args, "\n"), manifest.SBOMPath) || strings.Contains(strings.Join(runner.spec.ReadOnlyPaths, "\n"), manifest.SBOMPath) {
		t.Fatalf("source SBOM escaped private snapshot: %#v", runner.spec)
	}
	wantEnv := []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_CACHE_DIR=" + runner.spec.ReadOnlyPaths[2], "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_AGE=false", "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true"}
	if strings.Join(runner.spec.Env, "\n") != strings.Join(wantEnv, "\n") || runner.spec.HostNetwork || runner.spec.EgressPolicy != nil || runner.spec.CapAdd != nil || runner.spec.Timeout <= 0 || runner.spec.MaxOutputBytes <= 0 || runner.spec.MemMaxBytes <= 0 || runner.spec.PidsMax <= 0 {
		t.Fatalf("unexpected strict ToolSpec: %#v", runner.spec)
	}
}

func TestExternalProfilesUsePinnedNoNetworkSpecs(t *testing.T) {
	cases := []struct {
		engine  bench.Engine
		stdout  string
		want    []string
		wantEnv []string
	}{
		{engine: bench.EngineTrivy, stdout: `{"SchemaVersion":2,"Trivy":{"Version":"1.2.3"},"Results":[]}`, want: []string{"sbom", "--format", "json", "--scanners", "vuln", "--cache-dir", "{db}", "--config", "{config}", "--ignorefile", "{ignore}", "--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--skip-vex-repo-update", "--offline-scan", "--disable-telemetry", "--quiet", "--exit-code", "0", "{sbom}"}},
		{engine: bench.EngineOSVScanner, stdout: `{"results":[]}`, want: []string{"scan", "source", "--offline", "--offline-vulnerabilities", "--experimental-no-default-plugins", "--experimental-plugins=lockfile", "--experimental-plugins=sbom", "--format", "json", "--config={config}", "--lockfile={sbom}"}, wantEnv: []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={db}"}},
	}
	for _, test := range cases {
		t.Run(string(test.engine), func(t *testing.T) {
			catalog, manifest := testFixture(t, test.engine)
			runner := &fakeRunner{result: ports.ToolResult{Stdout: []byte(test.stdout)}}
			if test.engine == bench.EngineOSVScanner {
				runner.results = []ports.ToolResult{{Stdout: osvVersionProbeOutput("1.2.3")}, {Stdout: []byte(test.stdout)}}
			}
			result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
			if err != nil || result.Observation().State != bench.ObservationComplete {
				t.Fatalf("Capture state=%q err=%v", result.Observation().State, err)
			}
			if len(runner.spec.ReadOnlyPaths) != 5 || runner.spec.Name != runner.spec.ReadOnlyPaths[0] {
				t.Fatalf("snapshot ToolSpec identity = %#v", runner.spec)
			}
			if test.engine == bench.EngineOSVScanner && (len(runner.specs) != 2 || len(runner.specs[0].Args) != 1 || runner.specs[0].Args[0] != "--version") {
				t.Fatalf("OSV dispatches = %#v, want fixed version probe then scan", runner.specs)
			}
			resolved := strings.NewReplacer("{db}", runner.spec.ReadOnlyPaths[2], "{sbom}", runner.spec.ReadOnlyPaths[1], "{config}", runner.spec.ReadOnlyPaths[3], "{ignore}", runner.spec.ReadOnlyPaths[4]).Replace(strings.Join(test.want, "\x00"))
			if got := strings.Join(runner.spec.Args, "\x00"); got != resolved {
				t.Fatalf("args = %#v, want %q", runner.spec.Args, resolved)
			}
			resolvedEnv := strings.NewReplacer("{db}", runner.spec.ReadOnlyPaths[2]).Replace(strings.Join(test.wantEnv, "\x00"))
			if got := strings.Join(runner.spec.Env, "\x00"); got != resolvedEnv {
				t.Fatalf("environment = %#v, want %q", runner.spec.Env, resolvedEnv)
			}
			if runner.spec.HostNetwork || runner.spec.EgressPolicy != nil || runner.spec.CapAdd != nil {
				t.Fatalf("unexpected strict ToolSpec: %#v", runner.spec)
			}
		})
	}
}

func TestOSVProfileUsesEmptyTOMLConfigAndPinnedVersionProbe(t *testing.T) {
	limits := RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}
	profile, config, _, err := buildProfile(bench.EngineOSVScanner, DatabaseFormatOSVScannerOffline, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(config) != 0 || profile.ConfigContentDigest != bench.SHA256Digest([]byte{}) {
		t.Fatalf("OSV config must be empty TOML bytes: %q, profile=%+v", config, profile)
	}
	if got, want := strings.Join(profile.ArgvTemplate, "\x00"), strings.Join([]string{"scan", "source", "--offline", "--offline-vulnerabilities", "--experimental-no-default-plugins", "--experimental-plugins=lockfile", "--experimental-plugins=sbom", "--format", "json", "--config={config}", "--lockfile={sbom}"}, "\x00"); got != want {
		t.Fatalf("OSV argv profile = %#v, want %q", profile.ArgvTemplate, want)
	}
	for _, arg := range profile.ArgvTemplate {
		if arg == "{sbom}" {
			t.Fatalf("OSV argv profile must not contain a bare SBOM source: %#v", profile.ArgvTemplate)
		}
	}
	if got, want := strings.Join(profile.EnvironmentTemplate, "\x00"), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={db}"; got != want {
		t.Fatalf("OSV environment profile = %#v, want %q", profile.EnvironmentTemplate, want)
	}
	if !profile.NoNetwork || !profile.AutoUpdateDisabled {
		t.Fatalf("OSV profile must remain no-network and auto-update-disabled: %+v", profile)
	}
	if len(profile.VersionProbeArgvTemplate) != 1 || profile.VersionProbeArgvTemplate[0] != "--version" {
		t.Fatalf("OSV version probe profile = %#v", profile.VersionProbeArgvTemplate)
	}
}

func TestOSVProfileExcludesFilesystemAndOnlineVulnerabilityScanning(t *testing.T) {
	limits := RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}
	profile, _, _, err := buildProfile(bench.EngineOSVScanner, DatabaseFormatOSVScannerOffline, limits)
	if err != nil {
		t.Fatal(err)
	}

	joinedArgs := "\x00" + strings.Join(profile.ArgvTemplate, "\x00") + "\x00"
	for _, required := range []string{
		"--offline",
		"--offline-vulnerabilities",
		"--experimental-no-default-plugins",
		"--experimental-plugins=lockfile",
		"--experimental-plugins=sbom",
		"--lockfile={sbom}",
	} {
		if !strings.Contains(joinedArgs, "\x00"+required+"\x00") {
			t.Fatalf("OSV profile is missing required isolated-SBOM argument %q: %#v", required, profile.ArgvTemplate)
		}
	}
	for _, forbidden := range []string{"--experimental-plugins=directory", "--recursive", "{sbom}"} {
		if strings.Contains(joinedArgs, "\x00"+forbidden+"\x00") {
			t.Fatalf("OSV profile must not scan a filesystem path through %q: %#v", forbidden, profile.ArgvTemplate)
		}
	}
	for _, arg := range profile.ArgvTemplate {
		if strings.HasPrefix(arg, "--experimental-plugins=") && arg != "--experimental-plugins=lockfile" && arg != "--experimental-plugins=sbom" {
			t.Fatalf("OSV profile enables a plugin other than lockfile or sbom: %#v", profile.ArgvTemplate)
		}
	}
}

func TestOSVProfileResolvesPrivateDatabaseEnvironmentAndFinalSBOM(t *testing.T) {
	limits := RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}
	profile, _, _, err := buildProfile(bench.EngineOSVScanner, DatabaseFormatOSVScannerOffline, limits)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRoot := t.TempDir()
	sbomPath := filepath.Join(snapshotRoot, "bom.cdx.json")
	databasePath := filepath.Join(snapshotRoot, "osv-db")
	configPath := filepath.Join(snapshotRoot, "config.toml")
	args, env, err := instantiateProfile(profile, sbomPath, databasePath, configPath, filepath.Join(snapshotRoot, "ignore.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(args, "\x00"), strings.Join([]string{"scan", "source", "--offline", "--offline-vulnerabilities", "--experimental-no-default-plugins", "--experimental-plugins=lockfile", "--experimental-plugins=sbom", "--format", "json", "--config=" + configPath, "--lockfile=" + sbomPath}, "\x00"); got != want {
		t.Fatalf("OSV resolved argv = %#v, want %q", args, want)
	}
	if got, want := strings.Join(env, "\x00"), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+databasePath; got != want {
		t.Fatalf("OSV resolved environment = %#v, want %q", env, want)
	}
	if got, want := args[len(args)-1], "--lockfile="+sbomPath; got != want || filepath.Base(strings.TrimPrefix(got, "--lockfile=")) != "bom.cdx.json" {
		t.Fatalf("OSV final lockfile argument = %q, want private CycloneDX snapshot %q", got, want)
	}
	for _, arg := range args {
		if arg == "--local-db-path" {
			t.Fatalf("OSV argv must not use the removed database flag: %#v", args)
		}
	}
}

func TestParsersUseHandAuthoredPublicWireShapes(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}
	fixtures := []struct {
		name    string
		engine  bench.Engine
		version string
		format  DatabaseFormat
		data    string
	}{
		{name: "grype", engine: bench.EngineGrype, version: "1", data: `{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}]}`},
		{name: "trivy", engine: bench.EngineTrivy, version: "1", data: `{"SchemaVersion":2,"Trivy":{"Version":"1"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgIdentifier":{"PURL":"pkg:npm/a@1.0.0"},"InstalledVersion":"1.0.0"}]}]}`},
		{name: "osv", engine: bench.EngineOSVScanner, version: "2", data: `{"results":[{"source":{"path":"input"},"groups":[{"ids":["GHSA-AAAA-BBBB-CCCC","CVE-2024-0001"]}],"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-AAAA-BBBB-CCCC"}]}]}]}`},
		{name: "owned", engine: bench.EngineOwned, version: "1", format: DatabaseFormatOSVJSON, data: `{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1","advisories_ingested":1,"advisories_skipped":0,"findings":[{"purl":"pkg:npm/a@1.0.0","version":"1.0.0","advisory_id":"CVE-2024-0001"}]}`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			findings, err := parseEngine(fixture.engine, fixture.version, []byte(fixture.data), target, nil, fixture.format)
			if err != nil || len(findings) != 1 {
				t.Fatalf("parseEngine findings=%#v err=%v", findings, err)
			}
		})
	}
}

func TestDecodeEngineJSONRejectsCaseFoldedKeysAtEveryDepth(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "top level", data: `{"descriptor":{"name":"grype","version":"1"},"matches":[],"Matches":[]}`},
		{name: "nested object", data: `{"descriptor":{"name":"grype","Name":"other","version":"1"},"matches":[]}`},
		{name: "nested array object", data: `{"descriptor":{"name":"grype","version":"1"},"matches":[{"artifact":{"purl":"pkg:npm/a@1","PURL":"pkg:npm/a@1"}}]}`},
		{name: "Unicode simple fold", data: `{"descriptor":{"name":"grype","version":"1"},"matches":[],"S":[],"ſ":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire grypeWire
			if err := decodeEngineJSON([]byte(test.data), &wire, "descriptor", "matches"); err == nil {
				t.Fatal("case-folded scanner JSON keys were accepted")
			}
		})
	}
}

func TestCatalogComponentIndexRejectsAmbiguousKeysAndFindsUniqueKeys(t *testing.T) {
	target := bench.Target{Components: []bench.Component{
		{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"},
		{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"},
		{PURL: "pkg:npm/b@2.0.0", Version: "2.0.0"},
	}}
	index := indexCatalogComponents(target)
	if _, ok := index.component("pkg:npm/a@1.0.0", "1.0.0"); ok {
		t.Fatal("ambiguous catalog component key was accepted")
	}
	component, ok := index.component("pkg:npm/b@2.0.0", "2.0.0")
	if !ok || component.PURL != "pkg:npm/b@2.0.0" {
		t.Fatalf("unique catalog component index lookup = %#v, %t", component, ok)
	}
}

func TestOSVAliasGroupsChooseDeterministicRepresentative(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}
	first := []byte(`{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-ZZZZ-YYYY-XXXX"}],"groups":[{"ids":["GHSA-ZZZZ-YYYY-XXXX","CVE-2024-0001"]}]}]}]}`)
	second := []byte(`{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":"CVE-2024-0001"}],"groups":[{"ids":["CVE-2024-0001","GHSA-ZZZZ-YYYY-XXXX"]}]}]}]}`)
	left, err := parseOSV(first, target)
	if err != nil {
		t.Fatal(err)
	}
	right, err := parseOSV(second, target)
	if err != nil || len(left) != 1 || len(right) != 1 || left[0].AdvisoryID != right[0].AdvisoryID || left[0].AdvisoryID != "CVE-2024-0001" {
		t.Fatalf("alias group outputs = %#v %#v, err=%v", left, right, err)
	}
}

func TestCanonicalFindingsPreservesCaseSensitiveAdvisoryIDs(t *testing.T) {
	component := bench.Component{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}
	findings := canonicalFindings([]bench.Finding{
		{Component: component, AdvisoryID: "GO-2024-0001"},
		{Component: component, AdvisoryID: "go-2024-0001"},
	})
	if len(findings) != 2 {
		t.Fatalf("case-sensitive IDs collapsed: %#v", findings)
	}
}

func TestCaptureAcceptsOSVExitOne(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	runner := &fakeRunner{results: []ports.ToolResult{{Stdout: osvVersionProbeOutput("1.2.3")}, {ExitCode: 1, Stdout: []byte(`{"results":[]}`)}}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil || result.Observation().State != bench.ObservationComplete {
		t.Fatalf("state=%q err=%v", result.Observation().State, err)
	}
}

func TestCaptureDoesNotPublishOSVBlankVulnerabilityAsClean(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	result, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{
		{Stdout: osvVersionProbeOutput("1.2.3")},
		{ExitCode: 1, Stdout: []byte(`{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":" \t "}]}]}]}`)},
	}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureParser || evidence.ParserStatus != ParserFailed {
		t.Fatalf("malformed OSV output was published as clean: observation=%+v evidence=%+v", result.Observation(), evidence)
	}
}

func TestCaptureFailurePrecedenceNeverCompletes(t *testing.T) {
	cases := []struct {
		name     string
		runner   fakeRunner
		cancel   bool
		expected FailureCode
	}{
		{name: "runner", runner: fakeRunner{result: ports.ToolResult{ExitCode: 18}, err: errors.New("no scanner")}, expected: FailureRunnerError},
		{name: "cancelled", runner: fakeRunner{result: ports.ToolResult{ExitCode: 19}}, cancel: true, expected: FailureCancelled},
		{name: "timeout", runner: fakeRunner{result: ports.ToolResult{TimedOut: true}}, expected: FailureTimeout},
		{name: "truncated", runner: fakeRunner{result: ports.ToolResult{Truncated: true}}, expected: FailureOutputTruncated},
		{name: "connect", runner: fakeRunner{result: ports.ToolResult{ConnectLog: []ports.ConnEvent{{}}}}, expected: FailureConnectEvent},
		{name: "exit", runner: fakeRunner{result: ports.ToolResult{ExitCode: 9}}, expected: FailureUnacceptedExit},
		{name: "parser", runner: fakeRunner{result: ports.ToolResult{Stdout: []byte(`{`)}}, expected: FailureParser},
		{name: "version", runner: fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"wrong"},"matches":[]}`)}}, expected: FailureVersionMismatch},
		{name: "postflight", runner: fakeRunner{}, expected: FailureInputMutated},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineGrype)
			runner := test.runner
			if test.name != "parser" && test.name != "version" {
				runner.result.Stdout = []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)
			}
			if test.name == "postflight" {
				runner.mutateSpec = func(spec ports.ToolSpec) {
					if len(spec.ReadOnlyPaths) > 1 {
						_ = os.WriteFile(spec.ReadOnlyPaths[1], []byte("changed"), 0o600)
					}
				}
			}
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := NewCapturer(&runner).Capture(ctx, catalog, manifest)
			if err != nil {
				t.Fatal(err)
			}
			evidence := evidenceForTest(t, result)
			if result.Observation().State != bench.ObservationIncomplete || evidence.FailureCode != test.expected {
				t.Fatalf("state=%q failure=%q, want incomplete/%q", result.Observation().State, evidence.FailureCode, test.expected)
			}
			if test.name == "runner" {
				if evidence.Scan == nil {
					t.Fatal("runner failure omitted scan evidence")
				}
				if evidence.Scan.ExitKnown || evidence.Scan.ExitCode != 0 {
					t.Fatalf("runner failure process = %+v, want unknown zero exit", *evidence.Scan)
				}
			}
			if test.cancel {
				if runner.calls != 1 {
					t.Fatalf("runner calls = %d, want 1", runner.calls)
				}
				if evidence.Scan == nil {
					t.Fatal("cancelled capture omitted scan evidence")
				}
				if evidence.Scan.RunnerError || !evidence.Scan.Cancelled || evidence.Scan.ExitKnown || evidence.Scan.ExitCode != 0 {
					t.Fatalf("cancelled process = %+v, want no runner error and a cancelled unknown zero exit", *evidence.Scan)
				}
			}
			if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err != nil {
				t.Fatalf("write publication-valid %s bundle: %v", test.name, err)
			}
		})
	}
}

func TestCapturePostflightDetectsEnvironmentAttestationSnapshotMutation(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	runner := &fakeRunner{
		result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)},
		mutateSpec: func(spec ports.ToolSpec) {
			_ = os.WriteFile(filepath.Join(filepath.Dir(spec.Name), "environment-attestation.json"), []byte("mutated after dispatch"), 0o600)
		},
	}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if runner.calls != 1 || result.Observation().State != bench.ObservationIncomplete || evidence.InputIntegrity != InputsMutated || evidence.FailureCode != FailureInputMutated {
		t.Fatalf("mutated environment attestation result=%+v evidence=%+v calls=%d", result.Observation(), evidence, runner.calls)
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("write bundle with retained pre-mutation environment attestation: %v", err)
	}
	want, err := os.ReadFile(manifest.EnvironmentAttestation.Path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(bundle, "environment-attestation.json"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("published environment attestation does not retain exact pre-dispatch bytes: got=%q want=%q err=%v", got, want, err)
	}
}

func TestCaptureBoundsRetainedProcessEvidence(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = 32
	rebindFixtureProfile(t, &catalog, &manifest)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: bytes.Repeat([]byte("x"), 33), Stderr: bytes.Repeat([]byte("y"), 33)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if evidence.Scan == nil || evidence.FailureCode != FailureOutputTruncated || !evidence.Scan.Truncated || len(evidence.Scan.Stdout)+len(evidence.Scan.Stderr) > manifest.Limits.MaxOutputBytes {
		t.Fatalf("process evidence was not bounded: %+v", evidence.Scan)
	}
}

func TestCaptureBoundsEachOSVProcessRecord(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	probeOutput := osvVersionProbeOutput("1.2.3")
	manifest.Limits.MaxOutputBytes = len(probeOutput)
	rebindFixtureProfile(t, &catalog, &manifest)
	result, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{
		{Stdout: probeOutput},
		{Stdout: bytes.Repeat([]byte("x"), manifest.Limits.MaxOutputBytes+1)},
	}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if evidence.VersionProbe == nil || evidence.Scan == nil || evidence.FailureCode != FailureOutputTruncated || len(evidence.VersionProbe.Stdout)+len(evidence.VersionProbe.Stderr) > manifest.Limits.MaxOutputBytes || len(evidence.Scan.Stdout)+len(evidence.Scan.Stderr) > manifest.Limits.MaxOutputBytes {
		t.Fatalf("OSV process records were not independently bounded: %+v", evidence)
	}
}

func TestPreparedCaptureExecutesOnlyPrivateSnapshotsAndFreezesCatalog(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	runner := &fakeRunner{resultForSpec: func(spec ports.ToolSpec) ports.ToolResult {
		if len(spec.ReadOnlyPaths) != 5 {
			return ports.ToolResult{ExitCode: 91}
		}
		binary, binaryErr := os.ReadFile(spec.Name)
		sbom, sbomErr := os.ReadFile(spec.ReadOnlyPaths[1])
		database, databaseErr := os.ReadFile(filepath.Join(spec.ReadOnlyPaths[2], "advisory.json"))
		if binaryErr != nil || sbomErr != nil || databaseErr != nil || string(binary) != "scanner binary" || !bytes.Equal(sbom, canonicalSBOM()) || len(database) == 0 {
			return ports.ToolResult{ExitCode: 91}
		}
		return ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}]}`)}
	}}
	capturer := NewCapturer(runner).WithTempDir(t.TempDir())
	frozen, err := capturer.preflight(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &PreparedCapture{capture: frozen}
	info, err := os.Stat(frozen.binaryPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode()&0o100 == 0) {
		t.Fatalf("private binary snapshot is not executable: info=%v err=%v", info, err)
	}
	// Replacing every caller-owned source and catalog value after Prepare must not alter execution.
	if err := os.Remove(manifest.Binary.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest.SBOMPath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(manifest.Database.Path); err != nil {
		t.Fatal(err)
	}
	catalog.Targets[0].Components[0].PURL = "pkg:npm/changed@9.9.9"
	result, err := capturer.CapturePrepared(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation().State != bench.ObservationComplete || len(result.Observation().Findings) != 1 || result.Observation().Findings[0].Component.PURL != "pkg:npm/a@1.0.0" {
		t.Fatalf("snapshot capture result = %+v", result.Observation())
	}
	if len(runner.spec.ReadOnlyPaths) != 5 || strings.Contains(strings.Join(runner.spec.ReadOnlyPaths, "\n"), manifest.SBOMPath) || strings.Contains(strings.Join(runner.spec.Args, "\n"), manifest.Database.Path) {
		t.Fatalf("capture dispatched caller-owned input instead of snapshots: %+v", runner.spec)
	}
	if _, statErr := os.Stat(frozen.snapshotRoot); !os.IsNotExist(statErr) {
		t.Fatalf("snapshot root was not removed after capture: %v", statErr)
	}
}

func TestPreparedCaptureOSVUsesPrivateRecognizedCycloneDXSnapshot(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	runner := &fakeRunner{results: []ports.ToolResult{{Stdout: osvVersionProbeOutput("1.2.3")}, {Stdout: []byte(`{"results":[]}`)}}}
	prepared, err := Prepare(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest.SBOMPath); err != nil {
		t.Fatal(err)
	}
	result, err := NewCapturer(runner).CapturePrepared(context.Background(), prepared)
	if err != nil || result.Observation().State != bench.ObservationComplete {
		t.Fatalf("CapturePrepared state=%q err=%v", result.Observation().State, err)
	}
	if len(runner.specs) != 2 {
		t.Fatalf("OSV dispatches = %#v, want version probe then scan", runner.specs)
	}
	scan := runner.specs[1]
	if len(scan.Args) == 0 {
		t.Fatalf("OSV scan arguments are empty")
	}
	if len(scan.ReadOnlyPaths) < 3 {
		t.Fatalf("OSV private mounted paths = %#v", scan.ReadOnlyPaths)
	}
	if got, want := scan.Args[len(scan.Args)-1], "--lockfile="+scan.ReadOnlyPaths[1]; got != want {
		t.Fatalf("OSV final lockfile argument = %q, want private CycloneDX snapshot %q", got, want)
	}
	snapshotSBOMPath := strings.TrimPrefix(scan.Args[len(scan.Args)-1], "--lockfile=")
	if got, want := filepath.Base(snapshotSBOMPath), "bom.cdx.json"; got != want {
		t.Fatalf("OSV SBOM snapshot basename = %q, want recognized CycloneDX name %q", got, want)
	}
	if scan.ReadOnlyPaths[1] != snapshotSBOMPath {
		t.Fatalf("OSV lockfile path is not the private mounted snapshot: %#v", scan)
	}
	if got, want := strings.Join(scan.Env, "\x00"), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+scan.ReadOnlyPaths[2]; got != want {
		t.Fatalf("OSV database environment = %#v, want %q", scan.Env, want)
	}
	for _, arg := range scan.Args {
		if arg == "--local-db-path" {
			t.Fatalf("OSV scan must not pass the removed database flag: %#v", scan.Args)
		}
	}
	for _, callerOwnedPath := range []string{manifest.Binary.Path, manifest.SBOMPath, manifest.Database.Path} {
		if scan.Name == callerOwnedPath || strings.Contains(strings.Join(scan.Args, "\x00"), callerOwnedPath) || strings.Contains(strings.Join(scan.ReadOnlyPaths, "\x00"), callerOwnedPath) || strings.Contains(strings.Join(scan.Env, "\x00"), callerOwnedPath) {
			t.Fatalf("OSV dispatch escaped caller-owned path %q: %#v", callerOwnedPath, scan)
		}
	}
}

func TestPreparedCaptureLifecycleRejectsClosedAndSecondUse(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	capturer := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).WithTempDir(t.TempDir())
	frozen, err := capturer.preflight(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &PreparedCapture{capture: frozen}
	root := frozen.snapshotRoot
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if _, err := capturer.CapturePrepared(context.Background(), prepared); err == nil {
		t.Fatal("CapturePrepared accepted a closed snapshot")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("closed snapshot root still exists: %v", err)
	}

	frozen, err = capturer.preflight(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	prepared = &PreparedCapture{capture: frozen}
	if _, err := capturer.CapturePrepared(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := capturer.CapturePrepared(context.Background(), prepared); err == nil {
		t.Fatal("CapturePrepared accepted a second use")
	}
}

func TestCaptureResultAccessorsCannotMutatePublicationBinding(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	observation := result.Observation()
	observation.Findings = append(observation.Findings, bench.Finding{AdvisoryID: "CVE-2024-9999"})
	evidence := result.EvidenceJSON()
	profile := result.ProfileJSON()
	if len(evidence) == 0 || len(profile) == 0 {
		t.Fatal("capture result accessors returned empty artifacts")
	}
	evidence[0] ^= 1
	profile[0] ^= 1
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err != nil {
		t.Fatalf("mutating accessor copies changed publication: %v", err)
	}
}

func TestWriteBundleRejectsUnboundResult(t *testing.T) {
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), CaptureResult{}); err == nil {
		t.Fatal("WriteBundle accepted an unbound result")
	}
}

func TestCaptureRedactsPathsAndRawOutputDigestBindsCanonicalEvidence(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	runner := &fakeRunner{resultForSpec: func(spec ports.ToolSpec) ports.ToolResult {
		return ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"source":"` + spec.ReadOnlyPaths[1] + `","reference":"https://alice:secret@example.test/path","matches":[]}`)}
	}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation().State != bench.ObservationComplete {
		t.Fatalf("redacted parse state=%q", result.Observation().State)
	}
	if bytes.Contains(result.EvidenceJSON(), []byte(manifest.SBOMPath)) || bytes.Contains(result.EvidenceJSON(), []byte(runner.spec.ReadOnlyPaths[1])) || bytes.Contains(result.EvidenceJSON(), []byte("alice:secret")) {
		t.Fatalf("evidence retained secret or physical path: %s", result.EvidenceJSON())
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err != nil {
		t.Fatalf("redacted output was not replayable: %v", err)
	}
	if result.Observation().RawOutputDigest != rawOutputDigest(result.EvidenceJSON()) || result.Observation().RawOutputDigest != bench.SHA256Digest(result.EvidenceJSON()) {
		t.Fatal("raw output digest does not bind exact canonical evidence JSON")
	}
	secondCatalog, secondManifest := testFixture(t, bench.EngineGrype)
	secondRunner := &fakeRunner{resultForSpec: func(spec ports.ToolSpec) ports.ToolResult {
		return ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"source":"` + spec.ReadOnlyPaths[1] + `","reference":"https://alice:secret@example.test/path","matches":[]}`)}
	}}
	second, err := NewCapturer(secondRunner).Capture(context.Background(), secondCatalog, secondManifest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation().RawOutputDigest != second.Observation().RawOutputDigest || !bytes.Equal(result.EvidenceJSON(), second.EvidenceJSON()) {
		t.Fatal("redacted physical paths changed output-only evidence identity")
	}
}

func TestWriteBundleIsAtomicAndDoesNotOverwrite(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	runner := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(output, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"observation.json", "evidence.json", "profile.json", "environment.json", "environment-attestation.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatalf("bundle missing %s: %v", name, err)
		}
	}
	environmentJSON, err := os.ReadFile(filepath.Join(output, "environment.json"))
	if err != nil || !bytes.Equal(environmentJSON, result.environmentJSON) {
		t.Fatalf("published environment descriptor does not retain exact canonical bytes: %q", environmentJSON)
	}
	environmentAttestationJSON, err := os.ReadFile(filepath.Join(output, "environment-attestation.json"))
	if err != nil || !bytes.Equal(environmentAttestationJSON, result.environmentAttestationJSON) {
		t.Fatalf("published environment attestation does not retain exact pinned bytes: %q", environmentAttestationJSON)
	}
	profile, err := os.ReadFile(filepath.Join(output, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(profile, result.ProfileJSON()) {
		t.Fatal("published profile bytes differ from ConfigDigest input")
	}
	data, err := os.ReadFile(filepath.Join(output, "observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bench.DecodeObservationSet(bytes.NewReader(data)); err != nil {
		t.Fatalf("bundle observation compatibility: %v", err)
	}
	if err := WriteBundle(output, result); err == nil {
		t.Fatal("WriteBundle overwrote existing bundle")
	}
}

func TestValidateBundleRejectsEnvironmentArtifactSetViolations(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, bundle string)
	}{
		{
			name: "missing descriptor",
			mutate: func(t *testing.T, bundle string) {
				if err := os.Remove(filepath.Join(bundle, "environment.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing attestation",
			mutate: func(t *testing.T, bundle string) {
				if err := os.Remove(filepath.Join(bundle, "environment-attestation.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mutated descriptor",
			mutate: func(t *testing.T, bundle string) {
				path := filepath.Join(bundle, "environment.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mutated attestation",
			mutate: func(t *testing.T, bundle string) {
				path := filepath.Join(bundle, "environment-attestation.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unexpected artifact",
			mutate: func(t *testing.T, bundle string) {
				if err := os.WriteFile(filepath.Join(bundle, "unexpected.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := WriteBundle(bundle, result); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, bundle)
			if err := ValidateBundle(bundle); err == nil {
				t.Fatal("ValidateBundle accepted invalid environment bundle artifacts")
			}
		})
	}
}

func TestCaptureOwnedUsesPinnedHelperThroughRunner(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOwned)
	runner := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1.2.3","advisories_ingested":1,"advisories_skipped":0,"findings":[]}`)}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 || len(runner.spec.ReadOnlyPaths) != 5 || runner.spec.Name != runner.spec.ReadOnlyPaths[0] {
		t.Fatalf("owned helper calls=%d spec=%+v", runner.calls, runner.spec)
	}
	if result.Observation().State != bench.ObservationComplete {
		t.Fatalf("owned state=%q", result.Observation().State)
	}
	var profile ExecutionProfile
	if err := json.Unmarshal(result.ProfileJSON(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.ExecutionMode != "external" || !profile.NoNetwork || len(profile.ArgvTemplate) == 0 {
		t.Fatalf("owned profile does not describe a sandboxed helper: %+v", profile)
	}
}

func TestCaptureOwnedRequiresExactHelperVersion(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOwned)
	runner := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"wrong","advisories_ingested":1,"advisories_skipped":0,"findings":[]}`)}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Observation().State != bench.ObservationIncomplete || evidenceForTest(t, result).FailureCode != "version_mismatch" {
		t.Fatalf("owned helper version mismatch state=%q evidence=%+v", result.Observation().State, evidenceForTest(t, result))
	}
}

func TestOwnedFeedUsesDeclaredFormatWithoutFallback(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, directory, "SUSE-SLE-15.6.oval.xml.gz", []byte("not parsed by selection"))
	feed, err := ownedFeed(directory, DatabaseFormatOVAL)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := feed.(*ownadvisory.OVALDirFeed); !ok {
		t.Fatalf("feed type = %T, want OVALDirFeed", feed)
	}
	if _, err := ownedFeed(directory, DatabaseFormatOSVJSON); err == nil {
		t.Fatal("owned feed selected a fallback importer for a mismatched declaration")
	}
	writeFile(t, directory, "advisory.json", []byte(`{}`))
	if _, err := ownedFeed(directory, DatabaseFormatOVAL); err == nil {
		t.Fatal("owned feed accepted a mixed corpus")
	}
}

func TestPrepareRejectsOwnedCorpusLayoutsBeforeDispatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bench.Catalog, *CaptureManifest)
	}{
		{name: "empty", mutate: func(catalog *bench.Catalog, manifest *CaptureManifest) {
			if err := os.Remove(filepath.Join(manifest.Database.Path, "advisory.json")); err != nil {
				t.Fatal(err)
			}
			rebindFixtureDatabase(t, catalog, manifest)
		}},
		{name: "declared format mismatch", mutate: func(catalog *bench.Catalog, manifest *CaptureManifest) {
			manifest.Database.Format = DatabaseFormatOVAL
			rebindFixtureProfile(t, catalog, manifest)
		}},
		{name: "mixed", mutate: func(catalog *bench.Catalog, manifest *CaptureManifest) {
			if err := os.WriteFile(filepath.Join(manifest.Database.Path, "advisory.xml"), []byte("<oval_definitions/>"), 0o600); err != nil {
				t.Fatal(err)
			}
			rebindFixtureDatabase(t, catalog, manifest)
		}},
		{name: "unsupported extension", mutate: func(catalog *bench.Catalog, manifest *CaptureManifest) {
			if err := os.WriteFile(filepath.Join(manifest.Database.Path, "notes.txt"), []byte("not an advisory"), 0o600); err != nil {
				t.Fatal(err)
			}
			rebindFixtureDatabase(t, catalog, manifest)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineOwned)
			test.mutate(&catalog, &manifest)
			runner := &fakeRunner{}
			if _, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest); err == nil {
				t.Fatal("Capture accepted an invalid owned corpus layout")
			}
			if runner.calls != 0 {
				t.Fatalf("invalid owned corpus dispatched %d scanner calls", runner.calls)
			}
		})
	}
}

func TestParsersRejectMalformedRequiredWireFields(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}
	cases := []struct {
		name    string
		engine  bench.Engine
		version string
		format  DatabaseFormat
		data    string
	}{
		{name: "grype missing descriptor and matches", engine: bench.EngineGrype, version: "1", data: `{}`},
		{name: "grype duplicate matches", engine: bench.EngineGrype, version: "1", data: `{"descriptor":{"name":"grype","version":"1"},"matches":[],"matches":[]}`},
		{name: "trivy missing results", engine: bench.EngineTrivy, version: "1", data: `{"SchemaVersion":2,"Trivy":{"Version":"1"}}`},
		{name: "trivy unsupported schema", engine: bench.EngineTrivy, version: "1", data: `{"SchemaVersion":999,"Trivy":{"Version":"1"},"Results":[]}`},
		{name: "osv missing results", engine: bench.EngineOSVScanner, version: "1", data: `{}`},
		{name: "osv missing vulnerability ID", engine: bench.EngineOSVScanner, version: "1", data: `{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{}]}]}]}`},
		{name: "osv null vulnerability ID", engine: bench.EngineOSVScanner, version: "1", data: `{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":null}]}]}]}`},
		{name: "osv blank vulnerability ID", engine: bench.EngineOSVScanner, version: "1", data: `{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":""}]}]}]}`},
		{name: "osv whitespace vulnerability ID", engine: bench.EngineOSVScanner, version: "1", data: `{"results":[{"packages":[{"package":{"name":"a","ecosystem":"npm","version":"1.0.0"},"vulnerabilities":[{"id":" \t "}]}]}]}`},
		{name: "osv blank group ID", engine: bench.EngineOSVScanner, version: "1", data: `{"results":[{"groups":[{"ids":[""]}],"packages":[]}]}`},
		{name: "owned missing findings", engine: bench.EngineOwned, version: "1", format: DatabaseFormatOSVJSON, data: `{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1","advisories_ingested":1,"advisories_skipped":0}`},
		{name: "owned zero findings missing engine version", engine: bench.EngineOwned, version: "1", format: DatabaseFormatOSVJSON, data: `{"schema_version":"synapse-sca-benchmark-owned-wire-v2","advisories_ingested":1,"advisories_skipped":0,"findings":[]}`},
		{name: "owned missing advisories ingested", engine: bench.EngineOwned, version: "1", format: DatabaseFormatOSVJSON, data: `{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1","advisories_skipped":0,"findings":[]}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseEngine(test.engine, test.version, []byte(test.data), target, nil, test.format); err == nil {
				t.Fatal("parser accepted malformed complete-output shape")
			}
		})
	}
}

func TestParseOSVMatchesDistroEcosystemAndStructuralCatalogComponent(t *testing.T) {
	target := bench.Target{Components: []bench.Component{
		{PURL: "pkg:deb/debian/dpkg@1.18.25?arch=amd64&distro=debian-9"},
		{PURL: "pkg:npm/a@1.0.0?repository_url=https://catalog.example"},
	}}
	osv := []byte(`{"results":[{"packages":[{"package":{"name":"dpkg","os_package_name":"dpkg","ecosystem":"Debian:9","version":"1.18.25"},"vulnerabilities":[{"id":"CVE-2024-0001"}]}]}]}`)
	findings, err := parseOSV(osv, bench.Target{Components: target.Components[:1]})
	if err != nil || len(findings) != 1 || findings[0].Component.PURL != target.Components[0].PURL {
		t.Fatalf("distro OSV findings=%+v err=%v", findings, err)
	}
	grype := []byte(`{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0?repository_url=https://scanner.example","version":"1.0.0"}}]}`)
	findings, err = parseGrype("1", grype, bench.Target{Components: target.Components[1:]})
	if err != nil || len(findings) != 1 || findings[0].Component.PURL != target.Components[1].PURL {
		t.Fatalf("structural Grype findings=%+v err=%v", findings, err)
	}
}

func TestParsersIgnoreOnlyCompleteOutOfScopeFindings(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:rpm/sles/bash@5.1", Version: "5.1"}}}
	cases := []struct {
		name              string
		engine            bench.Engine
		outOfScope        string
		sameEcosystemMiss string
		malformed         string
		incomplete        string
	}{
		{
			name:              "grype",
			engine:            bench.EngineGrype,
			outOfScope:        `{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":"CVE-2026-0001"},"artifact":{"purl":"pkg:golang/stdlib@1.24.11","version":"go1.24.11"}}]}`,
			sameEcosystemMiss: `{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":"CVE-2026-0001"},"artifact":{"purl":"pkg:rpm/sles/coreutils@9.0","version":"9.0"}}]}`,
			malformed:         `{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":"CVE-2026-0001"},"artifact":{"purl":"pkg:golang/stdlib@%zz","version":"go1.24.11"}}]}`,
			incomplete:        `{"descriptor":{"name":"grype","version":"1"},"matches":[{"vulnerability":{"id":""},"artifact":{"purl":"pkg:golang/stdlib@1.24.11","version":"go1.24.11"}}]}`,
		},
		{
			name:              "trivy",
			engine:            bench.EngineTrivy,
			outOfScope:        `{"SchemaVersion":2,"Trivy":{"Version":"1"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgIdentifier":{"PURL":"pkg:golang/stdlib@1.24.11"},"InstalledVersion":"go1.24.11"}]}]}`,
			sameEcosystemMiss: `{"SchemaVersion":2,"Trivy":{"Version":"1"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgIdentifier":{"PURL":"pkg:rpm/sles/coreutils@9.0"},"InstalledVersion":"9.0"}]}]}`,
			malformed:         `{"SchemaVersion":2,"Trivy":{"Version":"1"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgIdentifier":{"PURL":"pkg:golang/stdlib@%zz"},"InstalledVersion":"go1.24.11"}]}]}`,
			incomplete:        `{"SchemaVersion":2,"Trivy":{"Version":"1"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"","PkgIdentifier":{"PURL":"pkg:golang/stdlib@1.24.11"},"InstalledVersion":"go1.24.11"}]}]}`,
		},
		{
			name:              "osv",
			engine:            bench.EngineOSVScanner,
			outOfScope:        `{"results":[{"packages":[{"package":{"name":"stdlib","ecosystem":"Go","version":"go1.24.11"},"vulnerabilities":[{"id":"CVE-2026-0001"}]}]}]}`,
			sameEcosystemMiss: `{"results":[{"packages":[{"package":{"name":"coreutils","os_package_name":"coreutils","ecosystem":"SUSE:15.6","version":"9.0"},"vulnerabilities":[{"id":"CVE-2026-0001"}]}]}]}`,
			malformed:         `{"results":[{"packages":[{"package":{"name":"stdlib","ecosystem":"Go","version":""},"vulnerabilities":[{"id":"CVE-2026-0001"}]}]}]}`,
			incomplete:        `{"results":[{"packages":[{"package":{"name":"stdlib","ecosystem":"Go","version":"go1.24.11"},"vulnerabilities":[{"id":""}]}]}]}`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			findings, err := parseEngine(test.engine, "1", []byte(test.outOfScope), target, nil, "")
			if err != nil || len(findings) != 0 {
				t.Fatalf("out-of-scope findings=%+v err=%v", findings, err)
			}
			for _, output := range []string{test.sameEcosystemMiss, test.malformed, test.incomplete} {
				if _, err := parseEngine(test.engine, "1", []byte(output), target, nil, ""); err == nil {
					t.Fatal("parser accepted an invalid out-of-scope finding")
				}
			}
		})
	}
}

func TestParseOwnedAllowsOnlyOVALSkippedAdvisories(t *testing.T) {
	target := bench.Target{Components: []bench.Component{{PURL: "pkg:rpm/sles/bash@5.1", Version: "5.1"}}}
	ovalWire := []byte(`{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1","advisories_ingested":1,"advisories_skipped":1,"findings":[]}`)
	if findings, err := parseOwned("1", ovalWire, target, DatabaseFormatOVAL); err != nil || len(findings) != 0 {
		t.Fatalf("OVAL skipped-advisory wire findings=%+v err=%v", findings, err)
	}
	for _, test := range []struct {
		name   string
		format DatabaseFormat
		data   []byte
	}{
		{name: "zero ingested", format: DatabaseFormatOVAL, data: []byte(`{"schema_version":"synapse-sca-benchmark-owned-wire-v2","engine_version":"1","advisories_ingested":0,"advisories_skipped":1,"findings":[]}`)},
		{name: "non OVAL skipped", format: DatabaseFormatOSVJSON, data: ovalWire},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseOwned("1", test.data, target, test.format); err == nil {
				t.Fatal("owned wire accepted invalid advisory-ingestion counts")
			}
		})
	}
}

func TestPURLIdentityStripsQueryAndFragment(t *testing.T) {
	ecosystem, name, version, ok := purlIdentity("pkg:npm/a@1.0.0?repository_url=https%3A%2F%2Fexample.test#fragment", "")
	if !ok || ecosystem != "npm" || name != "a" || version != "1.0.0" {
		t.Fatalf("purl identity = %q, %q, %q, %t", ecosystem, name, version, ok)
	}
}

func TestCaptureValidatesOSVVersionAndClassifiesAuthoritativeFailures(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	validProbeOutput := osvVersionProbeOutput(manifest.EngineVersion)
	validScan := ports.ToolResult{Stdout: []byte(`{"results":[]}`)}
	cases := []struct {
		name     string
		results  []ports.ToolResult
		errs     []error
		cancel   bool
		failure  FailureCode
		complete bool
	}{
		{name: "verified", results: []ports.ToolResult{{Stdout: validProbeOutput}, validScan}, complete: true},
		{name: "wrong version", results: []ports.ToolResult{{Stdout: osvVersionProbeOutput("9.9.9")}}, failure: FailureVersionMismatch},
		{name: "malformed output", results: []ports.ToolResult{{Stdout: []byte("osv-scanner 1.2.3\n")}}, failure: FailureVersionMismatch},
		{name: "timeout with runner error", results: []ports.ToolResult{{TimedOut: true}}, errs: []error{errors.New("deadline")}, failure: FailureTimeout},
		{name: "cancelled with runner error", results: []ports.ToolResult{{}}, errs: []error{errors.New("cancelled")}, cancel: true, failure: FailureCancelled},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := NewCapturer(&fakeRunner{results: test.results, errs: test.errs}).Capture(ctx, catalog, manifest)
			if err != nil {
				t.Fatal(err)
			}
			evidence := evidenceForTest(t, result)
			if test.complete {
				if result.Observation().State != bench.ObservationComplete || evidence.VersionProbe == nil || evidence.Scan == nil || evidence.VersionProbe.ParsedEngineVersion != manifest.EngineVersion {
					t.Fatalf("complete OSV evidence=%+v state=%q", evidence, result.Observation().State)
				}
				if !bytes.Equal(evidence.VersionProbe.Stdout, validProbeOutput) {
					t.Fatalf("version probe output was not retained: %q", evidence.VersionProbe.Stdout)
				}
				return
			}
			if result.Observation().State != bench.ObservationIncomplete || evidence.FailureCode != test.failure {
				t.Fatalf("state=%q failure=%q, want incomplete/%q", result.Observation().State, evidence.FailureCode, test.failure)
			}
			if evidence.VersionProbe == nil || evidence.Scan != nil || evidence.ParserStatus != ParserNotRun || result.Observation().RawOutputDigest != bench.SHA256Digest(result.EvidenceJSON()) {
				t.Fatalf("probe-failure evidence must retain only its version probe: %+v", evidence)
			}
			if test.name == "wrong version" && !bytes.Contains(evidence.VersionProbe.Stdout, []byte("9.9.9")) {
				t.Fatalf("failed version probe stdout was not retained: %q", evidence.VersionProbe.Stdout)
			}
		})
	}
}

func TestCaptureOSVVersionProbeNormalizationInputBoundary(t *testing.T) {
	for _, test := range []struct {
		name         string
		size         int
		validVersion bool
		complete     bool
		dispatches   int
	}{
		{name: "exact limit", size: int(bench.MaxJSONBytes), validVersion: true, complete: true, dispatches: 2},
		{name: "one byte over with valid prefix and no newline", size: int(bench.MaxJSONBytes) + 1, dispatches: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineOSVScanner)
			manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
			rebindFixtureProfile(t, &catalog, &manifest)

			prefix := []byte("osv-scanner version: " + manifest.EngineVersion)
			if test.validVersion {
				prefix = append(prefix, '\n')
			}
			if len(prefix) > test.size {
				t.Fatalf("probe prefix length %d exceeds requested size %d", len(prefix), test.size)
			}
			probeOutput := append(prefix, bytes.Repeat([]byte("x"), test.size-len(prefix))...)
			runner := &fakeRunner{results: []ports.ToolResult{
				{Stdout: probeOutput},
				{Stdout: []byte(`{"results":[]}`)},
			}}
			result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
			if err != nil {
				t.Fatal(err)
			}
			evidence := evidenceForTest(t, result)
			if runner.calls != test.dispatches || len(runner.specs) != test.dispatches {
				t.Fatalf("dispatches = calls %d specs %#v, want %d", runner.calls, runner.specs, test.dispatches)
			}
			if test.complete {
				if result.Observation().State != bench.ObservationComplete || evidence.FailureCode != FailureNone || evidence.ParserStatus != ParserOK || evidence.VersionProbe == nil || evidence.VersionProbe.ParsedEngineVersion != manifest.EngineVersion || evidence.Scan == nil || len(evidence.VersionProbe.Stdout) != int(bench.MaxJSONBytes) {
					t.Fatalf("exact-limit OSV probe result=%+v evidence=%+v", result.Observation(), evidence)
				}
				return
			}
			if result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.VersionProbe == nil || evidence.VersionProbe.ParsedEngineVersion != "" || evidence.Scan != nil || len(evidence.VersionProbe.Stdout) != int(bench.MaxJSONBytes)+1 || evidence.VersionProbe.Stdout[len(evidence.VersionProbe.Stdout)-1] == '\n' {
				t.Fatalf("oversized OSV probe result=%+v evidence=%+v", result.Observation(), evidence)
			}
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := WriteBundle(bundle, result); err != nil {
				t.Fatalf("WriteBundle did not publish replayable oversized OSV probe evidence: %v", err)
			}
			if err := ValidateBundle(bundle); err != nil {
				t.Fatalf("ValidateBundle rejected replayable oversized OSV probe evidence: %v", err)
			}
		})
	}
}

func TestCaptureOSVScanNormalizationInputTooLargeRetainsVerifiedProbe(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	scanOutput := append([]byte(`{"results":[]}`), bytes.Repeat([]byte("x"), int(bench.MaxJSONBytes)+1-len(`{"results":[]}`))...)
	runner := &fakeRunner{results: []ports.ToolResult{
		{Stdout: osvVersionProbeOutput(manifest.EngineVersion)},
		{Stdout: scanOutput},
	}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if runner.calls != 2 || result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.VersionProbe == nil || evidence.VersionProbe.ParsedEngineVersion != manifest.EngineVersion || evidence.Scan == nil || evidence.Scan.ParsedEngineVersion != "" || len(evidence.Scan.Stdout) != int(bench.MaxJSONBytes)+1 {
		t.Fatalf("oversized OSV scan result=%+v evidence=%+v", result.Observation(), evidence)
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("WriteBundle did not preserve oversized OSV scan evidence: %v", err)
	}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle rejected oversized OSV scan evidence: %v", err)
	}
}

func TestCaptureTruncatedOversizedOSVProbeUsesNormalizationInputFailure(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	probeOutput := bytes.Repeat([]byte("x"), int(bench.MaxJSONBytes)+1)
	runner := &fakeRunner{results: []ports.ToolResult{
		{Stdout: probeOutput, Truncated: true},
		{Stdout: []byte(`{"results":[]}`)},
	}}

	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if runner.calls != 1 || len(runner.specs) != 1 || len(runner.specs[0].Args) != 1 || runner.specs[0].Args[0] != "--version" {
		t.Fatalf("OSV probe dispatched a scan: calls=%d specs=%#v", runner.calls, runner.specs)
	}
	if evidence.VersionProbe == nil {
		t.Fatal("truncated oversized OSV probe omitted probe evidence")
	}
	if result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.VersionProbe.ParsedEngineVersion != "" || !evidence.VersionProbe.Truncated || evidence.Scan != nil || len(evidence.VersionProbe.Stdout) != int(bench.MaxJSONBytes)+1 {
		t.Fatalf("truncated oversized OSV probe state=%q findings=%d failure=%q parser=%q version=%q truncated=%t scan=%t stdout=%d", result.Observation().State, len(result.Observation().Findings), evidence.FailureCode, evidence.ParserStatus, evidence.VersionProbe.ParsedEngineVersion, evidence.VersionProbe.Truncated, evidence.Scan != nil, len(evidence.VersionProbe.Stdout))
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("WriteBundle did not publish truncated oversized OSV probe evidence: %v", err)
	}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle rejected truncated oversized OSV probe evidence: %v", err)
	}
}

func TestOSVVersionProbeNormalizationInputStateRejectsForgeries(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	probePrefix := []byte("osv-scanner version: " + manifest.EngineVersion)
	oversizedProbe := append(probePrefix, bytes.Repeat([]byte("x"), int(bench.MaxJSONBytes)+1-len(probePrefix))...)
	runner := &fakeRunner{results: []ports.ToolResult{{Stdout: oversizedProbe}, {Stdout: []byte(`{"results":[]}`)}}}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	observation := result.Observation()
	evidence := evidenceForTest(t, result)
	if evidence.VersionProbe == nil || evidence.Scan != nil {
		t.Fatalf("oversized OSV probe evidence=%+v", evidence)
	}

	normalResult, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{
		{Stdout: osvVersionProbeOutput(manifest.EngineVersion)},
		{Stdout: []byte(`{"results":[]}`)},
	}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	normalEvidence := evidenceForTest(t, normalResult)
	if normalEvidence.Scan == nil {
		t.Fatal("normal OSV capture omitted scan evidence")
	}

	exactProbe := append([]byte("osv-scanner version: "+manifest.EngineVersion+"\n"), bytes.Repeat([]byte("x"), int(bench.MaxJSONBytes)-len("osv-scanner version: "+manifest.EngineVersion+"\n"))...)
	cases := []struct {
		name   string
		mutate func(*bench.Observation, *Evidence)
	}{
		{name: "probe and scan", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan = cloneProcessEvidence(normalEvidence.Scan)
		}},
		{name: "non OSV probe", mutate: func(observation *bench.Observation, evidence *Evidence) {
			observation.Engine = bench.EngineGrype
			evidence.Engine = bench.EngineGrype
		}},
		{name: "probe at limit", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.VersionProbe.Stdout = exactProbe
		}},
		{name: "parsed probe version", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.VersionProbe.ParsedEngineVersion = manifest.EngineVersion
		}},
		{name: "parser ran", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.ParserStatus = ParserOK
		}},
		{name: "wrong failure code", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.FailureCode = FailureParser
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			forgedObservation := cloneObservation(observation)
			forgedEvidence := cloneEvidence(evidence)
			test.mutate(&forgedObservation, &forgedEvidence)
			encoded, err := canonicalJSON(forgedEvidence)
			if err != nil {
				t.Fatal(err)
			}
			forgedObservation.RawOutputDigest = rawOutputDigest(encoded)
			if _, err := validateEvidenceObservation(forgedObservation, encoded); err == nil {
				t.Fatalf("state machine accepted forged oversized OSV probe evidence: %+v", forgedEvidence)
			}
			if err := replayPublication(result, forgedEvidence); err == nil {
				t.Fatalf("replay accepted forged oversized OSV probe evidence: %+v", forgedEvidence)
			}
		})
	}
}

func TestWriteBundleRequiresReplayableSuccessfulOSVProbe(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	result, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{
		{Stdout: osvVersionProbeOutput("1.2.3")},
		{Stdout: []byte(`{"results":[]}`)},
	}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "valid"), result); err != nil {
		t.Fatalf("WriteBundle rejected valid OSV probe: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*CaptureResult)
	}{
		{name: "missing", mutate: func(result *CaptureResult) {
			result.evidence.VersionProbe = nil
			result.binding.evidence.VersionProbe = nil
		}},
		{name: "altered output", mutate: func(result *CaptureResult) {
			result.evidence.VersionProbe.Stdout = []byte("osv-scanner forged\n")
			result.binding.evidence.VersionProbe.Stdout = []byte("osv-scanner forged\n")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := result
			forged.evidence = cloneEvidence(result.evidence)
			forged.binding.evidence = cloneEvidence(result.binding.evidence)
			test.mutate(&forged)
			encoded, err := canonicalJSON(forged.evidence)
			if err != nil {
				t.Fatal(err)
			}
			forged.evidenceJSON = encoded
			forged.binding.evidenceJSON = append([]byte(nil), encoded...)
			forged.observation.RawOutputDigest = bench.SHA256Digest(encoded)
			forged.binding.observation.RawOutputDigest = bench.SHA256Digest(encoded)
			if err := WriteBundle(filepath.Join(t.TempDir(), "forged"), forged); err == nil {
				t.Fatal("WriteBundle accepted an unreplayable successful OSV probe")
			}
		})
	}
}

func TestWriteBundleRetainsMalformedOSVProbeAsIncomplete(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	result, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{{Stdout: []byte("osv-scanner\n")}}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if result.Observation().State != bench.ObservationIncomplete || evidence.FailureCode != FailureVersionMismatch || evidence.Scan != nil {
		t.Fatalf("malformed probe state=%q evidence=%+v", result.Observation().State, evidence)
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err != nil {
		t.Fatalf("WriteBundle rejected retained malformed OSV probe evidence: %v", err)
	}
}

func TestRedactOutputHandlesJSONEscapedWindowsPaths(t *testing.T) {
	path := `C:\bench\input.json`
	escaped, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	stdout := append([]byte(`{"source":{"path":`), escaped...)
	stdout = append(stdout, []byte(`}}`)...)
	redacted, _, changed := redactOutput(stdout, nil, []string{path})
	if !changed || bytes.Contains(redacted, escaped) || bytes.Contains(redacted, []byte(path)) {
		t.Fatalf("JSON-escaped path remained in evidence: %s", redacted)
	}
}

func TestWriteBundleBindsExactCanonicalProfileBytes(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	result.profileJSON = bytes.Replace(result.profileJSON, []byte(`"no_network":true`), []byte(`"no_network":false`), 1)
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err == nil {
		t.Fatal("WriteBundle accepted a profile that differs from its immutable binding")
	}
}

func TestWriteBundleRejectsEnvironmentArtifactBindingTampering(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, result *CaptureResult)
	}{
		{
			name: "descriptor identity",
			mutate: func(t *testing.T, result *CaptureResult) {
				descriptor := manifest.Environment
				descriptor.ID = "forged"
				data, err := canonicalJSON(descriptor)
				if err != nil {
					t.Fatal(err)
				}
				result.environmentJSON = data
				result.binding.environmentJSON = append([]byte(nil), data...)
			},
		},
		{
			name: "attestation digest",
			mutate: func(_ *testing.T, result *CaptureResult) {
				data := []byte("forged exact attestation")
				result.environmentAttestationJSON = data
				result.binding.environmentAttestationJSON = append([]byte(nil), data...)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := result
			forged.environmentJSON = append([]byte(nil), result.environmentJSON...)
			forged.binding.environmentJSON = append([]byte(nil), result.binding.environmentJSON...)
			forged.environmentAttestationJSON = append([]byte(nil), result.environmentAttestationJSON...)
			forged.binding.environmentAttestationJSON = append([]byte(nil), result.binding.environmentAttestationJSON...)
			test.mutate(t, &forged)
			if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), forged); err == nil {
				t.Fatal("WriteBundle accepted a forged environment artifact binding")
			}
		})
	}
}

func TestWriteBundleBindsEvidenceMetadataInRawOutputDigest(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	result.evidence.Scan.Redacted = !result.evidence.Scan.Redacted
	result.evidenceJSON, err = canonicalJSON(result.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err == nil {
		t.Fatal("WriteBundle accepted evidence metadata not bound to the capture")
	}
}

func TestWriteBundleRejectsProbeFailureClaimingScanDispatch(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineOSVScanner)
	result, err := NewCapturer(&fakeRunner{results: []ports.ToolResult{{Stdout: []byte("osv-scanner wrong\n")}}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "valid-probe-failure"), result); err != nil {
		t.Fatalf("WriteBundle rejected valid probe-failure evidence: %v", err)
	}
	result.evidence.Scan = &ProcessEvidence{ExitKnown: true, Stdout: []byte{}, Stderr: []byte{}}
	result.evidenceJSON, err = canonicalJSON(result.evidence)
	if err != nil {
		t.Fatal(err)
	}
	result.observation.RawOutputDigest = bench.SHA256Digest(result.evidenceJSON)
	if err := WriteBundle(filepath.Join(t.TempDir(), "contradictory-probe-failure"), result); err == nil {
		t.Fatal("WriteBundle accepted a probe failure that claims a scan record")
	}
}

func TestEvidenceStateMachineRejectsContradictoryProcessClaims(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	baseObservation := result.Observation()
	baseEvidence := evidenceForTest(t, result)
	cases := []struct {
		name   string
		mutate func(*bench.Observation, *Evidence)
	}{
		{name: "non OSV probe", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.VersionProbe = &ProcessEvidence{ExitKnown: true, Stdout: []byte{}, Stderr: []byte{}}
		}},
		{name: "timeout cannot parse", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan.TimedOut = true
		}},
		{name: "runner error cannot know exit", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan.RunnerError = true
		}},
		{name: "unknown failure code", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.FailureCode = FailureCode("made_up")
		}},
		{name: "timeout false lie", mutate: func(observation *bench.Observation, evidence *Evidence) {
			observation.State = bench.ObservationIncomplete
			evidence.ParserStatus = ParserNotRun
			evidence.FailureCode = FailureTimeout
		}},
		{name: "incomplete findings", mutate: func(observation *bench.Observation, evidence *Evidence) {
			observation.State = bench.ObservationIncomplete
			observation.Findings = []bench.Finding{{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-0001"}}
			evidence.ParserStatus = ParserFailed
			evidence.FailureCode = FailureParser
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := cloneObservation(baseObservation)
			evidence := cloneEvidence(baseEvidence)
			test.mutate(&observation, &evidence)
			encoded, err := canonicalJSON(evidence)
			if err != nil {
				t.Fatal(err)
			}
			observation.RawOutputDigest = bench.SHA256Digest(encoded)
			if _, err := validateEvidenceObservation(observation, encoded); err == nil {
				t.Fatal("state machine accepted a contradictory evidence claim")
			}
		})
	}
}

func TestWriteBundleReplaysCompleteFindingsAgainstImmutableTarget(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	result.observation.Findings = nil
	result.binding.observation.Findings = nil
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err == nil {
		t.Fatal("WriteBundle accepted complete findings that do not replay from redacted output")
	}
}

func TestWriteBundleRejectsIdentityAndEmptyOutputFindingTampering(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	captureEmpty := func(t *testing.T) CaptureResult {
		t.Helper()
		result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	t.Run("engine version", func(t *testing.T) {
		result := captureEmpty(t)
		result.observation.EngineVersion = "forged"
		result.binding.observation.EngineVersion = "forged"
		if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err == nil {
			t.Fatal("WriteBundle accepted a forged engine version")
		}
	})
	t.Run("empty Grype evidence finding", func(t *testing.T) {
		result := captureEmpty(t)
		forged := []bench.Finding{{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-0001"}}
		result.observation.Findings = forged
		result.binding.observation.Findings = append([]bench.Finding(nil), forged...)
		if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err == nil {
			t.Fatal("WriteBundle accepted a finding absent from empty Grype evidence")
		}
	})
}

func TestCaptureObservationTooLargeIsIncompleteAndReplayable(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes)
	rebindFixtureProfile(t, &catalog, &manifest)
	var output strings.Builder
	output.Grow(7 << 20)
	output.WriteString(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[`)
	advisoryPrefix := strings.Repeat("<", 100)
	for index := 0; index < 30000; index++ {
		if index != 0 {
			output.WriteByte(',')
		}
		fmt.Fprintf(&output, `{"vulnerability":{"id":"%s%06d"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}`, advisoryPrefix, index)
	}
	output.WriteString(`]}`)
	if output.Len() > int(bench.MaxJSONBytes) {
		t.Fatalf("scanner output is %d bytes, exceeding normalization input limit", output.Len())
	}
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(output.String())}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureObservationTooLarge || evidence.ParserStatus != ParserOK {
		t.Fatalf("oversized observation result=%+v evidence=%+v", result.Observation(), evidence)
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("WriteBundle did not replay a valid oversized observation claim: %v", err)
	}
	encoded, err := os.ReadFile(filepath.Join(bundle, "observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := bench.DecodeObservationSet(bytes.NewReader(encoded))
	if err != nil || len(set.Observations) != 1 || set.Observations[0].State != bench.ObservationIncomplete || len(set.Observations[0].Findings) != 0 {
		t.Fatalf("oversized bundle is not a bounded decoder-valid incomplete observation: set=%+v err=%v", set, err)
	}
}

func TestCaptureNormalizationInputLimitAllowsExactAndJustUnderLimit(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
	}{
		{name: "exact limit", size: int(bench.MaxJSONBytes)},
		{name: "just under limit", size: int(bench.MaxJSONBytes) - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := testFixture(t, bench.EngineGrype)
			manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes)
			rebindFixtureProfile(t, &catalog, &manifest)
			result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: grypeOutputAtLength(t, test.size)}}).Capture(context.Background(), catalog, manifest)
			if err != nil {
				t.Fatal(err)
			}
			evidence := evidenceForTest(t, result)
			if result.Observation().State != bench.ObservationComplete || evidence.FailureCode != FailureNone || evidence.ParserStatus != ParserOK || evidence.Scan == nil || evidence.Scan.ParsedEngineVersion != manifest.EngineVersion || len(evidence.Scan.Stdout) != test.size {
				t.Fatalf("exact-or-under-limit result=%+v evidence=%+v", result.Observation(), evidence)
			}
		})
	}
}

func TestCaptureNormalizationInputTooLargeIsIncompleteAndReplayable(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	output := grypeOutputAtLength(t, int(bench.MaxJSONBytes)+1)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: output}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.Scan == nil || evidence.Scan.ParsedEngineVersion != "" || evidence.Scan.Truncated || !bytes.Equal(evidence.Scan.Stdout, output) {
		t.Fatalf("normalization-input-too-large result=%+v evidence=%+v", result.Observation(), evidence)
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("WriteBundle did not publish replayable normalization-input-too-large evidence: %v", err)
	}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle rejected replayable normalization-input-too-large evidence: %v", err)
	}
}

func TestCaptureTruncatedOversizedScanUsesNormalizationInputFailure(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	output := grypeOutputAtLength(t, int(bench.MaxJSONBytes)+1)
	runner := &fakeRunner{result: ports.ToolResult{Stdout: output, Truncated: true}}

	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if evidence.Scan == nil {
		t.Fatal("truncated oversized scan omitted scan evidence")
	}
	if runner.calls != 1 || result.Observation().State != bench.ObservationIncomplete || len(result.Observation().Findings) != 0 || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.Scan.ParsedEngineVersion != "" || !evidence.Scan.Truncated || !bytes.Equal(evidence.Scan.Stdout, output) {
		t.Fatalf("truncated oversized scan calls=%d state=%q findings=%d failure=%q parser=%q version=%q truncated=%t stdout=%d", runner.calls, result.Observation().State, len(result.Observation().Findings), evidence.FailureCode, evidence.ParserStatus, evidence.Scan.ParsedEngineVersion, evidence.Scan.Truncated, len(evidence.Scan.Stdout))
	}
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := WriteBundle(bundle, result); err != nil {
		t.Fatalf("WriteBundle did not publish truncated oversized scan evidence: %v", err)
	}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("ValidateBundle rejected truncated oversized scan evidence: %v", err)
	}

	forgedEvidence := cloneEvidence(evidence)
	forgedEvidence.FailureCode = FailureOutputTruncated
	forgedEvidenceJSON, err := canonicalJSON(forgedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	forgedObservation := result.Observation()
	forgedObservation.RawOutputDigest = rawOutputDigest(forgedEvidenceJSON)
	if _, err := validateEvidenceObservation(forgedObservation, forgedEvidenceJSON); err == nil {
		t.Fatal("state machine accepted a truncated failure code for oversized normalization input")
	}
	if err := replayPublication(result, forgedEvidence); err == nil {
		t.Fatal("replay accepted a truncated failure code for oversized normalization input")
	}
}

func TestCaptureNormalizationInputTooLargePreservesPostflightIntegrityFailure(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	runner := &fakeRunner{
		result: ports.ToolResult{Stdout: grypeOutputAtLength(t, int(bench.MaxJSONBytes)+1)},
		mutateSpec: func(spec ports.ToolSpec) {
			if len(spec.ReadOnlyPaths) > 1 {
				_ = os.WriteFile(spec.ReadOnlyPaths[1], []byte("changed"), 0o600)
			}
		},
	}
	result, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForTest(t, result)
	if result.Observation().State != bench.ObservationIncomplete || evidence.FailureCode != FailureNormalizationInputTooLarge || evidence.ParserStatus != ParserNotRun || evidence.InputIntegrity != InputsMutated {
		t.Fatalf("normalization input boundary did not retain postflight integrity failure: result=%+v evidence=%+v", result.Observation(), evidence)
	}
	if err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), result); err != nil {
		t.Fatalf("WriteBundle rejected a postflight-mutated normalization boundary claim: %v", err)
	}
}

func TestEvidenceStateMachineRejectsNormalizationInputLimitForgeries(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes) + 1
	rebindFixtureProfile(t, &catalog, &manifest)
	tooLargeResult, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: grypeOutputAtLength(t, int(bench.MaxJSONBytes)+1)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	tooLargeObservation := tooLargeResult.Observation()
	tooLargeEvidence := evidenceForTest(t, tooLargeResult)
	if tooLargeEvidence.Scan == nil {
		t.Fatal("oversized capture omitted scan evidence")
	}

	normalCatalog, normalManifest := testFixture(t, bench.EngineGrype)
	normalResult, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), normalCatalog, normalManifest)
	if err != nil {
		t.Fatal(err)
	}
	normalObservation := normalResult.Observation()
	normalEvidence := evidenceForTest(t, normalResult)

	cases := []struct {
		name   string
		base   Evidence
		mutate func(*bench.Observation, *Evidence)
	}{
		{name: "dedicated code at limit", base: tooLargeEvidence, mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan.Stdout = grypeOutputAtLength(t, int(bench.MaxJSONBytes))
			evidence.FailureCode = FailureNormalizationInputTooLarge
		}},
		{name: "oversized parser ok", base: tooLargeEvidence, mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.ParserStatus = ParserOK
		}},
		{name: "oversized parser failed", base: tooLargeEvidence, mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.ParserStatus = ParserFailed
		}},
		{name: "oversized wrong code", base: tooLargeEvidence, mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.FailureCode = FailureParser
		}},
		{name: "oversized parsed version", base: tooLargeEvidence, mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan.ParsedEngineVersion = "1.2.3"
		}},
		{name: "normal successful scan not run", base: normalEvidence, mutate: func(observation *bench.Observation, evidence *Evidence) {
			observation.State = bench.ObservationIncomplete
			observation.Findings = nil
			evidence.ParserStatus = ParserNotRun
			evidence.Scan.ParsedEngineVersion = ""
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := cloneObservation(tooLargeObservation)
			if test.name == "normal successful scan not run" {
				observation = cloneObservation(normalObservation)
			}
			evidence := cloneEvidence(test.base)
			test.mutate(&observation, &evidence)
			encoded, err := canonicalJSON(evidence)
			if err != nil {
				t.Fatal(err)
			}
			observation.RawOutputDigest = rawOutputDigest(encoded)
			if _, err := validateEvidenceObservation(observation, encoded); err == nil {
				t.Fatalf("state machine accepted forged normalization-input claim: %+v", evidence)
			}
		})
	}
}

func BenchmarkCaptureNearNormalizationInputLimit(b *testing.B) {
	catalog, manifest := testFixture(b, bench.EngineGrype)
	manifest.Limits.MaxOutputBytes = int(bench.MaxJSONBytes)
	rebindFixtureProfile(b, &catalog, &manifest)
	payload := grypeOutputWithManyMatchesAtLength(b, int(bench.MaxJSONBytes))
	capturer := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: payload}})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := capturer.Capture(context.Background(), catalog, manifest)
		if err != nil {
			b.Fatal(err)
		}
		if result.Observation().State != bench.ObservationComplete || len(result.Observation().Findings) != 1 {
			b.Fatalf("near-limit capture result=%+v", result.Observation())
		}
	}
}

func grypeOutputAtLength(t testing.TB, length int) []byte {
	t.Helper()
	const output = `{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`
	if length < len(output) {
		t.Fatalf("requested Grype output length %d is below valid JSON length %d", length, len(output))
	}
	data := make([]byte, length)
	copy(data, output)
	for index := len(output); index < len(data); index++ {
		data[index] = ' '
	}
	return data
}

func grypeOutputWithManyMatchesAtLength(t testing.TB, length int) []byte {
	t.Helper()
	const (
		prefix = `{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[`
		match  = `{"vulnerability":{"id":"CVE-2024-0001"},"artifact":{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}}`
		suffix = `]}`
	)
	var output bytes.Buffer
	output.Grow(length)
	output.WriteString(prefix)
	matches := 0
	for {
		matchLength := len(match)
		if matches != 0 {
			matchLength++
		}
		if output.Len()+matchLength+len(suffix) > length {
			break
		}
		if matches != 0 {
			output.WriteByte(',')
		}
		output.WriteString(match)
		matches++
	}
	if matches < 2 {
		t.Fatalf("requested near-limit payload has only %d findings", matches)
	}
	output.WriteString(suffix)
	output.WriteString(strings.Repeat(" ", length-output.Len()))
	return output.Bytes()
}

func TestObservationSizeLimitCountsEscapedAndLongComponentContent(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	result, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		component bench.Component
		advisory  string
	}{
		{name: "escaped advisory", component: catalog.Targets[0].Components[0], advisory: strings.Repeat(`"`, int(bench.MaxJSONBytes/2)+1)},
		{name: "long component", component: bench.Component{PURL: "pkg:npm/" + strings.Repeat("a", int(bench.MaxJSONBytes)) + "@1.0.0", Version: "1.0.0"}, advisory: "CVE-2024-0001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := result.Observation()
			candidate.Findings = []bench.Finding{{Component: test.component, AdvisoryID: test.advisory}}
			over, err := observationExceedsLimit(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if !over {
				t.Fatal("finding content did not count against the observation JSON limit")
			}
		})
	}
}

func rebindFixtureProfile(t testing.TB, catalog *bench.Catalog, manifest *CaptureManifest) {
	t.Helper()
	profile, _, _, err := buildProfile(manifest.Engine, manifest.Database.Format, manifest.Limits)
	if err != nil {
		t.Fatal(err)
	}
	profileJSON, err := canonicalJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	for index := range catalog.Pins {
		if catalog.Pins[index].Reference == manifest.ProfilePinReference {
			catalog.Pins[index].Digest = bench.SHA256Digest(profileJSON)
			break
		}
	}
	catalogDigest, err := bench.DigestCatalog(*catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = catalogDigest
}

func rebindFixtureDatabase(t *testing.T, catalog *bench.Catalog, manifest *CaptureManifest) {
	t.Helper()
	digest, err := HashTree(manifest.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range catalog.Pins {
		if catalog.Pins[index].Reference == manifest.Database.Reference {
			catalog.Pins[index].Digest = digest
			break
		}
	}
	catalogDigest, err := bench.DigestCatalog(*catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = catalogDigest
}

func rebindFixtureCatalog(t *testing.T, catalog *bench.Catalog, manifest *CaptureManifest) {
	t.Helper()
	catalogDigest, err := bench.DigestCatalog(*catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = catalogDigest
}

func TestCapabilityComponentKeyAcceptsQualifiedPercentEncodedRPMVersion(t *testing.T) {
	component := bench.Component{PURL: "pkg:rpm/sles/bash@1%3A2.0?arch=x86_64&distro=sles-15.6", Version: "1:2.0"}
	key, err := capabilityComponentKey(component)
	if err != nil {
		t.Fatal(err)
	}
	if key.Ecosystem != "rpm" || key.Package != "sles/bash" || key.Version != "1:2.0" {
		t.Fatalf("capability component key = %+v", key)
	}
}

func TestCapabilityComponentKeyRejectsMissingEmbeddedVersion(t *testing.T) {
	_, err := capabilityComponentKey(bench.Component{PURL: "pkg:rpm/sles/bash@", Version: "1:2.0"})
	if err == nil {
		t.Fatal("capability component key accepted a missing PURL version")
	}
}

func TestCaptureCapabilityIgnoresUnrelatedGoComponentsAndPublishesZeroDispatchBundle(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	result, err := CaptureCapability(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	observation := result.Observation()
	if observation.State != bench.ObservationUnsupported || observation.CapabilityKind != bench.CapabilityKindOSVScannerSUSERPM || observation.CapabilityDigest == "" || len(observation.Findings) != 0 {
		t.Fatalf("capability observation = %+v", observation)
	}
	var evidence Evidence
	if err := json.Unmarshal(result.EvidenceJSON(), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.VersionProbe != nil || evidence.Scan != nil || evidence.ParserStatus != ParserNotRun || evidence.InputIntegrity != InputsVerified || evidence.FailureCode != FailureNone || evidence.Capability == nil {
		t.Fatalf("capability evidence = %+v", evidence)
	}
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if err := WriteBundle(first, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(second, result); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle(first); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct {
		name string
		data []byte
	}{
		{name: "environment.json", data: result.environmentJSON},
		{name: "environment-attestation.json", data: result.environmentAttestationJSON},
	} {
		data, err := os.ReadFile(filepath.Join(first, artifact.name))
		if err != nil || !bytes.Equal(data, artifact.data) {
			t.Fatalf("published %s does not retain exact bytes: data=%q err=%v", artifact.name, data, err)
		}
	}
	for _, name := range []string{"observation.json", "evidence.json", "profile.json", "environment.json", "environment-attestation.json", "capability-statement.json", capabilitySourceBundleName(0), capabilitySourceBundleName(1)} {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("publication is not deterministic for %q", name)
		}
	}
}

func TestCapabilityCaptureRejectsMalformedAndDuplicateSLESRPMComponents(t *testing.T) {
	cases := []struct {
		name string
		sbom []byte
	}{
		{
			name: "malformed",
			sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@1%3A5.1?arch=x86_64&distro=sles-15.6"},{"name":"coreutils","version":"9.0","purl":"pkg:rpm/sles/coreutils@9.0"},{"name":"broken-bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@%zz"}]}`),
		},
		{
			name: "empty embedded version",
			sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@"},{"name":"coreutils","version":"9.0","purl":"pkg:rpm/sles/coreutils@9.0"}]}`),
		},
		{
			name: "duplicate",
			sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@1%3A5.1?arch=x86_64&distro=sles-15.6"},{"name":"coreutils","version":"9.0","purl":"pkg:rpm/sles/coreutils@9.0"},{"name":"duplicate-bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@1%3A5.1?arch=x86_64&distro=sles-15.6"}]}`),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := capabilityFixture(t)
			rebindCapabilityFixtureSBOM(t, &catalog, &manifest, test.sbom)
			runner := &fakeRunner{}
			if _, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest); err == nil {
				t.Fatal("capability capture accepted an invalid in-scope SLES RPM component")
			}
			if runner.calls != 0 {
				t.Fatalf("invalid SLES RPM component dispatched %d tool calls", runner.calls)
			}
		})
	}
}

func TestCapabilityCaptureRejectsInvalidStatementsBeforeDispatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CapabilityStatement)
	}{
		{name: "component omission", mutate: func(statement *CapabilityStatement) { statement.Components = statement.Components[:1] }},
		{name: "component extra", mutate: func(statement *CapabilityStatement) {
			statement.Components = append(statement.Components, bench.Component{PURL: "pkg:rpm/sles/zlib@1.0", Version: "1.0"})
		}},
		{name: "component duplicate", mutate: func(statement *CapabilityStatement) {
			statement.Components = append(statement.Components, statement.Components[1])
		}},
		{name: "component duplicate replacing omitted", mutate: func(statement *CapabilityStatement) {
			statement.Components[1] = statement.Components[0]
		}},
		{name: "mixed PURL type", mutate: func(statement *CapabilityStatement) {
			statement.Components[0] = bench.Component{PURL: "pkg:npm/bash@5.1", Version: "5.1"}
		}},
		{name: "non SUSE RPM", mutate: func(statement *CapabilityStatement) {
			statement.Components[0] = bench.Component{PURL: "pkg:rpm/fedora/bash@5.1", Version: "5.1"}
		}},
		{name: "malformed PURL", mutate: func(statement *CapabilityStatement) {
			statement.Components[0] = bench.Component{PURL: "pkg:rpm/sles/@5.1", Version: "5.1"}
		}},
		{name: "catalog pin mismatch", mutate: func(statement *CapabilityStatement) { statement.CatalogDigest = digestByte('f') }},
		{name: "target pin mismatch", mutate: func(statement *CapabilityStatement) { statement.TargetDigest = digestByte('f') }},
		{name: "binary pin mismatch", mutate: func(statement *CapabilityStatement) { statement.EngineBinaryDigest = digestByte('f') }},
		{name: "database pin mismatch", mutate: func(statement *CapabilityStatement) { statement.DatabaseDigest = digestByte('f') }},
		{name: "environment pin mismatch", mutate: func(statement *CapabilityStatement) { statement.EnvironmentDigest = digestByte('f') }},
		{name: "profile pin mismatch", mutate: func(statement *CapabilityStatement) { statement.ConfigDigest = digestByte('f') }},
		{name: "source pin mismatch", mutate: func(statement *CapabilityStatement) { statement.Sources[0].Digest = digestByte('f') }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := capabilityFixture(t)
			rewriteCapabilityStatement(t, &manifest, test.mutate)
			runner := &fakeRunner{}
			if _, err := NewCapturer(runner).Capture(context.Background(), catalog, manifest); err == nil {
				t.Fatal("capability manifest was accepted for external dispatch")
			}
			if runner.calls != 0 {
				t.Fatalf("invalid capability dispatched %d tool calls", runner.calls)
			}
		})
	}
}

func TestCapabilityEvidenceRejectsFindingsAndProcessClaims(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	result, err := CaptureCapability(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	baseObservation := result.Observation()
	baseEvidence := evidenceForTest(t, result)
	cases := []struct {
		name   string
		mutate func(*bench.Observation, *Evidence)
	}{
		{name: "findings", mutate: func(observation *bench.Observation, _ *Evidence) {
			observation.Findings = []bench.Finding{{Component: bench.Component{PURL: "pkg:rpm/sles/bash@5.1", Version: "5.1"}, AdvisoryID: "CVE-2024-0001"}}
		}},
		{name: "version probe", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.VersionProbe = &ProcessEvidence{ExitKnown: true, Stdout: []byte{}, Stderr: []byte{}}
		}},
		{name: "scan", mutate: func(_ *bench.Observation, evidence *Evidence) {
			evidence.Scan = &ProcessEvidence{ExitKnown: true, Stdout: []byte{}, Stderr: []byte{}}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := cloneObservation(baseObservation)
			evidence := cloneEvidence(baseEvidence)
			test.mutate(&observation, &evidence)
			encoded, err := canonicalJSON(evidence)
			if err != nil {
				t.Fatal(err)
			}
			observation.RawOutputDigest = bench.SHA256Digest(encoded)
			if _, err := validateEvidenceObservation(observation, encoded); err == nil {
				t.Fatal("capability evidence accepted a prohibited claim")
			}
		})
	}
}

func TestCapabilityPublicationRejectsTamperingAndCallerMutation(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	result, err := CaptureCapability(catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	statement := result.CapabilityStatementJSON()
	statement[0] ^= 1
	if err := WriteBundle(filepath.Join(t.TempDir(), "accessor-copy"), result); err != nil {
		t.Fatalf("caller mutation of statement copy changed publication: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*CaptureResult)
	}{
		{name: "statement", mutate: func(result *CaptureResult) { result.capabilityStatementJSON[0] ^= 1 }},
		{name: "evidence", mutate: func(result *CaptureResult) { result.evidenceJSON[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, manifest := capabilityFixture(t)
			forged, err := CaptureCapability(catalog, manifest)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&forged)
			if err := WriteBundle(filepath.Join(t.TempDir(), "forged"), forged); err == nil {
				t.Fatal("WriteBundle accepted tampered capability evidence")
			}
		})
	}

	for _, name := range []string{"capability-statement.json", "evidence.json", "capability-source-00", "environment.json", "environment-attestation.json"} {
		t.Run("published "+name, func(t *testing.T) {
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := WriteBundle(bundle, result); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(bundle, name))
			if err != nil {
				t.Fatal(err)
			}
			data[0] ^= 1
			if err := os.WriteFile(filepath.Join(bundle, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted tampered %s", name)
			}
		})
	}
}

func testFixture(t testing.TB, engine bench.Engine) (bench.Catalog, CaptureManifest) {
	t.Helper()
	root := t.TempDir()
	binary := writeFile(t, root, "engine", []byte("scanner binary"))
	sbomPath := writeFile(t, root, "input.json", canonicalSBOM())
	database := filepath.Join(root, "database")
	if err := os.Mkdir(database, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(database, "advisory.json"), []byte(`{"id":"GHSA-AAAA-BBBB-CCCC","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, binaryDigest, err := verifyRegularFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	_, databaseDigest, err := verifyDatabasePath(database)
	if err != nil {
		t.Fatal(err)
	}
	limits := RuntimeLimits{TimeoutSeconds: 5, MaxOutputBytes: 1 << 20, MemoryBytes: 64 << 20, PIDsMax: 32}
	environmentAttestation := []byte("{\n  \"kind\": \"environment\",\n  \"subject\": \"local\"\n}\n")
	environmentAttestationPath := writeFile(t, root, "environment-attestation.json", environmentAttestation)
	environment := EnvironmentDescriptor{ID: "local", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: bench.SHA256Digest(environmentAttestation), SandboxIdentity: SandboxIdentityBubblewrapSeccompCgroupV2}
	environmentBytes, err := canonicalJSON(environment)
	if err != nil {
		t.Fatal(err)
	}
	databaseFormat := testDatabaseFormat(t, engine)
	profile, _, _, err := buildProfile(engine, databaseFormat, limits)
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := canonicalJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	catalog := bench.Catalog{
		SchemaVersion: bench.CatalogSchemaVersion, Revision: "test-r1",
		Targets: []bench.Target{{ID: "target", OCIRef: "registry.example/target@" + digestByte('a'), Digest: digestByte('a'), SBOMDigest: bench.SHA256Digest(canonicalSBOM()), Components: []bench.Component{{PURL: "pkg:npm/a@1.0.0", Version: "1.0.0"}}}},
		Pins:    []bench.ArtifactPin{{Reference: "binary", Digest: binaryDigest}, {Reference: "database", Digest: databaseDigest}, {Reference: "environment", Digest: bench.SHA256Digest(environmentBytes)}, {Reference: "environment-attestation", Digest: bench.SHA256Digest(environmentAttestation)}, {Reference: "profile", Digest: bench.SHA256Digest(profileBytes)}},
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	engineVersion := "1.2.3"
	if engine == bench.EngineOSVScanner {
		engineVersion = "v1.2.3"
	}
	manifest := CaptureManifest{SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", SBOMPath: sbomPath, Engine: engine, EngineVersion: engineVersion, Binary: Artifact{Reference: "binary", Path: binary}, Database: DatabaseArtifact{Reference: "database", Path: database, Build: "test-db", Format: databaseFormat}, Environment: environment, EnvironmentAttestation: Artifact{Reference: "environment-attestation", Path: environmentAttestationPath}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: limits}
	return catalog, manifest
}

func capabilityFixture(t *testing.T) (bench.Catalog, CaptureManifest) {
	t.Helper()
	root := t.TempDir()
	binary := writeFile(t, root, "osv-scanner", []byte("osv-scanner-v2.5.1"))
	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"bash","version":"1:5.1","purl":"pkg:rpm/sles/bash@1%3A5.1?arch=x86_64&distro=sles-15.6"},{"name":"coreutils","version":"9.0","purl":"pkg:rpm/sles/coreutils@9.0"},{"name":"image-spec","version":"v1.1.1","purl":"pkg:golang/github.com/opencontainers/image-spec@v1.1.1"},{"name":"stdlib","version":"go1.24.11","purl":"pkg:golang/stdlib@1.24.11"}]}`)
	sbomPath := writeFile(t, root, "input.json", sbomBytes)
	database := filepath.Join(root, "database")
	if err := os.Mkdir(database, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(database, "offline.zip"), []byte("offline database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, binaryDigest, err := verifyRegularFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	_, databaseDigest, err := verifyDatabasePath(database)
	if err != nil {
		t.Fatal(err)
	}
	limits := RuntimeLimits{TimeoutSeconds: 5, MaxOutputBytes: 1 << 20, MemoryBytes: 64 << 20, PIDsMax: 32}
	environmentAttestation := []byte("{\n  \"kind\": \"environment\",\n  \"subject\": \"capability\"\n}\n")
	environmentAttestationPath := writeFile(t, root, "environment-attestation.json", environmentAttestation)
	environment := EnvironmentDescriptor{ID: "local", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: bench.SHA256Digest(environmentAttestation), SandboxIdentity: SandboxIdentityBubblewrapSeccompCgroupV2}
	environmentJSON, err := canonicalJSON(environment)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, _, err := buildProfile(bench.EngineOSVScanner, DatabaseFormatOSVScannerOffline, limits)
	if err != nil {
		t.Fatal(err)
	}
	profileJSON, err := canonicalJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	catalog := bench.Catalog{
		SchemaVersion: bench.CatalogSchemaVersion, Revision: "capability-r1",
		Targets: []bench.Target{{ID: "target", OCIRef: "registry.example/target@" + digestByte('a'), Digest: digestByte('a'), SBOMDigest: bench.SHA256Digest(sbomBytes), Components: []bench.Component{{PURL: "pkg:rpm/sles/bash@1%3A5.1?arch=x86_64&distro=sles-15.6", Version: "1:5.1"}, {PURL: "pkg:rpm/sles/coreutils@9.0", Version: "9.0"}}}},
		Pins:    []bench.ArtifactPin{{Reference: "binary", Digest: binaryDigest}, {Reference: "database", Digest: databaseDigest}, {Reference: "environment", Digest: bench.SHA256Digest(environmentJSON)}, {Reference: "environment-attestation", Digest: bench.SHA256Digest(environmentAttestation)}, {Reference: "profile", Digest: bench.SHA256Digest(profileJSON)}},
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]CapabilityArtifact, len(capabilitySourceReferences))
	statementSources := make([]CapabilityStatementSource, len(capabilitySourceReferences))
	for i, reference := range capabilitySourceReferences {
		path := writeFile(t, root, fmt.Sprintf("source-%d", i), []byte(fmt.Sprintf("source %d", i)))
		_, digest, err := verifyRegularFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sources[i] = CapabilityArtifact{Reference: reference, Path: path, Digest: digest}
		statementSources[i] = CapabilityStatementSource{Reference: reference, Digest: digest}
	}
	statement := CapabilityStatement{
		SchemaVersion: CapabilityStatementSchemaVersion, Kind: bench.CapabilityKindOSVScannerSUSERPM, DecisionRuleRevision: CapabilityDecisionRuleRevision, Scope: CapabilityScopeSameSBOMOSPackageMatching,
		CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", TargetDigest: catalog.Targets[0].Digest, SBOMDigest: catalog.Targets[0].SBOMDigest,
		Engine: bench.EngineOSVScanner, EngineVersion: "v2.5.1", EngineBinaryDigest: binaryDigest, DatabaseBuild: "offline-2026-09-13", DatabaseDigest: databaseDigest,
		EnvironmentID: environment.ID, EnvironmentDigest: bench.SHA256Digest(environmentJSON), ConfigDigest: bench.SHA256Digest(profileJSON),
		Components: append([]bench.Component(nil), catalog.Targets[0].Components...), Sources: statementSources,
	}
	statementJSON, err := canonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	statementPath := writeFile(t, root, "statement.json", statementJSON)
	manifest := CaptureManifest{
		SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, TargetID: "target", SBOMPath: sbomPath,
		Engine: bench.EngineOSVScanner, EngineVersion: "v2.5.1", Binary: Artifact{Reference: "binary", Path: binary},
		Database:    DatabaseArtifact{Reference: "database", Path: database, Build: "offline-2026-09-13", Format: DatabaseFormatOSVScannerOffline},
		Environment: environment, EnvironmentAttestation: Artifact{Reference: "environment-attestation", Path: environmentAttestationPath}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: limits,
		Capability: &CapabilityManifest{Statement: CapabilityArtifact{Reference: "capability-statement", Path: statementPath, Digest: bench.SHA256Digest(statementJSON)}, Sources: sources},
	}
	return catalog, manifest
}

func rebindCapabilityFixtureSBOM(t *testing.T, catalog *bench.Catalog, manifest *CaptureManifest, sbom []byte) {
	t.Helper()
	manifest.SBOMPath = writeFile(t, t.TempDir(), "input.json", sbom)
	catalog.Targets[0].SBOMDigest = bench.SHA256Digest(sbom)
	catalogDigest, err := bench.DigestCatalog(*catalog)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CatalogDigest = catalogDigest
	rewriteCapabilityStatement(t, manifest, func(statement *CapabilityStatement) {
		statement.CatalogDigest = catalogDigest
		statement.SBOMDigest = catalog.Targets[0].SBOMDigest
	})
}

func rewriteCapabilityStatement(t *testing.T, manifest *CaptureManifest, mutate func(*CapabilityStatement)) {
	t.Helper()
	data, err := os.ReadFile(manifest.Capability.Statement.Path)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := decodeCapabilityStatement(data)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&statement)
	data, err = canonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest.Capability.Statement.Path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest.Capability.Statement.Digest = bench.SHA256Digest(data)
}

func testDatabaseFormat(t testing.TB, engine bench.Engine) DatabaseFormat {
	t.Helper()
	switch engine {
	case bench.EngineOwned:
		return DatabaseFormatOSVJSON
	case bench.EngineGrype:
		return DatabaseFormatGrypeDBV6
	case bench.EngineTrivy:
		return DatabaseFormatTrivyDBV2
	case bench.EngineOSVScanner:
		return DatabaseFormatOSVScannerOffline
	default:
		t.Fatalf("unsupported engine %q", engine)
		return ""
	}
}

func testManifestSkeleton() CaptureManifest {
	return CaptureManifest{SchemaVersion: CaptureManifestSchemaVersion, CatalogRevision: "r", CatalogDigest: digestByte('a'), TargetID: "target", SBOMPath: "input", Engine: bench.EngineGrype, EngineVersion: "v", Binary: Artifact{Reference: "binary", Path: "bin"}, Database: DatabaseArtifact{Reference: "database", Path: "db", Build: "build", Format: DatabaseFormatGrypeDBV6}, Environment: EnvironmentDescriptor{ID: "env", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, ImageDigest: digestByte('b'), SandboxIdentity: SandboxIdentityBubblewrapSeccompCgroupV2}, EnvironmentAttestation: Artifact{Reference: "environment-attestation", Path: "attestation"}, EnvironmentPinReference: "environment", ProfilePinReference: "profile", Limits: RuntimeLimits{TimeoutSeconds: 1, MaxOutputBytes: 1, MemoryBytes: 1, PIDsMax: 1}}
}

func canonicalSBOM() []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}]}`)
}

func writeFile(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestByte(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }

func osvVersionProbeOutput(version string) []byte {
	return []byte("osv-scanner version: " + version + "\nosv-scalibr version: 0.0.0\ncommit: test\nbuilt at: 2026-09-13T00:00:00Z\n")
}

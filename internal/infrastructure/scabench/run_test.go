package scabench

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

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

func TestCanonicalCapabilityComponentsUsesBenchmarkIdentityOrder(t *testing.T) {
	version := "4.4-150400.25.22"
	components, err := canonicalCapabilityComponents([]bench.Component{
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

func sourceTarget(t *testing.T, catalog bench.Catalog) bench.Target {
	t.Helper()
	if len(catalog.Targets) != 1 {
		t.Fatal("fixture catalog must contain exactly one target")
	}
	return catalog.Targets[0]
}

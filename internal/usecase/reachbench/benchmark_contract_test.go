package reachbench

import (
	"bytes"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestReachabilityBenchmarkHasFrozenShape(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	if err := contract.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, want := len(contract.Corpus.Cases), 83; got != want {
		t.Fatalf("corpus cases = %d, want %d", got, want)
	}
	if got, want := len(contract.Oracle.Cases), 83; got != want {
		t.Fatalf("oracle cases = %d, want %d", got, want)
	}
	if got, want := len(contract.Challenges.Challenges), 7; got != want {
		t.Fatalf("challenge declarations = %d, want %d", got, want)
	}

	oracleByCase := make(map[string]OracleCase, len(contract.Oracle.Cases))
	for _, oracle := range contract.Oracle.Cases {
		oracleByCase[oracle.CaseID] = oracle
	}
	challengeIDs := make(map[string]struct{}, len(contract.Challenges.Challenges))
	for _, challenge := range contract.Challenges.Challenges {
		if required, ok := requiredChallenges[challenge.CaseID]; !ok || !sameChallenge(challenge, required) {
			t.Fatalf("challenge declaration changed: %+v", challenge)
		}
		challengeIDs[challenge.CaseID] = struct{}{}
	}

	cohorts := map[string]int{}
	controls := map[string]map[OracleCategory]int{}
	totals := map[OracleCategory]int{}
	for _, item := range contract.Corpus.Cases {
		if item.LegacyOrigin != nil || item.Fixture == nil {
			t.Fatalf("case %q has legacy or missing fixture identity", item.ID)
		}
		oracle, ok := oracleByCase[item.ID]
		if !ok {
			t.Fatalf("case %q has no oracle", item.ID)
		}
		key := cohortKey(item.CohortID, item.ModeID)
		cohorts[key]++
		totals[oracle.Category]++
		if _, challenge := challengeIDs[item.ID]; challenge {
			continue
		}
		if controls[key] == nil {
			controls[key] = map[OracleCategory]int{}
		}
		controls[key][oracle.Category]++
	}
	for key, want := range requiredCohortCaseCounts() {
		if got := cohorts[key]; got != want {
			t.Errorf("cohort %s cases = %d, want %d", key, got, want)
		}
		for _, category := range []OracleCategory{OracleReachable, OracleTrulyUnreachable, OracleOpaque, OracleNoCoverage} {
			if got := controls[key][category]; got != 1 {
				t.Errorf("cohort %s %s controls = %d, want 1", key, category, got)
			}
		}
	}
	for category, want := range map[OracleCategory]int{OracleReachable: 26, OracleTrulyUnreachable: 19, OracleOpaque: 19, OracleNoCoverage: 19} {
		if got := totals[category]; got != want {
			t.Errorf("%s total = %d, want %d", category, got, want)
		}
	}
}

func TestFixtureSpecificationIdentityBindsAllMaterialChoices(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	base := fixtureSpecification(t, contract.Fixtures, "go-binary-input")
	baseDigest := digestFixture(t, base)
	baseCorpus := DigestContractCorpusMust(t, contract.Corpus)

	mutations := []struct {
		name  string
		apply func(*FixtureSpecification)
	}{
		{"helper", func(spec *FixtureSpecification) { spec.Files[1].Digest = "sha256:" + strings.Repeat("a", 64) }},
		{"manifest", func(spec *FixtureSpecification) { spec.Files[0].Digest = "sha256:" + strings.Repeat("b", 64) }},
		{"build step", func(spec *FixtureSpecification) { spec.Build.Steps[0].Argv[1] = "test" }},
		{"toolchain requirement", func(spec *FixtureSpecification) { spec.Build.Toolchain.Version = "1.27.1" }},
		{"provenance", func(spec *FixtureSpecification) { spec.Provenance.Description = "repository input set" }},
		{"subject locator", func(spec *FixtureSpecification) { spec.Subjects[0].Locator.Symbol += "Changed" }},
		{"materialized path", func(spec *FixtureSpecification) { spec.Files[0].MaterializedPath += ".changed" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := cloneFixtureSpecification(base)
			mutation.apply(&changed)
			changedDigest := digestFixture(t, changed)
			if changedDigest == baseDigest {
				t.Fatal("fixture identity did not change")
			}
			corpus := contract.Corpus
			corpus.Cases = append([]ContractCase(nil), corpus.Cases...)
			for index := range corpus.Cases {
				if corpus.Cases[index].Fixture != nil && corpus.Cases[index].Fixture.ID == changed.ID {
					ref := *corpus.Cases[index].Fixture
					ref.Digest = changedDigest
					corpus.Cases[index].Fixture = &ref
					break
				}
			}
			if got := DigestContractCorpusMust(t, corpus); got == baseCorpus {
				t.Fatal("corpus identity did not change with fixture reference")
			}
		})
	}
}

func TestFixtureValidationRejectsIncompleteOrUnsafeInventory(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	if err := validateFixtureFiles(root, contract.Fixtures); err != nil {
		t.Fatalf("valid inventory: %v", err)
	}

	missing := fixtureMap(t, contract.Fixtures)
	first := contract.Fixtures.Fixtures[0].Files[0]
	delete(missing, first.Path)
	if err := validateFixtureFiles(missing, contract.Fixtures); err == nil {
		t.Fatal("missing declared file accepted")
	}

	extra := fixtureMap(t, contract.Fixtures)
	extra["fixtures/unhashed.txt"] = &fstest.MapFile{Data: []byte("not declared")}
	if err := validateFixtureFiles(extra, contract.Fixtures); err == nil || !strings.Contains(err.Error(), "omits") {
		t.Fatalf("unhashed extra file error = %v", err)
	}

	wrongSize := contract.Fixtures
	wrongSize.Fixtures = append([]FixtureSpecification(nil), contract.Fixtures.Fixtures...)
	wrongSize.Fixtures[0] = cloneFixtureSpecification(wrongSize.Fixtures[0])
	wrongSize.Fixtures[0].Files[0].Size++
	if err := validateFixtureFiles(root, wrongSize); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("wrong file size error = %v", err)
	}

	wrongDigest := contract.Fixtures
	wrongDigest.Fixtures = append([]FixtureSpecification(nil), contract.Fixtures.Fixtures...)
	wrongDigest.Fixtures[0] = cloneFixtureSpecification(wrongDigest.Fixtures[0])
	wrongDigest.Fixtures[0].Files[0].Digest = "sha256:" + strings.Repeat("f", 64)
	if err := validateFixtureFiles(root, wrongDigest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("wrong file digest error = %v", err)
	}

	conflictingPhysicalPath := contract.Fixtures
	conflictingPhysicalPath.Fixtures = append([]FixtureSpecification(nil), contract.Fixtures.Fixtures...)
	duplicate := cloneFixtureSpecification(contract.Fixtures.Fixtures[0])
	duplicate.ID = "c-cpp-symbols-tier2-copy-input"
	duplicate.Files[0].Digest = "sha256:" + strings.Repeat("e", 64)
	conflictingPhysicalPath.Fixtures = append(conflictingPhysicalPath.Fixtures, duplicate)
	if err := validateFixtureFiles(root, conflictingPhysicalPath); err == nil || !strings.Contains(err.Error(), "conflicting declaration") {
		t.Fatalf("conflicting global physical path error = %v", err)
	}

	spec := fixtureSpecification(t, contract.Fixtures, "c-cpp-symbols-tier2-input")
	unsafe := cloneFixtureSpecification(spec)
	unsafe.Files[0].Path = "../outside"
	if err := unsafe.validate(); err == nil {
		t.Fatal("unsafe fixture path accepted")
	}

	caseFold := cloneFixtureSpecification(spec)
	caseFold.Files = append(caseFold.Files, FixtureFile{Path: strings.ToUpper(spec.Files[0].Path), Size: 1, Digest: "sha256:" + strings.Repeat("a", 64)})
	if err := caseFold.validate(); err == nil || !strings.Contains(err.Error(), "case-fold") {
		t.Fatalf("case-fold collision error = %v", err)
	}

	prefix := cloneFixtureSpecification(spec)
	prefix.Files = append(prefix.Files, FixtureFile{Path: spec.Files[0].Path + "/child", Size: 1, Digest: "sha256:" + strings.Repeat("a", 64)})
	if err := prefix.validate(); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("prefix collision error = %v", err)
	}

	excessive := cloneFixtureSpecification(spec)
	excessive.Files = make([]FixtureFile, maxFixtureFileCount+1)
	for index := range excessive.Files {
		excessive.Files[index] = FixtureFile{Path: "fixtures/bounded/" + strconv.Itoa(index), Size: 1, Digest: "sha256:" + strings.Repeat("a", 64)}
	}
	if err := excessive.validate(); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("excessive file count error = %v", err)
	}

	overlarge := cloneFixtureSpecification(spec)
	overlarge.Files[0].Size = maxFixtureFileBytes + 1
	if err := overlarge.validate(); err == nil || !strings.Contains(err.Error(), "bounded") {
		t.Fatalf("excessive file bytes error = %v", err)
	}
}

func TestFixtureSpecificationRejectsUnknownKindsAndUnsafeBuilds(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	spec := fixtureSpecification(t, contract.Fixtures, "go-binary-input")

	unknownRole := cloneFixtureSpecification(spec)
	unknownRole.Entries[0].Role = FixtureEntryRole("unknown")
	assertSpecificationError(t, unknownRole, "unknown entry role")

	unknownLocator := cloneFixtureSpecification(spec)
	unknownLocator.Subjects[0].Locator.Kind = FixtureLocatorKind("unknown")
	assertSpecificationError(t, unknownLocator, "unknown locator kind")

	unknownBuild := cloneFixtureSpecification(spec)
	unknownBuild.Build.Kind = FixtureBuildKind("unknown")
	assertSpecificationError(t, unknownBuild, "unknown build kind")

	floatingToolchain := cloneFixtureSpecification(spec)
	floatingToolchain.Build.Toolchain.Version = "latest"
	assertSpecificationError(t, floatingToolchain, "floating toolchain")

	taggedToolchain := cloneFixtureSpecification(spec)
	taggedToolchain.Build.Toolchain.Version = "1.27.0-rc1"
	assertSpecificationError(t, taggedToolchain, "tagged toolchain")

	invalidProvenance := cloneFixtureSpecification(spec)
	invalidProvenance.Provenance.StartingRevision = "not-a-revision"
	assertSpecificationError(t, invalidProvenance, "invalid provenance")

	shellStep := cloneFixtureSpecification(spec)
	shellStep.Build.Steps[0].Argv = []string{"sh", "-c", "touch unexpected"}
	assertSpecificationError(t, shellStep, "shell build step")

	overwrite := cloneFixtureSpecification(spec)
	overwrite.Build.Outputs[0].Path = overwrite.Files[0].Path
	assertSpecificationError(t, overwrite, "output overwrite")

	undeclaredOutput := cloneFixtureSpecification(spec)
	undeclaredOutput.Build.Outputs = nil
	assertSpecificationError(t, undeclaredOutput, "missing output declaration")
}

func TestFixtureReferencesAndRuntimeReplayAreBounded(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	mismatch := contract
	mismatch.Corpus.Cases = append([]ContractCase(nil), contract.Corpus.Cases...)
	ref := *mismatch.Corpus.Cases[0].Fixture
	ref.Digest = "sha256:" + strings.Repeat("0", 64)
	mismatch.Corpus.Cases[0].Fixture = &ref
	if err := mismatch.Validate(); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("fixture reference mismatch error = %v", err)
	}

	root := fixtureMap(t, contract.Fixtures)
	replayPath := "fixtures/runtime/library_loads/replay.json"
	replay := string(root[replayPath].Data)
	root[replayPath] = &fstest.MapFile{Data: []byte(strings.Replace(replay, `"complete": true`, `"complete": false`, 1))}
	manifest := contract.Fixtures
	manifest.Fixtures = append([]FixtureSpecification(nil), contract.Fixtures.Fixtures...)
	for index := range manifest.Fixtures {
		if manifest.Fixtures[index].ID != "runtime-library-loads-input" {
			continue
		}
		manifest.Fixtures[index] = cloneFixtureSpecification(manifest.Fixtures[index])
		for fileIndex := range manifest.Fixtures[index].Files {
			if manifest.Fixtures[index].Files[fileIndex].Path == replayPath {
				manifest.Fixtures[index].Files[fileIndex].Size = int64(len(root[replayPath].Data))
				manifest.Fixtures[index].Files[fileIndex].Digest = benchmark.SHA256Digest(root[replayPath].Data)
			}
		}
	}
	if err := validateFixtureFiles(root, manifest); err == nil || !strings.Contains(err.Error(), "complete") {
		t.Fatalf("incomplete runtime replay error = %v", err)
	}
}

func TestProductionImportFixturesBindDistinctPackageIdentities(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	families := []struct {
		fixtureID    string
		subjectIDs   []string
		bindingPaths []string
		bindings     []string
	}{
		{"javascript-import-input", []string{"pkg:npm/@reachbench/direct@1.0.0", "pkg:npm/@reachbench/dynamic@1.0.0", "pkg:npm/@reachbench/unused@1.0.0", "pkg:npm/@reachbench/unsupported@1.0.0"}, []string{"fixtures/javascript/import/package.json", "fixtures/javascript/import/package-lock.json"}, []string{"@reachbench/direct", "@reachbench/dynamic", "@reachbench/unused", "@reachbench/unsupported"}},
		{"php-import-input", []string{"pkg:composer/reachbench/direct@1.0.0", "pkg:composer/reachbench/dynamic@1.0.0", "pkg:composer/reachbench/unused@1.0.0", "pkg:composer/reachbench/unsupported@1.0.0"}, []string{"fixtures/php/import/composer.json", "fixtures/php/import/composer.lock"}, []string{"reachbench/direct", "reachbench/dynamic", "reachbench/unused", "reachbench/unsupported"}},
		{"ruby-import-input", []string{"pkg:gem/reachbench-direct@1.0.0", "pkg:gem/reachbench-dynamic@1.0.0", "pkg:gem/reachbench-unused@1.0.0", "pkg:gem/reachbench-unsupported@1.0.0"}, []string{"fixtures/ruby/import/Gemfile", "fixtures/ruby/import/Gemfile.lock"}, []string{"reachbench-direct", "reachbench-dynamic", "reachbench-unused", "reachbench-unsupported"}},
		{"dotnet-build-aware-import-input", []string{"pkg:nuget/Reachbench.Direct@1.0.0", "pkg:nuget/Reachbench.Dynamic@1.0.0", "pkg:nuget/Reachbench.Unused@1.0.0", "pkg:nuget/Reachbench.Unsupported@1.0.0"}, []string{"fixtures/dotnet/build_aware_import/Reachbench.Import.csproj"}, []string{"Reachbench.Direct", "Reachbench.Dynamic", "Reachbench.Unused", "Reachbench.Unsupported"}},
		{"jvm-coarse-input", []string{"pkg:maven/example.invalid.reachbench/jvm-direct@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-dynamic@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-unused@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-unsupported@1.0.0"}, []string{"fixtures/jvm/coarse/fixture-build.json"}, []string{"jvm-direct", "jvm-dynamic", "jvm-unused", "jvm-unsupported"}},
		{"jvm-tier2-input", []string{"pkg:maven/example.invalid.reachbench/jvm-direct@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-dynamic@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-unused@1.0.0", "pkg:maven/example.invalid.reachbench/jvm-unsupported@1.0.0"}, []string{"fixtures/jvm/tier2/fixture-build.json"}, []string{"jvm-direct", "jvm-dynamic", "jvm-unused", "jvm-unsupported"}},
		{"python-import-input", []string{"pkg:pypi/reachbench-direct@1.0.0", "pkg:pypi/reachbench-dynamic@1.0.0", "pkg:pypi/reachbench-unused@1.0.0", "pkg:pypi/reachbench-unsupported@1.0.0"}, []string{"fixtures/python/import/pyproject.toml", "fixtures/python/import/requirements.lock"}, []string{"reachbench-direct", "reachbench-dynamic", "reachbench-unused", "reachbench-unsupported"}},
		{"rust-import-input", []string{"pkg:cargo/reachbench-direct@1.0.0", "pkg:cargo/reachbench-dynamic@1.0.0", "pkg:cargo/reachbench-unused@1.0.0", "pkg:cargo/reachbench-unsupported@1.0.0"}, []string{"fixtures/rust/import/Cargo.toml", "fixtures/rust/import/Cargo.lock"}, []string{"reachbench-direct", "reachbench-dynamic", "reachbench-unused", "reachbench-unsupported"}},
	}
	for _, family := range families {
		t.Run(family.fixtureID, func(t *testing.T) {
			fixture := fixtureSpecification(t, contract.Fixtures, family.fixtureID)
			byID := make(map[string]FixtureSubject, len(fixture.Subjects))
			for _, item := range fixture.Subjects {
				byID[item.ID] = item
			}
			seen := make(map[string]struct{}, len(family.subjectIDs))
			for _, subjectID := range family.subjectIDs {
				subject, ok := byID[subjectID]
				if !ok {
					t.Fatalf("missing package subject %q", subjectID)
				}
				if subject.PackageIdentity != subjectID {
					t.Fatalf("subject %q package identity = %q", subjectID, subject.PackageIdentity)
				}
				if _, duplicate := seen[subject.PackageIdentity]; duplicate {
					t.Fatalf("duplicate P/U/O/N package identity %q", subject.PackageIdentity)
				}
				seen[subject.PackageIdentity] = struct{}{}
			}
			for _, path := range family.bindingPaths {
				contents, ok := root[path]
				if !ok {
					t.Fatalf("missing package binding %q", path)
				}
				for _, identity := range family.bindings {
					if !strings.Contains(string(contents.Data), identity) {
						t.Fatalf("binding %q omits %q", path, identity)
					}
				}
			}
		})
	}
}

func TestGeneratedFixturesDeclareAnalyzerConsumedOutputs(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	expectedOutputs := map[string][]string{
		"go-binary-input": {
			"generated/go-binary-pclntab",
		},
		"dotnet-build-aware-import-input": {
			"fixtures/dotnet/build_aware_import/obj/project.assets.json",
			"generated/dotnet-import/app/Reachbench.Import.dll",
			"generated/dotnet-import/app/Reachbench.Import.deps.json",
			"generated/dotnet-import/local-nupkgs/Reachbench.Direct.1.0.0.nupkg",
			"generated/dotnet-import/local-nupkgs/Reachbench.Dynamic.1.0.0.nupkg",
			"generated/dotnet-import/local-nupkgs/Reachbench.Unused.1.0.0.nupkg",
			"generated/dotnet-import/package-cache/reachbench.direct/1.0.0/lib/net8.0/Reachbench.Direct.dll",
			"generated/dotnet-import/package-cache/reachbench.dynamic/1.0.0/lib/net8.0/Reachbench.Dynamic.dll",
			"generated/dotnet-import/package-cache/reachbench.unused/1.0.0/lib/net8.0/Reachbench.Unused.dll",
		},
		"dotnet-symbols-tier2-input": {
			"fixtures/dotnet/symbols_tier2/obj/project.assets.json",
			"generated/dotnet-symbols/Reachbench.Symbols.dll",
			"generated/dotnet-symbols/Reachbench.Symbols.deps.json",
		},
		"jvm-coarse-input": jvmAnalyzerOutputs("coarse"),
		"jvm-tier2-input":  jvmAnalyzerOutputs("tier2"),
	}
	for fixtureID, want := range expectedOutputs {
		t.Run(fixtureID, func(t *testing.T) {
			fixture := fixtureSpecification(t, contract.Fixtures, fixtureID)
			if fixture.Build == nil {
				t.Fatal("missing generated build declaration")
			}
			if fixture.Build.Toolchain.Resolution != FixtureToolchainMaterializerRequired || fixture.Build.Toolchain.Family == "" || fixture.Build.Toolchain.Version == "" {
				t.Fatalf("toolchain requirement is not honest and materializer-bound: %+v", fixture.Build.Toolchain)
			}
			outputs := make(map[string]FixtureOutput, len(fixture.Build.Outputs))
			for _, output := range fixture.Build.Outputs {
				outputs[output.Path] = output
			}
			if len(outputs) != len(want) {
				t.Fatalf("generated outputs = %d, want %d", len(outputs), len(want))
			}
			for _, path := range want {
				output, ok := outputs[path]
				if !ok || output.Materialization != "materializer_required" {
					t.Fatalf("missing materializer output %q", path)
				}
			}
		})
	}

	runtime := fixtureSpecification(t, contract.Fixtures, "runtime-library-loads-input")
	if runtime.Provenance.Kind != FixtureDeterministicReplay {
		t.Fatalf("runtime provenance = %q, want deterministic replay", runtime.Provenance.Kind)
	}
}

func jvmAnalyzerOutputs(mode string) []string {
	prefix := "generated/jvm-" + mode
	return []string{
		prefix + "/jvm-direct.jar",
		prefix + "/jvm-dynamic.jar",
		prefix + "/jvm-unused.jar",
		prefix + "/classes/Main.class",
	}
}

func TestGeneratedBuildRecipesUseFrozenWorkingDirectories(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	for _, fixture := range contract.Fixtures.Fixtures {
		if fixture.Build == nil {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			wantWorkingDirectory := "."
			if fixture.ID == "go-binary-input" {
				wantWorkingDirectory = "fixtures/golang/binary"
			}
			if fixture.Build.WorkingDirectory != wantWorkingDirectory {
				t.Fatalf("working directory = %q, want %q", fixture.Build.WorkingDirectory, wantWorkingDirectory)
			}
			for _, step := range fixture.Build.Steps {
				for _, arg := range step.Argv {
					if strings.HasPrefix(arg, "fixtures/") || strings.HasPrefix(arg, "generated/") {
						t.Fatalf("build argument %q is not workspace-root-relative", arg)
					}
				}
			}
		})
	}
}

func TestDotNetPortablePublishUsesMatchingRestore(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	for _, test := range []struct {
		fixtureID   string
		restoreStep int
		publishStep int
	}{
		{fixtureID: "dotnet-build-aware-import-input", restoreStep: 2, publishStep: 3},
		{fixtureID: "dotnet-symbols-tier2-input", restoreStep: 0, publishStep: 1},
	} {
		t.Run(test.fixtureID, func(t *testing.T) {
			fixture := fixtureSpecification(t, contract.Fixtures, test.fixtureID)
			if fixture.Build == nil || len(fixture.Build.Steps) <= test.publishStep {
				t.Fatalf("dotnet fixture build recipe is incomplete: %+v", fixture.Build)
			}
			restore := fixture.Build.Steps[test.restoreStep].Argv
			publish := fixture.Build.Steps[test.publishStep].Argv
			if len(restore) < 3 || len(publish) < 3 || restore[0] != "dotnet" || restore[1] != "restore" || publish[0] != "dotnet" || publish[1] != "publish" || restore[2] != publish[2] {
				t.Fatalf("portable restore/publish project mismatch: restore=%q publish=%q", restore, publish)
			}
			for _, argv := range [][]string{restore, publish} {
				if hasArgument(argv, "--runtime") || hasArgument(argv, "-r") {
					t.Fatalf("portable .NET fixture declares a runtime identifier: %q", argv)
				}
				for _, property := range []string{"-p:SelfContained=false", "-p:UseAppHost=false"} {
					if !hasArgument(argv, property) {
						t.Fatalf("portable .NET fixture argv %q omits %q", argv, property)
					}
				}
			}
			if !hasAdjacentArguments(publish, "--no-restore", "--configuration") {
				t.Fatalf("portable publish does not consume its matching restore: %q", publish)
			}
		})
	}
}

func hasArgument(argv []string, target string) bool {
	for _, argument := range argv {
		if argument == target {
			return true
		}
	}
	return false
}

func hasAdjacentArguments(argv []string, first, second string) bool {
	for index := 0; index+1 < len(argv); index++ {
		if argv[index] == first && argv[index+1] == second {
			return true
		}
	}
	return false
}

func TestDotNetBuildAwareFixtureUsesLocalPackages(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	fixture := fixtureSpecification(t, contract.Fixtures, "dotnet-build-aware-import-input")
	if fixture.Build == nil || len(fixture.Build.Steps) != 4 {
		t.Fatalf("dotnet recipe = %+v, want restore/pack/restore/publish", fixture.Build)
	}

	app := string(root["fixtures/dotnet/build_aware_import/Reachbench.Import.csproj"].Data)
	for _, reference := range []string{
		`<PackageReference Include="Reachbench.Direct" Version="1.0.0" />`,
		`<PackageReference Include="Reachbench.Dynamic" Version="1.0.0" />`,
		`<PackageReference Include="Reachbench.Unused" Version="1.0.0" />`,
		`<PackageReference Include="Reachbench.Unsupported" Version="1.0.0" Condition="'$(TargetFramework)' == 'net9.0'" />`,
	} {
		if !strings.Contains(app, reference) {
			t.Fatalf("app project omits %q", reference)
		}
	}
	if strings.Contains(app, "ProjectReference") {
		t.Fatal("app project retains ProjectReference semantics")
	}
	if !strings.Contains(app, `<Compile Remove="packages/**/*.cs" />`) {
		t.Fatal("app project compiles package fixture sources as first-party code")
	}
	for _, project := range []string{"Reachbench.Direct", "Reachbench.Dynamic", "Reachbench.Unused", "Reachbench.Unsupported"} {
		path := "fixtures/dotnet/build_aware_import/packages/" + project + "/" + project + ".csproj"
		contents := string(root[path].Data)
		if !strings.Contains(contents, "<PackageId>"+project+"</PackageId>") || !strings.Contains(contents, "<Version>1.0.0</Version>") {
			t.Fatalf("package project %q lacks pinned package identity", project)
		}
	}
	solution := string(root["fixtures/dotnet/build_aware_import/Reachbench.Packages.sln"].Data)
	for _, project := range []string{"Reachbench.Direct", "Reachbench.Dynamic", "Reachbench.Unused"} {
		if !strings.Contains(solution, project) {
			t.Fatalf("package solution omits %q", project)
		}
	}
	if strings.Contains(solution, "Reachbench.Unsupported") {
		t.Fatal("unsupported package participates in the package build aggregate")
	}
	if !strings.Contains(string(root["fixtures/dotnet/build_aware_import/NuGet.Config"].Data), "<clear />") {
		t.Fatal("dotnet package restore allows inherited package sources")
	}

	recipe := make([]string, 0, len(fixture.Build.Steps)*8)
	for _, step := range fixture.Build.Steps {
		recipe = append(recipe, step.Argv...)
	}
	for _, required := range []string{
		"./fixtures/dotnet/build_aware_import/Reachbench.Packages.sln",
		"./generated/dotnet-import/local-nupkgs",
		"--source",
		"./generated/dotnet-import/package-cache",
		"./fixtures/dotnet/build_aware_import/Reachbench.Import.csproj",
		"--configfile",
	} {
		if !strings.Contains(strings.Join(recipe, "\n"), required) {
			t.Fatalf("dotnet recipe omits %q", required)
		}
	}
	outputs := map[string]struct{}{}
	for _, output := range fixture.Build.Outputs {
		outputs[output.Path] = struct{}{}
	}
	for _, path := range []string{
		"generated/dotnet-import/local-nupkgs/Reachbench.Direct.1.0.0.nupkg",
		"generated/dotnet-import/local-nupkgs/Reachbench.Dynamic.1.0.0.nupkg",
		"generated/dotnet-import/local-nupkgs/Reachbench.Unused.1.0.0.nupkg",
		"generated/dotnet-import/package-cache/reachbench.direct/1.0.0/lib/net8.0/Reachbench.Direct.dll",
		"generated/dotnet-import/package-cache/reachbench.dynamic/1.0.0/lib/net8.0/Reachbench.Dynamic.dll",
		"generated/dotnet-import/package-cache/reachbench.unused/1.0.0/lib/net8.0/Reachbench.Unused.dll",
	} {
		if _, exists := outputs[path]; !exists {
			t.Fatalf("missing analyzer-consumed local package output %q", path)
		}
	}
	for path := range outputs {
		if strings.Contains(path, "Unsupported") || strings.Contains(path, "unsupported") {
			t.Fatalf("unsupported package output is analyzer-consumed: %q", path)
		}
	}
}

func TestJVMFixturesUseSeparateCoordinateArchives(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	for _, mode := range []string{"coarse", "tier2"} {
		t.Run(mode, func(t *testing.T) {
			fixture := fixtureSpecification(t, contract.Fixtures, "jvm-"+mode+"-input")
			if fixture.Build == nil || len(fixture.Build.Steps) != 7 {
				t.Fatalf("jvm recipe = %+v, want three package pairs and app compilation", fixture.Build)
			}
			outputs := map[string]struct{}{}
			for _, output := range fixture.Build.Outputs {
				outputs[output.Path] = struct{}{}
			}
			for _, path := range jvmAnalyzerOutputs(mode) {
				if _, exists := outputs[path]; !exists {
					t.Fatalf("missing JVM analyzer output %q", path)
				}
			}
			for path := range outputs {
				if strings.Contains(path, "unsupported") || strings.Contains(path, "dependencies.jar") || strings.Contains(path, "app.jar") {
					t.Fatalf("invalid aggregate JVM output %q", path)
				}
			}

			classpath := "./generated/jvm-" + mode + "/jvm-direct.jar:./generated/jvm-" + mode + "/jvm-dynamic.jar:./generated/jvm-" + mode + "/jvm-unused.jar"
			if got := strings.Join(fixture.Build.Steps[len(fixture.Build.Steps)-1].Argv, "\n"); !strings.Contains(got, classpath) || !strings.Contains(got, "/classes") {
				t.Fatalf("app compilation does not use coordinate JARs and classes root: %s", got)
			}
			manifest := string(root["fixtures/jvm/"+mode+"/fixture-build.json"].Data)
			if strings.Contains(manifest, "reachbench-app.jar") || strings.Contains(manifest, "reachbench-dependencies.jar") {
				t.Fatal("JVM fixture manifest retains aggregate archive")
			}
			for _, artifact := range []string{"jvm-direct", "jvm-dynamic", "jvm-unused"} {
				metadata := "META-INF/maven/example.invalid.reachbench/" + artifact + "/pom.properties"
				if !strings.Contains(manifest, artifact) || !strings.Contains(manifest, metadata) {
					t.Fatalf("JVM fixture manifest omits coordinate metadata for %q", artifact)
				}
				metadataPath := "fixtures/jvm/" + mode + "/metadata/" + artifact + "/" + metadata
				contents := string(root[metadataPath].Data)
				if contents != "groupId=example.invalid.reachbench\nartifactId="+artifact+"\nversion=1.0.0\n" {
					t.Fatalf("JVM metadata %q = %q", metadataPath, contents)
				}
			}
		})
	}
}

func TestOpaqueFixtureDispatchIsConstrained(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	for _, path := range []string{
		"fixtures/dotnet/build_aware_import/Program.cs",
		"fixtures/jvm/coarse/app/Main.java",
		"fixtures/jvm/tier2/app/Main.java",
		"fixtures/php/import/main.php",
		"fixtures/ruby/import/main.rb",
	} {
		contents := string(root[path].Data)
		for _, ambient := range []string{"Environment.", "System.getenv", "getenv(", "ENV.fetch"} {
			if strings.Contains(contents, ambient) {
				t.Fatalf("opaque fixture %q accepts ambient dispatch through %q", path, ambient)
			}
		}
		if strings.Contains(contents, "Unused") || strings.Contains(contents, "unused") {
			t.Fatalf("opaque fixture %q can select the unreachable dependency", path)
		}
	}
	if !strings.Contains(string(root["fixtures/dotnet/build_aware_import/Program.cs"].Data), `string.Concat("Reachbench", ".Dynamic")`) {
		t.Fatal("dotnet reflection is not constrained to Reachbench.Dynamic")
	}
	if !strings.Contains(string(root["fixtures/jvm/coarse/app/Main.java"].Data), `String.join(".", "reachbench", "dynamic", "DynamicDependency")`) {
		t.Fatal("JVM reflection is not constrained to reachbench.dynamic.DynamicDependency")
	}
	if !strings.Contains(string(root["fixtures/php/import/main.php"].Data), `implode('\\', ['Reachbench', 'Dynamic', 'Entry'])`) {
		t.Fatal("PHP opaque dispatch is not constrained to Reachbench Dynamic Entry")
	}
	if !strings.Contains(string(root["fixtures/ruby/import/main.rb"].Data), `["Reachbench", "Dynamic"].join("::")`) {
		t.Fatal("Ruby opaque dispatch is not constrained to Reachbench::Dynamic")
	}
}

func TestNoCoverageLocatorsResolveStableMarkers(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	cases := []struct {
		fixtureID string
		subjectID string
		path      string
		line      int
		symbol    string
		marker    string
	}{
		{"c-cpp-symbols-tier2-input", "pkg:reachbench/c_cpp/symbols_tier2#controlNoCoverage", "fixtures/c_cpp/symbols_tier2/main.cpp", 13, "reachbench::controlNoCoverage", "void controlNoCoverage()"},
		{"javascript-interprocedural-input", "pkg:reachbench/javascript/interprocedural#controlNoCoverage", "fixtures/javascript/interprocedural/package.json", 7, "parser-unavailable", `"noCoverageCapability": "parser-unavailable"`},
		{"javascript-lexical-input", "pkg:reachbench/javascript/lexical#controlNoCoverage", "fixtures/javascript/lexical/package.json", 7, "parser-unavailable", `"noCoverageCapability": "parser-unavailable"`},
		{"php-symbols-tier2-input", "pkg:reachbench/php/symbols_tier2#controlNoCoverage", "fixtures/php/symbols_tier2/composer.json", 6, "unsupported-tier", `"no-coverage-capability": "unsupported-tier"`},
		{"python-semantic-input", "pkg:reachbench/python/semantic#controlNoCoverage", "fixtures/python/semantic/pyproject.toml", 11, "typing-stubs", `no_coverage_capability = "typing-stubs"`},
		{"ruby-symbols-tier2-input", "pkg:reachbench/ruby/symbols_tier2#controlNoCoverage", "fixtures/ruby/symbols_tier2/reachbench-ruby-symbols.gemspec", 5, "unsupported-tier", `spec.metadata["reachbench.no_coverage_capability"] = "unsupported-tier"`},
		{"rust-symbols-tier2-input", "pkg:reachbench/rust/symbols_tier2#controlNoCoverage", "fixtures/rust/symbols_tier2/Cargo.toml", 7, "macro-expansion", `no_coverage_capability = "macro-expansion"`},
	}
	for _, testCase := range cases {
		t.Run(testCase.fixtureID, func(t *testing.T) {
			fixture := fixtureSpecification(t, contract.Fixtures, testCase.fixtureID)
			var subject FixtureSubject
			for _, candidate := range fixture.Subjects {
				if candidate.ID == testCase.subjectID {
					subject = candidate
					break
				}
			}
			if subject.ID == "" || subject.Locator.Kind != FixtureLocatorManifestCapability && testCase.fixtureID != "c-cpp-symbols-tier2-input" {
				t.Fatalf("no-coverage subject has wrong locator: %+v", subject)
			}
			if subject.Locator.ModulePath != testCase.path || subject.Locator.Line != testCase.line || subject.Locator.Symbol != testCase.symbol {
				t.Fatalf("no-coverage locator = %+v, want %s:%d %s", subject.Locator, testCase.path, testCase.line, testCase.symbol)
			}
			lines := strings.Split(string(root[testCase.path].Data), "\n")
			if len(lines) < testCase.line || !strings.Contains(lines[testCase.line-1], testCase.marker) {
				t.Fatalf("marker %q is not grounded at %s:%d", testCase.marker, testCase.path, testCase.line)
			}
		})
	}
}

func TestGoBinaryRetainsButNeverCallsUnreachableControl(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	contents := string(root["fixtures/golang/binary/main.go.src"].Data)
	if !strings.Contains(contents, "keeps controlUnreachable in PCLNTAB without calling it") {
		t.Fatal("go binary fixture does not explain intentional PCLNTAB retention")
	}
	if strings.Count(contents, "controlUnreachable()") != 1 {
		t.Fatal("go binary unreachable control is called or no longer declared exactly once")
	}
}

func TestRuntimeReplaySemanticMappingRejectsTampering(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	replayPath := "fixtures/runtime/library_loads/replay.json"
	mutations := []struct {
		name     string
		mutate   func(string) string
		contains string
	}{
		{
			name: "wrong event category",
			mutate: func(replay string) string {
				return strings.Replace(replay, `"operation": "load"`, `"operation": "opaque"`, 1)
			},
			contains: "event/category",
		},
		{
			name: "spurious unreachable event",
			mutate: func(replay string) string {
				return strings.Replace(replay, "\n  ]", ",\n    {\"sequence\": 4, \"operation\": \"load\", \"library\": \"libreachbench_unused.so\", \"owner\": \"pkg:runtime/reachbench-unused@benchmark-v1\"}\n  ]", 1)
			},
			contains: "truly-unreachable",
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			root := fixtureMap(t, contract.Fixtures)
			root[replayPath] = &fstest.MapFile{Data: []byte(mutation.mutate(string(root[replayPath].Data)))}
			if err := validateRuntimeReplayContract(root, contract); err == nil || !strings.Contains(err.Error(), mutation.contains) {
				t.Fatalf("runtime semantic mutation error = %v", err)
			}
		})
	}
}

func TestRuntimeReplaySemanticMappingBindsVersionedOwner(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	contract.Fixtures.Fixtures = append([]FixtureSpecification(nil), contract.Fixtures.Fixtures...)
	for index := range contract.Fixtures.Fixtures {
		if contract.Fixtures.Fixtures[index].ID != "runtime-library-loads-input" {
			continue
		}
		contract.Fixtures.Fixtures[index] = cloneFixtureSpecification(contract.Fixtures.Fixtures[index])
		for subjectIndex := range contract.Fixtures.Fixtures[index].Subjects {
			subject := &contract.Fixtures.Fixtures[index].Subjects[subjectIndex]
			if subject.Locator.Symbol == "libreachbench_direct.so" {
				subject.PackageIdentity = "pkg:runtime/reachbench-direct@benchmark-v0"
			}
		}
	}
	if err := validateRuntimeReplayContract(fixtureMap(t, contract.Fixtures), contract); err == nil || !strings.Contains(err.Error(), "does not match the frozen subject") {
		t.Fatalf("versioned owner mismatch error = %v", err)
	}
}

func TestReachabilityBenchmarkLoadersAreStrictDeterministicAndPinned(t *testing.T) {
	for _, load := range []func(*strings.Reader) error{
		func(reader *strings.Reader) error { _, err := LoadBenchmarkCorpus(reader); return err },
		func(reader *strings.Reader) error { _, err := LoadBenchmarkOracle(reader); return err },
		func(reader *strings.Reader) error { _, err := LoadChallengeManifest(reader); return err },
		func(reader *strings.Reader) error { _, err := LoadFixtureManifest(reader); return err },
	} {
		if err := load(strings.NewReader(`{"unknown":true}`)); err == nil {
			t.Fatal("loader accepted unknown field")
		}
	}
	if _, err := LoadFixtureManifest(strings.NewReader(strings.Repeat(" ", int(maxFixtureDocumentBytes)+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("fixture document limit error = %v", err)
	}
	first, err := LoadReachabilityBenchmark()
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadReachabilityBenchmark()
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := benchmark.CanonicalJSON(canonicalReachabilityBenchmark(first))
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := benchmark.CanonicalJSON(canonicalReachabilityBenchmark(second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("loader result is not deterministic")
	}

	for _, item := range []struct {
		name string
		got  string
		want string
	}{
		{"corpus", DigestContractCorpusMust(t, first.Corpus), "sha256:973ecaa8d311f5f904a61e1738f52e1178994869ae1cd0a10527fa373cf46330"},
		{"oracle", DigestReachabilityOracleMust(t, first.Oracle), "sha256:0299297cb1bacbdab7156536d2de3b21992e1f3c085ab109f95162f4eef6dfe6"},
		{"challenges", DigestChallengeManifestMust(t, first.Challenges), "sha256:a967a0b5423e79961f28121cc5dfe71e1464850d1e2af0ca9fa74cebfc7db0aa"},
		{"fixtures", DigestFixtureManifestMust(t, first.Fixtures), "sha256:ae8c4e22d548cb0fa6a1fb2e370e8c9385ec16939ba04fada8a771db115bdef6"},
		{"benchmark", DigestReachabilityBenchmarkMust(t, first), "sha256:08a813afbac0b385a77753e4f243b2aa8565cd1f568c3a11a8ed24fcb342fb02"},
	} {
		if item.got != item.want {
			t.Errorf("%s digest = %s, want %s", item.name, item.got, item.want)
		}
	}
}

func fixtureSpecification(t *testing.T, manifest FixtureManifest, id string) FixtureSpecification {
	t.Helper()
	for _, specification := range manifest.Fixtures {
		if specification.ID == id {
			return cloneFixtureSpecification(specification)
		}
	}
	t.Fatalf("fixture %q not found", id)
	return FixtureSpecification{}
}

func cloneFixtureSpecification(specification FixtureSpecification) FixtureSpecification {
	out := specification
	out.Files = append([]FixtureFile(nil), specification.Files...)
	out.Entries = append([]FixtureEntry(nil), specification.Entries...)
	out.Subjects = append([]FixtureSubject(nil), specification.Subjects...)
	if specification.Build != nil {
		build := *specification.Build
		build.Steps = append([]FixtureBuildStep(nil), specification.Build.Steps...)
		for index := range build.Steps {
			build.Steps[index].Argv = append([]string(nil), build.Steps[index].Argv...)
		}
		build.Env = append([]FixtureBuildEnv(nil), specification.Build.Env...)
		build.Outputs = append([]FixtureOutput(nil), specification.Build.Outputs...)
		out.Build = &build
	}
	return out
}

func fixtureMap(t *testing.T, manifest FixtureManifest) fstest.MapFS {
	t.Helper()
	root, err := fs.Sub(reachabilityBenchmarkFiles, benchmarkAssetRoot)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{}
	for _, fixture := range manifest.Fixtures {
		for _, entry := range fixture.Files {
			if _, exists := files[entry.Path]; exists {
				continue
			}
			contents, err := fs.ReadFile(root, entry.Path)
			if err != nil {
				t.Fatalf("read %s: %v", entry.Path, err)
			}
			files[entry.Path] = &fstest.MapFile{Data: contents}
		}
	}
	return files
}

func assertSpecificationError(t *testing.T, specification FixtureSpecification, name string) {
	t.Helper()
	if _, err := DigestFixtureSpecification(specification); err == nil {
		t.Fatalf("%s accepted", name)
	}
}

func digestFixture(t *testing.T, specification FixtureSpecification) string {
	t.Helper()
	digest, err := DigestFixtureSpecification(specification)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func DigestContractCorpusMust(t *testing.T, corpus ContractCorpus) string {
	t.Helper()
	digest, err := DigestContractCorpus(corpus)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func DigestReachabilityOracleMust(t *testing.T, oracle ReachabilityOracle) string {
	t.Helper()
	digest, err := DigestReachabilityOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func DigestChallengeManifestMust(t *testing.T, manifest ChallengeManifest) string {
	t.Helper()
	digest, err := DigestChallengeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func DigestFixtureManifestMust(t *testing.T, manifest FixtureManifest) string {
	t.Helper()
	digest, err := DigestFixtureManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func DigestReachabilityBenchmarkMust(t *testing.T, contract ReachabilityBenchmark) string {
	t.Helper()
	digest, err := DigestReachabilityBenchmark(contract)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestDecodeRuntimeReplayReturnsFrozenPackageIdentity(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	replayPath := "fixtures/runtime/library_loads/replay.json"
	ownershipPath := "fixtures/runtime/library_loads/ownership.json"
	decoded, err := DecodeRuntimeReplay(bytes.NewReader(root[replayPath].Data), bytes.NewReader(root[ownershipPath].Data))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Session != "reachbench-library-loads" || !decoded.Complete || decoded.LossState != "none" {
		t.Fatalf("replay metadata = %+v", decoded)
	}
	if len(decoded.Events) != 3 || decoded.Events[0].Sequence != 1 || decoded.Events[0].Operation != "load" || decoded.Events[0].Library != "libreachbench_direct.so" {
		t.Fatalf("replay events = %+v", decoded.Events)
	}
	if got := decoded.Events[0].Owner; got.Identity != "pkg:runtime/reachbench-direct@benchmark-v1" || got.Name != "reachbench-direct" || got.Version != "benchmark-v1" {
		t.Fatalf("event owner = %+v", got)
	}
	if len(decoded.Owners) != 4 || decoded.Owners[0].Library != "libreachbench_direct.so" || decoded.Owners[0].Owner.Version != "benchmark-v1" {
		t.Fatalf("replay owners = %+v", decoded.Owners)
	}

	decoded.Events[0].Owner.Name = "changed"
	decoded.Owners[0].Owner.Version = "changed"
	fresh, err := DecodeRuntimeReplay(bytes.NewReader(root[replayPath].Data), bytes.NewReader(root[ownershipPath].Data))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Events[0].Owner.Name != "reachbench-direct" || fresh.Owners[0].Owner.Version != "benchmark-v1" {
		t.Fatalf("decoder did not return defensive copies: %+v", fresh)
	}
}

func TestDecodeRuntimeReplayRejectsInvalidDocuments(t *testing.T) {
	contract := DefaultReachabilityBenchmark()
	root := fixtureMap(t, contract.Fixtures)
	replayPath := "fixtures/runtime/library_loads/replay.json"
	ownershipPath := "fixtures/runtime/library_loads/ownership.json"
	replay := string(root[replayPath].Data)
	ownership := string(root[ownershipPath].Data)
	tests := []struct {
		name      string
		replay    string
		ownership string
	}{
		{name: "trailing JSON", replay: replay + "{}", ownership: ownership},
		{name: "old schema", replay: strings.Replace(replay, "synapse-runtime-library-replay-v2", "synapse-runtime-library-replay-v1", 1), ownership: ownership},
		{name: "malformed order", replay: strings.Replace(replay, `"sequence": 2`, `"sequence": 4`, 1), ownership: ownership},
		{name: "unknown operation", replay: strings.Replace(replay, `"operation": "load"`, `"operation": "unknown"`, 1), ownership: ownership},
		{name: "duplicate library", replay: strings.Replace(replay, `{"sequence": 2, "operation": "opaque", "library": "libreachbench_dynamic.so", "owner": "pkg:runtime/reachbench-dynamic@benchmark-v1"}`, `{"sequence": 2, "operation": "opaque", "library": "libreachbench_direct.so", "owner": "pkg:runtime/reachbench-direct@benchmark-v1"}`, 1), ownership: ownership},
		{name: "mismatched ownership", replay: strings.Replace(replay, `"owner": "pkg:runtime/reachbench-direct@benchmark-v1"`, `"owner": "pkg:runtime/reachbench-unused@benchmark-v1"`, 1), ownership: ownership},
		{name: "missing version", replay: strings.Replace(replay, `pkg:runtime/reachbench-direct@benchmark-v1`, `pkg:runtime/reachbench-direct`, 1), ownership: ownership},
		{name: "missing ownership", replay: replay, ownership: strings.Replace(ownership, `,
    "libreachbench_unsupported.so": "pkg:runtime/reachbench-unsupported@benchmark-v1"`, "", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeRuntimeReplay(strings.NewReader(test.replay), strings.NewReader(test.ownership)); err == nil {
				t.Fatal("expected strict replay decoder to reject invalid document")
			}
		})
	}
	if _, err := DecodeRuntimeReplay(strings.NewReader(strings.Repeat(" ", 1<<20+1)), strings.NewReader(ownership)); err == nil {
		t.Fatal("expected strict replay decoder to enforce its document bound")
	}
}

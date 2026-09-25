package reachbench

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestResolveReachabilityProfileRequiresOneRegisteredStaticTuple(t *testing.T) {
	legacy, err := DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(legacy)
	if err != nil {
		t.Fatalf("ResolveReachabilityProfile(default): %v", err)
	}
	if profile.Status != ReachabilityProfileAuthoritative || !profile.Authoritative || len(profile.Corpus.Cases) != 83 || profileEnabledCellCount(profile) != 95 {
		t.Fatalf("default profile = %+v", profile)
	}

	mixed := legacy
	mixed.ActiveSnapshot = SnapshotIdentity{}
	if _, err := ResolveReachabilityProfile(mixed); err == nil {
		t.Fatal("ResolveReachabilityProfile accepted a mixed tuple")
	}
}

func TestGoBinaryVersionedProfileIsPendingAndReplacesFiveCases(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatalf("ResolveReachabilityProfile(successor): %v", err)
	}
	if profile.Status != ReachabilityProfilePendingIndependentReview || profile.Authoritative {
		t.Fatalf("successor authority = status %q authoritative %t", profile.Status, profile.Authoritative)
	}
	if got := len(profile.Corpus.Cases); got != 83 {
		t.Fatalf("successor corpus cases = %d, want 83", got)
	}
	if got := profileEnabledCellCount(profile); got != 100 {
		t.Fatalf("successor enabled cells = %d, want 100", got)
	}
	legacyPolicy, err := DefaultMeasurementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if profile.Policy.Evaluator == legacyPolicy.Evaluator || profile.Policy.MetricDefinition == legacyPolicy.MetricDefinition {
		t.Fatal("successor policy reuses legacy evaluator or metric descriptor")
	}
	if profile.Policy.Evaluator.ID != goBinaryVersionedProfileID+"-evaluator" || profile.Policy.MetricDefinition.ID != goBinaryVersionedProfileID+"-metric-definition" {
		t.Fatalf("successor descriptor identities = evaluator %q metrics %q", profile.Policy.Evaluator.ID, profile.Policy.MetricDefinition.ID)
	}
	for _, item := range profile.Corpus.Cases {
		if item.CohortID == "go" && item.ModeID == "binary" && !strings.HasPrefix(item.ID, "go-binary-versioned-") {
			t.Fatalf("successor retains legacy Go binary case %q", item.ID)
		}
	}
}

func TestReachabilityProfileRejectsModifiedReturnedProfile(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	item := profileCase(t, profile, "go-binary-versioned-direct-call")
	if item.Fixture == nil {
		t.Fatal("versioned direct case lacks fixture")
	}
	profile.Fixtures.ID = "substituted-fixtures"
	if _, err := profile.ResolveFixtureSpecification(*item.Fixture); err == nil {
		t.Fatal("modified profile resolved a fixture")
	}
}

func TestRegisteredVersionedGoBinaryFixturesReturnPinnedBytes(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	item := profileCase(t, profile, "go-binary-versioned-direct-call")
	if item.Fixture == nil {
		t.Fatal("versioned direct case lacks fixture")
	}
	specification, err := ResolveRegisteredFixtureSpecification(*item.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := ReadRegisteredFixtureFile(specification.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := benchmark.SHA256Digest(contents), specification.Files[0].Digest; got != want {
		t.Fatalf("fixture bytes digest = %q, want %q", got, want)
	}
}

func TestRegisteredFixtureLookupsReuseImmutableRegistryAndRejectTamperedDigest(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	item := profileCase(t, profile, "go-binary-versioned-direct-call")
	if item.Fixture == nil {
		t.Fatal("versioned direct case lacks fixture")
	}
	specification, err := ResolveRegisteredFixtureSpecification(*item.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	buildsAfterWarmup := reachabilityProfileRegistryBuilds.Load()
	for range 33 {
		if _, err := ResolveRegisteredFixtureSpecification(*item.Fixture); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRegisteredFixtureFile(specification.Files[0]); err != nil {
			t.Fatal(err)
		}
	}
	if builds := reachabilityProfileRegistryBuilds.Load(); builds != buildsAfterWarmup {
		t.Fatalf("registry builds changed from %d to %d during repeated lookup", buildsAfterWarmup, builds)
	}
	tampered := specification.Files[0]
	tampered.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := ReadRegisteredFixtureFile(tampered); err == nil {
		t.Fatal("registered fixture lookup accepted a tampered declared digest")
	}
}

func TestVersionedGoBinaryFixtureEmbedsPinnedOfflineVendorTree(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	item := profileCase(t, profile, "go-binary-versioned-direct-call")
	if item.Fixture == nil {
		t.Fatal("versioned direct case lacks fixture")
	}
	specification, err := profile.ResolveFixtureSpecification(*item.Fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(specification.Files); got != 33 {
		t.Fatalf("versioned Go fixture files = %d, want 33", got)
	}
	if specification.Build == nil || len(specification.Build.Steps) != 1 || !containsBuildArg(specification.Build.Steps[0].Argv, "-mod=vendor") {
		t.Fatalf("versioned Go fixture does not force vendor build: %+v", specification.Build)
	}
	want := map[string]string{
		"go_binary_versioned/vendor/modules.txt":                                    "sha256:c15855252540dbe868184237cd60a1c23dcb20cea48c40c94502a490c137208d",
		"go_binary_versioned/vendor/golang.org/x/net/LICENSE":                       "sha256:911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
		"go_binary_versioned/vendor/golang.org/x/text/unicode/norm/tables17.0.0.go": "sha256:dade3c78c0b36426a6966f46926f2ab61c484ae425feb175a07fbe1ee8f855fa",
	}
	vendorFiles, vendorBytes := 0, int64(0)
	for _, file := range specification.Files {
		if strings.HasPrefix(file.Path, "go_binary_versioned/vendor/") {
			vendorFiles++
			vendorBytes += file.Size
		}
		if digest, found := want[file.Path]; found && file.Digest != digest {
			t.Fatalf("vendor file %q digest = %q, want %q", file.Path, file.Digest, digest)
		}
	}
	if vendorFiles != 30 || vendorBytes != 1_872_722 {
		t.Fatalf("vendor tree = %d files / %d bytes, want 30 / 1872722", vendorFiles, vendorBytes)
	}
	for path := range want {
		found := false
		for _, file := range specification.Files {
			if file.Path == path {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("versioned Go fixture omits vendor file %q", path)
		}
	}
}

func TestVersionedGoBinaryFixtureLocatorsPointToTargetCalls(t *testing.T) {
	input, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, caseID := range []string{
		"go-binary-versioned-direct-call",
		"go-binary-versioned-retained-but-uncalled",
		"go-binary-versioned-retained-and-called",
		"go-binary-versioned-indirect-function-value-call",
	} {
		t.Run(caseID, func(t *testing.T) {
			item := profileCase(t, profile, caseID)
			if item.Fixture == nil {
				t.Fatal("fixture is missing")
			}
			specification, err := profile.ResolveFixtureSpecification(*item.Fixture)
			if err != nil {
				t.Fatal(err)
			}
			if len(specification.Subjects) != 1 {
				t.Fatalf("subjects = %d, want 1", len(specification.Subjects))
			}
			var source FixtureFile
			for _, entry := range specification.Entries {
				if entry.Role != FixtureEntrySource {
					continue
				}
				for _, file := range specification.Files {
					if file.Path == entry.Path {
						source = file
						break
					}
				}
			}
			if source.Path == "" {
				t.Fatal("source fixture file is missing")
			}
			contents, err := profile.ReadFixtureFile(source)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(contents), "\n")
			line := specification.Subjects[0].Locator.Line
			if line < 1 || line > len(lines) || !strings.Contains(lines[line-1], "idna.ToASCII") {
				t.Fatalf("locator line %d = %q, want idna.ToASCII call", line, lineAt(lines, line))
			}
		})
	}
}

func TestRegisteredFixtureFileRetainsLegacySourceBytes(t *testing.T) {
	legacy := DefaultFixtureManifest()
	if len(legacy.Fixtures) == 0 || len(legacy.Fixtures[0].Files) == 0 {
		t.Fatal("legacy fixture manifest is empty")
	}
	file := legacy.Fixtures[0].Files[0]
	want, err := ReadFixtureFile(file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadRegisteredFixtureFile(file)
	if err != nil {
		t.Fatalf("registered legacy fixture lookup: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("registered legacy fixture %q changed bytes", file.Path)
	}
	successorInput, err := GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	successor, err := ResolveReachabilityProfile(successorInput)
	if err != nil {
		t.Fatal(err)
	}
	fromSuccessor, err := successor.ReadFixtureFile(file)
	if err != nil {
		t.Fatalf("successor profile rejected inherited fixture %q: %v", file.Path, err)
	}
	if string(fromSuccessor) != string(want) {
		t.Fatalf("successor profile changed inherited fixture %q", file.Path)
	}
}

func profileEnabledCellCount(profile ReachabilityProfile) int {
	cohorts := make(map[string]ProductionCohort, len(profile.Inventory.Cohorts))
	for _, cohort := range profile.Inventory.Cohorts {
		cohorts[cohortKey(cohort.ID, cohort.Mode)] = cohort
	}
	count := 0
	for _, item := range profile.Corpus.Cases {
		for _, binding := range cohorts[cohortKey(item.CohortID, item.ModeID)].Bindings {
			if binding.State == BindingEnabled {
				count++
			}
		}
	}
	return count
}

func profileCase(t *testing.T, profile ReachabilityProfile, id string) ContractCase {
	t.Helper()
	for _, item := range profile.Corpus.Cases {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("profile %q has no case %q", profile.ID, id)
	return ContractCase{}
}

func containsBuildArg(argv []string, want string) bool {
	for _, arg := range argv {
		if arg == want {
			return true
		}
	}
	return false
}

func lineAt(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

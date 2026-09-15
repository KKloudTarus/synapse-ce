package scabench

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type sourceNativeComparator struct {
	relations map[string]int
	requests  []ports.NativeVersionComparisonRequest
}

func (comparator *sourceNativeComparator) CompareNativeVersion(_ context.Context, request ports.NativeVersionComparisonRequest) (ports.NativeVersionComparisonResult, error) {
	comparator.requests = append(comparator.requests, request)
	relation, exists := comparator.relations[request.RightEVR]
	if !exists {
		return ports.NativeVersionComparisonResult{}, fmt.Errorf("unexpected fixed EVR %q", request.RightEVR)
	}
	return ports.NativeVersionComparisonResult{Relation: relation, ExecutionDigest: bench.SHA256Digest([]byte(request.LeftEVR + "\n" + request.RightEVR))}, nil
}

func TestBuildSourceNativeEvidenceUsesSupportedTrueORBranchWithoutPoisoning(t *testing.T) {
	oval := sourceOVAL(`<criteria operator="OR"><criteria operator="AND"><criterion test_ref="test-good"/></criteria><criteria operator="AND"><criterion test_ref="test-unsupported"/></criteria></criteria>`, `<dpkginfo_test id="test-good" check="all" check_existence="at_least_one_exists"><object object_ref="object-good"/><state state_ref="state-good"/></dpkginfo_test><dpkginfo_test id="test-unsupported" check="all"><object object_ref="object-good"/><state state_ref="state-unsupported"/></dpkginfo_test>`, `<dpkginfo_object id="object-good"><name>pkg</name><arch>amd64</arch></dpkginfo_object>`, `<dpkginfo_state id="state-good" operator="AND"><evr operation="less than">2</evr></dpkginfo_state><dpkginfo_state id="state-unsupported" operator="OR"><evr operation="less than">3</evr></dpkginfo_state>`)
	comparator := &sourceNativeComparator{relations: map[string]int{"2": -1}}
	source, native, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), comparator)
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected {
		t.Fatalf("source evidence = %+v", source)
	}
	if len(native.Targets) != 1 || len(native.Targets[0].Comparisons) != 1 || native.Targets[0].Comparisons[0].FixedEVR != "2" {
		t.Fatalf("native evidence = %+v", native)
	}
	if _, err := bench.BuildOracleCandidate(sourceFixtureFreeze(t, oval), source); err != nil {
		t.Fatalf("scanner-free candidate rejected a complete supported affected branch: %v", err)
	}
}

func TestBuildSourceNativeEvidenceORRequiresCompleteEvidenceForFixed(t *testing.T) {
	tests := []struct {
		name            string
		criteria        string
		tests           string
		states          string
		relations       map[string]int
		wantTruth       bench.Truth
		wantUnsupported bool
		wantRecords     int
	}{
		{
			name: "supported true and fixed sibling", criteria: `<criteria operator="OR"><criterion test_ref="test-affected"/><criterion test_ref="test-fixed"/></criteria>`,
			tests:     sourceTest("test-affected", "object-a", "state-affected") + sourceTest("test-fixed", "object-a", "state-fixed"),
			states:    sourceState("state-affected", "AND", "less than", "2") + sourceState("state-fixed", "AND", "less than", "1"),
			relations: map[string]int{"2": -1, "1": 0}, wantTruth: bench.TruthAffected, wantRecords: 1,
		},
		{
			name: "all applicable false", criteria: `<criteria operator="OR"><criterion test_ref="test-fixed-a"/><criterion test_ref="test-fixed-b"/></criteria>`,
			tests:     sourceTest("test-fixed-a", "object-a", "state-fixed-a") + sourceTest("test-fixed-b", "object-a", "state-fixed-b"),
			states:    sourceState("state-fixed-a", "AND", "less than", "1") + sourceState("state-fixed-b", "AND", "less than", "0"),
			relations: map[string]int{"1": 0, "0": 1}, wantTruth: bench.TruthFixed, wantRecords: 2,
		},
		{
			name: "unsupported without true", criteria: `<criteria operator="OR"><criterion test_ref="test-fixed"/><criterion test_ref="test-unsupported"/></criteria>`,
			tests:     sourceTest("test-fixed", "object-a", "state-fixed") + sourceTest("test-unsupported", "object-a", "state-unsupported"),
			states:    sourceState("state-fixed", "AND", "less than", "1") + sourceState("state-unsupported", "OR", "less than", "2"),
			relations: map[string]int{"1": 0}, wantUnsupported: true, wantRecords: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oval := sourceOVAL(test.criteria, test.tests, sourceObject("object-a", "pkg"), test.states)
			source, native, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: test.relations})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(native.Targets[0].Comparisons); got != test.wantRecords {
				t.Fatalf("native comparison records = %d, want %d", got, test.wantRecords)
			}
			if test.wantUnsupported {
				if len(source.Cases) != 0 || len(source.Unsupported) == 0 {
					t.Fatalf("source evidence did not retain the blocking unsupported branch: %+v", source)
				}
				if _, err := bench.BuildOracleCandidate(sourceFixtureFreeze(t, oval), source); err == nil {
					t.Fatal("scanner-free candidate accepted fixed evidence with an unsupported applicable branch")
				}
				return
			}
			if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != test.wantTruth {
				t.Fatalf("source evidence = %+v, want %q", source, test.wantTruth)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceFailsClosedForUnsupportedAndAmbiguousOVALSemantics(t *testing.T) {
	tests := []struct {
		name      string
		criteria  string
		tests     string
		objects   string
		states    string
		relations map[string]int
		pkg       bench.SourceEvidencePackage
	}{
		{name: "negation", criteria: `<criteria negate="true"><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "less than", "2"), relations: map[string]int{"2": -1}},
		{name: "case insensitive negation", criteria: `<criteria negate="TRUE"><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "less than", "2"), relations: map[string]int{"2": -1}},
		{name: "unknown negation", criteria: `<criteria negate="sometimes"><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "less than", "2"), relations: map[string]int{"2": -1}},
		{name: "extend definition", criteria: `<criteria><extend_definition definition_ref="missing"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "less than", "2"), relations: map[string]int{"2": -1}},
		{name: "missing state reference", criteria: `<criteria><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "missing"), objects: sourceObject("object-a", "pkg"), states: "", relations: map[string]int{"2": -1}},
		{name: "equality range", criteria: `<criteria><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "equals", "2"), relations: map[string]int{"2": -1}},
		{name: "non positive state operator", criteria: `<criteria><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "OR", "less than", "2"), relations: map[string]int{"2": -1}},
		{name: "split witness", criteria: `<criteria operator="AND"><criterion test_ref="test-a"/><criterion test_ref="test-b"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a") + sourceTest("test-b", "object-a", "state-b"), objects: sourceObject("object-a", "pkg"), states: sourceState("state-a", "AND", "less than", "2") + sourceState("state-b", "AND", "less than", "3"), relations: map[string]int{"2": -1, "3": 1}},
		{name: "source package lacks explicit mapping", criteria: `<criteria><criterion test_ref="test-a"/></criteria>`, tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "src-pkg"), states: sourceState("state-a", "AND", "less than", "2"), relations: map[string]int{"2": -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkg := test.pkg
			if pkg.Name == "" {
				pkg = sourceEvidencePackage("pkg", "1", "pkg", "1")
			}
			source, _, err := buildSourceEvidenceFixture(t, sourceOVAL(test.criteria, test.tests, test.objects, test.states), pkg, &sourceNativeComparator{relations: test.relations})
			if err != nil {
				if test.name == "extend definition" || test.name == "source package lacks explicit mapping" {
					return
				}
				t.Fatalf("build source evidence: %v", err)
			}
			if len(source.Unsupported) == 0 {
				t.Fatal("source builder silently omitted unsupported or ambiguous vendor OVAL semantics")
			}
			if _, err := bench.BuildOracleCandidate(sourceFixtureFreeze(t, sourceOVAL(test.criteria, test.tests, test.objects, test.states)), source); err == nil {
				t.Fatal("scanner-free candidate accepted unsupported or ambiguous vendor OVAL semantics")
			}
		})
	}
}

func TestBuildSourceNativeEvidenceNormalizesRepeatedUnsupportedBranches(t *testing.T) {
	pkg := sourceEvidencePackage("pkg", "1", "pkg", "1")
	oval := sourceOVAL(
		`<criteria operator="AND"><criterion test_ref="test-bad"/><criterion test_ref="test-bad"/></criteria>`,
		sourceTest("test-bad", "object-a", "state-bad"),
		sourceObject("object-a", "pkg"),
		sourceState("state-bad", "OR", "less than", "2"),
	)
	source, _, err := buildSourceEvidenceFixture(t, oval, pkg, &sourceNativeComparator{relations: map[string]int{}})
	if err != nil {
		t.Fatalf("build source evidence: %v", err)
	}
	if len(source.Cases) != 0 || len(source.Unsupported) != 1 {
		t.Fatalf("source evidence = %+v", source)
	}
	if _, err := bench.BuildOracleCandidate(sourceFixtureFreeze(t, oval), source); err == nil {
		t.Fatal("scanner-free candidate accepted unsupported vendor OVAL semantics")
	}
}

func TestNormalizeSourceEvidenceDiagnosticsRejectsConflictingPayloads(t *testing.T) {
	base := bench.SourceEvidenceDiagnostic{
		TargetID:     "target-a",
		Component:    bench.Component{PURL: "pkg:deb/debian/pkg@1", Version: "1"},
		DefinitionID: "definition-a",
		ElementKind:  "state",
		ElementID:    "state-a",
		Reason:       "unsupported state",
	}
	changedReason := base
	changedReason.Reason = "different unsupported state"
	changedVersion := base
	changedVersion.Component.Version = "2"

	tests := []struct {
		name           string
		diagnostics    []bench.SourceEvidenceDiagnostic
		wantConflict   bool
		wantNormalized int
	}{
		{name: "exact duplicates collapse", diagnostics: []bench.SourceEvidenceDiagnostic{base, base}, wantNormalized: 1},
		{name: "different reason conflicts", diagnostics: []bench.SourceEvidenceDiagnostic{base, changedReason}, wantConflict: true},
		{name: "different component version conflicts", diagnostics: []bench.SourceEvidenceDiagnostic{base, changedVersion}, wantConflict: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := normalizeSourceEvidenceDiagnostics(tc.diagnostics)
			if tc.wantConflict {
				if err == nil {
					t.Fatal("conflicting diagnostics were normalized")
				}
				if !strings.Contains(err.Error(), "conflicting source evidence diagnostics") {
					t.Fatalf("conflicting diagnostics error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(normalized) != tc.wantNormalized {
				t.Fatalf("normalized diagnostics = %+v", normalized)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceAcceptsCaseInsensitiveFalseNegation(t *testing.T) {
	oval := sourceOVAL(`<criteria negate="FALSE"><criterion test_ref="test-a"/></criteria>`, sourceTest("test-a", "object-a", "state-a"), sourceObject("object-a", "pkg"), sourceState("state-a", "AND", "less than", "2"))
	source, _, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected {
		t.Fatalf("false negation source evidence = %+v", source)
	}
}

func TestBuildSourceNativeEvidenceUsesExplicitSourceEVR(t *testing.T) {
	oval := sourceOVAL(`<criteria><criterion test_ref="test-source"/></criteria>`, sourceTest("test-source", "object-source", "state-source"), sourceObject("object-source", "src-pkg"), sourceState("state-source", "AND", "less than", "2"))
	comparator := &sourceNativeComparator{relations: map[string]int{"2": -1}}
	pkg := sourceEvidencePackage("pkg", "1+b1", "src-pkg", "1+b1")
	_, native, err := buildSourceEvidenceFixture(t, oval, pkg, comparator)
	if err != nil {
		t.Fatal(err)
	}
	if len(comparator.requests) != 1 || comparator.requests[0].LeftEVR != "1+b1" || native.Targets[0].Comparisons[0].PackageIdentity != "source:src-pkg" {
		t.Fatalf("source native comparison = %+v/%+v", comparator.requests, native)
	}
}

func TestBuildSourceNativeEvidenceResolvesApplicableExtendedDefinitions(t *testing.T) {
	oval := `<oval_definitions><definitions>
		<definition id="definition-a"><metadata><reference source="CVE" ref_id="CVE-2026-0001"/></metadata><criteria><extend_definition definition_ref="definition-b"/></criteria></definition>
		<definition id="definition-b"><metadata><reference source="CVE" ref_id="CVE-2026-0001"/></metadata><criteria><criterion test_ref="test-a"/></criteria></definition>
		</definitions><tests>` + sourceTest("test-a", "object-a", "state-a") + `</tests><objects>` + sourceObject("object-a", "pkg") + `</objects><states>` + sourceState("state-a", "AND", "less than", "2") + `</states></oval_definitions>`
	source, _, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected {
		t.Fatalf("extended source evidence = %+v", source)
	}
}

func TestBuildSourceNativeEvidenceIgnoresNonApplicableGuards(t *testing.T) {
	oval := sourceOVAL(`<criteria operator="OR"><criterion test_ref="test-wrong-arch"/><criterion test_ref="test-applicable"/></criteria>`, sourceTest("test-wrong-arch", "object-wrong-arch", "state-a")+sourceTest("test-applicable", "object-applicable", "state-a"), `<dpkginfo_object id="object-wrong-arch"><name>pkg</name><arch>arm64</arch></dpkginfo_object>`+sourceObject("object-applicable", "pkg"), sourceState("state-a", "AND", "less than", "2"))
	source, native, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected || len(native.Targets[0].Comparisons) != 1 {
		t.Fatalf("guarded source evidence = %+v/%+v", source, native)
	}
}

func TestBuildSourceNativeEvidenceDoesNotPoisonPackageWithUnrelatedUnsupportedBranch(t *testing.T) {
	oval := sourceOVAL(
		`<criteria operator="OR"><criterion test_ref="test-other"/><criterion test_ref="test-applicable"/></criteria>`,
		sourceTest("test-other", "object-other", "state-unsupported")+sourceTest("test-applicable", "object-applicable", "state-applicable"),
		sourceObject("object-other", "other-package")+sourceObject("object-applicable", "pkg"),
		sourceState("state-unsupported", "OR", "less than", "3")+sourceState("state-applicable", "AND", "less than", "2"),
	)
	source, native, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected || len(native.Targets) != 1 || len(native.Targets[0].Comparisons) != 1 {
		t.Fatalf("source evidence let an unrelated malformed branch poison this package: %+v/%+v", source, native)
	}
}

func TestBuildSourceNativeEvidenceRetainsMalformedTestWhenAnyReferencedObjectMatches(t *testing.T) {
	oval := sourceOVAL(
		`<criteria><criterion test_ref="test-ambiguous"/></criteria>`,
		`<dpkginfo_test id="test-ambiguous" check="all"><object object_ref="object-other"/><object object_ref="object-selected"/><state state_ref="state-a"/></dpkginfo_test>`,
		sourceObject("object-other", "other-package")+sourceObject("object-selected", "pkg"),
		sourceState("state-a", "AND", "less than", "2"),
	)
	source, _, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Cases) != 0 || len(source.Unsupported) != 1 || source.Unsupported[0].ElementKind != "test" || source.Unsupported[0].ElementID != "test-ambiguous" {
		t.Fatalf("source evidence silently omitted matching malformed test: %+v", source)
	}
}

func TestBuildSourceNativeEvidenceRetainsMalformedObjectWhenAnyPackageNameMatches(t *testing.T) {
	oval := sourceOVAL(
		`<criteria><criterion test_ref="test-a"/></criteria>`,
		sourceTest("test-a", "object-ambiguous", "state-a"),
		`<dpkginfo_object id="object-ambiguous"><name>other-package</name><name>pkg</name><arch>amd64</arch></dpkginfo_object>`,
		sourceState("state-a", "AND", "less than", "2"),
	)
	source, _, err := buildSourceEvidenceFixture(t, oval, sourceEvidencePackage("pkg", "1", "pkg", "1"), &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Cases) != 0 || len(source.Unsupported) != 1 || source.Unsupported[0].ElementKind != "object" || source.Unsupported[0].ElementID != "object-ambiguous" {
		t.Fatalf("source evidence silently omitted matching malformed object: %+v", source)
	}
}

func TestBuildSourceNativeEvidenceRejectsMisboundPackageSelection(t *testing.T) {
	oval := sourceOVAL(`<criteria><criterion test_ref="test-a"/></criteria>`, sourceTest("test-a", "object-a", "state-a"), sourceObject("object-a", "pkg"), sourceState("state-a", "AND", "less than", "2"))
	misbound := sourceEvidencePackage("different", "1", "different", "1")
	misbound.Component = bench.Component{PURL: "pkg:deb/debian/pkg@1?arch=amd64&distro=debian-12&upstream=different@1", Version: "1"}
	if _, _, err := buildSourceEvidenceFixture(t, oval, misbound, &sourceNativeComparator{relations: map[string]int{"2": -1}}); err == nil {
		t.Fatal("source evidence accepted an arbitrary package-to-component mapping")
	}
}

func TestBuildSourceNativeEvidenceRejectsSourceMappingOutsideComponentPURL(t *testing.T) {
	oval := sourceOVAL(`<criteria><criterion test_ref="test-a"/></criteria>`, sourceTest("test-a", "object-a", "state-a"), sourceObject("object-a", "src-pkg"), sourceState("state-a", "AND", "less than", "2"))
	tests := []struct {
		name string
		pkg  bench.SourceEvidencePackage
	}{
		{
			name: "missing qualifiers",
			pkg: bench.SourceEvidencePackage{
				Name: "pkg", Component: bench.Component{PURL: "pkg:deb/debian/pkg@1?arch=amd64&distro=debian-12", Version: "1"},
				Architecture: "amd64", Distro: "debian-12", Release: "12", SourcePackage: "src-pkg", SourceEVR: "1",
			},
		},
		{
			name: "mismatched source name",
			pkg:  sourceEvidencePackage("pkg", "1", "src-pkg", "1"),
		},
		{
			name: "duplicate upstream qualifier",
			pkg:  sourceEvidencePackage("pkg", "1", "src-pkg", "1"),
		},
		{
			name: "unescaped upstream plus",
			pkg:  sourceEvidencePackage("pkg", "1", "src-pkg", "1+1"),
		},
	}
	tests[1].pkg.SourcePackage = "arbitrary-source"
	tests[2].pkg.Component.PURL = "pkg:deb/debian/pkg@1?arch=amd64&distro=debian-12&upstream=src-pkg@1&upstream=src-pkg@1"
	tests[3].pkg.Component.PURL = "pkg:deb/debian/pkg@1?arch=amd64&distro=debian-12&upstream=src-pkg@1+1"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := buildSourceEvidenceFixture(t, oval, test.pkg, &sourceNativeComparator{relations: map[string]int{"2": -1}}); err == nil {
				t.Fatal("source evidence accepted a source mapping not bound exactly by the component purl")
			}
		})
	}
}

func TestSourceEvidencePlanValidatesRealPURLQualifierBindings(t *testing.T) {
	valid := bench.SourceEvidencePlan{
		SchemaVersion:      bench.SourceEvidencePlanSchemaVersion,
		CycleID:            "source-purl-binding",
		SourceFreezeDigest: sourceTestDigest('a'),
		Targets: []bench.SourceEvidenceTarget{{
			TargetID: "rpm-target", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "rpm", Product: "sles", Release: "15.6", Architecture: "x86_64",
			Packages: []bench.SourceEvidencePackage{{
				Name: "openssl", Component: bench.Component{PURL: "pkg:rpm/suse/openssl@3.1?arch=x86_64&distro=sles-15.6&upstream=openssl-3.1-1.src.rpm", Version: "3.1"},
				Architecture: "x86_64", Distro: "sles-15.6", Release: "15.6", SourcePackage: "openssl", SourceEVR: "3.1-1",
			}},
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("real rpm purl source mapping: %v", err)
	}
	tests := []struct {
		name string
		edit func(*bench.SourceEvidencePlan)
	}{
		{name: "duplicate architecture", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Component.PURL = "pkg:rpm/suse/openssl@3.1?arch=x86_64&arch=x86_64&distro=sles-15.6&upstream=openssl-3.1-1.src.rpm"
		}},
		{name: "architecture mismatch", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Component.PURL = "pkg:rpm/suse/openssl@3.1?arch=amd64&distro=sles-15.6&upstream=openssl-3.1-1.src.rpm"
		}},
		{name: "package distro must match purl", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Distro = "sles"
		}},
		{name: "package release must match target", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Release = "15.5"
		}},
		{name: "distro release mismatch", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Component.PURL = "pkg:rpm/suse/openssl@3.1?arch=x86_64&distro=sles-15.5&upstream=openssl-3.1-1.src.rpm"
		}},
		{name: "invalid rpm upstream", edit: func(plan *bench.SourceEvidencePlan) {
			plan.Targets[0].Packages[0].Component.PURL = "pkg:rpm/suse/openssl@3.1?arch=x86_64&distro=sles-15.6&upstream=openssl@3.1-1"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := valid
			plan.Targets = append([]bench.SourceEvidenceTarget(nil), valid.Targets...)
			plan.Targets[0].Packages = append([]bench.SourceEvidencePackage(nil), valid.Targets[0].Packages...)
			test.edit(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatal("source evidence plan accepted a PURL mapping that is not target and source bound")
			}
		})
	}
}

func TestBoundedOVALBytesWithLimitsSupportsVendorEncodingsDeterministically(t *testing.T) {
	payload := []byte("vendor OVAL payload\n")
	cases := []struct {
		name string
		body []byte
	}{
		{name: "plain", body: payload},
		{name: "gzip", body: gzipOVALBytes(t, payload)},
		{name: "bzip2", body: bzip2OVALBytes(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := boundedOVALBytesWithLimits(tc.body, 128, len(payload))
			if err != nil {
				t.Fatal(err)
			}
			second, err := boundedOVALBytesWithLimits(tc.body, 128, len(payload))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, payload) || !bytes.Equal(second, payload) || !bytes.Equal(first, second) {
				t.Fatalf("decoded payloads = %q and %q, want %q", first, second, payload)
			}
		})
	}
}

func TestBoundedOVALBytesWithLimitsRejectsEmptyAndOversizedInput(t *testing.T) {
	for _, tc := range []struct {
		name            string
		body            []byte
		compressedLimit int
	}{
		{name: "empty", body: nil, compressedLimit: 1},
		{name: "over-compressed", body: []byte("12345"), compressedLimit: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := boundedOVALBytesWithLimits(tc.body, tc.compressedLimit, 16); err == nil {
				t.Fatal("expected input to be rejected")
			}
		})
	}
}

func TestBoundedOVALBytesWithLimitsRejectsOverDecompressedInput(t *testing.T) {
	payload := []byte("vendor OVAL payload\n")
	body := gzipOVALBytes(t, payload)
	if _, err := boundedOVALBytesWithLimits(body, len(body), len(payload)-1); err == nil {
		t.Fatal("expected expanded input to be rejected")
	}
}

func TestBoundedOVALBytesWithLimitsRejectsMalformedAndTruncatedStreams(t *testing.T) {
	payload := []byte("vendor OVAL payload\n")
	gzipBody := gzipOVALBytes(t, payload)
	bzip2Body := bzip2OVALBytes(t)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "malformed gzip", body: []byte{0x1f, 0x8b, 0x08}},
		{name: "malformed bzip2", body: []byte("BZh9not-a-bzip2-stream")},
		{name: "truncated gzip", body: gzipBody[:len(gzipBody)-4]},
		{name: "truncated bzip2", body: bzip2Body[:len(bzip2Body)-4]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := boundedOVALBytesWithLimits(tc.body, 128, len(payload)); err == nil {
				t.Fatal("expected compressed stream to be rejected")
			}
		})
	}
}

func TestOVALInputLimitsPreserveVendorFeedHeadroom(t *testing.T) {
	if maxOVALCompressedBytes != 96<<20 {
		t.Fatalf("compressed limit = %d, want %d", maxOVALCompressedBytes, 96<<20)
	}
	if maxOVALDecompressedBytes != 1536<<20 {
		t.Fatalf("decompressed limit = %d, want %d", maxOVALDecompressedBytes, 1536<<20)
	}
}

func gzipOVALBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func bzip2OVALBytes(t *testing.T) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWaj4MuAAAAlXgAAQQAAgBIEAJgXRICAAIoDamTMoUwAE0FcDMJqKKKMOn+LuSKcKEhUfBlwA")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func buildSourceEvidenceFixture(t *testing.T, oval string, pkg bench.SourceEvidencePackage, comparator *sourceNativeComparator) (bench.SourceCaseEvidenceSet, bench.NativeEvidenceSet, error) {
	t.Helper()
	selection := bench.SourceEvidenceTarget{TargetID: "target-a", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "deb", Release: "12", Product: "debian", Architecture: "amd64", Packages: []bench.SourceEvidencePackage{pkg}}
	return buildSourceEvidenceForTarget(t, oval, selection, []bench.Component{pkg.Component}, comparator)
}

func buildSourceEvidenceForTarget(t *testing.T, oval string, selection bench.SourceEvidenceTarget, components []bench.Component, comparator *sourceNativeComparator) (bench.SourceCaseEvidenceSet, bench.NativeEvidenceSet, error) {
	t.Helper()
	root := t.TempDir()
	freeze := sourceFixtureFreeze(t, oval)
	if err := os.MkdirAll(filepath.Join(root, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sources", "vendor.xml"), []byte(oval), 0o600); err != nil {
		t.Fatal(err)
	}
	targetDigest := sourceTestDigest('a')
	catalog := bench.Catalog{SchemaVersion: bench.CatalogSchemaVersion, Revision: "source-evidence", Targets: []bench.Target{{ID: selection.TargetID, OCIRef: "registry.example.test/target@" + targetDigest, Digest: targetDigest, SBOMDigest: sourceTestDigest('b'), Components: components}}}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	plan := bench.SourceEvidencePlan{SchemaVersion: bench.SourceEvidencePlanSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []bench.SourceEvidenceTarget{selection}}
	return BuildSourceNativeEvidence(context.Background(), root, freeze, catalog, plan, func(bench.Target) (ports.NativeVersionComparator, error) { return comparator, nil })
}

func sourceFixtureFreeze(t *testing.T, oval string) bench.SourceFreeze {
	t.Helper()
	asset := bench.ContentReference{Locator: "sources/vendor.xml", Digest: bench.SHA256Digest([]byte(oval)), Size: int64(len(oval))}
	digest, err := bench.DigestContentReferences([]bench.ContentReference{asset})
	if err != nil {
		t.Fatal(err)
	}
	return bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "source-evidence", Assets: []bench.ContentReference{asset}, ContentDigest: digest}
}

func sourceTestDigest(marker byte) string { return "sha256:" + strings.Repeat(string(marker), 64) }

func sourceEvidencePackage(name, version, sourceName, sourceEVR string) bench.SourceEvidencePackage {
	return bench.SourceEvidencePackage{
		Name: name, Component: bench.Component{PURL: "pkg:deb/debian/" + name + "@" + version + "?arch=amd64&distro=debian-12&upstream=" + url.QueryEscape(sourceName) + "@" + url.QueryEscape(sourceEVR), Version: version},
		Architecture: "amd64", Distro: "debian-12", Release: "12", SourcePackage: sourceName, SourceEVR: sourceEVR,
	}
}

func sourceOVAL(criteria, tests, objects, states string) string {
	return `<oval_definitions><definitions><definition id="definition-a"><metadata><reference source="CVE" ref_id="CVE-2026-0001"/></metadata>` + criteria + `</definition></definitions><tests>` + tests + `</tests><objects>` + objects + `</objects><states>` + states + `</states></oval_definitions>`
}

func sourceTest(id, object, state string) string {
	return `<dpkginfo_test id="` + id + `" check="all" check_existence="at_least_one_exists"><object object_ref="` + object + `"/><state state_ref="` + state + `"/></dpkginfo_test>`
}

func sourceObject(id, name string) string {
	return `<dpkginfo_object id="` + id + `"><name>` + name + `</name><arch>amd64</arch></dpkginfo_object>`
}

func sourceState(id, operator, operation, evr string) string {
	return `<dpkginfo_state id="` + id + `" operator="` + operator + `"><evr datatype="debian_evr_string" operation="` + operation + `">` + evr + `</evr></dpkginfo_state>`
}

func sourceEvidenceRPMPackage(name, evr string) bench.SourceEvidencePackage {
	return bench.SourceEvidencePackage{
		Name: name, Component: bench.Component{PURL: "pkg:rpm/suse/" + name + "@" + url.PathEscape(evr) + "?arch=x86_64&distro=sles-15.6&upstream=" + url.QueryEscape(name+"-"+evr+".src.rpm"), Version: evr},
		Architecture: "x86_64", Distro: "sles-15.6", Release: "15.6", SourcePackage: name, SourceEVR: evr,
	}
}

func sourceSLESSelection(pkg bench.SourceEvidencePackage) bench.SourceEvidenceTarget {
	return bench.SourceEvidenceTarget{TargetID: "target-a", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "rpm", Product: "sles", Release: "15.6", Architecture: "x86_64", Packages: []bench.SourceEvidencePackage{pkg}}
}

func sourceSLESReleaseComponent(version string) bench.Component {
	return bench.Component{PURL: "pkg:rpm/suse/sles-release@" + url.PathEscape(version) + "?arch=x86_64&distro=sles-15.6&upstream=sles-release-" + url.QueryEscape(version) + ".src.rpm", Version: version}
}

func evaluateSourceOVAL(t *testing.T, oval string, target bench.Target, selection bench.SourceEvidenceTarget, pkg bench.SourceEvidencePackage, comparator *sourceNativeComparator) ovalResult {
	t.Helper()
	document, err := parseVendorOVAL([]byte(oval))
	if err != nil {
		t.Fatal(err)
	}
	definition, exists := document.definitions["definition-a"]
	if !exists {
		t.Fatal("fixture definition is missing")
	}
	result, err := (ovalEvaluator{ctx: context.Background(), document: document, target: target, selection: selection, pkg: pkg, comparator: comparator, definitionStack: map[string]struct{}{"definition-a": {}}}).evaluate(definition.criteria)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBuildSourceNativeEvidenceRecognizesDebianCurrentGuards(t *testing.T) {
	pkg := sourceEvidencePackage("pkg", "1", "pkg", "1")
	selection := bench.SourceEvidenceTarget{TargetID: "target-a", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "deb", Product: "debian", Release: "12", Architecture: "amd64", Packages: []bench.SourceEvidencePackage{pkg}}
	target := bench.Target{ID: "target-a", Digest: sourceTestDigest('a'), Components: []bench.Component{pkg.Component}}
	cases := []struct {
		name            string
		release         string
		releaseObject   string
		unameObject     string
		wantApplicable  bool
		wantUnsupported bool
	}{
		{name: "release guard matches", release: "12", releaseObject: sourceDebianReleaseObject("release-object"), unameObject: `<uname_object id="uname-object"/>`, wantApplicable: true},
		{name: "release mismatch is non-applicable", release: "11", releaseObject: sourceDebianReleaseObject("release-object"), unameObject: `<uname_object id="uname-object"/>`},
		{name: "malformed release guard is unsupported", release: "12", releaseObject: `<textfilecontent54_object id="release-object"><path>/etc</path><filename>debian_version</filename><pattern operation="equals">(\d+)\.\d</pattern><instance datatype="int">1</instance></textfilecontent54_object>`, unameObject: `<uname_object id="uname-object"/>`, wantApplicable: true, wantUnsupported: true},
		{name: "uname variant is unsupported", release: "12", releaseObject: sourceDebianReleaseObject("release-object"), unameObject: `<uname_object id="uname-object"><machine>x86_64</machine></uname_object>`, wantApplicable: true, wantUnsupported: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oval := sourceDebianGuardOVAL(tc.release, tc.releaseObject, tc.unameObject)
			result := evaluateSourceOVAL(t, oval, target, selection, pkg, &sourceNativeComparator{relations: map[string]int{"2": -1}})
			if result.applicable != tc.wantApplicable || (len(result.unsupported) != 0) != tc.wantUnsupported {
				t.Fatalf("guard result = %+v", result)
			}
			if tc.wantUnsupported || !tc.wantApplicable {
				return
			}
			source, native, err := buildSourceEvidenceForTarget(t, oval, selection, []bench.Component{pkg.Component}, &sourceNativeComparator{relations: map[string]int{"2": -1}})
			if err != nil {
				t.Fatal(err)
			}
			if len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected || len(native.Targets[0].Comparisons) != 1 {
				t.Fatalf("source/native evidence = %+v/%+v", source, native)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceEvaluatesSLESReleaseGuards(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "1:1-1")
	selection := sourceSLESSelection(pkg)
	cases := []struct {
		name            string
		components      []bench.Component
		wantApplicable  bool
		wantUnsupported bool
	}{
		{name: "exact release component matches", components: []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1")}, wantApplicable: true},
		{name: "release mismatch is non-applicable", components: []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.5-1")}},
		{name: "release component is missing", components: []bench.Component{pkg.Component}, wantApplicable: true, wantUnsupported: true},
		{name: "duplicate release components fail closed", components: []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1"), sourceSLESReleaseComponent("0:15.6-2")}, wantApplicable: true, wantUnsupported: true},
		{name: "non-rpm release component fails closed", components: []bench.Component{pkg.Component, {PURL: "pkg:deb/suse/sles-release@15.6-1", Version: "15.6-1"}}, wantApplicable: true, wantUnsupported: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := bench.Target{ID: "target-a", Digest: sourceTestDigest('a'), Components: tc.components}
			result := evaluateSourceOVAL(t, sourceSLESGuardOVAL(`<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test"/></criteria>`, `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, `<rpminfo_state id="pkg-state"><evr operation="less than">2</evr></rpminfo_state>`), target, selection, pkg, &sourceNativeComparator{relations: map[string]int{"2": -1}})
			if result.applicable != tc.wantApplicable || (len(result.unsupported) != 0) != tc.wantUnsupported {
				t.Fatalf("release guard result = %+v", result)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceSLESCurrentPredicates(t *testing.T) {
	cases := []struct {
		name            string
		pkgEVR          string
		criteria        string
		tests           string
		states          string
		relations       map[string]int
		wantTruth       bench.Truth
		wantUnsupported bool
		wantRecords     int
	}{
		{
			name: "single check at least one supports affected EVR", pkgEVR: "1:1-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><evr operation="less than">2</evr></rpminfo_state>`, relations: map[string]int{"2": -1}, wantTruth: bench.TruthAffected, wantRecords: 1,
		},
		{
			name: "multiple refs with check at least one remains unsupported", pkgEVR: "1:1-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><evr operation="less than">2</evr></rpminfo_state>`, relations: map[string]int{}, wantUnsupported: true,
		},
		{
			name: "fixed EVR remains fixed", pkgEVR: "1:2-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><evr operation="less than">2</evr></rpminfo_state>`, relations: map[string]int{"2": 0}, wantTruth: bench.TruthFixed, wantRecords: 1,
		},
		{
			name: "nonzero package sentinel derives not affected", pkgEVR: "1:1-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test" comment="pkg is not affected"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one" comment="pkg is ==0"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><version operation="equals">0</version></rpminfo_state>`, relations: map[string]int{"0": 1}, wantTruth: bench.TruthNotAffected, wantRecords: 1,
		},
		{
			name: "zero package collides with sentinel", pkgEVR: "0", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test" comment="pkg is not affected"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one" comment="pkg is ==0"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><version operation="equals">0</version></rpminfo_state>`, relations: map[string]int{"0": 0}, wantUnsupported: true,
		},
		{
			name: "nonzero equality is unsupported", pkgEVR: "1:1-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test" comment="pkg is not affected"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one" comment="pkg is ==0"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><version operation="equals">1</version></rpminfo_state>`, relations: map[string]int{}, wantUnsupported: true,
		},
		{
			name: "mixed sentinel predicates are unsupported", pkgEVR: "0", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test" comment="pkg is not affected"/></criteria>`,
			tests: `<rpminfo_test id="pkg-test" check="at least one" comment="pkg is ==0"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, states: `<rpminfo_state id="pkg-state"><version operation="equals">0</version><evr operation="less than">2</evr></rpminfo_state>`, relations: map[string]int{}, wantUnsupported: true,
		},
		{
			name: "mixed fixed and not affected OR is unsupported", pkgEVR: "1:1-1", criteria: `<criteria operator="AND"><criterion test_ref="release-test"/><criteria operator="OR"><criterion test_ref="fixed-test"/><criterion test_ref="zero-test" comment="pkg is not affected"/></criteria></criteria>`,
			tests: `<rpminfo_test id="fixed-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="fixed-state"/></rpminfo_test><rpminfo_test id="zero-test" check="at least one" comment="pkg is ==0"><object object_ref="pkg-object"/><state state_ref="zero-state"/></rpminfo_test>`, states: `<rpminfo_state id="fixed-state"><evr operation="less than">1</evr></rpminfo_state><rpminfo_state id="zero-state"><version operation="equals">0</version></rpminfo_state>`, relations: map[string]int{"1": 0, "0": 1}, wantUnsupported: true, wantRecords: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := sourceEvidenceRPMPackage("pkg", tc.pkgEVR)
			selection := sourceSLESSelection(pkg)
			oval := sourceSLESGuardOVAL(tc.criteria, tc.tests, tc.states)
			components := []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1")}
			source, native, err := buildSourceEvidenceForTarget(t, oval, selection, components, &sourceNativeComparator{relations: tc.relations})
			if err != nil {
				t.Fatal(err)
			}
			if len(native.Targets) != 1 || len(native.Targets[0].Comparisons) != tc.wantRecords {
				t.Fatalf("native evidence = %+v", native)
			}
			if tc.wantUnsupported {
				if len(source.Cases) != 0 || len(source.Unsupported) == 0 {
					t.Fatalf("source evidence did not retain failure: %+v", source)
				}
				return
			}
			if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != tc.wantTruth {
				t.Fatalf("source evidence = %+v", source)
			}
			if tc.wantTruth == bench.TruthNotAffected && native.Targets[0].Comparisons[0].PredicateKind != bench.NativePredicateVersionEqualsZero {
				t.Fatalf("not-affected record is not explicit: %+v", native.Targets[0].Comparisons[0])
			}
		})
	}
}

func TestParseVendorOVALFiltersOnlyNamespaceDeclarations(t *testing.T) {
	validDebianGuards := sourceDebianGuardOVAL("12", sourceDebianReleaseObject("release-object"), `<uname_object id="uname-object"/>`)
	cases := []struct {
		name    string
		oval    string
		wantErr bool
	}{
		{name: "current Debian guard namespace declarations", oval: validDebianGuards},
		{
			name:    "qualified semantic attribute is rejected",
			oval:    sourceOVAL(`<criteria><criterion test_ref="test-a"/></criteria>`, sourceTest("test-a", "object-a", "state-a"), sourceObject("object-a", "pkg"), `<dpkginfo_state id="state-a"><evr xmlns:external="urn:external" external:datatype="debian_evr_string" operation="less than">2</evr></dpkginfo_state>`),
			wantErr: true,
		},
		{
			name:    "duplicate local semantic attribute is rejected",
			oval:    sourceOVAL(`<criteria><criterion test_ref="test-a"/></criteria>`, sourceTest("test-a", "object-a", "state-a"), sourceObject("object-a", "pkg"), `<dpkginfo_state id="state-a" xmlns:external="urn:external" external:id="state-b"><evr datatype="debian_evr_string" operation="less than">2</evr></dpkginfo_state>`),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseVendorOVAL([]byte(tc.oval))
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseVendorOVAL() error = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceAcceptsOnlyFamilyEVRDatatypes(t *testing.T) {
	debianPkg := sourceEvidencePackage("pkg", "1", "pkg", "1")
	debianSelection := bench.SourceEvidenceTarget{TargetID: "target-a", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "deb", Product: "debian", Release: "12", Architecture: "amd64", Packages: []bench.SourceEvidencePackage{debianPkg}}
	slesPkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
	slesSelection := sourceSLESSelection(slesPkg)
	cases := []struct {
		name            string
		pkg             bench.SourceEvidencePackage
		selection       bench.SourceEvidenceTarget
		components      []bench.Component
		tests           string
		objects         string
		states          string
		wantUnsupported bool
	}{
		{
			name: "Debian current datatype", pkg: debianPkg, selection: debianSelection, components: []bench.Component{debianPkg.Component},
			tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: `<dpkginfo_state id="state-a"><evr datatype="debian_evr_string" operation="less than">2</evr></dpkginfo_state>`,
		},
		{
			name: "Debian arbitrary datatype is unsupported", pkg: debianPkg, selection: debianSelection, components: []bench.Component{debianPkg.Component},
			tests: sourceTest("test-a", "object-a", "state-a"), objects: sourceObject("object-a", "pkg"), states: `<dpkginfo_state id="state-a"><evr datatype="evr_string" operation="less than">2</evr></dpkginfo_state>`, wantUnsupported: true,
		},
		{
			name: "SLES current datatype", pkg: slesPkg, selection: slesSelection, components: []bench.Component{slesPkg.Component},
			tests: `<rpminfo_test id="test-a" check="at least one"><object object_ref="object-a"/><state state_ref="state-a"/></rpminfo_test>`, objects: `<rpminfo_object id="object-a"><name>pkg</name></rpminfo_object>`, states: `<rpminfo_state id="state-a"><evr datatype="evr_string" operation="less than">2</evr></rpminfo_state>`,
		},
		{
			name: "SLES arbitrary datatype is unsupported", pkg: slesPkg, selection: slesSelection, components: []bench.Component{slesPkg.Component},
			tests: `<rpminfo_test id="test-a" check="at least one"><object object_ref="object-a"/><state state_ref="state-a"/></rpminfo_test>`, objects: `<rpminfo_object id="object-a"><name>pkg</name></rpminfo_object>`, states: `<rpminfo_state id="state-a"><evr datatype="debian_evr_string" operation="less than">2</evr></rpminfo_state>`, wantUnsupported: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oval := sourceOVAL(`<criteria><criterion test_ref="test-a"/></criteria>`, tc.tests, tc.objects, tc.states)
			source, native, err := buildSourceEvidenceForTarget(t, oval, tc.selection, tc.components, &sourceNativeComparator{relations: map[string]int{"2": -1}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantUnsupported {
				if len(source.Cases) != 0 || len(source.Unsupported) == 0 || len(native.Targets[0].Comparisons) != 0 {
					t.Fatalf("unsupported datatype evidence = %+v/%+v", source, native)
				}
				return
			}
			if len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected || len(source.Unsupported) != 0 || len(native.Targets[0].Comparisons) != 1 {
				t.Fatalf("datatype evidence = %+v/%+v", source, native)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceEvaluatesSLESArchitectureAlternation(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
	cases := []struct {
		name            string
		architecture    string
		pattern         string
		wantApplicable  bool
		wantUnsupported bool
		wantRecords     int
	}{
		{name: "exact architecture matches", architecture: "x86_64", pattern: `(aarch64|ppc64le|s390x|x86_64)`, wantApplicable: true, wantRecords: 1},
		{name: "current five architecture guard matches", architecture: "x86_64", pattern: `(aarch64|i586|ppc64le|s390x|x86_64)`, wantApplicable: true, wantRecords: 1},
		{name: "architecture mismatch is non-applicable", architecture: "armv7l", pattern: `(aarch64|ppc64le|s390x|x86_64)`},
		{name: "unknown architecture is unsupported", architecture: "x86_64", pattern: `(aarch64|mips|ppc64le|s390x|x86_64)`, wantApplicable: true, wantUnsupported: true},
		{name: "malformed pattern is unsupported", architecture: "x86_64", pattern: `aarch64|x86_64`, wantApplicable: true, wantUnsupported: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selection := sourceSLESSelection(pkg)
			selection.Architecture = tc.architecture
			oval := sourceOVAL(`<criteria><criterion test_ref="pkg-test"/></criteria>`, `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, `<rpminfo_object id="pkg-object"><name>pkg</name></rpminfo_object>`, `<rpminfo_state id="pkg-state"><arch datatype="string" operation="pattern match">`+tc.pattern+`</arch><evr datatype="evr_string" operation="less than">2</evr></rpminfo_state>`)
			target := bench.Target{ID: "target-a", Digest: sourceTestDigest('a'), Components: []bench.Component{pkg.Component}}
			result := evaluateSourceOVAL(t, oval, target, selection, pkg, &sourceNativeComparator{relations: map[string]int{"2": -1}})
			if result.applicable != tc.wantApplicable || (len(result.unsupported) != 0) != tc.wantUnsupported || len(result.records) != tc.wantRecords {
				t.Fatalf("architecture result = %+v", result)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceEvaluatesSLESEVRGreaterThan(t *testing.T) {
	cases := []struct {
		name      string
		relation  int
		wantTruth bench.Truth
	}{
		{name: "after establishes affected", relation: 1, wantTruth: bench.TruthAffected},
		{name: "before establishes fixed", relation: -1, wantTruth: bench.TruthFixed},
		{name: "equal establishes fixed", relation: 0, wantTruth: bench.TruthFixed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
			selection := sourceSLESSelection(pkg)
			oval := sourceOVAL(`<criteria><criterion test_ref="pkg-test"/></criteria>`, `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, `<rpminfo_object id="pkg-object"><name>pkg</name></rpminfo_object>`, `<rpminfo_state id="pkg-state"><arch datatype="string" operation="pattern match">(aarch64|ppc64le|s390x|x86_64)</arch><evr datatype="evr_string" operation="greater than">0:0-0</evr></rpminfo_state>`)
			source, native, err := buildSourceEvidenceForTarget(t, oval, selection, []bench.Component{pkg.Component}, &sourceNativeComparator{relations: map[string]int{"0:0-0": tc.relation}})
			if err != nil {
				t.Fatal(err)
			}
			if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != tc.wantTruth || len(native.Targets[0].Comparisons) != 1 || native.Targets[0].Comparisons[0].PredicateKind != bench.NativePredicateEVRGreaterThan {
				t.Fatalf("greater-than evidence = %+v/%+v", source, native)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceUsesNestedSLESGuardOnlyOR(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
	selection := sourceSLESSelection(pkg)
	oval := sourceOVAL(
		`<criteria operator="AND"><criteria operator="OR"><criterion test_ref="primary-release-test"/><criterion test_ref="alternate-release-test"/><criterion test_ref="unsupported-release-test"/></criteria><criteria operator="OR"><criterion test_ref="pkg-test"/></criteria></criteria>`,
		`<rpminfo_test id="primary-release-test" check="at least one"><object object_ref="primary-release-object"/><state state_ref="release-state"/></rpminfo_test><rpminfo_test id="alternate-release-test" check="at least one"><object object_ref="alternate-release-object"/><state state_ref="release-state"/></rpminfo_test><rpminfo_test id="unsupported-release-test" check="at least one"><object object_ref="primary-release-object"/><state state_ref="missing-state"/></rpminfo_test><rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`,
		`<rpminfo_object id="primary-release-object"><name>sles-release</name></rpminfo_object><rpminfo_object id="alternate-release-object"><name>SLES_SAP-release</name></rpminfo_object><rpminfo_object id="pkg-object"><name>pkg</name></rpminfo_object>`,
		`<rpminfo_state id="release-state"><version operation="equals">15.6</version></rpminfo_state><rpminfo_state id="pkg-state"><arch datatype="string" operation="pattern match">(aarch64|ppc64le|s390x|x86_64)</arch><evr datatype="evr_string" operation="greater than">0:0-0</evr></rpminfo_state>`,
	)
	source, native, err := buildSourceEvidenceForTarget(t, oval, selection, []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1")}, &sourceNativeComparator{relations: map[string]int{"0:0-0": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Unsupported) != 0 || len(source.Cases) != 1 || source.Cases[0].DerivedTruth != bench.TruthAffected || len(native.Targets[0].Comparisons) != 1 || native.Targets[0].Comparisons[0].PredicateKind != bench.NativePredicateEVRGreaterThan {
		t.Fatalf("nested guard-only OR evidence = %+v/%+v", source, native)
	}
}

func TestBuildSourceNativeEvidenceRejectsTopLevelSLESGuardOnlyOR(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
	selection := sourceSLESSelection(pkg)
	oval := sourceOVAL(
		`<criteria operator="OR"><criterion test_ref="primary-release-test"/><criterion test_ref="non-applicable-pkg-test"/></criteria>`,
		`<rpminfo_test id="primary-release-test" check="at least one"><object object_ref="primary-release-object"/><state state_ref="release-state"/></rpminfo_test><rpminfo_test id="non-applicable-pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`,
		`<rpminfo_object id="primary-release-object"><name>sles-release</name></rpminfo_object><rpminfo_object id="pkg-object"><name>pkg</name><arch>armv7l</arch></rpminfo_object>`,
		`<rpminfo_state id="release-state"><version operation="equals">15.6</version></rpminfo_state><rpminfo_state id="pkg-state"><evr datatype="evr_string" operation="greater than">0:0-0</evr></rpminfo_state>`,
	)
	source, native, err := buildSourceEvidenceForTarget(t, oval, selection, []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1")}, &sourceNativeComparator{relations: map[string]int{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Cases) != 0 || len(source.Unsupported) == 0 || len(native.Targets[0].Comparisons) != 0 {
		t.Fatalf("top-level guard-only OR evidence = %+v/%+v", source, native)
	}
}

func TestBuildSourceNativeEvidenceDistinguishesSLESReleaseAbsence(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "0:2.9.11-150600.1.90")
	selection := sourceSLESSelection(pkg)
	cases := []struct {
		name            string
		releasePackage  string
		wantApplicable  bool
		wantUnsupported bool
	}{
		{name: "alternate release absence is non-applicable", releasePackage: "SLES_SAP-release"},
		{name: "missing primary release fails closed", releasePackage: "sles-release", wantApplicable: true, wantUnsupported: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oval := sourceOVAL(`<criteria><criterion test_ref="release-test"/></criteria>`, `<rpminfo_test id="release-test" check="at least one"><object object_ref="release-object"/><state state_ref="release-state"/></rpminfo_test>`, `<rpminfo_object id="release-object"><name>`+tc.releasePackage+`</name></rpminfo_object>`, `<rpminfo_state id="release-state"><version operation="equals">15.6</version></rpminfo_state>`)
			target := bench.Target{ID: "target-a", Digest: sourceTestDigest('a'), Components: []bench.Component{pkg.Component}}
			result := evaluateSourceOVAL(t, oval, target, selection, pkg, &sourceNativeComparator{relations: map[string]int{}})
			if result.applicable != tc.wantApplicable || (len(result.unsupported) != 0) != tc.wantUnsupported {
				t.Fatalf("release absence result = %+v", result)
			}
		})
	}
}

func TestOVALCVECanonicalizationRejectsAmbiguity(t *testing.T) {
	cases := []struct {
		name  string
		refID string
		want  string
		valid bool
	}{
		{name: "direct case insensitive", refID: "cve-2003-1605", want: "CVE-2003-1605", valid: true},
		{name: "Mitre prefix case insensitive", refID: "mItRe cVe-2003-1605", want: "CVE-2003-1605", valid: true},
		{name: "multiple identities", refID: "CVE-2003-1605 CVE-2003-1606"},
		{name: "malformed identity", refID: "Mitre CVE-2003-16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, valid := canonicalOVALCVE(tc.refID)
			if got != tc.want || valid != tc.valid {
				t.Fatalf("canonicalOVALCVE(%q) = %q, %t", tc.refID, got, valid)
			}
		})
	}
}

func TestBuildSourceNativeEvidenceDeterministicGuardedOutput(t *testing.T) {
	pkg := sourceEvidenceRPMPackage("pkg", "1:1-1")
	selection := sourceSLESSelection(pkg)
	oval := sourceSLESGuardOVAL(`<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="pkg-test"/></criteria>`, `<rpminfo_test id="pkg-test" check="at least one"><object object_ref="pkg-object"/><state state_ref="pkg-state"/></rpminfo_test>`, `<rpminfo_state id="pkg-state"><evr operation="less than">2</evr></rpminfo_state>`)
	components := []bench.Component{pkg.Component, sourceSLESReleaseComponent("0:15.6-1")}
	firstSource, firstNative, err := buildSourceEvidenceForTarget(t, oval, selection, components, &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	secondSource, secondNative, err := buildSourceEvidenceForTarget(t, oval, selection, components, &sourceNativeComparator{relations: map[string]int{"2": -1}})
	if err != nil {
		t.Fatal(err)
	}
	firstSourceDigest, err := bench.DigestSourceCaseEvidence(firstSource)
	if err != nil {
		t.Fatal(err)
	}
	secondSourceDigest, err := bench.DigestSourceCaseEvidence(secondSource)
	if err != nil {
		t.Fatal(err)
	}
	firstNativeDigest, err := bench.DigestNativeEvidenceSet(firstNative)
	if err != nil {
		t.Fatal(err)
	}
	secondNativeDigest, err := bench.DigestNativeEvidenceSet(secondNative)
	if err != nil {
		t.Fatal(err)
	}
	if firstSourceDigest != secondSourceDigest || firstNativeDigest != secondNativeDigest {
		t.Fatalf("guarded output digests differ: %s/%s != %s/%s", firstSourceDigest, firstNativeDigest, secondSourceDigest, secondNativeDigest)
	}
}

func sourceDebianReleaseObject(id string) string {
	return `<textfilecontent54_object id="` + id + `"><path>/etc</path><filename>debian_version</filename><pattern operation="pattern match">(\d+)\.\d</pattern><instance datatype="int">1</instance></textfilecontent54_object>`
}

func sourceDebianGuardOVAL(release, releaseObject, unameObject string) string {
	return sourceOVAL(`<criteria operator="AND"><criterion test_ref="release-test"/><criterion test_ref="uname-test"/><criterion test_ref="pkg-test"/></criteria>`, `<textfilecontent54_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="release-test" version="1" check="all" check_existence="at_least_one_exists" comment="Debian GNU/Linux 12 is installed"><object object_ref="release-object"/><state state_ref="release-state"/></textfilecontent54_test><uname_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" id="uname-test" version="1" check="all" check_existence="at_least_one_exists" comment="Installed architecture is all"><object object_ref="uname-object"/></uname_test>`+sourceTest("pkg-test", "pkg-object", "pkg-state"), releaseObject+unameObject+sourceObject("pkg-object", "pkg"), `<textfilecontent54_state id="release-state"><subexpression operation="equals">`+release+`</subexpression></textfilecontent54_state>`+sourceState("pkg-state", "AND", "less than", "2"))
}

func sourceSLESGuardOVAL(criteria, packageTests, packageStates string) string {
	releaseTest := `<rpminfo_test id="release-test" check="at least one"><object object_ref="release-object"/><state state_ref="release-state"/></rpminfo_test>`
	releaseObject := `<rpminfo_object id="release-object"><name>sles-release</name></rpminfo_object>`
	releaseState := `<rpminfo_state id="release-state"><version operation="equals">15.6</version></rpminfo_state>`
	return sourceOVAL(criteria, releaseTest+packageTests, releaseObject+`<rpminfo_object id="pkg-object"><name>pkg</name></rpminfo_object>`, releaseState+packageStates)
}

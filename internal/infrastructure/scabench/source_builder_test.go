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
	root := t.TempDir()
	freeze := sourceFixtureFreeze(t, oval)
	if err := os.MkdirAll(filepath.Join(root, "sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sources", "vendor.xml"), []byte(oval), 0o600); err != nil {
		t.Fatal(err)
	}
	targetDigest := sourceTestDigest('a')
	catalog := bench.Catalog{SchemaVersion: bench.CatalogSchemaVersion, Revision: "source-evidence", Targets: []bench.Target{{ID: "target-a", OCIRef: "registry.example.test/target@" + targetDigest, Digest: targetDigest, SBOMDigest: sourceTestDigest('b'), Components: []bench.Component{pkg.Component}}}}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	plan := bench.SourceEvidencePlan{SchemaVersion: bench.SourceEvidencePlanSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []bench.SourceEvidenceTarget{{TargetID: "target-a", SourceAssetLocator: "sources/vendor.xml", PackageFamily: "deb", Release: "12", Product: "debian", Architecture: "amd64", Packages: []bench.SourceEvidencePackage{pkg}}}}
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
	return `<dpkginfo_state id="` + id + `" operator="` + operator + `"><evr operation="` + operation + `">` + evr + `</evr></dpkginfo_state>`
}

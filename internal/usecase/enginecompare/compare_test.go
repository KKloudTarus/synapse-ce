package enginecompare

import (
	"context"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

type fakeSource struct {
	name string
	out  []vulnerability.RawFinding
}

func (f fakeSource) Name() string { return f.name }
func (f fakeSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return f.out, nil
}

func raw(comp, id string, aliases ...string) vulnerability.RawFinding {
	return vulnerability.RawFinding{Component: comp, AdvisoryID: id, Aliases: aliases}
}

// A mixed differential: one shared pair, one candidate-only (extra coverage), one baseline-only (recall gap).
func TestCompareDifferential(t *testing.T) {
	base := []vulnerability.RawFinding{raw("a", "CVE-1"), raw("b", "CVE-2")}
	cand := []vulnerability.RawFinding{raw("a", "CVE-1"), raw("c", "CVE-3")}
	rep := Compare("grype", "owned", base, cand)
	if rep.Both != 1 || rep.BaselinePairs != 2 || rep.CandidatePairs != 2 {
		t.Fatalf("counts wrong: %+v", rep)
	}
	if len(rep.CandidateOnly) != 1 || rep.CandidateOnly[0] != (Divergence{"c", "CVE-3"}) {
		t.Errorf("candidate-only wrong: %+v", rep.CandidateOnly)
	}
	if len(rep.BaselineOnly) != 1 || rep.BaselineOnly[0] != (Divergence{"b", "CVE-2"}) {
		t.Errorf("baseline-only wrong: %+v", rep.BaselineOnly)
	}
	if rep.CandidateMatchesBaselineRecall {
		t.Error("a baseline-only pair means the candidate did NOT match recall")
	}
}

// The real-world winning shape: the candidate is a strict superset of the baseline (no recall gap, plus
// extra coverage). Mirrors the observed owned-vs-Grype result on a real SLES image.
func TestCompareCandidateSupersetMatchesRecall(t *testing.T) {
	base := []vulnerability.RawFinding{raw("curl", "CVE-1"), raw("glibc", "CVE-2")}
	cand := []vulnerability.RawFinding{raw("curl", "CVE-1"), raw("glibc", "CVE-2"), raw("curl", "CVE-3")}
	rep := Compare("grype", "owned", base, cand)
	if !rep.CandidateMatchesBaselineRecall {
		t.Fatalf("candidate superset must match baseline recall (no baseline-only), got %+v", rep.BaselineOnly)
	}
	if rep.Both != 2 || len(rep.CandidateOnly) != 1 {
		t.Errorf("want both=2 candidate-only=1, got %+v", rep)
	}
}

// Two engines keying the same vulnerability under different primary ids (GHSA vs CVE) must compare equal via
// the CVE alias, so the differential is not inflated by id-scheme differences.
func TestCompareCVEAliasMatching(t *testing.T) {
	base := []vulnerability.RawFinding{raw("pkg", "GHSA-xxxx", "CVE-9")}
	cand := []vulnerability.RawFinding{raw("pkg", "CVE-9")}
	rep := Compare("grype", "owned", base, cand)
	if rep.Both != 1 || len(rep.CandidateOnly) != 0 || len(rep.BaselineOnly) != 0 {
		t.Fatalf("CVE alias must unify the pair, got %+v", rep)
	}
}

// A finding with no component or no id contributes no pair (never a spurious divergence).
func TestCompareDropsUnkeyable(t *testing.T) {
	base := []vulnerability.RawFinding{raw("", "CVE-1"), raw("a", "")}
	cand := []vulnerability.RawFinding{raw("a", "CVE-1")}
	rep := Compare("grype", "owned", base, cand)
	if rep.BaselinePairs != 0 || rep.CandidatePairs != 1 || len(rep.CandidateOnly) != 1 {
		t.Fatalf("unkeyable findings must be dropped, got %+v", rep)
	}
}

// Run scans both sources over the doc and records the component count.
func TestRunWithSources(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "a"}, {Name: "b"}}}
	base := fakeSource{name: "grype", out: []vulnerability.RawFinding{raw("a", "CVE-1")}}
	cand := fakeSource{name: "owned", out: []vulnerability.RawFinding{raw("a", "CVE-1"), raw("a", "CVE-2")}}
	rep, err := Run(context.Background(), base, cand, doc)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BaselineName != "grype" || rep.CandidateName != "owned" || rep.ComponentCount != 2 {
		t.Fatalf("run report metadata wrong: %+v", rep)
	}
	if !rep.CandidateMatchesBaselineRecall || len(rep.CandidateOnly) != 1 {
		t.Fatalf("owned superset should match recall + one extra, got %+v", rep)
	}
}

// CVE ids differing only in case must compare equal (canonicalized), never a false divergence.
func TestCompareCanonicalizesCVECase(t *testing.T) {
	base := []vulnerability.RawFinding{raw("curl", "cve-2024-1")}
	cand := []vulnerability.RawFinding{raw("curl", "CVE-2024-1")}
	rep := Compare("grype", "owned", base, cand)
	if rep.Both != 1 || len(rep.CandidateOnly) != 0 || len(rep.BaselineOnly) != 0 {
		t.Fatalf("case-different CVEs must unify, got %+v", rep)
	}
}

// A finding that aliases several CVEs must contribute a pair PER CVE, so a real recall gap on one of them
// is not hidden by agreement on another (the candidate found CVE-1 but not the aliased CVE-2).
func TestCompareExpandsMultipleCVEAliases(t *testing.T) {
	base := []vulnerability.RawFinding{raw("openssl", "GHSA-x", "CVE-1", "CVE-2")}
	cand := []vulnerability.RawFinding{raw("openssl", "CVE-1")}
	rep := Compare("grype", "owned", base, cand)
	if rep.BaselinePairs != 2 || rep.Both != 1 {
		t.Fatalf("multi-CVE alias must expand to 2 baseline pairs, got %+v", rep)
	}
	if len(rep.BaselineOnly) != 1 || rep.BaselineOnly[0] != (Divergence{"openssl", "CVE-2"}) {
		t.Fatalf("the aliased CVE-2 gap must be surfaced, got %+v", rep.BaselineOnly)
	}
	if rep.CandidateMatchesBaselineRecall {
		t.Fatal("a hidden aliased-CVE gap must NOT report recall match (the overstatement Codex flagged)")
	}
}

// A finding with no CVE id (GHSA only) still contributes a pair (keyed by the advisory id), never silently
// dropped, so a competitor-only GHSA finding shows as a recall gap.
func TestCompareNonCVEFindingStillCounts(t *testing.T) {
	base := []vulnerability.RawFinding{raw("pkg", "GHSA-only-1234")}
	cand := []vulnerability.RawFinding{}
	rep := Compare("grype", "owned", base, cand)
	if rep.BaselinePairs != 1 || len(rep.BaselineOnly) != 1 {
		t.Fatalf("a non-CVE finding must still count, got %+v", rep)
	}
}

// A non-CVE fallback id that is case-SENSITIVE (a URL/vendor advisory ref) must not be collapsed by
// case-folding: two differently-cased ids are two advisories, so a gap on one must surface.
func TestCompareNonCVEFallbackPreservesCase(t *testing.T) {
	base := []vulnerability.RawFinding{
		raw("pkg", "https://advisories.example/foo/a"),
		raw("pkg", "https://advisories.example/foo/A"),
	}
	cand := []vulnerability.RawFinding{raw("pkg", "https://advisories.example/foo/A")}
	rep := Compare("vendor", "owned", base, cand)
	if rep.BaselinePairs != 2 {
		t.Fatalf("case-sensitive URL ids must stay distinct (2 pairs), got %+v", rep)
	}
	if len(rep.BaselineOnly) != 1 || rep.CandidateMatchesBaselineRecall {
		t.Fatalf("the lower-case id must show as a recall gap, got %+v", rep)
	}
}

// A GHSA fallback id IS case-insensitive, so differently-cased GHSA ids unify (no false divergence).
func TestCompareGHSAFallbackCaseFolds(t *testing.T) {
	base := []vulnerability.RawFinding{raw("pkg", "ghsa-aaaa-bbbb-cccc")}
	cand := []vulnerability.RawFinding{raw("pkg", "GHSA-AAAA-BBBB-CCCC")}
	rep := Compare("vendor", "owned", base, cand)
	if rep.Both != 1 || len(rep.BaselineOnly) != 0 {
		t.Fatalf("GHSA ids must case-fold to one pair, got %+v", rep)
	}
}

func TestCompareManyRejectsInvalidNamesAndIsPermutationDeterministic(t *testing.T) {
	input := comparisonInputIdentity()
	candidate := EngineFindingSet{Name: "owned", InputIdentity: input, Findings: []vulnerability.RawFinding{raw("curl", "CVE-1"), raw("curl", "CVE-2")}}
	grype := EngineFindingSet{Name: "grype", InputIdentity: input, Findings: []vulnerability.RawFinding{raw("curl", "CVE-1")}}
	trivy := EngineFindingSet{Name: "trivy", InputIdentity: input, Findings: []vulnerability.RawFinding{raw("curl", "CVE-3")}}
	first, err := CompareMany(candidate, []EngineFindingSet{trivy, grype})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompareMany(candidate, []EngineFindingSet{grype, trivy})
	if err != nil {
		t.Fatal(err)
	}
	if !first.DiagnosticOnly || first.InputIdentity != input || !reflect.DeepEqual(first, second) || len(first.Comparisons) != 2 || first.Comparisons[0].BaselineName != "grype" {
		t.Fatalf("CompareMany must be deterministic diagnostic output: %+v / %+v", first, second)
	}
	mismatched := trivy
	mismatched.InputIdentity.TargetDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, err := CompareMany(candidate, []EngineFindingSet{mismatched}); err == nil {
		t.Fatal("comparison across different target inputs was accepted")
	}
	for _, invalid := range []struct {
		name      string
		candidate EngineFindingSet
		baselines []EngineFindingSet
	}{
		{name: "empty baseline set", candidate: candidate},
		{name: "blank candidate", candidate: EngineFindingSet{Name: " ", InputIdentity: input}, baselines: []EngineFindingSet{grype}},
		{name: "missing input identity", candidate: EngineFindingSet{Name: "owned"}, baselines: []EngineFindingSet{grype}},
		{name: "duplicate baseline", candidate: candidate, baselines: []EngineFindingSet{grype, grype}},
		{name: "candidate collision", candidate: candidate, baselines: []EngineFindingSet{{Name: "owned", InputIdentity: input}}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if _, err := CompareMany(invalid.candidate, invalid.baselines); err == nil {
				t.Fatal("invalid comparison names or inputs were accepted")
			}
		})
	}
}

func TestCompareManyRejectsMoreThanThreeBaselines(t *testing.T) {
	identity := comparisonInputIdentity()
	candidate := EngineFindingSet{Name: "owned", InputIdentity: identity}
	baselines := []EngineFindingSet{
		{Name: "grype", InputIdentity: identity},
		{Name: "trivy", InputIdentity: identity},
		{Name: "osv-scanner", InputIdentity: identity},
		{Name: "other", InputIdentity: identity},
	}
	if _, err := CompareMany(candidate, baselines); err == nil {
		t.Fatal("compare-many accepted more than three baselines")
	}
}

func comparisonInputIdentity() InputIdentity {
	return InputIdentity{
		CatalogRevision: "catalog-r1",
		CatalogDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SBOMDigest:      "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}

package advisory

import (
	"strings"
	"testing"
)

// hostcve_bench_test.go is the runtime host-CVE correlation accuracy gate (#1040). It scores the owned
// advisory matcher on a labeled corpus of installed OS packages against fixture advisories, covering the four
// dimensions the issue names: package identity, advisory version range (native distro ordering), alias
// resolution, and unsupported-distro behavior. It is a pure-domain gate: fixture advisories + labeled cases,
// no feed ingestion or network, so it is deterministic and does not touch the (separately gated) SCA oracle.

// hostFixtureAdvisories are fixture OS-package advisories with native distro version ranges. Versions and
// fixed boundaries are realistic dpkg/apk/rpm strings; the family before the ':' selects the comparator.
func hostFixtureAdvisories() []Advisory {
	return []Advisory{
		{
			ID:      "CVE-2022-0778",
			Aliases: []string{"GHSA-fake-openssl"},
			Affected: []AffectedPackage{{
				Ecosystem:    "Debian:11",
				Package:      "openssl",
				Ranges:       []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "1.1.1n-0+deb11u1"}}}},
				FixedVersion: "1.1.1n-0+deb11u1",
			}},
		},
		{
			ID: "CVE-2022-37434",
			Affected: []AffectedPackage{{
				Ecosystem:    "Alpine:v3.16",
				Package:      "zlib",
				Ranges:       []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "1.2.12-r2"}}}},
				FixedVersion: "1.2.12-r2",
			}},
		},
		{
			ID: "CVE-2021-4034",
			Affected: []AffectedPackage{{
				Ecosystem:    "Red Hat:8",
				Package:      "polkit",
				Ranges:       []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "0.115-13.el8_5.1"}}}},
				FixedVersion: "0.115-13.el8_5.1",
			}},
		},
		{
			// An advisory keyed to an UNSUPPORTED distro family (Gentoo has no owned ordering). It carries a
			// range and NO explicit versions, so the only way a query could match is if the family were given a
			// version scheme. osFamilyScheme returns ok=false for Gentoo, so the range is skipped and the query
			// fails closed: this is what the unsupported-distro corpus case exercises (a regression that gave
			// Gentoo a lexical ordering would flip that case to a match and fail the gate).
			ID: "CVE-9999-GENTOO",
			Affected: []AffectedPackage{{
				Ecosystem: "Gentoo:1",
				Package:   "openssl",
				Ranges:    []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "1.1.1n"}}}},
			}},
		},
	}
}

// hostCase is one labeled host-package correlation case: an installed package at a version, and whether the
// fixture corpus should report it affected.
type hostCase struct {
	name      string
	ecosystem string
	pkg       string
	version   string
	affected  bool
}

var hostCorpus = []hostCase{
	// Advisory range on the native distro ordering: a version below the fix is affected, the fix and above are not.
	{"debian-openssl-vulnerable", "Debian:11", "openssl", "1.1.1k-1+deb11u1", true},
	{"debian-openssl-fixed", "Debian:11", "openssl", "1.1.1n-0+deb11u1", false},
	{"debian-openssl-past-fix", "Debian:11", "openssl", "1.1.1n-0+deb11u2", false},
	{"alpine-zlib-vulnerable", "Alpine:v3.16", "zlib", "1.2.12-r0", true},
	{"alpine-zlib-fixed", "Alpine:v3.16", "zlib", "1.2.12-r2", false},
	{"redhat-polkit-vulnerable", "Red Hat:8", "polkit", "0.115-13.el8", true},
	{"redhat-polkit-fixed", "Red Hat:8", "polkit", "0.115-13.el8_5.1", false},
	// Package identity: the right ecosystem+version but the wrong package name must not correlate.
	{"debian-wrong-package", "Debian:11", "curl", "1.1.1k-1+deb11u1", false},
	// Unsupported distro: the corpus HAS a Gentoo-keyed advisory for this package with a range that would
	// include 1.1.1k under any ordering, but Gentoo has no owned version scheme, so the range is skipped and
	// the query fails closed (a vulnerable-looking version is NOT silently reported affected). A regression
	// that gave Gentoo a lexical ordering would flip this to a match and fail the gate.
	{"unsupported-distro", "Gentoo:1", "openssl", "1.1.1k", false},
}

const (
	hostCVERecallFloor    = 1.0
	hostCVEPrecisionFloor = 1.0
)

// matchCorpusAgainst reports whether any advisory in the corpus reports (ecosystem, pkg, version) affected.
func matchCorpusAgainst(advs []Advisory, ecosystem, pkg, version string) bool {
	for _, a := range advs {
		if ok, _ := a.Match(ecosystem, pkg, version, ""); ok {
			return true
		}
	}
	return false
}

// TestHostCVECorrelationAccuracy gates the owned host-package advisory matcher: every truly-affected case must
// correlate (recall) and no safe/fixed/wrong-package/unsupported case may (precision).
func TestHostCVECorrelationAccuracy(t *testing.T) {
	advs := hostFixtureAdvisories()
	tp, fp, fn, tn := 0, 0, 0, 0
	for _, c := range hostCorpus {
		got := matchCorpusAgainst(advs, c.ecosystem, c.pkg, c.version)
		switch {
		case c.affected && got:
			tp++
		case c.affected && !got:
			fn++
			t.Errorf("%s: expected %s %s@%s to correlate an advisory, but none matched", c.name, c.ecosystem, c.pkg, c.version)
		case !c.affected && got:
			fp++
			t.Errorf("%s: %s %s@%s must NOT correlate (fixed/wrong-package/unsupported), but one matched", c.name, c.ecosystem, c.pkg, c.version)
		default:
			tn++
		}
	}
	recall, precision := rateFloat(tp, fn), rateFloat(tp, fp)
	t.Logf("host-cve correlation: cases=%d tp=%d fp=%d fn=%d tn=%d recall=%.3f precision=%.3f", len(hostCorpus), tp, fp, fn, tn, recall, precision)
	if recall < hostCVERecallFloor {
		t.Errorf("host-cve recall %.3f below floor %.3f", recall, hostCVERecallFloor)
	}
	if precision < hostCVEPrecisionFloor {
		t.Errorf("host-cve precision %.3f below floor %.3f", precision, hostCVEPrecisionFloor)
	}
}

// TestHostCVEAliasResolution: a host finding correlated by its CVE id must resolve to the advisory's other
// ids (GHSA), so a query by either alias reaches the same advisory. This is the "aliases" dimension.
func TestHostCVEAliasResolution(t *testing.T) {
	g := NewAliasGraph([]AliasEdge{{AliasID: "GHSA-fake-openssl", CanonicalID: "CVE-2022-0778"}})
	// The graph canonicalizes id case, so compare case-insensitively.
	if !containsFold(g.Expand([]string{"CVE-2022-0778"}), "GHSA-fake-openssl") {
		t.Errorf("alias closure of CVE-2022-0778 must include GHSA-fake-openssl; got %v", g.Expand([]string{"CVE-2022-0778"}))
	}
	// Symmetric: querying by the GHSA alias must reach the CVE.
	if !containsFold(g.Expand([]string{"GHSA-fake-openssl"}), "CVE-2022-0778") {
		t.Errorf("alias closure of GHSA-fake-openssl must include CVE-2022-0778; got %v", g.Expand([]string{"GHSA-fake-openssl"}))
	}
}

func containsFold(ids []string, want string) bool {
	for _, id := range ids {
		if strings.EqualFold(id, want) {
			return true
		}
	}
	return false
}

func rateFloat(tp, other int) float64 {
	if tp+other == 0 {
		return 0
	}
	return float64(tp) / float64(tp+other)
}

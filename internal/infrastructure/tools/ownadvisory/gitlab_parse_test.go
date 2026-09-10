package ownadvisory

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// realGemnasium is a faithful gemnasium-db YAML advisory (GitLab's format).
const realGemnasium = `---
identifier: "CVE-2007-5712"
identifiers:
- "CVE-2007-5712"
- "GHSA-9v8h-57gv-qch6"
package_slug: "pypi/Django"
title: "Django DoS via i18n middleware"
description: "denial of service"
affected_range: ">=0.96.0,<0.96.1||==0.96.0||>=0.95,<0.95.2"
fixed_versions:
- "0.96.1"
- "0.95.2"
cvss_v3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
`

func TestParseGemnasiumRealRecord(t *testing.T) {
	adv, ok := ParseGemnasium([]byte(realGemnasium))
	if !ok {
		t.Fatal("a valid gemnasium record must parse")
	}
	if adv.ID != "CVE-2007-5712" || !containsStr(adv.Aliases, "GHSA-9v8h-57gv-qch6") {
		t.Fatalf("id/aliases wrong: %s %v", adv.ID, adv.Aliases)
	}
	if adv.CVSSVector == "" || adv.CVSSScore < 3.0 {
		t.Fatalf("cvss wrong: %q %v", adv.CVSSVector, adv.CVSSScore)
	}
	if len(adv.Affected) != 1 {
		t.Fatalf("affected: %+v", adv.Affected)
	}
	p := adv.Affected[0]
	if p.Ecosystem != "PyPI" || p.Package != "Django" || p.FixedVersion != "0.96.1" {
		t.Fatalf("package wrong: %+v", p)
	}
	// Two range groups + one exact version.
	if len(p.Ranges) != 2 || len(p.Versions) != 1 || p.Versions[0] != "0.96.0" {
		t.Fatalf("ranges/versions wrong: ranges=%+v versions=%v", p.Ranges, p.Versions)
	}
	if p.Ranges[0].Events[0].Introduced != "0.96.0" || p.Ranges[0].Events[1].Fixed != "0.96.1" {
		t.Fatalf("first range wrong: %+v", p.Ranges[0].Events)
	}
}

func TestParseGemnasiumUnmappedSlugDropped(t *testing.T) {
	doc := `---
identifier: "GMS-1"
package_slug: "conda/weird"
affected_range: "<1.0.0"
`
	if _, ok := ParseGemnasium([]byte(doc)); ok {
		t.Fatal("an unmapped ecosystem prefix must drop the advisory")
	}
}

// TestParseGemnasiumRange is the FP-critical table: every parse either produces the exact intended
// ranges/versions or refuses the WHOLE range (ok=false), so no input yields a range matching wrong versions.
func TestParseGemnasiumRange(t *testing.T) {
	cases := []struct {
		raw        string
		wantRanges int
		wantVers   []string
		wantOK     bool
	}{
		{raw: ">=1.0.0,<2.0.0", wantRanges: 1, wantOK: true},
		{raw: "==1.2.3", wantVers: []string{"1.2.3"}, wantOK: true},
		{raw: "<1.0.0", wantRanges: 1, wantOK: true},
		{raw: "<=1.9.9", wantRanges: 1, wantOK: true},
		{raw: ">=1.0.0,<1.1.0||==2.0.0||>=3.0.0,<3.1.0", wantRanges: 2, wantVers: []string{"2.0.0"}, wantOK: true},
		{raw: ">1.0.0", wantOK: false},                 // exclusive lower bound refused
		{raw: ">=1.0.0", wantOK: false},                // open-ended refused
		{raw: ">=1.0.0,<1.1.0||>2.0.0", wantOK: false}, // one bad OR group fails the whole range
		{raw: "==1.0.0,<2.0.0", wantOK: false},         // exact + bound contradictory
		{raw: ">=2.0.0,>=1.0.0,<3.0.0", wantOK: false}, // duplicate lower bound: refuse (would over-broaden)
		{raw: "<2.0.0,<3.0.0", wantOK: false},          // duplicate upper bound: refuse
		{raw: "<=2.0.0,<3.0.0", wantOK: false},         // mixed upper bounds: refuse
		{raw: "~>1.2", wantOK: false},                  // unknown operator
		{raw: "", wantOK: false},
		{raw: "||<1.0.0", wantOK: false}, // empty group
	}
	for _, c := range cases {
		ranges, vers, ok := parseGemnasiumRange(c.raw)
		if ok != c.wantOK {
			t.Errorf("%q: ok=%v want %v", c.raw, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if len(ranges) != c.wantRanges {
			t.Errorf("%q: ranges=%d want %d", c.raw, len(ranges), c.wantRanges)
		}
		if !equalStr(vers, c.wantVers) {
			t.Errorf("%q: versions=%v want %v", c.raw, vers, c.wantVers)
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var _ = shared.SeverityUnknown

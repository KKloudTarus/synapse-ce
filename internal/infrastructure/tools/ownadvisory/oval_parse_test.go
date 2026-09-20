package ownadvisory

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

func TestParseUbuntuOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL: %v", err)
	}
	// Only the fixed CVE yields an advisory; the deferred (no "less than" fix) one is skipped.
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory (deferred CVE dropped), got %d: %+v", len(advs), advs)
	}
	a := advs[0]
	if a.ID != "CVE-2023-1000" {
		t.Errorf("id = %q, want CVE-2023-1000", a.ID)
	}
	if a.CVSSScore != 5.5 { // Medium mapped to a representative base score
		t.Errorf("CVSSScore = %v, want 5.5 (Medium)", a.CVSSScore)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("want 1 affected package, got %d", len(a.Affected))
	}
	ap := a.Affected[0]
	if ap.Ecosystem != "Ubuntu:22.04" || ap.Package != "openssl" || ap.FixedVersion != "3.0.2-0ubuntu1.10" {
		t.Errorf("affected = %+v, want Ubuntu:22.04 openssl fixed 3.0.2-0ubuntu1.10", ap)
	}
	if ap.Ranges[0].Type != "ECOSYSTEM" {
		t.Error("OVAL affected range must be ECOSYSTEM type so the owned dpkg comparator orders it")
	}
}

func TestParseUbuntuOVALNegatedCriteriaFailClosed(t *testing.T) {
	doc := `<oval_definitions xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
	  <definitions><definition class="vulnerability" id="oval:com.ubuntu.jammy:def:2026100000000001">
	    <metadata><title>CVE-2026-10001 on Ubuntu 22.04 LTS</title>
	      <reference source="CVE" ref_id="CVE-2026-10001"/></metadata>
	    <criteria><criterion test_ref="oval:com.ubuntu.jammy:tst:2026100000000001" negate="true"/></criteria>
	  </definition></definitions>
	  <tests><linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:2026100000000001">
	    <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:2026100000000001"/>
	    <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:2026100000000001"/>
	  </linux-def:dpkginfo_test></tests>
	  <objects><linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:2026100000000001">
	    <linux-def:name>openssl</linux-def:name>
	  </linux-def:dpkginfo_object></objects>
	  <states><linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:2026100000000001">
	    <linux-def:evr operation="less than">3.0.2-0ubuntu1.10</linux-def:evr>
	  </linux-def:dpkginfo_state></states>
	</oval_definitions>`

	advs, err := ParseUbuntuOVAL([]byte(doc))
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("negated dpkg criterion minted fixed affected authority: %+v", advs)
	}
}

func TestParseUbuntuOVALResolvesCurrentConstantVariablePackageList(t *testing.T) {
	doc := `<oval_definitions xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
	  <definitions><definition class="vulnerability" id="oval:com.ubuntu.jammy:def:2026100000000000">
	    <metadata><title>CVE-2026-10000 on Ubuntu 22.04 LTS</title><affected><platform>Ubuntu 22.04 LTS</platform></affected>
	      <reference source="CVE" ref_id="CVE-2026-10000"/><advisory><severity>High</severity></advisory></metadata>
	    <criteria><criterion test_ref="oval:com.ubuntu.jammy:tst:2026100000000000"/></criteria>
	  </definition></definitions>
	  <tests><linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:2026100000000000">
	    <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:2026100000000000"/>
	    <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:2026100000000000"/>
	  </linux-def:dpkginfo_test></tests>
	  <objects><linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:2026100000000000">
	    <linux-def:name var_ref="oval:com.ubuntu.jammy:var:2026100000000000"/>
	  </linux-def:dpkginfo_object></objects>
	  <states><linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:2026100000000000">
	    <linux-def:evr operation="less than">2.4.52-1ubuntu4.3</linux-def:evr>
	  </linux-def:dpkginfo_state></states>
	  <variables><constant_variable id="oval:com.ubuntu.jammy:var:2026100000000000">
	    <value>apache2</value><value>apache2-bin</value><value>apache2</value>
	  </constant_variable></variables>
	</oval_definitions>`

	advs, err := ParseUbuntuOVAL([]byte(doc))
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory, got %d: %+v", len(advs), advs)
	}
	if got := advs[0].Affected; len(got) != 2 || got[0].Package != "apache2" || got[1].Package != "apache2-bin" {
		t.Fatalf("constant-variable packages = %+v, want apache2 and apache2-bin once each", got)
	}
}

func TestParseUbuntuOVALMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatal(err)
	}
	a := advs[0]
	// A lower dpkg version is affected; at/above the fixed version it is not – proves the owned dpkg
	// comparator wires up end to end through the "Ubuntu:22.04" ecosystem key.
	if ok, fixed := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.9"); !ok || fixed != "3.0.2-0ubuntu1.10" {
		t.Errorf("older openssl must match with fix 3.0.2-0ubuntu1.10, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.10"); ok {
		t.Error("openssl at the fixed version must not match")
	}
	if ok, _ := a.Match("Ubuntu:20.04", "openssl", "3.0.2-0ubuntu1.9"); ok {
		t.Error("a different release must not match (ecosystem key differs)")
	}
}

func TestParseUbuntuOVALBzip2(t *testing.T) {
	// The .bz2 fixture must parse identically to the plain XML (bzip2 magic-sniff path).
	data, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL(bz2): %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2023-1000" || advs[0].Affected[0].Ecosystem != "Ubuntu:22.04" {
		t.Errorf("bz2 parse mismatch: %+v", advs)
	}
}

func TestParseUbuntuOVALUnknownReleaseSkipped(t *testing.T) {
	// A codename not in the release table is a per-file skip (error), not a mis-keyed advisory.
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:com.ubuntu.bogus:def:1">
	    <metadata><reference source="CVE" ref_id="CVE-2023-9"/></metadata>
	    <criteria><criterion test_ref="oval:com.ubuntu.bogus:tst:1"/></criteria>
	  </definition></definitions></oval_definitions>`
	if _, err := ParseUbuntuOVAL([]byte(x)); err == nil {
		t.Error("an unknown ubuntu codename must return an error (per-file skip), not silently key it wrong")
	}
}

func TestUbuntuReleaseTable(t *testing.T) {
	cases := map[string]string{"focal": "20.04", "jammy": "22.04", "noble": "24.04", "bionic": "18.04", "unknown": ""}
	for codename, want := range cases {
		if got := ubuntuRelease(codename); got != want {
			t.Errorf("ubuntuRelease(%q) = %q, want %q", codename, got, want)
		}
	}
}

func TestUbuntuSeverityScore(t *testing.T) {
	cases := map[string]float64{"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 3.0, "Negligible": 1.0, "untriaged": 0}
	for sev, want := range cases {
		if got := ovalSeverityScore(sev); got != want {
			t.Errorf("ovalSeverityScore(%q) = %v, want %v", sev, got, want)
		}
	}
}

// TestOVALEcosystemKeyRoundTrip locks the feed side (ubuntuRelease) to the matcher side (osDistroEcosystem):
// the key ParseUbuntuOVAL writes for a codename MUST equal the key a Syft ubuntu PURL for that release
// derives, or every finding for that release silently vanishes. A point-release qualifier must land on the
// same major.minor key.
func TestOVALEcosystemKeyRoundTrip(t *testing.T) {
	for _, codename := range []string{"bionic", "focal", "jammy", "noble"} {
		rel := ubuntuRelease(codename)
		if rel == "" {
			t.Fatalf("release table missing %q", codename)
		}
		want := "Ubuntu:" + rel // the exact key ParseUbuntuOVAL stores
		if got := osDistroEcosystem("pkg:deb/ubuntu/bash@5?distro=ubuntu-" + rel); got != want {
			t.Errorf("release %s: matcher key %q != feed key %q", rel, got, want)
		}
		// a point-release qualifier must normalize to the same key
		if got := osDistroEcosystem("pkg:deb/ubuntu/bash@5?distro=ubuntu-" + rel + ".2"); got != want {
			t.Errorf("release %s point-release: matcher key %q != feed key %q", rel, got, want)
		}
	}
}

func TestParseUbuntuOVALMalformedXML(t *testing.T) {
	if _, err := ParseUbuntuOVAL([]byte("<oval_definitions><definitions><definition")); err == nil {
		t.Error("truncated XML must return an error so the walk skips + counts the file")
	}
}

// TestParseDebianOVAL parses a real (trimmed) Debian bookworm OVAL fixture into Debian:12 advisories.
func TestParseDebianOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-debian-bookworm.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(debian): %v", err)
	}
	got := map[string]string{} // "CVE|pkg" -> fixed
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Ecosystem != "Debian:12" {
				t.Errorf("%s: ecosystem = %q, want Debian:12", a.ID, ap.Ecosystem)
			}
			if ap.Ranges[0].Type != "ECOSYSTEM" {
				t.Errorf("%s: range type = %q, want ECOSYSTEM", a.ID, ap.Ranges[0].Type)
			}
			got[a.ID+"|"+ap.Package] = ap.FixedVersion
		}
	}
	for key, want := range map[string]string{
		"CVE-1999-0199|glibc": "0:2.2-1",
		"CVE-1999-0710|squid": "0:2.5.7-1",
	} {
		if got[key] != want {
			t.Errorf("%s fixed = %q, want %q (all: %v)", key, got[key], want, got)
		}
	}
}

// TestParseDebianOVALMatchesViaDomainMatcher proves the Debian:12 key and the epoch-aware dpkg comparator
// wire end to end: a lower version (with or without an explicit epoch) matches, the fixed version and a
// different release do not.
func TestParseDebianOVALMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "oval-debian-bookworm.xml"))
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatal(err)
	}
	var glibc advisory.Advisory
	for _, a := range advs {
		if a.ID == "CVE-1999-0199" {
			glibc = a
		}
	}
	if glibc.ID == "" {
		t.Fatal("glibc advisory not parsed")
	}
	if ok, fixed := glibc.Match("Debian:12", "glibc", "2.1-1"); !ok || fixed != "0:2.2-1" {
		t.Errorf("older glibc (no epoch) must match with fix 0:2.2-1, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := glibc.Match("Debian:12", "glibc", "0:2.1-1"); !ok {
		t.Error("older glibc with an explicit epoch must match")
	}
	if ok, _ := glibc.Match("Debian:12", "glibc", "0:2.2-1"); ok {
		t.Error("glibc at the fixed version must not match")
	}
	if ok, _ := glibc.Match("Debian:11", "glibc", "2.1-1"); ok {
		t.Error("a different Debian release must not match (ecosystem key differs)")
	}
}

func TestDebianPlatformRelease(t *testing.T) {
	cases := map[string]string{
		"Debian GNU/Linux 12":   "12",
		"debian gnu/linux 11":   "11", // case-insensitive
		"Debian GNU/Linux 12.4": "12", // leading integer only
		"Ubuntu 22.04":          "",   // not a Debian platform
		"Debian GNU/Linux":      "",   // no numeric release
		"":                      "",
	}
	for platform, want := range cases {
		if got := debianPlatformRelease(platform); got != want {
			t.Errorf("debianPlatformRelease(%q) = %q, want %q", platform, got, want)
		}
	}
}

// TestDebianReleaseRejectsMixed proves a file that mixes releases (never a real per-release feed) refuses to
// key any advisory rather than mis-key some to the wrong release.
func TestDebianReleaseRejectsMixed(t *testing.T) {
	defs := []ovalDefinition{
		{Platforms: []string{"Debian GNU/Linux 12"}},
		{Platforms: []string{"Debian GNU/Linux 11"}},
	}
	if got := debianRelease(defs); got != "" {
		t.Errorf("mixed-release file must return no release, got %q", got)
	}
	single := []ovalDefinition{{Platforms: []string{"Debian GNU/Linux 12"}}, {Platforms: []string{"Debian GNU/Linux 12"}}}
	if got := debianRelease(single); got != "12" {
		t.Errorf("single-release file must return 12, got %q", got)
	}
}

// TestDebianOVALEcosystemKeyRoundTrip locks the feed key (Debian:<major>) to the matcher key a Syft debian
// PURL derives, tolerating a point-release qualifier.
func TestDebianOVALEcosystemKeyRoundTrip(t *testing.T) {
	for _, ver := range []string{"12", "11", "12.4"} {
		want := "Debian:" + strings.SplitN(ver, ".", 2)[0]
		if got := osDistroEcosystem("pkg:deb/debian/bash@5?distro=debian-" + ver); got != want {
			t.Errorf("debian-%s: matcher key %q != feed key %q", ver, got, want)
		}
	}
}

// TestParseOVALAutoDetectsFamily proves the single ParseOVAL entry point resolves the correct distro from the
// document, so one dir feed handles a mixed Ubuntu+Debian directory.
func TestParseOVALAutoDetectsFamily(t *testing.T) {
	ubuntu, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	advs, err := ParseOVAL(ubuntu)
	if err != nil || len(advs) == 0 || advs[0].Affected[0].Ecosystem != "Ubuntu:22.04" {
		t.Fatalf("ubuntu doc must key Ubuntu:22.04, got err=%v advs=%+v", err, advs)
	}
	debian, _ := os.ReadFile(filepath.Join("testdata", "oval-debian-bookworm.xml"))
	advs, err = ParseOVAL(debian)
	if err != nil || len(advs) == 0 || advs[0].Affected[0].Ecosystem != "Debian:12" {
		t.Fatalf("debian doc must key Debian:12, got err=%v advs=%+v", err, advs)
	}
}

// TestParseOVALUnknownFamilySkipped proves a document of neither known family is a per-file skip (error), not
// a mis-keyed advisory.
func TestParseOVALUnknownFamilySkipped(t *testing.T) {
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:org.example:def:1">
	    <metadata><reference source="CVE" ref_id="CVE-2023-9"/></metadata>
	    <criteria><criterion test_ref="x"/></criteria>
	  </definition></definitions></oval_definitions>`
	if _, err := ParseOVAL([]byte(x)); err == nil {
		t.Error("an unknown OVAL distro family must return an error (per-file skip)")
	}
}

// TestParseOVALMixedFamilyRejected proves a document that mixes Ubuntu and Debian definitions is rejected
// wholesale, so Debian package facts can never be keyed under an Ubuntu ecosystem (a false match).
func TestParseOVALMixedFamilyRejected(t *testing.T) {
	x := `<oval_definitions><definitions>
	  <definition class="inventory" id="oval:com.ubuntu.jammy:def:1"><metadata></metadata><criteria></criteria></definition>
	  <definition class="vulnerability" id="oval:org.debian:def:2">
	    <metadata><affected><platform>Debian GNU/Linux 12</platform></affected>
	      <reference source="CVE" ref_id="CVE-2099-0001"/></metadata>
	    <criteria><criterion test_ref="oval:org.debian.oval:tst:3"/></criteria>
	  </definition></definitions>
	  <tests><linux:dpkginfo_test id="oval:org.debian.oval:tst:3" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
	    <object object_ref="o3"/><state state_ref="s3"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o3" xmlns:linux="x"><name>bash</name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s3" xmlns:linux="x"><evr operation="less than">0:9.9-1</evr></linux:dpkginfo_state></states>
	</oval_definitions>`
	if _, err := ParseOVAL([]byte(x)); err == nil {
		t.Error("a document mixing ubuntu and debian definitions must be rejected (no wrong-ecosystem keying)")
	}
}

// TestOVALAmbiguousStateSkipped proves a dpkginfo_state carrying BOTH <version> and <evr> with divergent
// values yields no advisory, rather than silently choosing one boundary.
func TestOVALAmbiguousStateSkipped(t *testing.T) {
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:org.debian:def:1">
	    <metadata><affected><platform>Debian GNU/Linux 12</platform></affected>
	      <reference source="CVE" ref_id="CVE-2099-0002"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:dpkginfo_test id="t1" xmlns:linux="x"><object object_ref="o1"/><state state_ref="s1"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o1" xmlns:linux="x"><name>openssl</name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s1" xmlns:linux="x">
	    <version operation="less than">0:1.2-1</version>
	    <evr operation="less than">0:9.9-1</evr></linux:dpkginfo_state></states>
	</oval_definitions>`
	advs, err := ParseOVAL([]byte(x))
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Errorf("an ambiguous version/evr state must yield no advisory, got %+v", advs)
	}
}

// TestOVALConsistentBothElementsAccepted proves a state carrying both elements with the SAME value is not
// ambiguous and still yields the advisory (no over-skip).
func TestOVALConsistentBothElementsAccepted(t *testing.T) {
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:org.debian:def:1">
	    <metadata><affected><platform>Debian GNU/Linux 12</platform></affected>
	      <reference source="CVE" ref_id="CVE-2099-0003"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:dpkginfo_test id="t1" xmlns:linux="x"><object object_ref="o1"/><state state_ref="s1"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o1" xmlns:linux="x"><name>openssl</name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s1" xmlns:linux="x">
	    <version operation="less than">0:1.2-1</version>
	    <evr operation="less than">0:1.2-1</evr></linux:dpkginfo_state></states>
	</oval_definitions>`
	advs, err := ParseOVAL([]byte(x))
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].Affected[0].FixedVersion != "0:1.2-1" {
		t.Errorf("consistent both-elements state must yield the advisory, got %+v", advs)
	}
}

// TestDebianZeroBoundSkipped proves the "less than 0:0" missing-data sentinel yields no advisory.
func TestDebianZeroBoundSkipped(t *testing.T) {
	for _, sentinel := range []string{"0:0", "0", "0:0-0"} {
		x := `<oval_definitions><definitions>
		  <definition class="vulnerability" id="oval:org.debian:def:1">
		    <metadata><affected><platform>Debian GNU/Linux 12</platform></affected>
		      <reference source="CVE" ref_id="CVE-2099-0004"/></metadata>
		    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
		  <tests><linux:dpkginfo_test id="t1" xmlns:linux="x"><object object_ref="o1"/><state state_ref="s1"/></linux:dpkginfo_test></tests>
		  <objects><linux:dpkginfo_object id="o1" xmlns:linux="x"><name>bash</name></linux:dpkginfo_object></objects>
		  <states><linux:dpkginfo_state id="s1" xmlns:linux="x"><evr operation="less than">` + sentinel + `</evr></linux:dpkginfo_state></states>
		</oval_definitions>`
		advs, err := ParseOVAL([]byte(x))
		if err != nil {
			t.Fatalf("ParseOVAL(%s): %v", sentinel, err)
		}
		if len(advs) != 0 {
			t.Errorf("zero-bound %q must yield no advisory, got %+v", sentinel, advs)
		}
	}
}

func TestIsDebianZeroBound(t *testing.T) {
	for v, want := range map[string]bool{
		"0:0": true, "0": true, "0:0-0": true, "0.0": true, "": true,
		"0:2.2-1": false, "2.2-1": false, "0:0.1": false, "0ubuntu1": false,
	} {
		if got := isDebianZeroBound(v); got != want {
			t.Errorf("isDebianZeroBound(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestParseOVALFamilyAnchoredNotSubstring proves family detection is anchored to the id prefix: a Debian id
// that merely contains the substring "com.ubuntu" is still keyed Debian, not misclassified as Ubuntu.
func TestParseOVALFamilyAnchoredNotSubstring(t *testing.T) {
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:org.debian.com.ubuntu.jammy:def:1">
	    <metadata><affected><platform>Debian GNU/Linux 12</platform></affected>
	      <reference source="CVE" ref_id="CVE-2099-0005"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:dpkginfo_test id="t1" xmlns:linux="x"><object object_ref="o1"/><state state_ref="s1"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o1" xmlns:linux="x"><name>zlib</name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s1" xmlns:linux="x"><evr operation="less than">0:1.2.13-1</evr></linux:dpkginfo_state></states>
	</oval_definitions>`
	advs, err := ParseOVAL([]byte(x))
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].Affected[0].Ecosystem != "Debian:12" {
		t.Fatalf("an org.debian id must key Debian:12 despite a com.ubuntu substring, got %+v", advs)
	}
}

// TestParseOracleOVAL parses a real (trimmed) Oracle Linux ELSA OVAL fixture: a non-modular patch fixing
// several CVEs expands to one advisory per CVE keyed Oracle Linux:9, and a modular definition is skipped.
func TestParseOracleOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-oracle-linux.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(oracle): %v", err)
	}
	cves := map[string]bool{}
	pkgs := map[string]bool{}
	for _, a := range advs {
		cves[a.ID] = true
		if len(a.Affected) == 0 {
			t.Errorf("%s has no affected packages", a.ID)
		}
		for _, ap := range a.Affected {
			pkgs[ap.Package] = true
			if ap.Ecosystem != "Oracle Linux:9" {
				t.Errorf("%s: ecosystem = %q, want Oracle Linux:9", a.ID, ap.Ecosystem)
			}
			if ap.Ranges[0].Type != "ECOSYSTEM" {
				t.Errorf("%s: range type = %q, want ECOSYSTEM", a.ID, ap.Ranges[0].Type)
			}
			if strings.Contains(ap.FixedVersion, ".module") {
				t.Errorf("%s: modular fixed version leaked: %s", a.ID, ap.FixedVersion)
			}
		}
	}
	// One ELSA fixing 7 CVEs in microcode_ctl becomes 7 advisories sharing that package.
	if len(cves) != 7 {
		t.Errorf("want 7 CVE advisories from the non-modular ELSA, got %d: %v", len(cves), cves)
	}
	if !pkgs["microcode_ctl"] {
		t.Error("the non-modular microcode_ctl package must be present")
	}
	// The modular ELSA (a "Module ... is enabled" gate and a .module fixed version) is skipped wholesale.
	if pkgs["cjose"] || pkgs["mod_auth_openidc"] {
		t.Errorf("a modular definition must be skipped, got packages %v", pkgs)
	}
}

// TestParseOracleMatchesViaDomainMatcher proves the Oracle Linux:9 key and the rpm comparator wire end to
// end, including the .elN dist tag and epoch.
func TestParseOracleMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "oval-oracle-linux.xml"))
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatal(err)
	}
	var mc advisory.Advisory
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Package == "microcode_ctl" {
				mc = a
			}
		}
	}
	if mc.ID == "" {
		t.Fatal("microcode_ctl advisory not parsed")
	}
	fixed := mc.Affected[0].FixedVersion // 4:20240910-1.0.1.el9_5
	if ok, got := mc.Match("Oracle Linux:9", "microcode_ctl", "4:20240815-1.0.1.el9_5"); !ok || got != fixed {
		t.Errorf("older microcode_ctl must match with fix %s, got ok=%v fixed=%q", fixed, ok, got)
	}
	if ok, _ := mc.Match("Oracle Linux:9", "microcode_ctl", fixed); ok {
		t.Error("microcode_ctl at the fixed version must not match")
	}
	if ok, _ := mc.Match("Oracle Linux:8", "microcode_ctl", "4:20240815-1.0.1.el9_5"); ok {
		t.Error("a different Oracle release must not match")
	}
}

func TestOraclePlatformRelease(t *testing.T) {
	cases := map[string]string{
		"Oracle Linux 8":             "8",
		"oracle linux 9":             "9",
		"Oracle Linux 7.9":           "7",
		"Red Hat Enterprise Linux 9": "",
		"Oracle Linux":               "",
		"":                           "",
	}
	for platform, want := range cases {
		if got := oraclePlatformRelease(platform); got != want {
			t.Errorf("oraclePlatformRelease(%q) = %q, want %q", platform, got, want)
		}
	}
}

// TestOracleEcosystemKeyRoundTrip locks the feed key (Oracle Linux:<major>) to the matcher key a Syft ol rpm
// PURL derives.
func TestOracleEcosystemKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:rpm/ol/bash@5?arch=x86_64&distro=ol-9", "Oracle Linux:9"},
		{"pkg:rpm/oracle/bash@5?distro=oracle-8.10", "Oracle Linux:8"},
	} {
		if got := osDistroEcosystem(tc.purl); got != tc.want {
			t.Errorf("osDistroEcosystem(%s) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

// TestIsModuleComment covers the modular-gate detector.
func TestIsModuleComment(t *testing.T) {
	for c, want := range map[string]bool{
		"Module python39:3.9 is enabled":         true,
		"Module mod_auth_openidc:2.3 is enabled": true,
		"Oracle Linux 8 is installed":            false,
		"bash is earlier than 0:1.2-3.el8":       false,
		"":                                       false,
	} {
		if got := isModuleComment(c); got != want {
			t.Errorf("isModuleComment(%q) = %v, want %v", c, got, want)
		}
	}
}

// oracleDoc builds a minimal Oracle ELSA OVAL document from inline definitions/tests/objects/states.
func oracleDoc(body string) []byte {
	return []byte(`<oval_definitions xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">` + body + `</oval_definitions>`)
}

// TestParseOracleUnionsByCVE proves a CVE fixed on two releases (two definitions) yields ONE advisory
// carrying both ecosystems, so the store's upsert-by-id cannot drop a release.
func TestParseOracleUnionsByCVE(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="patch" id="oval:com.oracle.elsa:def:1"><metadata><title>ELSA-1</title>
	    <affected><platform>Oracle Linux 8</platform></affected><reference source="CVE" ref_id="CVE-2099-1000"/></metadata>
	    <criteria><criterion test_ref="t8"/></criteria></definition>
	  <definition class="patch" id="oval:com.oracle.elsa:def:2"><metadata><title>ELSA-2</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-1000"/></metadata>
	    <criteria><criterion test_ref="t9"/></criteria></definition></definitions>
	  <tests>
	    <linux:rpminfo_test id="t8"><object object_ref="o1"/><state state_ref="s8"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="t9"><object object_ref="o1"/><state state_ref="s9"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><name>glibc</name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="s8"><evr operation="less than">0:2.28-1.el8_10</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="s9"><evr operation="less than">0:2.34-1.el9_4</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2099-1000" {
		t.Fatalf("want one unioned advisory for CVE-2099-1000, got %+v", advs)
	}
	got := map[string]string{}
	for _, ap := range advs[0].Affected {
		got[ap.Ecosystem] = ap.FixedVersion
	}
	if got["Oracle Linux:8"] != "0:2.28-1.el8_10" || got["Oracle Linux:9"] != "0:2.34-1.el9_4" {
		t.Errorf("union must carry both releases, got %v", got)
	}
}

// TestParseOracleKeysByDistTag proves a package is keyed by its OWN version's dist tag, not the definition's
// first platform: a multi-platform definition with an .el8uek build lands only on Oracle Linux:8, and a
// version whose dist tag is not among the definition's platforms is skipped (no false match).
func TestParseOracleKeysByDistTag(t *testing.T) {
	// A UEK build tagged el8uek in an OL8+OL9 definition: keyed to OL8 by its dist tag, not both.
	doc := oracleDoc(`<definitions>
	  <definition class="patch" id="oval:com.oracle.elsa:def:1"><metadata><title>ELSA-UEK</title>
	    <affected><platform>Oracle Linux 8</platform><platform>Oracle Linux 9</platform></affected>
	    <reference source="CVE" ref_id="CVE-2099-2000"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="t1"><object object_ref="o1"/><state state_ref="s1"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><name>kernel-uek</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s1"><evr operation="less than">0:5.15.0-1.el8uek</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 || advs[0].Affected[0].Ecosystem != "Oracle Linux:8" {
		t.Fatalf("el8uek build must key Oracle Linux:8 only, got %+v", advs)
	}

	// A version whose dist tag (.el9) is NOT one of the definition's platforms (OL8) must be skipped, never
	// keyed under OL8 (which would be a false match).
	doc2 := oracleDoc(`<definitions>
	  <definition class="patch" id="oval:com.oracle.elsa:def:1"><metadata><title>ELSA-X</title>
	    <affected><platform>Oracle Linux 8</platform></affected><reference source="CVE" ref_id="CVE-2099-3000"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="t1"><object object_ref="o1"/><state state_ref="s1"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><name>glibc</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s1"><evr operation="less than">0:2.34-1.el9_4</evr></linux:rpminfo_state></states>`)
	advs2, err := ParseOVAL(doc2)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs2) != 0 {
		t.Errorf("an el9 version in an OL8-only definition must be skipped, got %+v", advs2)
	}
}

func TestOracleReleaseFromEVR(t *testing.T) {
	cases := map[string]string{
		"0:5.15.0-303.171.5.2.el8uek":     "8",
		"0:1.2-3.el8_10":                  "8",
		"4:20240910-1.0.1.el9_5":          "9",
		"0:1.12.1-11.11.ol9_202312212316": "9",
		// A module build ("+el8", no leading dot) yields no dist tag here; modular versions are skipped
		// upstream of this function anyway, so it never gates a real emitted package.
		"0:3.9.19-7.module+el8.10.0+90395": "",
		"1.2.3-4":                          "",
	}
	for evr, want := range cases {
		if got := oracleReleaseFromEVR(evr); got != want {
			t.Errorf("oracleReleaseFromEVR(%q) = %q, want %q", evr, got, want)
		}
	}
}

// TestParseAlmaLinuxOVAL parses a real (trimmed) AlmaLinux ALSA OVAL fixture into AlmaLinux:9 advisories,
// exercising the rpm-family path with the release taken from the affected CPE (AlmaLinux leaves <platform>
// empty).
func TestParseAlmaLinuxOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-almalinux.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(alma): %v", err)
	}
	if len(advs) == 0 {
		t.Fatal("no AlmaLinux advisories parsed")
	}
	var grafana advisory.Advisory
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Ecosystem != "AlmaLinux:9" {
				t.Errorf("%s: ecosystem = %q, want AlmaLinux:9", a.ID, ap.Ecosystem)
			}
			if strings.Contains(ap.FixedVersion, ".module") {
				t.Errorf("%s: modular version leaked: %s", a.ID, ap.FixedVersion)
			}
			if ap.Package == "grafana" {
				grafana = a
			}
		}
	}
	if grafana.ID == "" || grafana.Affected[0].FixedVersion != "0:7.5.11-5.el9_0" {
		t.Fatalf("grafana advisory not parsed as expected: %+v", grafana)
	}
	// end-to-end match through the rpm comparator and the AlmaLinux:9 key
	if ok, _ := grafana.Match("AlmaLinux:9", "grafana", "0:7.5.11-4.el9_0"); !ok {
		t.Error("an older grafana must match")
	}
	if ok, _ := grafana.Match("AlmaLinux:9", "grafana", "0:7.5.11-5.el9_0"); ok {
		t.Error("grafana at the fixed version must not match")
	}
	if ok, _ := grafana.Match("AlmaLinux:8", "grafana", "0:7.5.11-4.el9_0"); ok {
		t.Error("a different AlmaLinux release must not match")
	}
}

func TestAlmaCPERelease(t *testing.T) {
	cases := map[string]string{
		"cpe:/a:almalinux:almalinux:9":            "9",
		"cpe:/a:almalinux:almalinux:9::appstream": "9",
		"cpe:/a:almalinux:almalinux:8::crb":       "8",
		"cpe:/o:redhat:enterprise_linux:9":        "",
		"cpe:/a:almalinux:almalinux:":             "",
		"":                                        "",
	}
	for cpe, want := range cases {
		if got := almaCPERelease(cpe); got != want {
			t.Errorf("almaCPERelease(%q) = %q, want %q", cpe, got, want)
		}
	}
}

// TestAlmaEcosystemKeyRoundTrip locks the AlmaLinux feed key to the matcher key a Syft almalinux rpm PURL
// derives.
func TestAlmaEcosystemKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:rpm/almalinux/bash@5?arch=x86_64&distro=almalinux-9.4", "AlmaLinux:9"},
		{"pkg:rpm/alma/bash@5?distro=almalinux-8", "AlmaLinux:8"},
	} {
		if got := osDistroEcosystem(tc.purl); got != tc.want {
			t.Errorf("osDistroEcosystem(%s) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

// TestParseOpenSUSEOVAL parses a real (trimmed) openSUSE Leap OVAL fixture into openSUSE:15.6 advisories,
// exercising the SUSE specifics: the CVE is taken from the <title>, and the release from the affected
// "openSUSE Leap 15.6" platform (SUSE rpm versions carry no distro dist tag).
func TestParseOpenSUSEOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-opensuse.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(opensuse): %v", err)
	}
	var rc advisory.Advisory
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Ecosystem != "openSUSE:15.6" {
				t.Errorf("%s: ecosystem = %q, want openSUSE:15.6", a.ID, ap.Ecosystem)
			}
			if ap.Ranges[0].Type != "ECOSYSTEM" {
				t.Errorf("%s: range type = %q, want ECOSYSTEM", a.ID, ap.Ranges[0].Type)
			}
			if ap.Package == "roundcubemail" {
				rc = a
			}
		}
	}
	if rc.ID != "CVE-2026-25916" || rc.Affected[0].FixedVersion != "0:1.6.13-bp156.2.12.1" {
		t.Fatalf("roundcubemail advisory (CVE from title) not parsed as expected: %+v", rc)
	}
	// end-to-end match through the rpm comparator on SUSE's version format
	if ok, _ := rc.Match("openSUSE:15.6", "roundcubemail", "0:1.6.13-bp156.2.11.1"); !ok {
		t.Error("an older roundcubemail must match")
	}
	if ok, _ := rc.Match("openSUSE:15.6", "roundcubemail", "0:1.6.13-bp156.2.12.1"); ok {
		t.Error("roundcubemail at the fixed version must not match")
	}
	if ok, _ := rc.Match("openSUSE:15.5", "roundcubemail", "0:1.6.13-bp156.2.11.1"); ok {
		t.Error("a different openSUSE release must not match")
	}
}

// TestParseOVALGzip proves the gzip-compressed feed path (SUSE ships .gz) parses identically to plain XML.
func TestParseOVALGzip(t *testing.T) {
	plain, err := os.ReadFile(filepath.Join("testdata", "oval-opensuse.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	advs, err := ParseOVAL(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseOVAL(gzip): %v", err)
	}
	if len(advs) == 0 || advs[0].Affected[0].Ecosystem != "openSUSE:15.6" {
		t.Errorf("gzip parse mismatch: %+v", advs)
	}
}

func TestSusePlatformRelease(t *testing.T) {
	cases := map[string]string{
		"openSUSE Leap 15.6":                  "15.6",
		"opensuse leap 15.5":                  "15.5",
		"SUSE Linux Enterprise Server 15 SP5": "",
		"openSUSE Leap":                       "",
		"":                                    "",
	}
	for platform, want := range cases {
		if got := susePlatformRelease(platform); got != want {
			t.Errorf("susePlatformRelease(%q) = %q, want %q", platform, got, want)
		}
	}
}

func TestOpenSUSEEcosystemKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:rpm/opensuse/bash@5?arch=x86_64&distro=opensuse-leap-15.6", "openSUSE:15.6"},
		{"pkg:rpm/opensuse/bash@5?distro=opensuse-leap-15.5", "openSUSE:15.5"},
	} {
		if got := osDistroEcosystem(tc.purl); got != tc.want {
			t.Errorf("osDistroEcosystem(%s) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

// TestRpmOvalCVEsFromTitle proves a CVE named only in the <title> (SUSE) is extracted, while an ELSA-style
// title (Oracle/Alma) contributes no bogus CVE.
func TestRpmOvalCVEsFromTitle(t *testing.T) {
	suse := &ovalDefinition{Title: "CVE-2001-0405"}
	if got := rpmOvalCVEs(suse); len(got) != 1 || got[0] != "CVE-2001-0405" {
		t.Errorf("SUSE title CVE not extracted: %v", got)
	}
	elsa := &ovalDefinition{Title: "ELSA-2024-5962: python39:3.9 security update (MODERATE)"}
	if got := rpmOvalCVEs(elsa); len(got) != 0 {
		t.Errorf("ELSA title must yield no CVE, got %v", got)
	}
}

// TestRpmOvalBoundedRangeSkipped proves a package constrained by BOTH a "greater than or equal" and a "less
// than" state in one definition (a [X, Y) range) is skipped rather than emitted as an overshooting [0, Y).
func TestRpmOvalBoundedRangeSkipped(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="patch" id="oval:com.oracle.elsa:def:1"><metadata><title>ELSA-B</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9000"/></metadata>
	    <criteria>
	      <criterion test_ref="tge"/>
	      <criterion test_ref="tlt"/>
	      <criterion test_ref="tok"/></criteria></definition></definitions>
	  <tests>
	    <linux:rpminfo_test id="tge"><object object_ref="o1"/><state state_ref="sge"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tlt"><object object_ref="o1"/><state state_ref="slt"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tok"><object object_ref="o2"/><state state_ref="sok"/></linux:rpminfo_test></tests>
	  <objects>
	    <linux:rpminfo_object id="o1"><name>bounded-pkg</name></linux:rpminfo_object>
	    <linux:rpminfo_object id="o2"><name>plain-pkg</name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="sge"><evr operation="greater than or equal">0:1.0-1.el9</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="slt"><evr operation="less than">0:2.0-1.el9</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="sok"><evr operation="less than">0:3.0-1.el9</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]bool{}
	for _, a := range advs {
		for _, ap := range a.Affected {
			pkgs[ap.Package] = true
		}
	}
	if pkgs["bounded-pkg"] {
		t.Error("a package with a ge+lt bounded range must be skipped, not emitted as [0, Y)")
	}
	if !pkgs["plain-pkg"] {
		t.Error("a plain less-than package in the same definition must still be emitted")
	}
}

func TestRpmOvalNotYetFixedZeroFloor(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9001"><metadata><title>ELSA not yet fixed</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9100"/></metadata>
	    <criteria><criterion test_ref="t0"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="t0" check="at least one" comment="openssl is affected"><object object_ref="o0"/><state state_ref="s0"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o0"><name>openssl</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s0"><evr operation="greater than">0:0-0</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("not-yet-fixed advisory not emitted: %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "Oracle Linux:9" || ap.Package != "openssl" || ap.FixedVersion != "" ||
		len(ap.Ranges) != 1 || len(ap.Ranges[0].Events) != 1 || ap.Ranges[0].Events[0].Introduced != "0" {
		t.Fatalf("not-yet-fixed binding = %+v", ap)
	}
	if ok, fixed := advs[0].Match("Oracle Linux:9", "openssl", "0:3.2.2-1.el9"); !ok || fixed != "" {
		t.Fatalf("installed rpm must match open-ended vendor affected state: ok=%v fixed=%q", ok, fixed)
	}
}

func TestRpmOvalExistenceOnlyNotYetFixed(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9002"><metadata><title>ELSA existence affected</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9101"/></metadata>
	    <criteria><criterion test_ref="texists"/></criteria></definition></definitions>
	  <tests>
	    <linux:rpminfo_test id="texists" check="at least one" comment="kernel-tools is affected"><object object_ref="oexists"/></linux:rpminfo_test>
	  </tests>
	  <objects><linux:rpminfo_object id="oexists"><name>kernel-tools</name></linux:rpminfo_object></objects>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("default at_least_one_exists test not emitted: %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "Oracle Linux:9" || ap.Package != "kernel-tools" || ap.FixedVersion != "" {
		t.Fatalf("existence-only binding = %+v", ap)
	}
	if ok, _ := advs[0].Match("Oracle Linux:9", "kernel-tools", "0:5.14.0-999.el9"); !ok {
		t.Fatal("existence-only affected package must match an installed version")
	}
}

func TestRpmOvalExistenceOnlyDoesNotPromoteInstalledPlatformGate(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:90025"><metadata><title>ELSA platform gate</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9105"/></metadata>
	    <criteria><criterion test_ref="tplatform"/></criteria></definition></definitions>
	  <tests>
	    <linux:rpminfo_test id="tplatform" check="at least one" comment="oraclelinux-release is installed"><object object_ref="oplatform"/></linux:rpminfo_test>
	  </tests>
	  <objects><linux:rpminfo_object id="oplatform"><name>oraclelinux-release</name></linux:rpminfo_object></objects>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Fatalf("platform/package presence gate must not become CVE affected authority: %+v", advs)
	}
}

func TestRpmOvalExistenceOnlyFailsClosedWhenAmbiguous(t *testing.T) {
	t.Run("multi release", func(t *testing.T) {
		doc := oracleDoc(`<definitions>
		  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9003"><metadata><title>ELSA ambiguous release</title>
		    <affected><platform>Oracle Linux 8</platform><platform>Oracle Linux 9</platform></affected>
		    <reference source="CVE" ref_id="CVE-2099-9102"/></metadata>
		    <criteria><criterion test_ref="texists"/></criteria></definition></definitions>
		  <tests><linux:rpminfo_test id="texists" check="at least one" check_existence="at_least_one_exists"><object object_ref="o"/></linux:rpminfo_test></tests>
		  <objects><linux:rpminfo_object id="o"><name>bash</name></linux:rpminfo_object></objects>`)
		advs, err := ParseOVAL(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(advs) != 0 {
			t.Fatalf("release-ambiguous open-ended advisory must be skipped: %+v", advs)
		}
	})
	t.Run("non affirmative existence", func(t *testing.T) {
		doc := oracleDoc(`<definitions>
		  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9004"><metadata><title>ELSA none-exist</title>
		    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9103"/></metadata>
		    <criteria><criterion test_ref="texists"/></criteria></definition></definitions>
		  <tests><linux:rpminfo_test id="texists" check="at least one" check_existence="none_exist"><object object_ref="o"/></linux:rpminfo_test></tests>
		  <objects><linux:rpminfo_object id="o"><name>bash</name></linux:rpminfo_object></objects>`)
		advs, err := ParseOVAL(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(advs) != 0 {
			t.Fatalf("none_exist must never become affected authority: %+v", advs)
		}
	})
}

func TestRpmOvalFixedAuthorityClipsNotYetFixedRegardlessOfDefinitionOrder(t *testing.T) {
	openDef := `<definition class="vulnerability" id="oval:com.oracle.elsa:def:9100"><metadata><title>ELSA affected</title>
	  <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9200"/></metadata>
	  <criteria><criterion test_ref="topen"/></criteria></definition>`
	fixedDef := `<definition class="patch" id="oval:com.oracle.elsa:def:9101"><metadata><title>ELSA fixed</title>
	  <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9200"/></metadata>
	  <criteria><criterion test_ref="tfixed"/></criteria></definition>`
	tail := `</definitions><tests>
	  <linux:rpminfo_test id="topen" check="at least one" comment="openssl is affected"><object object_ref="o"/><state state_ref="sopen"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="tfixed"><object object_ref="o"/><state state_ref="sfixed"/></linux:rpminfo_test>
	  </tests><objects><linux:rpminfo_object id="o"><name>openssl</name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="sopen"><evr operation="greater than">0:0-0</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="sfixed"><evr operation="less than">0:3.2.2-6.el9_5</evr></linux:rpminfo_state>
	  </states>`

	for _, tc := range []struct {
		name string
		defs string
	}{
		{name: "open then fixed", defs: openDef + fixedDef},
		{name: "fixed then open", defs: fixedDef + openDef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advs, err := ParseOVAL(oracleDoc(`<definitions>` + tc.defs + tail))
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 1 || len(advs[0].Affected) != 1 {
				t.Fatalf("merged advisory = %+v", advs)
			}
			ap := advs[0].Affected[0]
			if ap.FixedVersion != "0:3.2.2-6.el9_5" {
				t.Fatalf("fixed authority did not clip open-ended claim: %+v", ap)
			}
			if ok, _ := advs[0].Match("Oracle Linux:9", "openssl", "0:3.2.2-5.el9_5"); !ok {
				t.Fatal("pre-fix package should remain affected")
			}
			if ok, _ := advs[0].Match("Oracle Linux:9", "openssl", "0:3.2.2-6.el9_5"); ok {
				t.Fatal("vendor fixed version must not match stale not-yet-fixed authority")
			}
			if ok, _ := advs[0].Match("Oracle Linux:9", "openssl", "0:3.2.2-7.el9_5"); ok {
				t.Fatal("post-fix package must not match stale not-yet-fixed authority")
			}
		})
	}
}

func TestRpmOvalNonZeroLowerBoundNeverWidensToAllVersions(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9200"><metadata><title>ELSA bounded-only</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9300"/></metadata>
	    <criteria><criterion test_ref="tge"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="tge" check="at least one"><object object_ref="o"/><state state_ref="sge"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o"><name>openssl</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="sge"><evr operation="greater than or equal">0:3.0-1.el9</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Fatalf("non-zero lower bound was widened to open-ended affected range: %+v", advs)
	}
}

func TestRpmExplicitAffectedAuthorityUsesCriterionOrTestLayer(t *testing.T) {
	for _, tc := range []struct {
		name, criterion, test string
		want                  bool
	}{
		{name: "criterion authority", criterion: "openssl is affected", test: "openssl is >0", want: true},
		{name: "test authority", criterion: "", test: "openssl is affected", want: true},
		{name: "installed gate", criterion: "openssl is installed", test: "openssl is >0", want: false},
		{name: "wrong package", criterion: "libssl is affected", test: "openssl is >0", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rpmExplicitAffectedAuthority(tc.criterion, tc.test, "openssl"); got != tc.want {
				t.Fatalf("rpmExplicitAffectedAuthority(%q,%q)=%v want %v", tc.criterion, tc.test, got, tc.want)
			}
		})
	}
}

func TestRpmOvalZeroFloorDoesNotPromoteInstalledGate(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9249"><metadata><title>ELSA zero-floor gate</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9349"/></metadata>
	    <criteria><criterion test_ref="t"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="t" check="at least one" comment="openssl is installed"><object object_ref="o"/><state state_ref="s"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o"><name>openssl</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s"><evr operation="greater than">0:0-0</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Fatalf("zero-floor installed gate must not become affected authority: %+v", advs)
	}
}

func TestRpmOvalOpenEndedRejectsNegatedOrMultiPackageTests(t *testing.T) {
	t.Run("none satisfy", func(t *testing.T) {
		doc := oracleDoc(`<definitions>
		  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9250"><metadata><title>ELSA negated</title>
		    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9350"/></metadata>
		    <criteria><criterion test_ref="t"/></criteria></definition></definitions>
		  <tests><linux:rpminfo_test id="t" check="none satisfy"><object object_ref="o"/><state state_ref="s"/></linux:rpminfo_test></tests>
		  <objects><linux:rpminfo_object id="o"><name>openssl</name></linux:rpminfo_object></objects>
		  <states><linux:rpminfo_state id="s"><evr operation="greater than or equal">0</evr></linux:rpminfo_state></states>`)
		advs, err := ParseOVAL(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(advs) != 0 {
			t.Fatalf("negated OVAL test minted affected authority: %+v", advs)
		}
	})

	t.Run("variable expands to multiple packages", func(t *testing.T) {
		def := &ovalDefinition{}
		def.Criteria.Criterion = []ovalCriterion{{TestRef: "t"}}
		tests := map[string]ovalTest{
			"t": {
				ID:    "t",
				Check: "at least one",
				State: struct {
					Ref string `xml:"state_ref,attr"`
				}{Ref: "s"},
				Object: struct {
					Ref string `xml:"object_ref,attr"`
				}{Ref: "o"},
			},
		}
		objects := map[string][]string{"o": {"openssl", "libssl"}}
		states := map[string]ovalState{"s": {ID: "s", Evr: ovalEVR{Operation: "greater than or equal", Value: "0"}}}
		got := rpmOvalAffected(def, "Oracle Linux:", map[string]bool{"9": true}, tests, objects, states)
		if len(got) != 0 {
			t.Fatalf("multi-package open-ended object must fail closed: %+v", got)
		}
	})
}

func TestRpmOvalNegatedCriteriaFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		criteria string
		test     string
		state    string
	}{
		{
			name:     "zero floor criterion",
			criteria: `<criteria><criterion test_ref="t" comment="openssl is affected" negate="true"/></criteria>`,
			test:     `<linux:rpminfo_test id="t" check="at least one"><object object_ref="o"/><state state_ref="s"/></linux:rpminfo_test>`,
			state:    `<states><linux:rpminfo_state id="s"><evr operation="greater than">0:0-0</evr></linux:rpminfo_state></states>`,
		},
		{
			name:     "zero floor parent criteria",
			criteria: `<criteria><criteria negate="1"><criterion test_ref="t" comment="openssl is affected"/></criteria></criteria>`,
			test:     `<linux:rpminfo_test id="t" check="at least one"><object object_ref="o"/><state state_ref="s"/></linux:rpminfo_test>`,
			state:    `<states><linux:rpminfo_state id="s"><evr operation="greater than or equal">0</evr></linux:rpminfo_state></states>`,
		},
		{
			name:     "existence only criterion",
			criteria: `<criteria><criterion test_ref="t" comment="openssl is affected" negate="true"/></criteria>`,
			test:     `<linux:rpminfo_test id="t" check="at least one" check_existence="at_least_one_exists"><object object_ref="o"/></linux:rpminfo_test>`,
		},
		{
			name:     "existence only parent criteria",
			criteria: `<criteria negate="true"><criterion test_ref="t" comment="openssl is affected"/></criteria>`,
			test:     `<linux:rpminfo_test id="t" check="at least one" check_existence="at_least_one_exists"><object object_ref="o"/></linux:rpminfo_test>`,
		},
		{
			name:     "fixed criterion",
			criteria: `<criteria><criterion test_ref="t" negate="true"/></criteria>`,
			test:     `<linux:rpminfo_test id="t"><object object_ref="o"/><state state_ref="s"/></linux:rpminfo_test>`,
			state:    `<states><linux:rpminfo_state id="s"><evr operation="less than">0:3.2.2-1.el9</evr></linux:rpminfo_state></states>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := oracleDoc(`<definitions>
			  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9251"><metadata><title>ELSA negated criteria</title>
			    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9351"/></metadata>` +
				tc.criteria + `</definition></definitions><tests>` + tc.test + `</tests>
			  <objects><linux:rpminfo_object id="o"><name>openssl</name></linux:rpminfo_object></objects>` + tc.state)
			advs, err := ParseOVAL(doc)
			if err != nil {
				t.Fatal(err)
			}
			if len(advs) != 0 {
				t.Fatalf("negated criteria minted affected authority: %+v", advs)
			}
		})
	}
}

func TestRpmAllVersionsFloorVendorShapes(t *testing.T) {
	for _, tc := range []struct {
		op, value string
		want      bool
	}{
		{op: "greater than", value: "0:0-0", want: true},
		{op: "greater than or equal", value: "0", want: true},
		{op: "greater than or equal", value: "0:0", want: true},
		{op: "greater than", value: "0:1-0", want: false},
		{op: "less than", value: "0:0-0", want: false},
	} {
		if got := rpmAllVersionsFloor(tc.op, tc.value); got != tc.want {
			t.Errorf("rpmAllVersionsFloor(%q,%q)=%v want %v", tc.op, tc.value, got, tc.want)
		}
	}
}

func TestRpmZeroFloorIsNarrow(t *testing.T) {
	for _, value := range []string{"0", "0:0", "0:0-0"} {
		if !rpmZeroFloor(value) {
			t.Errorf("rpmZeroFloor(%q)=false, want true", value)
		}
	}
	for _, value := range []string{"", "0:0-1", "0:1", "1", "0.0", "0:0-0.1"} {
		if rpmZeroFloor(value) {
			t.Errorf("rpmZeroFloor(%q)=true, want false", value)
		}
	}
}

func TestParseSLENotYetFixedOVAL(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:org.opensuse.security:def:9900"><metadata>
	    <title>CVE-2099-9400</title>
	    <affected><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected>
	    </metadata><criteria><criterion test_ref="t0" comment="libxml2 is affected"/></criteria></definition>
	  </definitions>
	  <tests>
	    <linux:rpminfo_test id="t0" check="at least one" check_existence="at_least_one_exists" comment="libxml2 is >0">
	      <object object_ref="o0"/><state state_ref="s0"/>
	    </linux:rpminfo_test>
	  </tests>
	  <objects><linux:rpminfo_object id="o0"><name>libxml2</name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s0"><evr operation="greater than">0:0-0</evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2099-9400" || len(advs[0].Affected) != 1 {
		t.Fatalf("SLE not-yet-fixed advisory = %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "SUSE:15.6" || ap.Package != "libxml2" || ap.FixedVersion != "" {
		t.Fatalf("SLE not-yet-fixed binding = %+v", ap)
	}
	if ok, fixed := advs[0].Match("SUSE:15.6", "libxml2", "0:2.12.5-150600.3.9"); !ok || fixed != "" {
		t.Fatalf("SLE installed rpm must match open-ended affected state: ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := advs[0].Match("SUSE:15.5", "libxml2", "0:2.12.5-150600.3.9"); ok {
		t.Fatal("a different SLE service pack must not match")
	}
}

func TestRpmOvalAmbiguousFixedAuthorityNeverFallsBackOpenEnded(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="vulnerability" id="oval:com.oracle.elsa:def:9300"><metadata><title>ELSA affected</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9500"/></metadata>
	    <criteria><criterion test_ref="topen"/></criteria></definition>
	  <definition class="patch" id="oval:com.oracle.elsa:def:9301"><metadata><title>ELSA fixed lineage one</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9500"/></metadata>
	    <criteria><criterion test_ref="tfixed1"/></criteria></definition>
	  <definition class="patch" id="oval:com.oracle.elsa:def:9302"><metadata><title>ELSA fixed lineage two</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-9500"/></metadata>
	    <criteria><criterion test_ref="tfixed2"/></criteria></definition>
	  </definitions>
	  <tests>
	    <linux:rpminfo_test id="topen" check="at least one"><object object_ref="o"/><state state_ref="sopen"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tfixed1"><object object_ref="o"/><state state_ref="sfixed1"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tfixed2"><object object_ref="o"/><state state_ref="sfixed2"/></linux:rpminfo_test>
	  </tests>
	  <objects><linux:rpminfo_object id="o"><name>kernel</name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="sopen"><evr operation="greater than or equal">0</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="sfixed1"><evr operation="less than">0:4.18.0-1.el9</evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="sfixed2"><evr operation="less than">0:5.14.0-1.el9</evr></linux:rpminfo_state>
	  </states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Fatalf("cross-lineage fixed authority is ambiguous and must skip instead of falling back open-ended: %+v", advs)
	}
}

// EPIC #860 D1.4: SUSE Linux Enterprise OVAL shares openSUSE's definition-id prefix but uses "SUSE Linux
// Enterprise ... 15 SP6" platform strings, so it must key "SUSE:15.6" (per service pack), not "openSUSE:".
func TestParseSLEOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(sle): %v", err)
	}
	var oss advisory.Advisory
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Ecosystem != "SUSE:15.6" {
				t.Errorf("%s: ecosystem = %q, want SUSE:15.6 (SLE must not key as openSUSE)", a.ID, ap.Ecosystem)
			}
			if ap.Package == "libopenssl1_1" {
				oss = a
			}
		}
	}
	if oss.ID != "CVE-2026-12345" || len(oss.Affected) == 0 || oss.Affected[0].FixedVersion != "0:1.1.1w-150600.3.10" {
		t.Fatalf("libopenssl1_1 advisory (CVE from title, SUSE:15.6) not parsed as expected: %+v", oss)
	}
	// end-to-end match through the rpm comparator on SUSE's version format
	if ok, _ := oss.Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.9"); !ok {
		t.Error("an older libopenssl1_1 must match")
	}
	if ok, _ := oss.Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.10"); ok {
		t.Error("libopenssl1_1 at the fixed version must not match")
	}
	// A different service pack must NOT match: a SP6 fixed NEVR keyed SUSE:15.6 cannot apply to a SUSE:15.5
	// (SP5) package, mirroring why bare-major keying would be unsound.
	if ok, _ := oss.Match("SUSE:15.5", "libopenssl1_1", "0:1.1.1w-150600.3.9"); ok {
		t.Error("a different SLE service pack must not match")
	}
}

// slePlatformRelease extracts the per-service-pack release from a SUSE Linux Enterprise platform string and
// returns "" for any non-SLE platform (so an openSUSE Leap document is never mis-detected as SLE).
func TestSLEPlatformRelease(t *testing.T) {
	cases := map[string]string{
		"SUSE Linux Enterprise Server 15 SP6":                "15.6",
		"SUSE Linux Enterprise Module for Basesystem 15 SP6": "15.6",
		"SUSE Linux Enterprise Server 12 SP5":                "12.5",
		"SUSE Linux Enterprise Server 15":                    "15",
		"SUSE Linux Enterprise Server 16.0":                  "16.0",
		"openSUSE Leap 15.6":                                 "", // not SLE
		"Ubuntu 22.04":                                       "",
		"SUSE Linux Enterprise Server":                       "", // no version token
	}
	for in, want := range cases {
		if got := slePlatformRelease(in); got != want {
			t.Errorf("slePlatformRelease(%q) = %q, want %q", in, got, want)
		}
	}
}

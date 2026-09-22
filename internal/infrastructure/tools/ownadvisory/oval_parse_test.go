package ownadvisory

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	if len(advs) != 1 {
		t.Fatalf("want 1 fixed advisory, got %d: %+v", len(advs), advs)
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

func TestParseOVALSnapshotRejectsUnrepresentableDebDefinition(t *testing.T) {
	fixed, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := os.ReadFile(filepath.Join("testdata", "oval-jammy-deferred.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, documents := range [][][]byte{{fixed, deferred}, {deferred, fixed}} {
		advs, err := ParseOVALSnapshot(documents)
		if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
			t.Fatalf("a present deferred definition must reject the complete snapshot: err=%v advisories=%+v", err, advs)
		}
	}
}

func TestParseUbuntuOVALResolvesCurrentConstantVariablePackageList(t *testing.T) {
	doc := `<oval_definitions xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
	  <definitions><definition class="vulnerability" id="oval:com.ubuntu.jammy:def:2026100000000000">
	    <metadata><title>CVE-2026-10000 on Ubuntu 22.04 LTS</title><affected><platform>Ubuntu 22.04 LTS</platform></affected>
	      <reference source="CVE" ref_id="CVE-2026-10000"/><advisory><severity>High</severity></advisory></metadata>
	    <criteria><criterion test_ref="oval:com.ubuntu.jammy:tst:2026100000000000"/></criteria>
	  </definition></definitions>
	  <tests><linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:2026100000000000" check="at least one">
	    <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:2026100000000000"/>
	    <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:2026100000000000"/>
	  </linux-def:dpkginfo_test></tests>
	  <objects><linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:2026100000000000">
	    <linux-def:name var_ref="oval:com.ubuntu.jammy:var:2026100000000000"/>
	  </linux-def:dpkginfo_object></objects>
	  <states><linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:2026100000000000">
	    <linux-def:evr datatype="debian_evr_string" operation="less than">2.4.52-1ubuntu4.3</linux-def:evr>
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
	if ok, fixed := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.9", ""); !ok || fixed != "3.0.2-0ubuntu1.10" {
		t.Errorf("older openssl must match with fix 3.0.2-0ubuntu1.10, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.10", ""); ok {
		t.Error("openssl at the fixed version must not match")
	}
	if ok, _ := a.Match("Ubuntu:20.04", "openssl", "3.0.2-0ubuntu1.9", ""); ok {
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
	if ok, fixed := glibc.Match("Debian:12", "glibc", "2.1-1", ""); !ok || fixed != "0:2.2-1" {
		t.Errorf("older glibc (no epoch) must match with fix 0:2.2-1, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := glibc.Match("Debian:12", "glibc", "0:2.1-1", ""); !ok {
		t.Error("older glibc with an explicit epoch must match")
	}
	if ok, _ := glibc.Match("Debian:12", "glibc", "0:2.2-1", ""); ok {
		t.Error("glibc at the fixed version must not match")
	}
	if ok, _ := glibc.Match("Debian:11", "glibc", "2.1-1", ""); ok {
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

// TestOVALAmbiguousStateRejected proves a dpkginfo_state carrying both <version> and <evr> with divergent
// values rejects the complete snapshot rather than silently choosing or omitting a boundary.
func TestOVALAmbiguousStateRejected(t *testing.T) {
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
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("an ambiguous version/evr state must reject the snapshot: err=%v advisories=%+v", err, advs)
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
	  <tests><linux:dpkginfo_test id="t1" check="at least one" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o1" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><linux:name>openssl</linux:name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s1" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
	    <linux:version datatype="debian_evr_string" operation="less than">0:1.2-1</linux:version>
	    <linux:evr datatype="debian_evr_string" operation="less than">0:1.2-1</linux:evr></linux:dpkginfo_state></states>
	</oval_definitions>`
	advs, err := ParseOVAL([]byte(x))
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].Affected[0].FixedVersion != "0:1.2-1" {
		t.Errorf("consistent both-elements state must yield the advisory, got %+v", advs)
	}
}

// TestDebianZeroBoundPreservesEmptyAdvisory proves an impossible bound retires stale state without widening.
func TestDebianZeroBoundPreservesEmptyAdvisory(t *testing.T) {
	for _, sentinel := range []string{"0:0", "0", "0:0-0"} {
		x := `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
		  <definitions><definition class="vulnerability" id="oval:org.debian:def:1">
		    <metadata><title>CVE-2099-0004 bash</title><affected family="unix"><platform>Debian GNU/Linux 12</platform><product>bash</product></affected>
		      <reference source="CVE" ref_id="CVE-2099-0004"/></metadata>
		    <criteria operator="AND"><criterion test_ref="release" comment="Debian 12 is installed"/>
		      <criteria operator="OR"><criteria operator="AND"><criterion test_ref="arch" comment="all architecture"/><criterion test_ref="t1" comment="bash DPKG is earlier than ` + sentinel + `"/></criteria></criteria>
		    </criteria></definition></definitions>
		  <tests><linux:dpkginfo_test id="t1" check="all" check_existence="at_least_one_exists"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:dpkginfo_test></tests>
		  <objects><linux:dpkginfo_object id="o1"><linux:name>bash</linux:name></linux:dpkginfo_object></objects>
		  <states><linux:dpkginfo_state id="s1"><linux:evr datatype="debian_evr_string" operation="less than">` + sentinel + `</linux:evr></linux:dpkginfo_state></states>
		</oval_definitions>`
		advs, err := ParseOVAL([]byte(x))
		if err != nil {
			t.Fatalf("zero-bound %q: %v", sentinel, err)
		}
		if len(advs) != 1 || advs[0].ID != "CVE-2099-0004" || len(advs[0].Affected) != 0 {
			t.Fatalf("zero-bound %q must preserve one empty current advisory: %+v", sentinel, advs)
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
	  <tests><linux:dpkginfo_test id="t1" check="at least one" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:dpkginfo_test></tests>
	  <objects><linux:dpkginfo_object id="o1" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><linux:name>zlib</linux:name></linux:dpkginfo_object></objects>
	  <states><linux:dpkginfo_state id="s1" xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><linux:evr datatype="debian_evr_string" operation="less than">0:1.2.13-1</linux:evr></linux:dpkginfo_state></states>
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
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("architecture- and signature-restricted Oracle criteria must reject the snapshot: err=%v advisories=%+v", err, advs)
	}
}

// TestParseOracleMatchesViaDomainMatcher proves the Oracle Linux:9 key and the rpm comparator wire end to
// end, including the .elN dist tag and epoch.
func TestParseOracleMatchesViaDomainMatcher(t *testing.T) {
	doc := oracleDoc(`<definitions>
	  <definition class="patch" id="oval:com.oracle.elsa:def:1"><metadata><title>ELSA-1</title>
	    <affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2099-0001"/></metadata>
	    <criteria><criterion test_ref="t1"/></criteria></definition></definitions>
	  <tests><linux:rpminfo_test id="t1" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><linux:name>microcode_ctl</linux:name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s1"><linux:evr datatype="evr_string" operation="less than">4:20240910-1.0.1.el9_5</linux:evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("safe bounded Oracle definition not parsed: %+v", advs)
	}
	mc := advs[0]
	fixed := mc.Affected[0].FixedVersion
	if ok, got := mc.Match("Oracle Linux:9", "microcode_ctl", "4:20240815-1.0.1.el9_5", ""); !ok || got != fixed {
		t.Errorf("older microcode_ctl must match with fix %s, got ok=%v fixed=%q", fixed, ok, got)
	}
	if ok, _ := mc.Match("Oracle Linux:9", "microcode_ctl", fixed, ""); ok {
		t.Error("microcode_ctl at the fixed version must not match")
	}
	if ok, _ := mc.Match("Oracle Linux:8", "microcode_ctl", "4:20240815-1.0.1.el9_5", ""); ok {
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
	    <linux:rpminfo_test id="t8" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="s8"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="t9" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="s9"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><linux:name>glibc</linux:name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="s8"><linux:evr datatype="evr_string" operation="less than">0:2.28-1.el8_10</linux:evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="s9"><linux:evr datatype="evr_string" operation="less than">0:2.34-1.el9_4</linux:evr></linux:rpminfo_state></states>`)
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
	  <tests><linux:rpminfo_test id="t1" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><linux:name>kernel-uek</linux:name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s1"><linux:evr datatype="evr_string" operation="less than">0:5.15.0-1.el8uek</linux:evr></linux:rpminfo_state></states>`)
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
	  <tests><linux:rpminfo_test id="t1" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="s1"/></linux:rpminfo_test></tests>
	  <objects><linux:rpminfo_object id="o1"><linux:name>glibc</linux:name></linux:rpminfo_object></objects>
	  <states><linux:rpminfo_state id="s1"><linux:evr datatype="evr_string" operation="less than">0:2.34-1.el9_4</linux:evr></linux:rpminfo_state></states>`)
	advs2, err := ParseOVAL(doc2)
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs2) != 0 {
		t.Fatalf("an el9 version in an OL8-only definition must reject the snapshot: err=%v advisories=%+v", err, advs2)
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
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("architecture- and signature-restricted AlmaLinux criteria must reject the snapshot: err=%v advisories=%+v", err, advs)
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
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("architecture-restricted openSUSE criteria must reject the snapshot: err=%v advisories=%+v", err, advs)
	}
}

// TestParseOVALGzip proves the gzip-compressed feed path (SUSE ships .gz) parses identically to plain XML.
func TestParseOVALGzip(t *testing.T) {
	plain, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	plainAdvisories, err := ParseOVAL(plain)
	if err != nil {
		t.Fatalf("ParseOVAL(plain): %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compressedAdvisories, err := ParseOVAL(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseOVAL(gzip): %v", err)
	}
	if len(plainAdvisories) != 1 || len(compressedAdvisories) != 1 ||
		plainAdvisories[0].ID != compressedAdvisories[0].ID ||
		len(plainAdvisories[0].Affected) != len(compressedAdvisories[0].Affected) {
		t.Errorf("gzip parse mismatch: plain=%+v compressed=%+v", plainAdvisories, compressedAdvisories)
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
	    <linux:rpminfo_test id="tge" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="sge"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tlt" check="at least one"><linux:object object_ref="o1"/><linux:state state_ref="slt"/></linux:rpminfo_test>
	    <linux:rpminfo_test id="tok" check="at least one"><linux:object object_ref="o2"/><linux:state state_ref="sok"/></linux:rpminfo_test></tests>
	  <objects>
	    <linux:rpminfo_object id="o1"><linux:name>bounded-pkg</linux:name></linux:rpminfo_object>
	    <linux:rpminfo_object id="o2"><linux:name>plain-pkg</linux:name></linux:rpminfo_object></objects>
	  <states>
	    <linux:rpminfo_state id="sge"><linux:evr datatype="evr_string" operation="greater than or equal">0:1.0-1.el9</linux:evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="slt"><linux:evr datatype="evr_string" operation="less than">0:2.0-1.el9</linux:evr></linux:rpminfo_state>
	    <linux:rpminfo_state id="sok"><linux:evr datatype="evr_string" operation="less than">0:3.0-1.el9</linux:evr></linux:rpminfo_state></states>`)
	advs, err := ParseOVAL(doc)
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("an unsupported conjunction must reject the whole definition rather than widen one branch: err=%v advisories=%+v", err, advs)
	}
}

// SUSE Linux Enterprise OVAL shares openSUSE's definition-id prefix. Architecture-qualified package evidence
// is authoritative applicability, so it is projected with its exact architecture set and enforced at match
// time. The architecture-free match below is the invariant that mattered when this evidence was suppressed
// outright, and it still holds: a component whose architecture is unknown cannot be proven to be inside the
// vendor's set, so it must not match.
func TestParseSLEOVALBindsArchitectureQualifiedFixedPackage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(sle): %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2026-12345" || len(advs[0].Affected) != 1 {
		t.Fatalf("architecture-qualified evidence must bind exactly one affected block: %+v", advs)
	}
	if got, want := strings.Join(advs[0].Affected[0].Architectures, ","), "aarch64,ppc64le,s390x,x86_64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.9", ""); ok {
		t.Error("architecture-qualified evidence must not match a component of unknown architecture")
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.9", "i586"); ok {
		t.Error("architecture-qualified evidence must not match an architecture outside the vendor's set")
	}
	// It must match inside the set, below the fixed boundary. That recall is the point of #1295's fix.
	if ok, fixed := advs[0].Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.9", "x86_64"); !ok || fixed != "0:1.1.1w-150600.3.10" {
		t.Errorf("in-set architecture must match with its fixed hint, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libopenssl1_1", "0:1.1.1w-150600.3.10", "x86_64"); ok {
		t.Error("a version at the fixed boundary must not match")
	}
}

func TestParseSLEAffectedOVALNotYetFixed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(sle affected): %v", err)
	}

	var got advisory.Advisory
	for _, adv := range advs {
		if adv.ID == "CVE-2026-53910" {
			got = adv
			break
		}
	}
	if got.ID == "" {
		t.Fatalf("not-yet-fixed CVE missing: %+v", advs)
	}
	if len(got.Affected) != 2 {
		t.Fatalf("want the two package branches from the authoritative definition, got %+v", got.Affected)
	}
	seen := map[string]bool{}
	for _, ap := range got.Affected {
		seen[ap.Package] = true
		if ap.Ecosystem != "SUSE:15.6" {
			t.Errorf("%s ecosystem = %q, want SUSE:15.6", ap.Package, ap.Ecosystem)
		}
		if ap.FixedVersion != "" {
			t.Errorf("%s fabricated fixed version %q", ap.Package, ap.FixedVersion)
		}
		if len(ap.Ranges) != 1 || ap.Ranges[0].Type != "ECOSYSTEM" || len(ap.Ranges[0].Events) != 1 || ap.Ranges[0].Events[0].Introduced != "0" {
			t.Errorf("%s range = %+v, want one open introduced:0 range", ap.Package, ap.Ranges)
		}
	}
	if !seen["diffutils"] || !seen["diffutils-lang"] {
		t.Fatalf("package branches = %v, want diffutils and diffutils-lang", seen)
	}
	if ok, fixed := got.Match("SUSE:15.6", "diffutils", "3.6-4.3.1", ""); !ok || fixed != "" {
		t.Fatalf("installed affected diffutils must match without a fabricated fix: ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := got.Match("SUSE:15.5", "diffutils", "3.6-4.3.1", ""); ok {
		t.Error("a different SLES service pack must not match")
	}
	if ok, _ := got.Match("SUSE:15.6", "findutils", "3.6-4.3.1", ""); ok {
		t.Error("an unrelated package must not inherit the open range")
	}
}

func TestParseSLEAffectedOVALAcceptsExplicitVersionDatatype(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data,
		[]byte(`<linux:version operation="equals">15.6`),
		[]byte(`<linux:version datatype="version" operation="equals">15.6`),
		1,
	)
	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL(sle affected): %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" || len(advs[0].Affected) != 2 {
		t.Fatalf("an explicit version datatype must retain the authoritative lifecycle evidence: %+v", advs)
	}
}

func TestParseSLEAffectedOVALRejectsAmbiguousApplicability(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	base = bytes.ReplaceAll(base, []byte("\r\n"), []byte("\n"))
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "product state disagrees with metadata", old: `operation="equals">15.6`, new: `operation="equals">15.5`},
		{name: "undeclared product platform", old: `<platform>SUSE Linux Enterprise Server 15 SP6</platform>`, new: `<platform>SUSE Linux Enterprise Server 15 SP6-Unlisted</platform>`},
		{name: "unsupported explicit version datatype", old: `<linux:version operation="equals">15.6`, new: `<linux:version datatype="string" operation="equals">15.6`},
		{name: "wrong product predicate", old: `<linux:name>sles-release</linux:name>`, new: `<linux:name>sles-ltss-release</linux:name>`},
		{name: "negated package criterion", old: `test_ref="oval:org.opensuse.security:tst:diffutils-affected"`, new: `test_ref="oval:org.opensuse.security:tst:diffutils-affected" negate="true"`},
		{name: "architecture restricted state", old: `<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr>`, new: `<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr><linux:arch operation="equals">x86_64</linux:arch>`},
		{name: "object filter", old: `<linux:name>diffutils</linux:name>`, new: `<linux:name>diffutils</linux:name><linux:filter action="include">oval:unsupported:state:1</linux:filter>`},
		{name: "unresolved state", old: `state_ref="oval:org.opensuse.security:ste:affected-zero-sentinel"`, new: `state_ref="oval:org.opensuse.security:ste:missing"`},
		{name: "unsupported criteria child", old: "</criteria>\n        <criteria operator=\"OR\">", new: "<extend_definition definition_ref=\"oval:unsupported:def:1\"/>\n        </criteria>\n        <criteria operator=\"OR\">"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(base, []byte(tc.old)) {
				t.Fatalf("fixture mutation anchor missing: %q", tc.old)
			}
			doc := bytes.Replace(base, []byte(tc.old), []byte(tc.new), 1)
			advs, err := ParseOVAL(doc)
			if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
				t.Fatalf("ambiguous present evidence must reject the complete snapshot: err=%v advisories=%+v", err, advs)
			}
		})
	}
}

func TestParseSLEAffectedOVALSuppressesUnrepresentablePackageEvidence(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	base = bytes.ReplaceAll(base, []byte("\r\n"), []byte("\n"))
	tests := []struct {
		name        string
		old         string
		new         string
		wantPackage string
	}{
		{
			name:        "universal check",
			old:         `id="oval:org.opensuse.security:tst:diffutils-affected" version="1" comment="diffutils is >0" check="at least one"`,
			new:         `id="oval:org.opensuse.security:tst:diffutils-affected" version="1" comment="diffutils is >0" check="all"`,
			wantPackage: "diffutils-lang",
		},
		{name: "real lower bound", old: `operation="greater than">0:0-0`, new: `operation="greater than">0:3.6-4.3.1`},
		{
			name: "multiple evr constraints",
			old:  `<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr>`,
			new:  `<linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr><linux:evr datatype="evr_string" operation="less than">0:3.6-4.3.2</linux:evr>`,
		},
		{
			name: "package conjunction",
			old:  "<criteria operator=\"OR\">\n          <criterion test_ref=\"oval:org.opensuse.security:tst:diffutils-affected\"",
			new:  "<criteria operator=\"AND\">\n          <criterion test_ref=\"oval:org.opensuse.security:tst:diffutils-affected\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(base, []byte(tc.old)) {
				t.Fatalf("fixture mutation anchor missing: %q", tc.old)
			}
			doc := bytes.Replace(base, []byte(tc.old), []byte(tc.new), 1)
			advs, parseErr := ParseOVAL(doc)
			if parseErr != nil {
				t.Fatalf("ParseOVAL: %v", parseErr)
			}
			if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" {
				t.Fatalf("unrepresentable exact-package evidence must preserve one current advisory: %+v", advs)
			}
			if tc.wantPackage == "" {
				if len(advs[0].Affected) != 0 {
					t.Fatalf("unrepresentable package evidence must emit no widened range: %+v", advs[0].Affected)
				}
				return
			}
			if len(advs[0].Affected) != 1 || advs[0].Affected[0].Package != tc.wantPackage {
				t.Fatalf("independent representable sibling must survive suppression: %+v", advs[0].Affected)
			}
		})
	}
}

func TestParseSLEAffectedOVALRejectsCrossBoundOrdinaryServer(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	server := []byte(`comment="SUSE Linux Enterprise Server 15 SP6 is installed"`)
	sap := []byte(`comment="SUSE Linux Enterprise Server for SAP Applications 15 SP6 is installed"`)
	marker := []byte(`comment="SUSE Linux Enterprise Server 15 SP6 swap marker"`)
	data = bytes.Replace(data, server, marker, 1)
	data = bytes.Replace(data, sap, server, 1)
	data = bytes.Replace(data, marker, sap, 1)
	advs, err := ParseOVAL(data)
	if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
		t.Fatalf("a cross-bound server predicate must reject the complete snapshot: err=%v advisories=%+v", err, advs)
	}
}

func TestParseSLEAffectedOVALIgnoresDeclaredRealTimeClause(t *testing.T) {
	data := oracleDoc(`<definitions>
	<definition id="oval:org.opensuse.security:def:real-time-sibling" version="1" class="vulnerability">
	  <metadata>
	    <title>CVE-2026-53910</title>
	    <affected family="unix">
	      <platform>SUSE Linux Enterprise Server 15 SP6</platform>
	      <platform>SUSE Linux Enterprise Real Time 15 SP6</platform>
	      <platform>SUSE Real Time Module 15 SP6</platform>
	    </affected>
	  </metadata>
	  <criteria operator="OR">
	    <criteria operator="AND">
	      <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:open" comment="diffutils is affected"/></criteria>
	    </criteria>
	    <criteria operator="AND">
	      <criteria operator="OR">
	        <criterion test_ref="oval:test:real-time" comment="SUSE Linux Enterprise Real Time 15 SP6 is installed"/>
	        <criterion test_ref="oval:test:real-time-module" comment="SUSE Real Time Module 15 SP6 is installed"/>
	      </criteria>
	      <criteria operator="OR"><criterion test_ref="oval:test:not-affected" comment="kernel-devel-rt is not affected"/></criteria>
	    </criteria>
	  </criteria>
	</definition>
	</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:real-time" check="at least one" comment="sle-rt-release is ==15.6"><linux:object object_ref="oval:obj:real-time"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:real-time-module" check="at least one" comment="sle-module-rt-release is ==15.6"><linux:object object_ref="oval:obj:real-time-module"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:open" check="at least one" comment="diffutils is &gt;0"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:open"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:not-affected" check="at least one" comment="kernel-devel-rt is ==0"><linux:object object_ref="oval:obj:kernel-devel-rt"/><linux:state state_ref="oval:state:not-affected"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:real-time"><linux:name>sle-rt-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:real-time-module"><linux:name>sle-module-rt-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:diffutils"><linux:name>diffutils</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:kernel-devel-rt"><linux:name>kernel-devel-rt</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:open"><linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:not-affected"><linux:version operation="equals">0</linux:version></linux:rpminfo_state>
	</states>`)

	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 || advs[0].Affected[0].Package != "diffutils" {
		t.Fatalf("a declared nonordinary product must not reject or widen ordinary SLES applicability: %+v", advs)
	}
}

func TestParseSLEAffectedOVALFixedWinsRegardlessOfDefinitionOrder(t *testing.T) {
	open := sleAffectedDefinition("open", "oval:test:open")
	fixed := sleAffectedDefinition("fixed", "oval:test:fixed")
	for _, tc := range []struct {
		name        string
		definitions string
	}{
		{name: "open first", definitions: open + fixed},
		{name: "fixed first", definitions: fixed + open},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advs, err := ParseOVAL(sleAffectedDefinitionsDoc(tc.definitions))
			if err != nil {
				t.Fatalf("ParseOVAL: %v", err)
			}
			if len(advs) != 1 || len(advs[0].Affected) != 1 {
				t.Fatalf("want one deterministic binding, got %+v", advs)
			}
			ap := advs[0].Affected[0]
			if ap.Package != "diffutils" || ap.Ecosystem != "SUSE:15.6" || ap.FixedVersion != "0:3.6-4.3.2" {
				t.Fatalf("bounded current evidence must replace open evidence, got %+v", ap)
			}
			if len(ap.Ranges) != 1 || len(ap.Ranges[0].Events) != 2 || ap.Ranges[0].Events[1].Fixed != "0:3.6-4.3.2" {
				t.Fatalf("want [0, fixed) range, got %+v", ap.Ranges)
			}
		})
	}
}

func TestParseSLEAffectedOVALNotAffectedEmitsEmptyReplacement(t *testing.T) {
	advs, err := ParseOVAL(sleNotAffectedDoc())
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" {
		t.Fatalf("want a current replacement record for CVE-2026-53910, got %+v", advs)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("authoritative not-affected state must clear package applicability, got %+v", advs[0].Affected)
	}
}

func sleNotAffectedDoc() []byte {
	return oracleDoc(`<definitions>
	<definition id="oval:org.opensuse.security:def:not-affected" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-53910</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="AND">
	    <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	    <criteria operator="OR"><criterion test_ref="oval:test:not-affected" comment="diffutils is not affected"/></criteria>
	  </criteria>
	</definition>
	</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:not-affected" check="at least one" comment="diffutils is ==0"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:not-affected"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:diffutils"><linux:name>diffutils</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:not-affected"><linux:version operation="equals">0</linux:version></linux:rpminfo_state>
	</states>`)
}

func sleAffectedDefinition(id, packageTest string) string {
	packageComment := "diffutils is affected"
	if packageTest == "oval:test:fixed" {
		packageComment = "diffutils-3.6-4.3.2 is installed"
	}
	return `<definition id="oval:org.opensuse.security:def:` + id + `" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-53910</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="AND">
	    <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	    <criteria operator="OR"><criterion test_ref="` + packageTest + `" comment="` + packageComment + `"/></criteria>
	  </criteria>
	</definition>`
}

func sleAffectedDefinitionsDoc(definitions string) []byte {
	return oracleDoc(`<definitions>` + definitions + `</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:open" check="at least one" comment="diffutils is >0"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:open"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:fixed" check="at least one" comment="diffutils is &lt;0:3.6-4.3.2"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:fixed"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:diffutils"><linux:name>diffutils</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:open"><linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:fixed"><linux:evr datatype="evr_string" operation="less than">0:3.6-4.3.2</linux:evr></linux:rpminfo_state>
	</states>`)
}

func TestParseOVALSnapshotResolvesSUSELifecycleAcrossDocuments(t *testing.T) {
	open := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	fixed := sleAffectedDefinitionsDoc(sleAffectedDefinition("fixed", "oval:test:fixed"))
	for _, documents := range [][][]byte{{open, fixed}, {fixed, open}} {
		advs, err := ParseOVALSnapshot(documents)
		if err != nil {
			t.Fatalf("ParseOVALSnapshot: %v", err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 1 {
			t.Fatalf("want one resolved advisory, got %+v", advs)
		}
		ap := advs[0].Affected[0]
		if ap.Ecosystem != "SUSE:15.6" || ap.Package != "diffutils" || ap.FixedVersion != "0:3.6-4.3.2" {
			t.Fatalf("fixed evidence must replace open evidence across documents: %+v", ap)
		}
	}
}

func TestParseOVALSnapshotNotAffectedClearsOpenAcrossDocuments(t *testing.T) {
	open := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	notAffected := sleNotAffectedDoc()
	for _, documents := range [][][]byte{{open, notAffected}, {notAffected, open}} {
		advs, err := ParseOVALSnapshot(documents)
		if err != nil {
			t.Fatalf("ParseOVALSnapshot: %v", err)
		}
		if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" || len(advs[0].Affected) != 0 {
			t.Fatalf("explicit not-affected evidence must emit an empty current replacement: %+v", advs)
		}
	}
}

func TestParseOVALSnapshotSupersededFixedBoundariesUseGreatest(t *testing.T) {
	first := sleAffectedDefinitionsDoc(sleAffectedDefinition("fixed-a", "oval:test:fixed"))
	second := bytes.ReplaceAll(first, []byte("3.6-4.3.2"), []byte("3.6-4.3.3"))
	for _, documents := range [][][]byte{{first, second}, {second, first}} {
		advs, err := ParseOVALSnapshot(documents)
		if err != nil {
			t.Fatalf("ParseOVALSnapshot: %v", err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 1 || advs[0].Affected[0].FixedVersion != "0:3.6-4.3.3" {
			t.Fatalf("superseded fixed evidence must keep the greatest boundary independent of document order: %+v", advs)
		}
	}
}

func TestParseSLESupersededFixedAlternativesUseGreatest(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		advs, err := ParseOVAL(sleSupersededFixedAlternativesDoc(reverse))
		if err != nil {
			t.Fatalf("ParseOVAL: %v", err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 1 {
			t.Fatalf("want one superseded package projection, got %+v", advs)
		}
		ap := advs[0].Affected[0]
		if ap.Ecosystem != "SUSE:15.6" || ap.Package != "golang-github-prometheus-node_exporter" || ap.FixedVersion != "0:1.10.2-150100.3.41.2" {
			t.Fatalf("OR alternatives must reduce to the greatest fixed boundary: %+v", ap)
		}
	}
}

func sleSupersededFixedAlternativesDoc(reverse bool) []byte {
	older := `<criteria operator="AND">
	  <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	  <criteria operator="OR"><criterion test_ref="oval:test:fixed-older" comment="golang-github-prometheus-node_exporter-1.3.0-150100.3.18.1 is installed"/></criteria>
	</criteria>`
	newer := `<criteria operator="AND">
	  <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	  <criteria operator="OR"><criterion test_ref="oval:test:fixed-newer" comment="golang-github-prometheus-node_exporter-1.10.2-150100.3.41.2 is installed"/></criteria>
	</criteria>`
	if reverse {
		older, newer = newer, older
	}
	return oracleDoc(`<definitions>
	<definition id="oval:org.opensuse.security:def:202221698" version="1" class="vulnerability">
	  <metadata><title>CVE-2022-21698</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="OR">` + older + newer + `</criteria>
	</definition>
	</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:fixed-older" check="at least one" comment="golang-github-prometheus-node_exporter is &lt;0:1.3.0-150100.3.18.1"><linux:object object_ref="oval:obj:package"/><linux:state state_ref="oval:state:fixed-older"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:fixed-newer" check="at least one" comment="golang-github-prometheus-node_exporter is &lt;0:1.10.2-150100.3.41.2"><linux:object object_ref="oval:obj:package"/><linux:state state_ref="oval:state:fixed-newer"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:package"><linux:name>golang-github-prometheus-node_exporter</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:fixed-older"><linux:evr datatype="evr_string" operation="less than">0:1.3.0-150100.3.18.1</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:fixed-newer"><linux:evr datatype="evr_string" operation="less than">0:1.10.2-150100.3.41.2</linux:evr></linux:rpminfo_state>
	</states>`)
}

func TestParseOVALSnapshotSUSESuppressionClearsOpenAcrossDocuments(t *testing.T) {
	open := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	suppressed := sleAffectedDefinitionsDoc(sleAffectedDefinition("unsupported-fixed", "oval:test:fixed"))
	anchor := []byte(`id="oval:test:fixed" check="at least one"`)
	if !bytes.Contains(suppressed, anchor) {
		t.Fatal("suppression fixture mutation anchor missing")
	}
	suppressed = bytes.Replace(suppressed, anchor, []byte(`id="oval:test:fixed" check="all"`), 1)

	for _, documents := range [][][]byte{{open, suppressed}, {suppressed, open}} {
		advs, err := ParseOVALSnapshot(documents)
		if err != nil {
			t.Fatalf("ParseOVALSnapshot: %v", err)
		}
		if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" || len(advs[0].Affected) != 0 {
			t.Fatalf("unsupported exact-package evidence must suppress stale open applicability: %+v", advs)
		}
	}
}

func TestParseSLECorrelatedBranchSuppressesAllDependentPackages(t *testing.T) {
	advs, err := ParseOVAL(sleCorrelatedSuppressionDoc())
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 || advs[0].Affected[0].Package != "diffutils" {
		t.Fatalf("the independent package must survive while the complete correlated branch is suppressed: %+v", advs)
	}
}

func TestParseSLESuppressionAllowsSupersededFixedBoundaries(t *testing.T) {
	first := sleAffectedDefinitionsDoc(sleAffectedDefinition("fixed-a", "oval:test:fixed"))
	second := bytes.ReplaceAll(first, []byte("3.6-4.3.2"), []byte("3.6-4.3.3"))
	suppressed := bytes.Replace(first,
		[]byte(`id="oval:test:fixed" check="at least one"`),
		[]byte(`id="oval:test:fixed" check="all"`),
		1,
	)
	for _, documents := range [][][]byte{
		{suppressed, first, second},
		{first, suppressed, second},
		{first, second, suppressed},
	} {
		advs, err := ParseOVALSnapshot(documents)
		if err != nil {
			t.Fatalf("ParseOVALSnapshot: %v", err)
		}
		if len(advs) != 1 || len(advs[0].Affected) != 0 {
			t.Fatalf("suppression must keep the superseded package out of the current projection: %+v", advs)
		}
	}
}

func sleCorrelatedSuppressionDoc() []byte {
	return oracleDoc(`<definitions>
	<definition id="oval:org.opensuse.security:def:correlated" version="1" class="vulnerability">
	  <metadata><title>CVE-2026-53910</title><affected family="unix"><platform>SUSE Linux Enterprise Server 15 SP6</platform></affected></metadata>
	  <criteria operator="AND">
	    <criteria operator="OR"><criterion test_ref="oval:test:product" comment="SUSE Linux Enterprise Server 15 SP6 is installed"/></criteria>
	    <criteria operator="OR">
	      <criterion test_ref="oval:test:open" comment="diffutils is affected"/>
	      <criteria operator="OR">
	        <criterion test_ref="oval:test:kernel-vulnerable" comment="kernel-default-6.4.0-150600.21.3 is installed"/>
	        <criteria operator="AND">
	          <criterion test_ref="oval:test:kernel-exact" comment="kernel-default 6.4.0-150600.21.3 is installed"/>
	          <criterion test_ref="oval:test:livepatch" comment="no kernel-livepatch-6_4_0-150600_21_3-default is greater or equal than 1-1"/>
	        </criteria>
	      </criteria>
	    </criteria>
	  </criteria>
	</definition>
	</definitions>
	<tests>
	  <linux:rpminfo_test id="oval:test:product" check="at least one" comment="sles-release is ==15.6"><linux:object object_ref="oval:obj:product"/><linux:state state_ref="oval:state:product"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:open" check="at least one" comment="diffutils is &gt;0"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:open"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:kernel-vulnerable" check="all" comment="kernel-default is &lt;6.4.0-150600.21.3"><linux:object object_ref="oval:obj:kernel"/><linux:state state_ref="oval:state:kernel-vulnerable"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:kernel-exact" check="at least one" comment="kernel-default is ==6.4.0-150600.21.3"><linux:object object_ref="oval:obj:kernel"/><linux:state state_ref="oval:state:kernel-exact"/></linux:rpminfo_test>
	  <linux:rpminfo_test id="oval:test:livepatch" check="none satisfy" comment="kernel-livepatch-6_4_0-150600_21_3-default is &gt;=1-1"><linux:object object_ref="oval:obj:livepatch"/><linux:state state_ref="oval:state:livepatch"/></linux:rpminfo_test>
	</tests>
	<objects>
	  <linux:rpminfo_object id="oval:obj:product"><linux:name>sles-release</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:diffutils"><linux:name>diffutils</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:kernel"><linux:name>kernel-default</linux:name></linux:rpminfo_object>
	  <linux:rpminfo_object id="oval:obj:livepatch"><linux:name>kernel-livepatch-6_4_0-150600_21_3-default</linux:name></linux:rpminfo_object>
	</objects>
	<states>
	  <linux:rpminfo_state id="oval:state:product"><linux:version operation="equals">15.6</linux:version></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:open"><linux:evr datatype="evr_string" operation="greater than">0:0-0</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:kernel-vulnerable"><linux:evr datatype="evr_string" operation="less than">0:6.4.0-150600.21.3</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:kernel-exact"><linux:evr datatype="evr_string" operation="equals">0:6.4.0-150600.21.3</linux:evr></linux:rpminfo_state>
	  <linux:rpminfo_state id="oval:state:livepatch"><linux:evr datatype="evr_string" operation="greater than or equal">0:1-1</linux:evr></linux:rpminfo_state>
	</states>`)
}

func TestParseSLEInvalidDefinitionRejectsIndependentOpen(t *testing.T) {
	valid := sleAffectedDefinition("valid-open", "oval:test:open")
	invalid := strings.ReplaceAll(valid, "def:valid-open", "def:invalid-open")
	invalid = strings.ReplaceAll(invalid, `test_ref="oval:test:open" comment="diffutils is affected"`, `test_ref="oval:test:open" comment="diffutils is affected" negate="true"`)
	for _, definitions := range []string{invalid + valid, valid + invalid} {
		advs, err := ParseOVAL(sleAffectedDefinitionsDoc(definitions))
		if err == nil || !errors.Is(err, shared.ErrValidation) || len(advs) != 0 {
			t.Fatalf("one valid definition must not hide relevant unrepresentable evidence: err=%v advisories=%+v", err, advs)
		}
	}
}

func TestParseSLEIrrelevantDefinitionDoesNotRejectSnapshot(t *testing.T) {
	valid := sleAffectedDefinition("valid-open", "oval:test:open")
	irrelevant := `<definition id="oval:org.opensuse.security:def:inventory" class="inventory"><metadata><title>inventory helper</title></metadata><criteria operator="AND"/></definition>`
	advs, err := ParseOVAL(sleAffectedDefinitionsDoc(irrelevant + valid))
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2026-53910" || len(advs[0].Affected) != 1 {
		t.Fatalf("a positively irrelevant definition must not hide or reject the valid advisory: %+v", advs)
	}
}

func TestParseSLERejectsWrongElementKindAndNamespace(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6-affected.xml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  []byte
		new  []byte
	}{
		{name: "dpkg lookalike", old: []byte("rpminfo_"), new: []byte("dpkginfo_")},
		{name: "foreign namespace", old: []byte("http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"), new: []byte("https://example.invalid/oval/linux")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := bytes.ReplaceAll(base, tc.old, tc.new)
			advs, parseErr := ParseOVAL(doc)
			if parseErr == nil || !errors.Is(parseErr, shared.ErrValidation) || len(advs) != 0 {
				t.Fatalf("foreign element identity must reject the complete snapshot: err=%v advisories=%+v", parseErr, advs)
			}
		})
	}
}

func TestParseOVALRejectsDuplicateRPMIDs(t *testing.T) {
	doc := sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open"))
	duplicate := `<linux:rpminfo_test id="oval:test:open" check="at least one" comment="diffutils is &gt;0"><linux:object object_ref="oval:obj:diffutils"/><linux:state state_ref="oval:state:open"/></linux:rpminfo_test>`
	doc = bytes.Replace(doc, []byte("</tests>"), []byte(duplicate+"</tests>"), 1)
	if advs, err := ParseOVAL(doc); err == nil || len(advs) != 0 {
		t.Fatalf("duplicate test IDs must reject the document, got err=%v advisories=%+v", err, advs)
	}
}

func TestParseOVALRejectsMixedRPMFamilies(t *testing.T) {
	sle := string(sleAffectedDefinitionsDoc(sleAffectedDefinition("open", "oval:test:open")))
	oracleDefinition := `<definition id="oval:com.oracle.elsa:def:1" class="patch"><metadata><affected><platform>Oracle Linux 9</platform></affected><reference source="CVE" ref_id="CVE-2026-9999"/></metadata><criteria operator="AND"/></definition>`
	doc := strings.Replace(sle, "</definitions>", oracleDefinition+"</definitions>", 1)
	if advs, err := ParseOVAL([]byte(doc)); err == nil || len(advs) != 0 {
		t.Fatalf("a document mixing supported RPM families must be rejected, got err=%v advisories=%+v", err, advs)
	}
}

func TestParseSLEFixedBindsArchitectureQualifiedDirectPackageCriterion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	// Fixture bytes are checked out with platform line endings, so a multi-line mutation anchored on "\n"
	// must normalise first or it silently stops matching on a CRLF checkout.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	group := []byte("        <criteria operator=\"AND\">\n          <criterion test_ref=\"oval:org.opensuse.security:tst:2010099999\" comment=\"libopenssl1_1-1.1.1w-150600.3.10 is installed\"/>\n        </criteria>")
	direct := []byte("        <criterion test_ref=\"oval:org.opensuse.security:tst:2010099999\" comment=\"libopenssl1_1-1.1.1w-150600.3.10 is installed\"/>")
	if !bytes.Contains(data, group) {
		t.Fatal("fixture mutation anchor missing")
	}
	data = bytes.Replace(data, group, direct, 1)
	data = bytes.ReplaceAll(data, []byte("libopenssl1_1"), []byte("libopenssl-1_1-devel"))
	data = bytes.Replace(data,
		[]byte(`comment="libopenssl-1_1-devel is &lt;1.1.1w-150600.3.10"`),
		[]byte(`comment="libopenssl-1_1-devel is &lt;1.1.1w-150600.3.10 for aarch64,i586,ppc64le,s390x,x86_64"`),
		1,
	)
	data = bytes.Replace(data,
		[]byte("(aarch64|ppc64le|s390x|x86_64)"),
		[]byte("(aarch64|i586|ppc64le|s390x|x86_64)"),
		1,
	)

	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("an architecture-qualified direct package criterion must bind with its architecture set: %+v", advs)
	}
	if got, want := strings.Join(advs[0].Affected[0].Architectures, ","), "aarch64,i586,ppc64le,s390x,x86_64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "libopenssl-1_1-devel", "0:1.1.1w-150600.3.9", ""); ok {
		t.Error("an unknown component architecture must not satisfy an architecture-scoped block")
	}
}

func TestParseSLEFixedBindsNoarchPackageToNoarchOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	// Fixture bytes are checked out with platform line endings, so a multi-line mutation anchored on "\n"
	// must normalise first or it silently stops matching on a CRLF checkout.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	group := []byte("        <criteria operator=\"AND\">\n          <criterion test_ref=\"oval:org.opensuse.security:tst:2010099999\" comment=\"libopenssl1_1-1.1.1w-150600.3.10 is installed\"/>\n        </criteria>")
	direct := []byte("        <criterion test_ref=\"oval:org.opensuse.security:tst:2010099999\" comment=\"libopenssl1_1-1.1.1w-150600.3.10 is installed\"/>")
	if !bytes.Contains(data, group) {
		t.Fatal("fixture mutation anchor missing")
	}
	data = bytes.Replace(data, group, direct, 1)
	data = bytes.ReplaceAll(data, []byte("libopenssl1_1"), []byte("apache2-doc"))
	data = bytes.ReplaceAll(data, []byte("1.1.1w-150600.3.10"), []byte("2.4.51-150400.6.6.1"))
	data = bytes.Replace(data, []byte("(aarch64|ppc64le|s390x|x86_64)"), []byte("(noarch)"), 1)
	data = bytes.Replace(data,
		[]byte(`comment="apache2-doc is &lt;2.4.51-150400.6.6.1"`),
		[]byte(`comment="apache2-doc is &lt;2.4.51-150400.6.6.1 for noarch"`),
		1,
	)

	advs, err := ParseOVAL(data)
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("a noarch package fact must bind with a noarch architecture scope: %+v", advs)
	}
	if got, want := strings.Join(advs[0].Affected[0].Architectures, ","), "noarch"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if ok, _ := advs[0].Match("SUSE:15.6", "apache2-doc", "0:2.4.51-150400.6.6.0", "noarch"); !ok {
		t.Error("a noarch component must match a noarch-scoped block")
	}
	// noarch is compared literally, never as a wildcard across architectures.
	if ok, _ := advs[0].Match("SUSE:15.6", "apache2-doc", "0:2.4.51-150400.6.6.0", "x86_64"); ok {
		t.Error("noarch must not act as a wildcard across architectures")
	}
}

func TestParseSLEFixedRejectsUnrepresentableRestrictions(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "negated package", old: `test_ref="oval:org.opensuse.security:tst:2010099999"`, new: `test_ref="oval:org.opensuse.security:tst:2010099999" negate="true"`},
		{name: "unsupported check existence", old: `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="at least one"`, new: `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="at least one" check_existence="none_exist"`},
		{name: "unsupported state operator", old: `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="at least one"`, new: `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="at least one" state_operator="OR"`},
		{name: "signature restriction", old: `</red-def:rpminfo_state>`, new: `<signature_keyid operation="equals">deadbeef</signature_keyid></red-def:rpminfo_state>`},
		{name: "object filter", old: `<red-def:name>libopenssl1_1</red-def:name>`, new: `<red-def:name>libopenssl1_1</red-def:name><red-def:filter action="include">oval:state:filter</red-def:filter>`},
		{name: "unknown state child", old: `</red-def:rpminfo_state>`, new: `<unknown>value</unknown></red-def:rpminfo_state>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(base, []byte(tc.old)) {
				t.Fatalf("fixture mutation anchor missing: %q", tc.old)
			}
			doc := bytes.Replace(base, []byte(tc.old), []byte(tc.new), 1)
			advs, parseErr := ParseOVAL(doc)
			if parseErr == nil || !errors.Is(parseErr, shared.ErrValidation) || len(advs) != 0 {
				t.Fatalf("unrepresentable fixed restriction must reject the complete snapshot: err=%v advisories=%+v", parseErr, advs)
			}
		})
	}
}

func TestParseSLEFixedSuppressesRepresentableIdentityWithUnsupportedRestriction(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "oval-sle15sp6.xml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "universal check",
			old:  `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="at least one"`,
			new:  `comment="libopenssl1_1 is &lt;1.1.1w-150600.3.10" check="all"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(base, []byte(tc.old)) {
				t.Fatalf("fixture mutation anchor missing: %q", tc.old)
			}
			doc := bytes.Replace(base, []byte(tc.old), []byte(tc.new), 1)
			advs, parseErr := ParseOVAL(doc)
			if parseErr != nil {
				t.Fatalf("ParseOVAL: %v", parseErr)
			}
			if len(advs) != 1 || len(advs[0].Affected) != 0 {
				t.Fatalf("unsupported exact-package restriction must suppress rather than widen: %+v", advs)
			}
		})
	}
}

// slePlatformRelease extracts the per-service-pack release from a SUSE Linux Enterprise platform string and
// returns "" for any non-SLE platform (so an openSUSE Leap document is never mis-detected as SLE).
func TestSLEPlatformRelease(t *testing.T) {
	cases := map[string]string{
		"SUSE Linux Enterprise Server 15 SP6":                "15.6",
		"SUSE Linux Enterprise Server 15 SP6-LTSS":           "15.6",
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

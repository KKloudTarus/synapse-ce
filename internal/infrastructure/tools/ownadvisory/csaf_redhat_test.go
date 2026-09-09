package ownadvisory

import (
	"context"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// redHatCSAF is a minimal but faithful RedHat CSAF 2.0 VEX document for one RHEL 9 rpm advisory. It uses the
// real RedHat shape: a platform product (product_name branch, carrying the RHEL CPE) and a package product
// (product_version branch, carrying the rpm PURL) are bound by a default_component_of relationship whose
// composite product_id is what the vulnerability's product_status references. The epoch rides in the PURL's
// "epoch=" qualifier, not the version, exactly as RedHat and Syft emit it.
const redHatCSAF = `{
  "document": {"title": "Red Hat Security Advisory: openssl security update"},
  "product_tree": {
    "branches": [
      {
        "category": "vendor", "name": "Red Hat",
        "branches": [
          {
            "category": "product_family", "name": "Red Hat Enterprise Linux",
            "branches": [
              {
                "category": "product_name", "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
                "product": {
                  "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
                  "product_id": "BaseOS-9.2.0.Z.MAIN.EUS",
                  "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"}
                }
              }
            ]
          },
          {
            "category": "product_version", "name": "openssl-1:3.0.7-6.el9_2.x86_64",
            "product": {
              "name": "openssl-1:3.0.7-6.el9_2.x86_64",
              "product_id": "openssl-1:3.0.7-6.el9_2.x86_64",
              "product_identification_helper": {"purl": "pkg:rpm/redhat/openssl@3.0.7-6.el9_2?arch=x86_64&epoch=1"}
            }
          }
        ]
      }
    ],
    "relationships": [
      {
        "category": "default_component_of",
        "full_product_name": {
          "name": "openssl-1:3.0.7-6.el9_2.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)",
          "product_id": "BaseOS-9.2.0.Z.MAIN.EUS:openssl-1:3.0.7-6.el9_2.x86_64"
        },
        "product_reference": "openssl-1:3.0.7-6.el9_2.x86_64",
        "relates_to_product_reference": "BaseOS-9.2.0.Z.MAIN.EUS"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2023-0464",
      "title": "openssl: Excessive Resource Usage Verifying X.509 Policy Constraints",
      "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "baseScore": 7.5}}],
      "product_status": {"fixed": ["BaseOS-9.2.0.Z.MAIN.EUS:openssl-1:3.0.7-6.el9_2.x86_64"]}
    }
  ]
}`

// TestParseCSAFRedHatRPM asserts the RedHat rpm binding resolves to a release-versioned "Red Hat:9" advisory
// with an rpm "[0, fixed)" ECOSYSTEM range, where the fixed EVR carries the epoch from the PURL qualifier.
func TestParseCSAFRedHatRPM(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory, got %d: %+v", len(advs), advs)
	}
	a := advs[0]
	if a.ID != "CVE-2023-0464" {
		t.Fatalf("advisory id = %q", a.ID)
	}
	if a.CVSSScore != 7.5 || a.CVSSVector == "" {
		t.Errorf("CVSS must be extracted, got score=%v vector=%q", a.CVSSScore, a.CVSSVector)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("want 1 affected package, got %+v", a.Affected)
	}
	ap := a.Affected[0]
	if ap.Ecosystem != "Red Hat:9" || ap.Package != "openssl" {
		t.Fatalf("binding must resolve to Red Hat:9/openssl, got %s/%s", ap.Ecosystem, ap.Package)
	}
	if ap.FixedVersion != "1:3.0.7-6.el9_2" {
		t.Errorf("fixed EVR must carry the epoch qualifier, got %q", ap.FixedVersion)
	}
	if len(ap.Ranges) != 1 || ap.Ranges[0].Type != "ECOSYSTEM" {
		t.Fatalf("a distro binding must be an ECOSYSTEM range, got %+v", ap.Ranges)
	}
	evs := ap.Ranges[0].Events
	if len(evs) != 2 || evs[0].Introduced != "0" || evs[1].Fixed != "1:3.0.7-6.el9_2" {
		t.Errorf("range must be introduced:0 → fixed:1:3.0.7-6.el9_2, got %+v", evs)
	}
	if len(ap.Versions) != 0 {
		t.Errorf("a distro binding must not carry exact versions, got %v", ap.Versions)
	}
}

// TestScanMatchesRedHatRPM is the end-to-end slice: the parsed RedHat advisory (keyed "Red Hat:9|openssl")
// matches a vulnerable RHEL 9 openssl rpm, declines the patched build, and declines the wrong RHEL major —
// all through the owned rpm comparator, no third-party engine.
func TestScanMatchesRedHatRPM(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	adv := advs[0]
	store := memStore{byKey: map[string][]advisory.Advisory{"Red Hat:9|openssl": {adv}}}

	doc := &sbom.SBOM{Components: []sbom.Component{
		// vulnerable: el9_1 < el9_2 fix, same epoch (from the qualifier) → affected.
		{Name: "openssl", Version: "3.0.7-6.el9_1", PURL: "pkg:rpm/rhel/openssl@3.0.7-6.el9_1?arch=x86_64&distro=rhel-9.2&epoch=1"},
		// patched: exactly the fixed EVR → not affected.
		{Name: "openssl", Version: "3.0.7-6.el9_2", PURL: "pkg:rpm/rhel/openssl@3.0.7-6.el9_2?arch=x86_64&distro=rhel-9.2&epoch=1"},
		// wrong major: RHEL 8 → keyed "Red Hat:8", no advisory → no match (never cross-major).
		{Name: "openssl", Version: "3.0.7-6.el8", PURL: "pkg:rpm/rhel/openssl@3.0.7-6.el8?arch=x86_64&distro=rhel-8.8&epoch=1"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding (only the vulnerable el9_1 build), got %d: %+v", len(raws), raws)
	}
	if raws[0].AdvisoryID != "CVE-2023-0464" || raws[0].Component != "openssl" || raws[0].Version != "3.0.7-6.el9_1" {
		t.Errorf("raw finding wrong: %+v", raws[0])
	}
	if raws[0].FixedVersion != "1:3.0.7-6.el9_2" {
		t.Errorf("finding must carry the fixed EVR, got %q", raws[0].FixedVersion)
	}
}

// TestScanRedHatEpochAsymmetryNoFalsePositive guards the epoch hazard directly: a component whose version is
// already patched but whose epoch is written differently on the two sides must NOT be flagged. Both sides
// canonicalize epoch, so the patched build stays clean regardless of where the epoch was carried.
func TestScanRedHatEpochAsymmetryNoFalsePositive(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Red Hat:9|openssl": {advs[0]}}}
	// The component embeds the epoch in the version ("1:...") instead of the qualifier; canonicalization must
	// still line it up with the feed's "1:3.0.7-6.el9_2" fix so this patched build is not a false positive.
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "1:3.0.7-6.el9_2", PURL: "pkg:rpm/rhel/openssl@3.0.7-6.el9_2?arch=x86_64&distro=rhel-9.2"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("patched build must not be flagged (no false positive), got %+v", raws)
	}
}

// TestScanRedHatModuleStreamSkipped proves AppStream MODULE packages are excluded from the linear-range
// distro matcher on BOTH sides. A module's streams (nodejs:16 vs nodejs:20) coexist as independent version
// lines, so a "[0, fixed)" range built from one stream would falsely flag another. The sound behavior is to
// skip modular builds entirely (release "...module+el..."): the feed emits no affected package for them, and
// the scan matches none. This is a miss, never a false positive. rpmPurlNameEVR still decodes the %2B (see
// TestRPMPurlNameEVR); the skip happens in the binding resolver, not the parser.
func TestScanRedHatModuleStreamSkipped(t *testing.T) {
	doc := `{
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "RHEL 8",
             "product": {"product_id": "rhel8", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:8::appstream"}}},
            {"category": "product_version", "name": "nodejs",
             "product": {"product_id": "nodejs-1:20.11.1-1.x86_64",
                         "product_identification_helper": {"purl": "pkg:rpm/redhat/nodejs@20.11.1-1.module%2Bel8.9.0%2B21380%2B12032667?arch=x86_64&epoch=1"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of",
           "full_product_name": {"product_id": "rhel8:nodejs-1:20.11.1-1.x86_64"},
           "product_reference": "nodejs-1:20.11.1-1.x86_64",
           "relates_to_product_reference": "rhel8"}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-2024-MOD", "product_status": {"fixed": ["rhel8:nodejs-1:20.11.1-1.x86_64"]}}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory, got %+v", advs)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("a modular package must yield no affected binding (skipped), got %+v", advs[0].Affected)
	}

	// Even if a modular advisory somehow reached the store, the scan side must not match a modular build.
	moduleAdv := advisory.Advisory{ID: "CVE-2024-MOD", Affected: []advisory.AffectedPackage{{
		Ecosystem: "Red Hat:8", Package: "nodejs",
		Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1:20.11.1-1.module+el8.9.0+21380+12032667"}}}},
	}}}
	store := memStore{byKey: map[string][]advisory.Advisory{"Red Hat:8|nodejs": {moduleAdv}}}
	doc2 := &sbom.SBOM{Components: []sbom.Component{
		// A lower module build that WOULD compare below the fix: must NOT be flagged (module skipped on scan).
		{Name: "nodejs", Version: "16.20.2-1.module+el8.9.0+20974+d99e30fd", PURL: "pkg:rpm/rhel/nodejs@16.20.2-1.module%2Bel8.9.0%2B20974%2Bd99e30fd?arch=x86_64&distro=rhel-8.9&epoch=1"},
	}}
	raws, err := New(store).Scan(context.Background(), doc2)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("a modular component must not match a linear range (no cross-stream false positive), got %+v", raws)
	}
}

func TestRHELMajorFromCPE(t *testing.T) {
	cases := []struct {
		cpe   string
		major string
		ok    bool
	}{
		{"cpe:/o:redhat:enterprise_linux:9::baseos", "9", true},
		{"cpe:/o:redhat:enterprise_linux:8::appstream", "8", true},
		{"cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*", "9", true},
		{"cpe:/a:redhat:openshift:4.13::el9", "", false},          // not enterprise_linux
		{"cpe:/o:redhat:enterprise_linux:*::baseos", "", false},   // non-numeric major
		{"cpe:/o:centos:centos:9", "", false},                     // not redhat vendor
		{"cpe:2.3:a:djangoproject:django:3.2:*:*:*:*:*:*:*", "", false},
		{"not-a-cpe", "", false},
	}
	for _, c := range cases {
		got, ok := rhelMajorFromCPE(c.cpe)
		if got != c.major || ok != c.ok {
			t.Errorf("rhelMajorFromCPE(%q) = (%q,%v), want (%q,%v)", c.cpe, got, ok, c.major, c.ok)
		}
	}
}

func TestRPMPurlNameEVR(t *testing.T) {
	cases := []struct {
		purl string
		name string
		evr  string
		ok   bool
	}{
		{"pkg:rpm/redhat/openssl@3.0.7-6.el9_2?arch=x86_64&epoch=1", "openssl", "1:3.0.7-6.el9_2", true},
		{"pkg:rpm/redhat/kernel@5.14.0-70.el9?arch=x86_64", "kernel", "0:5.14.0-70.el9", true}, // no epoch qualifier → 0
		{"pkg:rpm/redhat/grub2@1%3A2.06-27.el9?arch=x86_64", "grub2", "1:2.06-27.el9", true},   // %3A-escaped epoch in version
		{"pkg:rpm/redhat/python3-libs@3.9.16-1.el9?arch=noarch&epoch=0", "python3-libs", "0:3.9.16-1.el9", true},
		// Modular stream: RedHat percent-encodes the '+' in "module+el8" as %2B. It MUST decode to '+' so the
		// EVR matches the decoded version the scan side carries (else a patched module build is a false positive).
		{"pkg:rpm/redhat/nodejs@20.11.1-1.module%2Bel8.9.0%2B21380%2B12032667?arch=x86_64&epoch=1", "nodejs", "1:20.11.1-1.module+el8.9.0+21380+12032667", true},
		{"pkg:npm/leftpad@1.0.0", "", "", false}, // not rpm
		{"pkg:rpm/redhat/openssl", "", "", false}, // no version
	}
	for _, c := range cases {
		name, evr, ok := rpmPurlNameEVR(c.purl)
		if name != c.name || evr != c.evr || ok != c.ok {
			t.Errorf("rpmPurlNameEVR(%q) = (%q,%q,%v), want (%q,%q,%v)", c.purl, name, evr, ok, c.name, c.evr, c.ok)
		}
	}
}

// TestParseCSAFRedHatKnownAffectedNoFix covers a RedHat rpm the advisory lists as affected with no fix
// available (product_status.known_affected): the whole package is affected in that major (open range, no
// fixed event).
func TestParseCSAFRedHatKnownAffectedNoFix(t *testing.T) {
	doc := `{
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "RHEL 9",
             "product": {"product_id": "rhel9", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::appstream"}}},
            {"category": "product_version", "name": "webkitgtk",
             "product": {"product_id": "webkitgtk-0:2.0-1.el9.x86_64", "product_identification_helper": {"purl": "pkg:rpm/redhat/webkitgtk@2.0-1.el9?arch=x86_64"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of",
           "full_product_name": {"product_id": "rhel9:webkitgtk-0:2.0-1.el9.x86_64"},
           "product_reference": "webkitgtk-0:2.0-1.el9.x86_64",
           "relates_to_product_reference": "rhel9"}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-2024-XX", "product_status": {"known_affected": ["rhel9:webkitgtk-0:2.0-1.el9.x86_64"]}}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want 1 advisory with 1 affected pkg, got %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "Red Hat:9" || ap.Package != "webkitgtk" {
		t.Fatalf("binding must resolve to Red Hat:9/webkitgtk, got %s/%s", ap.Ecosystem, ap.Package)
	}
	if ap.FixedVersion != "" {
		t.Errorf("a no-fix advisory must carry no fixed version, got %q", ap.FixedVersion)
	}
	// A no-fix known_affected is bounded by the highest observed affected EVR (last_affected, inclusive), NOT
	// an open [0, ∞) range: a later, not-yet-evaluated build must not be swept in.
	if len(ap.Ranges) != 1 || len(ap.Ranges[0].Events) != 2 {
		t.Fatalf("no-fix binding must be a bounded [0, lastAffected] range, got %+v", ap.Ranges)
	}
	evs := ap.Ranges[0].Events
	if evs[0].Introduced != "0" || evs[1].LastAffected != "0:2.0-1.el9" {
		t.Errorf("range must be introduced:0 → last_affected:0:2.0-1.el9, got %+v", evs)
	}
	if !reflect.DeepEqual(ap.Versions, []string(nil)) {
		t.Errorf("no exact versions expected, got %v", ap.Versions)
	}
}

// TestParseCSAFRedHatKnownNotAffectedDropsGroup covers fix #3: when a (major, package) also appears in
// known_not_affected (a CVE that is arch- or variant-specific for that package), the arch-less key cannot
// bound it soundly, so the whole group is DROPPED rather than emitted with a range that would flag the
// not-affected arch. This is a miss on that package, never a false positive.
func TestParseCSAFRedHatKnownNotAffectedDropsGroup(t *testing.T) {
	doc := `{
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "RHEL 9",
             "product": {"product_id": "rhel9", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"}}},
            {"category": "product_version", "name": "kernel-x86_64",
             "product": {"product_id": "kernel-0:5.14.0-362.el9.x86_64", "product_identification_helper": {"purl": "pkg:rpm/redhat/kernel@5.14.0-362.el9?arch=x86_64"}}},
            {"category": "product_version", "name": "kernel-s390x",
             "product": {"product_id": "kernel-0:5.14.0-362.el9.s390x", "product_identification_helper": {"purl": "pkg:rpm/redhat/kernel@5.14.0-362.el9?arch=s390x"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:kernel-x86_64"},
           "product_reference": "kernel-0:5.14.0-362.el9.x86_64", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:kernel-s390x"},
           "product_reference": "kernel-0:5.14.0-362.el9.s390x", "relates_to_product_reference": "rhel9"}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-2024-ARCH", "product_status": {
        "fixed": ["rhel9:kernel-x86_64"],
        "known_not_affected": ["rhel9:kernel-s390x"]
      }}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory, got %+v", advs)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("a package with a known_not_affected arch must be dropped (arch-ambiguous), got %+v", advs[0].Affected)
	}

	// End-to-end: the dropped group means nothing is stored for kernel, so the not-affected s390x kernel below
	// the x86_64 fix finds no advisory and is not flagged.
	store := memStore{byKey: map[string][]advisory.Advisory{}}
	doc2 := &sbom.SBOM{Components: []sbom.Component{
		{Name: "kernel", Version: "5.14.0-300.el9", PURL: "pkg:rpm/rhel/kernel@5.14.0-300.el9?arch=s390x&distro=rhel-9.2&epoch=0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc2)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("not-affected arch must not be flagged, got %+v", raws)
	}
}

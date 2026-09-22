package ownadvisory

import (
	"context"
	"os"
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
	if ap.Ecosystem != "Red Hat:9.2" || ap.Package != "openssl" {
		t.Fatalf("binding must resolve to Red Hat:9.2/openssl, got %s/%s", ap.Ecosystem, ap.Package)
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

// TestScanMatchesRedHatRPM is the end-to-end slice: the parsed RedHat advisory (keyed "Red Hat:9.2|openssl")
// matches a vulnerable RHEL 9 openssl rpm, declines the patched build, and declines the wrong RHEL major —
// all through the owned rpm comparator, no third-party engine.
func TestScanMatchesRedHatRPM(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	adv := advs[0]
	store := memStore{byKey: map[string][]advisory.Advisory{"Red Hat:9.2|openssl": {adv}}}

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
	store := memStore{byKey: map[string][]advisory.Advisory{"Red Hat:9.2|openssl": {advs[0]}}}
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
		{"cpe:/a:redhat:openshift:4.13::el9", "", false},        // not enterprise_linux
		{"cpe:/o:redhat:enterprise_linux:*::baseos", "", false}, // non-numeric major
		{"cpe:/o:centos:centos:9", "", false},                   // not redhat vendor
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
		{"pkg:npm/leftpad@1.0.0", "", "", false},  // not rpm
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
	if ok, fixed := advs[0].Match("Red Hat:9", "webkitgtk", "0:2.0-1.el9", ""); !ok || fixed != "" {
		t.Fatalf("the exact vendor known-affected EVR must match without a fabricated fix: ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := advs[0].Match("Red Hat:9", "webkitgtk", "0:2.0-2.el9", ""); ok {
		t.Fatal("a higher unobserved EVR must not be swept into the bounded no-fix range")
	}
	if ok, _ := advs[0].Match("Red Hat:8", "webkitgtk", "0:2.0-1.el9", ""); ok {
		t.Fatal("a different RHEL major must not match")
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

func redHatBinaryLifecycleDocument(status string) string {
	return `{
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "RHEL 9",
             "product": {"product_id": "rhel9", "product_identification_helper": {"cpe": "cpe:/a:redhat:enterprise_linux:9"}}},
            {"category": "product_version", "name": "curl-minimal",
             "product": {"product_id": "curl-minimal-open", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl-minimal?upstream=curl"}}},
            {"category": "product_version", "name": "curl-minimal ambiguous",
             "product": {"product_id": "curl-minimal-ambiguous", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl-minimal"}}},
            {"category": "product_version", "name": "curl-minimal fixed",
             "product": {"product_id": "curl-minimal-fixed", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl-minimal@7.76.1-31.el9_6.2?epoch=0&upstream=curl"}}},
            {"category": "product_version", "name": "curl-minimal wrong major",
             "product": {"product_id": "curl-minimal-wrong-major", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl-minimal@8.0.0-1.el10?epoch=0&upstream=curl"}}},
            {"category": "product_version", "name": "curl-minimal tagless",
             "product": {"product_id": "curl-minimal-tagless", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl-minimal@8.0.0-1.hum1?epoch=0&upstream=curl"}}},
            {"category": "product_version", "name": "curl source",
             "product": {"product_id": "curl-src-open", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl?arch=src"}}},
            {"category": "product_version", "name": "curl source version",
             "product": {"product_id": "curl-src-fixed", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl@7.76.1-31.el9_6.2?arch=src&epoch=0"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-minimal-open"},
           "product_reference": "curl-minimal-open", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-minimal-ambiguous"},
           "product_reference": "curl-minimal-ambiguous", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-minimal-fixed"},
           "product_reference": "curl-minimal-fixed", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-minimal-wrong-major"},
           "product_reference": "curl-minimal-wrong-major", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-minimal-tagless"},
           "product_reference": "curl-minimal-tagless", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-src-open"},
           "product_reference": "curl-src-open", "relates_to_product_reference": "rhel9"},
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9:curl-src-fixed"},
           "product_reference": "curl-src-fixed", "relates_to_product_reference": "rhel9"}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-2024-0001", "product_status": ` + status + `}]
    }`
}

func TestParseCSAFRedHatUnversionedBinaryKnownAffectedOpenRangeRequiresSnapshot(t *testing.T) {
	document := []byte(redHatBinaryLifecycleDocument(
		`{"known_affected": ["rhel9:curl-minimal-open"]}`,
	))
	ordinary, err := ParseCSAF(document)
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(ordinary) != 1 || len(ordinary[0].Affected) != 0 {
		t.Fatalf("streaming CSAF must not emit an unbounded Red Hat RPM range: %+v", ordinary)
	}

	advs, err := ParseCSAFSnapshot([][]byte{document})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one open binary snapshot binding, got %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "Red Hat:9" || ap.Package != "curl-minimal" || ap.FixedVersion != "" {
		t.Fatalf("unexpected open binding: %+v", ap)
	}
	if len(ap.Ranges) != 1 || !reflect.DeepEqual(ap.Ranges[0].Events, []advisory.Event{{Introduced: "0"}}) {
		t.Fatalf("unversioned known_affected binary must emit an open introduced-only range, got %+v", ap.Ranges)
	}
	for _, version := range []string{"0:7.76.1-31.el9_6.1", "0:99.0-1.el9"} {
		if ok, fixed := advs[0].Match("Red Hat:9", "curl-minimal", version, ""); !ok || fixed != "" {
			t.Fatalf("authoritative open range must match %s without a fabricated fix: ok=%v fixed=%q", version, ok, fixed)
		}
	}
	if ok, _ := advs[0].Match("Red Hat:8", "curl-minimal", "0:7.76.1-31.el9_6.1", ""); ok {
		t.Fatal("an open RHEL 9 range must not match another RHEL major")
	}
}

func TestParseCSAFRedHatBinaryAwareUnfixedFixture(t *testing.T) {
	// Minimized from the Red Hat binary-aware VEX archive's 2024/cve-2024-11053.json record
	// (SHA-256 32b0742cfec3523bec52d69f875473fb6e428bb3a1f73f55b180f0a8a857f3c3).
	data, err := os.ReadFile("testdata/csaf-redhat-rhel9-unfixed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	advs, err := ParseCSAFSnapshot([][]byte{data})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 2 {
		t.Fatalf("want one advisory with two affected binary packages, got %+v", advs)
	}
	wantVersions := map[string]string{
		"curl-minimal":    "0:7.76.1-40.el9_8.5",
		"libcurl-minimal": "0:7.76.1-40.el9_8.5",
	}
	for _, ap := range advs[0].Affected {
		version, ok := wantVersions[ap.Package]
		if !ok {
			t.Fatalf("source or not-affected product leaked into binary projection: %+v", ap)
		}
		if ap.Ecosystem != "Red Hat:9.8" || len(ap.Ranges) != 1 ||
			!reflect.DeepEqual(ap.Ranges[0].Events, []advisory.Event{{Introduced: "0"}}) {
			t.Fatalf("unexpected minor-scoped open binary binding: %+v", ap)
		}
		if matched, fixed := advs[0].Match(ap.Ecosystem, ap.Package, version, ""); !matched || fixed != "" {
			t.Fatalf("pinned UBI 9.8 package must match %s: matched=%v fixed=%q", version, matched, fixed)
		}
		delete(wantVersions, ap.Package)
	}
	if len(wantVersions) != 0 {
		t.Fatalf("missing expected binary bindings: %v", wantVersions)
	}
}

func TestScanRedHatOpenRangePreservesMinorScope(t *testing.T) {
	doc := `{
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "Red Hat Enterprise Linux 9.10",
             "product": {"name": "Red Hat Enterprise Linux 9.10", "product_id": "rhel-9.10", "product_identification_helper": {"cpe": "cpe:/a:redhat:enterprise_linux:9"}}},
            {"category": "product_version", "name": "glib2",
             "product": {"name": "glib2", "product_id": "glib2", "product_identification_helper": {"purl": "pkg:rpm/redhat/glib2?upstream=glib2"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel-9.10:glib2"},
           "product_reference": "glib2", "relates_to_product_reference": "rhel-9.10"}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-2026-0002", "product_status": {"known_affected": ["rhel-9.10:glib2"]}}]
    }`
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(doc)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 || advs[0].Affected[0].Ecosystem != "Red Hat:9.10" {
		t.Fatalf("RHEL 9.10 evidence must retain its minor scope, got %+v", advs)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Red Hat:9.10|glib2": advs,
	}}
	source := New(store)
	for _, tc := range []struct {
		name string
		purl string
		want int
	}{
		{name: "same minor", purl: "pkg:rpm/redhat/glib2@2.68.4-19.el9_10?arch=x86_64&distro=rhel-9.10", want: 1},
		{name: "different minor", purl: "pkg:rpm/redhat/glib2@2.68.4-19.el9_8?arch=x86_64&distro=rhel-9.8", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raws, err := source.Scan(context.Background(), &sbom.SBOM{Components: []sbom.Component{{
				Name: "glib2", Version: "2.68.4-19.el9", PURL: tc.purl,
			}}})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(raws) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(raws), tc.want, raws)
			}
		})
	}
}

func TestRHELPlatformEcosystem(t *testing.T) {
	for _, tc := range []struct {
		name        string
		major       string
		productID   string
		productName string
		want        string
		ok          bool
	}{
		{name: "exact minor", major: "9", productID: "rhel-9.8", productName: "Red Hat Enterprise Linux 9.8", want: "Red Hat:9.8", ok: true},
		{name: "z stream", major: "9", productID: "rhel-9.7.z", productName: "Red Hat Enterprise Linux 9.7 Extended Update Support", want: "Red Hat:9.7", ok: true},
		{name: "generic id with exact name", major: "9", productID: "rhel-9", productName: "Red Hat Enterprise Linux 9.10", want: "Red Hat:9.10", ok: true},
		{name: "explicit major", major: "9", productID: "rhel9", productName: "RHEL 9", want: "Red Hat:9", ok: true},
		{name: "contradictory labels", major: "9", productID: "rhel-9.8", productName: "Red Hat Enterprise Linux 9.10", want: "Red Hat:9", ok: false},
		{name: "unknown scope", major: "9", productID: "platform", productName: "Enterprise Linux", want: "Red Hat:9", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rhelPlatformEcosystem(tc.major, tc.productID, tc.productName)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("rhelPlatformEcosystem(%q,%q,%q)=(%q,%v), want (%q,%v)", tc.major, tc.productID, tc.productName, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestParseCSAFRedHatRejectsNonBinaryOrInconsistentAffectedProducts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		productID string
	}{
		{name: "unversioned source rpm", productID: "rhel9:curl-src-open"},
		{name: "versioned source rpm", productID: "rhel9:curl-src-fixed"},
		{name: "version contradicts platform major", productID: "rhel9:curl-minimal-wrong-major"},
		{name: "version lacks a rhel major tag", productID: "rhel9:curl-minimal-tagless"},
		// A streaming document never emits an open range at all, so an unversioned binary stays inert here even
		// though a complete snapshot admits it. TestParseCSAFSnapshotAdmitsRedHatNotYetFixedBinary covers that.
		{name: "unversioned binary is inert in a streaming document", productID: "rhel9:curl-minimal-ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := redHatBinaryLifecycleDocument(`{"known_affected": ["` + tc.productID + `"]}`)
			advs, err := ParseCSAF([]byte(doc))
			if err != nil {
				t.Fatalf("ParseCSAF: %v", err)
			}
			if len(advs) != 1 || len(advs[0].Affected) != 0 {
				t.Fatalf("unsupported product identity must not become a binary RPM range, got %+v", advs)
			}
		})
	}
}

func TestParseCSAFRedHatFixedClosesUnversionedBinaryRange(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatBinaryLifecycleDocument(
		`{"known_affected": ["rhel9:curl-minimal-open"], "fixed": ["rhel9:curl-minimal-fixed"]}`,
	)))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one fixed binary binding, got %+v", advs)
	}
	ap := advs[0].Affected[0]
	if ap.FixedVersion != "0:7.76.1-31.el9_6.2" || len(ap.Ranges) != 1 ||
		!reflect.DeepEqual(ap.Ranges[0].Events, []advisory.Event{{Introduced: "0"}, {Fixed: ap.FixedVersion}}) {
		t.Fatalf("fixed evidence must close the prior open range, got %+v", ap)
	}
	if ok, _ := advs[0].Match("Red Hat:9", "curl-minimal", ap.FixedVersion, ""); ok {
		t.Fatal("the fixed package version must not remain affected")
	}
}

func TestParseCSAFRedHatUnsupportedFixedStateSuppressesOpenRange(t *testing.T) {
	for _, productID := range []string{
		"rhel9:curl-minimal-open",
		"rhel9:curl-minimal-wrong-major",
		"rhel9:curl-minimal-tagless",
	} {
		t.Run(productID, func(t *testing.T) {
			doc := redHatBinaryLifecycleDocument(
				`{"known_affected": ["rhel9:curl-minimal-open"], "fixed": ["` + productID + `"]}`,
			)
			advs, err := ParseCSAF([]byte(doc))
			if err != nil {
				t.Fatalf("ParseCSAF: %v", err)
			}
			if len(advs) != 1 || len(advs[0].Affected) != 0 {
				t.Fatalf("a fixed state without a sound boundary must suppress the open range, got %+v", advs)
			}
		})
	}
}

func TestParseCSAFRedHatUnversionedKnownNotAffectedSuppressesOpenRange(t *testing.T) {
	advs, err := ParseCSAF([]byte(redHatBinaryLifecycleDocument(
		`{"known_affected": ["rhel9:curl-minimal-open"], "known_not_affected": ["rhel9:curl-minimal-open"]}`,
	)))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 0 {
		t.Fatalf("known_not_affected must remove only the scoped binary package binding, got %+v", advs)
	}
}

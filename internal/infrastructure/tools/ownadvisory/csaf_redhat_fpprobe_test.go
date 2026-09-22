package ownadvisory

import (
	"strings"
	"testing"
)

// These probes are adversarial: each one asks whether the unversioned-binary admission can produce a match the
// vendor did not state. They exist because the owned matcher's governing invariant is that a miss is acceptable
// and a false positive is not.

// A platform product that is neither an exact minor release nor an explicit major-wide product cannot scope an
// open range, so an unversioned affected binary under it must contribute no match at all.
func TestParseCSAFSnapshotRefusesOpenRangeOnUnscopedPlatform(t *testing.T) {
	document := `{
      "document": {"category": "csaf_vex", "tracking": {"id": "CVE-2026-40002"}},
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "Red Hat Enterprise Linux 9 Extended Lifecycle Support for SAP",
             "product": {"product_id": "rhel9_weird_variant", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}},
            {"category": "product_version", "name": "expat",
             "product": {"product_id": "expat", "product_identification_helper": {"purl": "pkg:rpm/redhat/expat"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "rhel9_weird_variant:expat"},
           "product_reference": "expat", "relates_to_product_reference": "rhel9_weird_variant"}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-2026-40002", "product_status": {"known_affected": ["rhel9_weird_variant:expat"]}}
      ]
    }`
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(document)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("an unscopeable platform must not yield an open range, got %+v", advs[0].Affected)
	}
	if ok, _ := advs[0].Match("Red Hat:9", "expat", "0:2.5.0-6.el9_8.3", "x86_64"); ok {
		t.Fatal("an unscopeable platform must never match an installed component")
	}
}

// known_not_affected must still remove a binding the unversioned path would otherwise emit, because the
// (ecosystem, package) key cannot represent the architecture or variant the negative applies to.
func TestParseCSAFSnapshotNotAffectedSuppressesUnversionedBinary(t *testing.T) {
	document := `{
      "document": {"category": "csaf_vex", "tracking": {"id": "CVE-2026-40003"}},
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "Red Hat Enterprise Linux 9",
             "product": {"product_id": "red_hat_enterprise_linux_9", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}},
            {"category": "product_version", "name": "expat",
             "product": {"product_id": "expat", "product_identification_helper": {"purl": "pkg:rpm/redhat/expat"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "red_hat_enterprise_linux_9:expat"},
           "product_reference": "expat", "relates_to_product_reference": "red_hat_enterprise_linux_9"}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-2026-40003", "product_status": {
           "known_affected": ["red_hat_enterprise_linux_9:expat"],
           "known_not_affected": ["red_hat_enterprise_linux_9:expat"]}}
      ]
    }`
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(document)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("an explicit negative must drop the binding, got %+v", advs[0].Affected)
	}
}

// The streaming parser must keep suppressing unbounded RPM ranges: one document is not evidence that a later
// document will not close the range.
func TestParseCSAFStreamingStillSuppressesUnversionedBinary(t *testing.T) {
	document := `{
      "document": {"category": "csaf_vex", "tracking": {"id": "CVE-2026-40004"}},
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_name", "name": "Red Hat Enterprise Linux 9",
             "product": {"product_id": "red_hat_enterprise_linux_9", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}},
            {"category": "product_version", "name": "expat",
             "product": {"product_id": "expat", "product_identification_helper": {"purl": "pkg:rpm/redhat/expat"}}}
          ]}
        ],
        "relationships": [
          {"category": "default_component_of", "full_product_name": {"product_id": "red_hat_enterprise_linux_9:expat"},
           "product_reference": "expat", "relates_to_product_reference": "red_hat_enterprise_linux_9"}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-2026-40004", "product_status": {"known_affected": ["red_hat_enterprise_linux_9:expat"]}}
      ]
    }`
	advs, err := ParseCSAF([]byte(document))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs[0].Affected) != 0 {
		t.Fatalf("streaming CSAF must not emit an unbounded RPM range, got %+v", advs[0].Affected)
	}
}

// An open range must not escape the major it was stated for: a RHEL 9 affected binary must not match a RHEL 8
// component of the same name.
func TestParseCSAFSnapshotOpenRangeDoesNotCrossMajor(t *testing.T) {
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(redHatNotYetFixedSnapshot)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	for _, ecosystem := range []string{"Red Hat:8", "Red Hat:10", "Red Hat:7"} {
		if ok, _ := advs[0].Match(ecosystem, "expat", "0:2.5.0-6.el9_8.3", "x86_64"); ok {
			t.Fatalf("a RHEL 9 open range must not match %s", ecosystem)
		}
	}
	// A different package name on the stated major must also not match.
	if ok, _ := advs[0].Match("Red Hat:9", "expat-devel", "0:2.5.0-6.el9_8.3", "x86_64"); ok {
		t.Fatal("a binding must not match a package the vendor did not name")
	}
}

// A source identity that reaches the discriminator without arch=src must still be refused on its id alone,
// and a modular id must be refused regardless of where its stream marker sits.
func TestRedHatBinaryProductIDRefusesSourceAndModularVariants(t *testing.T) {
	for _, productID := range []string{
		"expat.src",
		"expat.SRC",
		"compat-expat1.src",
		"cargo::rust-toolset:rhel8",
		"nodejs::nodejs:20",
		"::",
		"a::b",
		// A single colon must be refused too. An RPM package name cannot contain a colon (it delimits the
		// epoch in NEVRA), so any colon means the id carries extra structure. Refusing every colon rather
		// than only the doubled form avoids depending on Red Hat keeping exactly the "name::module:stream"
		// spelling.
		"nodejs:20",
		"cargo:rust-toolset",
		"a:b",
	} {
		if redHatBinaryProductID(productID) {
			t.Fatalf("%q must not be treated as an installable binary", productID)
		}
	}
	// Names that merely contain "src" or a single colon are ordinary binaries and must stay admitted.
	for _, productID := range []string{"srcpkg", "libsrc", "expat-devel", "mingw64-expat", "compat-openldap"} {
		if !redHatBinaryProductID(productID) {
			t.Fatalf("%q is an ordinary binary name and must be admitted", productID)
		}
	}
}

// A non-RPM or malformed PURL must never reach the unversioned-binary path.
func TestRedHatRPMPurlRejectsNonRPMAndMalformedPURLs(t *testing.T) {
	for _, purl := range []string{
		"pkg:npm/left-pad",
		"pkg:rpm/suse/expat",
		"pkg:rpm/redhat/",
		"pkg:rpm/redhat/nested/name",
		"pkg:rpm/redhat/expat@",
		"",
	} {
		if _, _, _, ok := redHatRPMPurl("expat", purl); ok {
			t.Fatalf("purl %q must not resolve to a Red Hat binary RPM", purl)
		}
	}
	// arch=src is refused even when the product id looks like a plain binary.
	if _, _, _, ok := redHatRPMPurl("expat", "pkg:rpm/redhat/expat?arch=src"); ok {
		t.Fatal("an explicit source architecture must be refused regardless of the product id")
	}
	// An upstream qualifier alone is still sufficient proof, independent of the id.
	if _, _, kind, ok := redHatRPMPurl("expat.src", "pkg:rpm/redhat/expat?upstream=expat"); !ok || kind != rpmProductOpen {
		t.Fatalf("an upstream-qualified unversioned binary must remain admitted, got ok=%t kind=%v", ok, kind)
	}
}

// The open path has no EVR to screen for modularity, so the platform side is checked as a second, independent
// signal. A module or AppStream scope expressed on the platform must refuse the open range even when the
// package id looks like a plain binary.
func TestParseCSAFSnapshotRefusesOpenRangeOnModularPlatformScope(t *testing.T) {
	for _, platform := range []struct {
		name string
		id   string
		cpe  string
	}{
		{"appstream scoped cpe", "rhel9_appstream", "cpe:/o:redhat:enterprise_linux:9::appstream"},
		{"module scoped cpe", "rhel9_mod", "cpe:/o:redhat:enterprise_linux:9::appstream-nodejs20"},
		{"module named platform", "rhel9_nodejs_module", "cpe:/o:redhat:enterprise_linux:9"},
	} {
		t.Run(platform.name, func(t *testing.T) {
			label := "Red Hat Enterprise Linux 9"
			if platform.id == "rhel9_nodejs_module" {
				label = "Red Hat Enterprise Linux 9 nodejs:20 module"
			}
			document := `{
              "document": {"category": "csaf_vex", "tracking": {"id": "CVE-2026-40005"}},
              "product_tree": {
                "branches": [
                  {"category": "vendor", "name": "Red Hat", "branches": [
                    {"category": "product_name", "name": "` + label + `",
                     "product": {"product_id": "` + platform.id + `", "product_identification_helper": {"cpe": "` + platform.cpe + `"}}},
                    {"category": "product_version", "name": "nodejs",
                     "product": {"product_id": "nodejs", "product_identification_helper": {"purl": "pkg:rpm/redhat/nodejs"}}}
                  ]}
                ],
                "relationships": [
                  {"category": "default_component_of", "full_product_name": {"product_id": "` + platform.id + `:nodejs"},
                   "product_reference": "nodejs", "relates_to_product_reference": "` + platform.id + `"}
                ]
              },
              "vulnerabilities": [
                {"cve": "CVE-2026-40005", "product_status": {"known_affected": ["` + platform.id + `:nodejs"]}}
              ]
            }`
			advs, err := ParseCSAFSnapshot([][]byte{[]byte(document)})
			if err != nil {
				t.Fatalf("ParseCSAFSnapshot: %v", err)
			}
			if len(advs[0].Affected) != 0 {
				t.Fatalf("a module-scoped platform must not yield an open range, got %+v", advs[0].Affected)
			}
			// The concrete cross-stream false positive: a nodejs:20 flaw must not hit an installed nodejs:18.
			if ok, _ := advs[0].Match("Red Hat:9", "nodejs", "1:18.20.4-1.el9", "x86_64"); ok {
				t.Fatal("a module-scoped open range must never match an installed component of another stream")
			}
		})
	}
}

func TestModularPlatformScopeDiscriminatesPlainReleases(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		cpe     string
		id      string
		label   string
		modular bool
	}{
		{"plain rhel 9", "cpe:/o:redhat:enterprise_linux:9", "red_hat_enterprise_linux_9", "Red Hat Enterprise Linux 9", false},
		{"plain rhel 9 minor", "cpe:/o:redhat:enterprise_linux:9.8", "rhel_9_8", "Red Hat Enterprise Linux 9.8", false},
		{"appstream cpe", "cpe:/o:redhat:enterprise_linux:9::appstream", "rhel9", "Red Hat Enterprise Linux 9", true},
		{"module cpe", "cpe:/o:redhat:enterprise_linux:8::appstream-nodejs20", "rhel8", "Red Hat Enterprise Linux 8", true},
		{"module in id", "cpe:/o:redhat:enterprise_linux:9", "rhel9_module_nodejs", "Red Hat Enterprise Linux 9", true},
		{"appstream in name", "cpe:/o:redhat:enterprise_linux:9", "rhel9", "Red Hat Enterprise Linux 9 AppStream", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := modularPlatformScope(testCase.cpe, testCase.id, testCase.label); got != testCase.modular {
				t.Fatalf("modularPlatformScope(%q,%q,%q)=%t, want %t", testCase.cpe, testCase.id, testCase.label, got, testCase.modular)
			}
		})
	}
}

// Guard the comment's claim that decoding happens before the source check, so a percent-encoded arch cannot
// smuggle a source product through.
func TestRedHatRPMPurlDecodesArchBeforeSourceCheck(t *testing.T) {
	if _, _, _, ok := redHatRPMPurl("expat", "pkg:rpm/redhat/expat?arch=%73rc"); ok {
		t.Fatal("a percent-encoded source architecture must still be refused")
	}
	if _, _, _, ok := redHatRPMPurl("expat", "pkg:rpm/redhat/expat?arch="+strings.ToUpper("src")); ok {
		t.Fatal("an uppercase source architecture must still be refused")
	}
}

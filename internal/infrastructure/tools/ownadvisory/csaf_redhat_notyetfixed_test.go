package ownadvisory

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// Red Hat publishes a not-yet-fixed binary as an unversioned product carrying neither an arch nor an upstream
// qualifier, and states the identities that are NOT installable binaries explicitly: the source product is
// arch=src with a ".src" id, and a modular build embeds its stream as "<name>::<module>:<stream>". These tests
// pin that real feed shape, because it is the shape the authoritative RHEL 9 VEX snapshot actually emits.
const redHatNotYetFixedSnapshot = `{
  "document": {"category": "csaf_vex", "title": "expat: unfixed flaw", "tracking": {"id": "CVE-2026-40001"}},
  "product_tree": {
    "branches": [
      {"category": "vendor", "name": "Red Hat", "branches": [
        {"category": "product_name", "name": "Red Hat Enterprise Linux 9",
         "product": {"product_id": "red_hat_enterprise_linux_9", "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}},
        {"category": "product_version", "name": "expat",
         "product": {"product_id": "expat", "product_identification_helper": {"purl": "pkg:rpm/redhat/expat"}}},
        {"category": "product_version", "name": "expat.src",
         "product": {"product_id": "expat.src", "product_identification_helper": {"purl": "pkg:rpm/redhat/expat?arch=src"}}},
        {"category": "product_version", "name": "cargo",
         "product": {"product_id": "cargo::rust-toolset:rhel9", "product_identification_helper": {"purl": "pkg:rpm/redhat/cargo"}}}
      ]}
    ],
    "relationships": [
      {"category": "default_component_of", "full_product_name": {"product_id": "red_hat_enterprise_linux_9:expat"},
       "product_reference": "expat", "relates_to_product_reference": "red_hat_enterprise_linux_9"},
      {"category": "default_component_of", "full_product_name": {"product_id": "red_hat_enterprise_linux_9:expat.src"},
       "product_reference": "expat.src", "relates_to_product_reference": "red_hat_enterprise_linux_9"},
      {"category": "default_component_of", "full_product_name": {"product_id": "red_hat_enterprise_linux_9:cargo"},
       "product_reference": "cargo::rust-toolset:rhel9", "relates_to_product_reference": "red_hat_enterprise_linux_9"}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2026-40001",
     "product_status": {"known_affected": [
       "red_hat_enterprise_linux_9:expat",
       "red_hat_enterprise_linux_9:expat.src",
       "red_hat_enterprise_linux_9:cargo"
     ]},
     "remediations": [{"category": "none_available", "details": "no fix available",
       "product_ids": ["red_hat_enterprise_linux_9:expat"]}]}
  ]
}`

func TestParseCSAFSnapshotAdmitsRedHatNotYetFixedBinary(t *testing.T) {
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(redHatNotYetFixedSnapshot)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("want one advisory, got %d", len(advs))
	}
	if len(advs[0].Affected) != 1 {
		t.Fatalf("only the installable binary may project a range, got %+v", advs[0].Affected)
	}
	affected := advs[0].Affected[0]
	if affected.Ecosystem != "Red Hat:9" || affected.Package != "expat" {
		t.Fatalf("unexpected binding %+v", affected)
	}
	if affected.FixedVersion != "" {
		t.Fatalf("a not-yet-fixed advisory must carry no fixed version, got %q", affected.FixedVersion)
	}
	if len(affected.Ranges) != 1 ||
		!reflect.DeepEqual(affected.Ranges[0].Events, []advisory.Event{{Introduced: "0"}}) {
		t.Fatalf("not-yet-fixed evidence must stay an open range, got %+v", affected.Ranges)
	}
	// The installed RHEL 9.8 binary is inside the open range, so the vulnerability is reported with no fix.
	matched, fixed := advs[0].Match("Red Hat:9", "expat", "0:2.5.0-6.el9_8.3", "x86_64")
	if !matched || fixed != "" {
		t.Fatalf("installed binary must match with no fixed version, got matched=%t fixed=%q", matched, fixed)
	}
}

func TestParseCSAFSnapshotRejectsRedHatSourceAndModularIdentities(t *testing.T) {
	advs, err := ParseCSAFSnapshot([][]byte{[]byte(redHatNotYetFixedSnapshot)})
	if err != nil {
		t.Fatalf("ParseCSAFSnapshot: %v", err)
	}
	for _, affected := range advs[0].Affected {
		if affected.Package == "cargo" {
			t.Fatalf("a modular stream identity must not project a linear range, got %+v", affected)
		}
	}
	// The source product shares the "expat" name, so it must contribute no second binding and no arch=src range.
	if len(advs[0].Affected) != 1 {
		t.Fatalf("source and modular identities must be excluded, got %+v", advs[0].Affected)
	}
	if ok, _ := advs[0].Match("Red Hat:9", "cargo", "0:1.75.0-1.el9", "x86_64"); ok {
		t.Fatal("a modular product must never match an installed component")
	}
}

func TestRedHatBinaryProductIDDiscriminatesInstallableBinaries(t *testing.T) {
	for _, tc := range []struct {
		productID string
		want      bool
	}{
		{"expat", true},
		{"openldap", true},
		{"expat-devel", true},
		{"openldap-clients", true},
		{"expat.src", false},
		{"openldap.src", false},
		{"EXPAT.SRC", false},
		{"cargo::rust-toolset:rhel9", false},
		{"nodejs::nodejs:20", false},
		{"", false},
		{"   ", false},
	} {
		t.Run(tc.productID, func(t *testing.T) {
			if got := redHatBinaryProductID(tc.productID); got != tc.want {
				t.Fatalf("redHatBinaryProductID(%q)=%t, want %t", tc.productID, got, tc.want)
			}
		})
	}
}

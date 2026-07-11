package ownadvisory

import (
	"reflect"
	"strings"
	"testing"
)

const csafFixture = `{
  "document": {"title": "Test Advisory Bundle"},
  "product_tree": {
    "full_product_names": [
      {"product_id": "P-DJANGO-321", "product_identification_helper": {"cpe": "cpe:2.3:a:djangoproject:django:3.2.1:*:*:*:*:python:*:*"}},
      {"product_id": "P-DJANGO-322", "product_identification_helper": {"cpe": "cpe:2.3:a:djangoproject:django:3.2.2:*:*:*:*:python:*:*"}},
      {"product_id": "P-APACHE",     "product_identification_helper": {"cpe": "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"}}
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2021-0001",
      "title": "SQL injection in Django",
      "cwe": {"id": "CWE-89"},
      "ids": [{"text": "GHSA-aaaa-bbbb-cccc"}],
      "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}],
      "product_status": {"known_affected": ["P-DJANGO-321"], "fixed": ["P-DJANGO-322"]}
    },
    {
      "cve": "CVE-2021-0002",
      "title": "Apache-only issue (does not map to an ecosystem)",
      "product_status": {"known_affected": ["P-APACHE"]}
    },
    {
      "title": "no cve – must be skipped",
      "product_status": {"known_affected": ["P-DJANGO-321"]}
    }
  ]
}`

func TestParseCSAF(t *testing.T) {
	advs, err := ParseCSAF([]byte(csafFixture))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	// Two vulns have a CVE; the third (no CVE) is skipped.
	if len(advs) != 2 {
		t.Fatalf("want 2 advisories (the no-CVE vuln skipped), got %d: %+v", len(advs), advs)
	}

	a := advs[0]
	if a.ID != "CVE-2021-0001" {
		t.Fatalf("first advisory id = %q", a.ID)
	}
	if !reflect.DeepEqual(a.Aliases, []string{"GHSA-aaaa-bbbb-cccc"}) {
		t.Errorf("aliases must carry the non-CVE id, got %v", a.Aliases)
	}
	if a.Summary != "SQL injection in Django" {
		t.Errorf("summary = %q", a.Summary)
	}
	if a.CVSSScore != 9.8 || a.CVSSVector == "" {
		t.Errorf("CVSS must be extracted (score 9.8 + vector), got score=%v vector=%q", a.CVSSScore, a.CVSSVector)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("want 1 affected package, got %+v", a.Affected)
	}
	ap := a.Affected[0]
	if ap.Ecosystem != "PyPI" || ap.Package != "django" {
		t.Errorf("affected must resolve the python CPE to PyPI/django, got %s/%s", ap.Ecosystem, ap.Package)
	}
	if !reflect.DeepEqual(ap.Versions, []string{"3.2.1"}) {
		t.Errorf("known_affected CPE version must become the explicit affected version, got %v", ap.Versions)
	}
	if ap.FixedVersion != "3.2.2" {
		t.Errorf("the fixed product's CPE version must become the remediation hint, got %q", ap.FixedVersion)
	}

	// CVE-2021-0002: the Apache CPE has no language target_sw → unmappable → empty Affected (still emitted).
	if advs[1].ID != "CVE-2021-0002" || len(advs[1].Affected) != 0 {
		t.Errorf("an unmappable-CPE vuln must yield an advisory with empty Affected, got %+v", advs[1])
	}
}

func TestParseCSAFAllVersionsBecomesOpenRange(t *testing.T) {
	// A known_affected CPE with version "*" means every version is affected → an open ECOSYSTEM range,
	// closed by the fixed version.
	doc := `{
      "product_tree": {"full_product_names": [
        {"product_id": "PA", "product_identification_helper": {"cpe": "cpe:2.3:a:x:requests:*:*:*:*:*:python:*:*"}},
        {"product_id": "PF", "product_identification_helper": {"cpe": "cpe:2.3:a:x:requests:2.20.0:*:*:*:*:python:*:*"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-2020-1", "product_status": {"known_affected": ["PA"], "fixed": ["PF"]}}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want 1 advisory with 1 affected pkg, got %+v", advs)
	}
	ap := advs[0].Affected[0]
	if len(ap.Ranges) != 1 || ap.Ranges[0].Type != "ECOSYSTEM" {
		t.Fatalf("version * must become an ECOSYSTEM range, got %+v", ap.Ranges)
	}
	evs := ap.Ranges[0].Events
	if len(evs) != 2 || evs[0].Introduced != "0" || evs[1].Fixed != "2.20.0" {
		t.Errorf("open range must be introduced:0 → fixed:2.20.0, got %+v", evs)
	}
}

func TestParseCSAFDeterministic(t *testing.T) {
	a, err := ParseCSAF([]byte(csafFixture))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	b, _ := ParseCSAF([]byte(csafFixture))
	if !reflect.DeepEqual(a, b) {
		t.Error("ParseCSAF must be deterministic for identical input")
	}
}

// The RedHat/SUSE shape: products are defined in a recursive branches tree (vendor→product→version) and the
// fixed version comes from a vendor_fix remediation, not product_status.fixed.
func TestParseCSAFBranchesAndVendorFix(t *testing.T) {
	doc := `{
      "product_tree": {"branches": [
        {"category": "vendor", "name": "Acme", "branches": [
          {"category": "product_name", "name": "flask", "branches": [
            {"category": "product_version", "name": "1.0", "product": {"product_id": "PV-AFF", "product_identification_helper": {"cpe": "cpe:2.3:a:acme:flask:1.0:*:*:*:*:python:*:*"}}},
            {"category": "product_version", "name": "1.1", "product": {"product_id": "PV-FIX", "product_identification_helper": {"cpe": "cpe:2.3:a:acme:flask:1.1:*:*:*:*:python:*:*"}}}
          ]}
        ]}
      ]},
      "vulnerabilities": [{
        "cve": "CVE-2022-1",
        "product_status": {"known_affected": ["PV-AFF"]},
        "remediations": [{"category": "vendor_fix", "product_ids": ["PV-FIX"]}]
      }]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2022-1" {
		t.Fatalf("want 1 advisory CVE-2022-1, got %+v", advs)
	}
	if len(advs[0].Affected) != 1 {
		t.Fatalf("want 1 affected pkg (resolved from the branches tree), got %+v", advs[0].Affected)
	}
	ap := advs[0].Affected[0]
	if ap.Ecosystem != "PyPI" || ap.Package != "flask" {
		t.Errorf("branch leaf must resolve to PyPI/flask, got %s/%s", ap.Ecosystem, ap.Package)
	}
	if !reflect.DeepEqual(ap.Versions, []string{"1.0"}) {
		t.Errorf("affected version must come from the known_affected branch leaf, got %v", ap.Versions)
	}
	if ap.FixedVersion != "1.1" {
		t.Errorf("fixed version must come from the vendor_fix remediation, got %q", ap.FixedVersion)
	}
}

// A pathologically deep branches tree (well past maxBranchDepth, but small bytes + under the JSON decoder's
// own nesting limit) must NOT panic – collectBranchCPEs is depth-bounded; the too-deep product is dropped.
func TestParseCSAFDeepBranchesBounded(t *testing.T) {
	const depth = 500
	open := strings.Repeat(`{"category":"x","name":"n","branches":[`, depth)
	leaf := `{"category":"product_version","name":"x","product":{"product_id":"DEEP","product_identification_helper":{"cpe":"cpe:2.3:a:x:flask:1.0:*:*:*:*:python:*:*"}}}`
	closes := strings.Repeat(`]}`, depth)
	doc := `{"product_tree":{"branches":[` + open + leaf + closes + `]},"vulnerabilities":[{"cve":"CVE-DEEP","product_status":{"known_affected":["DEEP"]}}]}`

	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("a deep (but small) tree must parse without error or panic, got %v", err)
	}
	// The over-deep product is dropped by the depth cap → its vuln resolves nothing → inert.
	if len(advs) != 1 || len(advs[0].Affected) != 0 {
		t.Errorf("the over-deep product must be dropped (inert advisory), got %+v", advs)
	}
}

// A vendor_fix with no corresponding known_affected must NOT create an affected entry (no false match).
func TestParseCSAFVendorFixWithoutAffected(t *testing.T) {
	doc := `{
      "product_tree": {"full_product_names": [
        {"product_id": "PF", "product_identification_helper": {"cpe": "cpe:2.3:a:x:flask:1.1:*:*:*:*:python:*:*"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-X", "remediations": [{"category": "vendor_fix", "product_ids": ["PF"]}]}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 0 {
		t.Errorf("a vendor_fix with no known_affected must yield NO affected entry, got %+v", advs)
	}
}

// Branches with no product (a vendor node) or an empty product must not panic and resolve nothing.
func TestParseCSAFEmptyAndNilProductBranches(t *testing.T) {
	doc := `{
      "product_tree": {"branches": [
        {"category": "vendor", "name": "Acme", "branches": [
          {"category": "product_name", "name": "x", "product": {"product_id": "", "product_identification_helper": {"cpe": ""}}}
        ]}
      ]},
      "vulnerabilities": [{"cve": "CVE-Y", "product_status": {"known_affected": ["whatever"]}}]
    }`
	advs, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF must not error on nil/empty product branches: %v", err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 0 {
		t.Errorf("nil/empty product branches must resolve nothing, got %+v", advs)
	}
}

func TestParseCSAFRejectsBadJSON(t *testing.T) {
	if _, err := ParseCSAF([]byte("{not json")); err == nil {
		t.Error("malformed CSAF JSON must fail closed")
	}
}

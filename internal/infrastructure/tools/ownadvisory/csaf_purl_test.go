package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// languageCSAF is a CSAF 2.0 document that keys its affected products by PURL rather than CPE, the way a
// GitHub Security Advisory export and other language-ecosystem VEX documents do. It carries an npm and a
// PyPI affected product plus an npm fixed product.
const languageCSAF = `{
  "document": {"title": "Language-ecosystem advisories"},
  "product_tree": {"full_product_names": [
    {"product_id": "P-LODASH-VULN", "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.11"}},
    {"product_id": "P-LODASH-FIX",  "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.12"}},
    {"product_id": "P-FLASK-VULN",  "product_identification_helper": {"purl": "pkg:pypi/Flask@2.0.0"}}
  ]},
  "vulnerabilities": [
    {"cve": "CVE-2021-23337", "title": "Command injection in lodash",
     "product_status": {"known_affected": ["P-LODASH-VULN"], "fixed": ["P-LODASH-FIX"]}},
    {"cve": "CVE-2023-30861", "title": "Flask session cookie exposure",
     "product_status": {"known_affected": ["P-FLASK-VULN"]}}
  ]
}`

// TestParseCSAFLanguagePURL is D1.9: CSAF products named by a language-ecosystem PURL resolve to the owned
// (ecosystem, package, version) key, so a GitHub CSAF export matches components without a CPE.
func TestParseCSAFLanguagePURL(t *testing.T) {
	advs, err := ParseCSAF([]byte(languageCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
	}
	lodash := byID["CVE-2021-23337"]
	if len(lodash.Affected) != 1 {
		t.Fatalf("lodash advisory affected = %+v", lodash.Affected)
	}
	ap := lodash.Affected[0]
	if ap.Ecosystem != "npm" || ap.Package != "lodash" {
		t.Fatalf("npm PURL must resolve to npm/lodash, got %s/%s", ap.Ecosystem, ap.Package)
	}
	if len(ap.Versions) != 1 || ap.Versions[0] != "4.17.11" || ap.FixedVersion != "4.17.12" {
		t.Errorf("explicit affected version + fixed wrong: versions=%v fixed=%q", ap.Versions, ap.FixedVersion)
	}
	// The PyPI PURL folds "Flask" to the canonical "flask" key, matching the SBOM producer.
	flask := byID["CVE-2023-30861"]
	if len(flask.Affected) != 1 || flask.Affected[0].Ecosystem != "PyPI" || flask.Affected[0].Package != "flask" {
		t.Fatalf("PyPI PURL must resolve to PyPI/flask, got %+v", flask.Affected)
	}
}

// TestScanMatchesLanguageCSAF is the end-to-end slice: the PURL-keyed CSAF advisory matches a scanned npm
// component at the affected version, and declines the fixed version and an unrelated one.
func TestScanMatchesLanguageCSAF(t *testing.T) {
	advs, err := ParseCSAF([]byte(languageCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	byKey := map[string][]advisory.Advisory{}
	for _, a := range advs {
		for _, ap := range a.Affected {
			byKey[ap.Ecosystem+"|"+ap.Package] = append(byKey[ap.Ecosystem+"|"+ap.Package], a)
		}
	}
	store := memStore{byKey: byKey}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.11", PURL: "pkg:npm/lodash@4.17.11"}, // affected → match
		{Name: "lodash", Version: "4.17.12", PURL: "pkg:npm/lodash@4.17.12"}, // fixed → no explicit-version match
		{Name: "flask", Version: "2.0.0", PURL: "pkg:pypi/flask@2.0.0"},      // affected → match
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := map[string]bool{}
	for _, r := range raws {
		got[r.AdvisoryID+"|"+r.Component] = true
	}
	if !got["CVE-2021-23337|lodash"] {
		t.Errorf("expected the lodash CVE to match the affected version, got %+v", raws)
	}
	if !got["CVE-2023-30861|flask"] {
		t.Errorf("expected the flask CVE to match, got %+v", raws)
	}
	if got["CVE-2021-23337|lodash"] && len(raws) != 2 {
		t.Errorf("the fixed lodash build must not match an explicit-version advisory, got %d findings: %+v", len(raws), raws)
	}
}

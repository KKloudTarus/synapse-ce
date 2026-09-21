package ownadvisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// A CSAF bundle with one mappable (python) product and one unmappable (apache) product: the mappable vuln
// is ingested; the unmappable one is inert (no resolvable package) and counted as skipped.
const csafBundle = `{
  "product_tree": {"full_product_names": [
    {"product_id": "P1", "product_identification_helper": {"cpe": "cpe:2.3:a:x:flask:1.0:*:*:*:*:python:*:*"}},
    {"product_id": "P2", "product_identification_helper": {"cpe": "cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*"}}
  ]},
  "vulnerabilities": [
    {"cve": "CVE-1", "product_status": {"known_affected": ["P1"]}},
    {"cve": "CVE-2", "product_status": {"known_affected": ["P2"]}}
  ]
}`

// TestCSAFDirFeedIngestsMappableSkipsInert: a CSAF doc yields its mappable advisory; an inert (unmappable)
// advisory and an unparseable file are both counted as skipped (honest coverage).
func TestCSAFDirFeedIngestsMappableSkipsInert(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.json", csafBundle)
	writeFile(t, dir, "broken.json", `{not json`) // unparseable file -> skipped + counted
	writeFile(t, dir, "notes.txt", csafBundle)    // wrong extension -> ignored, not counted

	var got []advisory.Advisory
	skipped, err := NewCSAFDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-1" {
		t.Fatalf("only the mappable advisory must be ingested, got %+v", got)
	}
	if len(got[0].Affected) != 1 || got[0].Affected[0].Ecosystem != "PyPI" || got[0].Affected[0].Package != "flask" {
		t.Errorf("the ingested advisory must resolve to PyPI/flask, got %+v", got[0].Affected)
	}
	if skipped != 2 { // CVE-2 inert + broken.json unparseable
		t.Errorf("want skipped=2 (1 inert advisory + 1 unparseable file), got %d", skipped)
	}
}

func TestCSAFDirFeedSkipsRedHatUnfixedBinaryProductsWithoutSnapshot(t *testing.T) {
	data, err := os.ReadFile("testdata/csaf-redhat-rhel9-unfixed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, dir, "cve-2024-11053.json", string(data))

	var got []advisory.Advisory
	skipped, err := NewCSAFDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if skipped != 1 || len(got) != 0 {
		t.Fatalf("streaming CSAF must not ingest an unbounded Red Hat RPM range: skipped=%d got=%+v", skipped, got)
	}
}

// TestCSAFDirFeedNotADir: a non-directory path fails loud (parity with DirFeed via the shared walk).
func TestCSAFDirFeedNotADir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x.json", csafBundle)
	f := filepath.Join(dir, "x.json")
	if _, err := NewCSAFDirFeed(f).Each(context.Background(), func(advisory.Advisory) error { return nil }); err == nil {
		t.Fatal("a file path (not a dir) must fail loud")
	}
}

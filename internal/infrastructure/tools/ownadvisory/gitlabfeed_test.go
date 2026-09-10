package ownadvisory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// tarGzOf builds an in-memory .tar.gz from name->content pairs (gemnasium-db archive shape).
func tarGzOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGitLabFeedFetchesAndParses(t *testing.T) {
	good := `---
identifier: "CVE-2007-5712"
identifiers: ["CVE-2007-5712","GHSA-9v8h-57gv-qch6"]
package_slug: "pypi/Django"
title: "Django DoS"
affected_range: ">=0.96.0,<0.96.1"
fixed_versions: ["0.96.1"]
cvss_v3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
`
	archive := tarGzOf(t, map[string]string{
		"gemnasium-db-master/pypi/Django/CVE-2007-5712.yml": good,
		"gemnasium-db-master/pypi/Django/bad.yml":           "{not: [valid",                                                       // unparseable -> skipped
		"gemnasium-db-master/README.md":                     "not an advisory",                                                    // non-yml -> ignored
		"gemnasium-db-master/conda/x/GMS-1.yml":             "identifier: GMS-1\npackage_slug: conda/x\naffected_range: <1.0.0\n", // unmapped eco -> skipped
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	var got []advisory.Advisory
	skipped, err := NewGitLabFeed(srv.URL, srv.Client()).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("each: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2007-5712" || got[0].Affected[0].Ecosystem != "PyPI" {
		t.Fatalf("want 1 parsed pypi advisory, got %+v", got)
	}
	if skipped != 2 { // bad.yml + the unmapped-ecosystem conda file
		t.Fatalf("want skipped=2, got %d", skipped)
	}
}

func TestGitLabFeedFetchErrorFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusNotFound) }))
	defer srv.Close()
	if _, err := NewGitLabFeed(srv.URL, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil }); err == nil {
		t.Fatal("a non-2xx archive fetch must be fatal, not a silent skip")
	}
}

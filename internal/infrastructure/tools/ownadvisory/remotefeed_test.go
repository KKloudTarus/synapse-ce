package ownadvisory

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// zipAllOf builds an in-memory OSV-style all.zip from name->content pairs.
func zipAllOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveZip returns a test server that serves the given zip at /<eco>/all.zip and 404s everything else.
func serveZip(t *testing.T, eco string, zipBytes []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+eco+"/all.zip" {
			_, _ = w.Write(zipBytes)
			return
		}
		http.NotFound(w, r)
	}))
}

// TestRemoteFeedFetchesAndParses: a fetched all.zip yields its valid advisories; a malformed entry inside is
// skipped+counted; a non-.json entry is ignored.
func TestRemoteFeedFetchesAndParses(t *testing.T) {
	z := zipAllOf(t, map[string]string{
		"GHSA-1.json": validOSV1,
		"GHSA-2.json": validOSV2,
		"bad.json":    `{not json`,          // malformed -> skipped
		"README.txt":  "not an advisory",    // non-json -> ignored
		"noid.json":   `{"summary":"none"}`, // ParseOSV rejects (no id) -> skipped
	})
	srv := serveZip(t, "Go", z)
	defer srv.Close()

	var got []string
	skipped, err := NewRemoteFeed(srv.URL, []string{"Go"}, srv.Client()).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("each: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 parsed advisories, got %v", got)
	}
	if skipped != 2 { // bad.json + noid.json
		t.Fatalf("want skipped=2, got %d", skipped)
	}
}

func TestRemoteFeedSkipsZipBombEntry(t *testing.T) {
	z := zipAllOf(t, map[string]string{"bomb.json": `{"id":"CVE-2026-9999","summary":"` + strings.Repeat("a", maxAdvisoryBytes) + `"}`})
	reader, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readZipEntry(reader.File[0]); ok {
		t.Fatal("oversized decompressed zip entry was accepted")
	}
}

// TestRemoteFeedMultiEcosystem: advisories from two ecosystems are all yielded.
func TestRemoteFeedMultiEcosystem(t *testing.T) {
	zGo := zipAllOf(t, map[string]string{"a.json": validOSV1})
	zNpm := zipAllOf(t, map[string]string{"b.json": validOSV2})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			_, _ = w.Write(zGo)
		case "/npm/all.zip":
			_, _ = w.Write(zNpm)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var n int
	skipped, err := NewRemoteFeed(srv.URL, []string{"Go", "npm"}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error {
		n++
		return nil
	})
	if err != nil || n != 2 || skipped != 0 {
		t.Fatalf("both ecosystems must be ingested: n=%d skipped=%d err=%v", n, skipped, err)
	}
}

// TestRemoteFeedFetchErrorFatal: a 404 for an ecosystem aborts loud (a silently-skipped ecosystem would be a
// large hidden gap).
func TestRemoteFeedFetchErrorFatal(t *testing.T) {
	srv := serveZip(t, "Go", zipAllOf(t, map[string]string{"a.json": validOSV1}))
	defer srv.Close()
	// ask for an ecosystem the server 404s
	_, err := NewRemoteFeed(srv.URL, []string{"npm"}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("a non-2xx fetch must be fatal, not a silent skip")
	}
}

// TestRemoteFeedRejectsUnsafeEcosystem: an ecosystem name that isn't a safe path segment fails loud (no path
// redirect / SSRF), and never even issues a request.
func TestRemoteFeedRejectsUnsafeEcosystem(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	for _, bad := range []string{"../secret", "a/b", "x/../y"} {
		if _, err := NewRemoteFeed(srv.URL, []string{bad}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil }); err == nil {
			t.Fatalf("unsafe ecosystem %q must be rejected", bad)
		}
	}
	if hit {
		t.Fatal("an unsafe ecosystem must be rejected before any request is issued")
	}
}

// TestRemoteFeedDefaults: empty baseURL/ecosystems/client fall back to the OSV bucket + covered set.
func TestRemoteFeedDefaults(t *testing.T) {
	f := NewRemoteFeed("", nil, nil)
	if f.baseURL != defaultOSVBulkURL || len(f.ecosystems) != len(defaultBulkEcosystems) || f.client == nil {
		t.Fatalf("defaults not applied: %+v", f)
	}
}

// TestRemoteFeedNoRedirectOnInjectedClient (defense-in-depth): a stock injected client (no redirect policy)
// gets the no-redirect policy, so it can't follow a 3xx to an internal host even if the operator injects it.
func TestRemoteFeedNoRedirectOnInjectedClient(t *testing.T) {
	c := &http.Client{}
	NewRemoteFeed("", nil, c)
	if c.CheckRedirect == nil {
		t.Fatal("an injected stock client must be given the no-redirect policy")
	}
}

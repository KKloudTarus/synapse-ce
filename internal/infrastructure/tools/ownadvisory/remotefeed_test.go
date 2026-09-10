package ownadvisory

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"hash/crc32"
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

// serveZipHashed serves a zip at /<eco>/all.zip with the given x-goog-hash header values (one Add per value,
// mirroring GCS which sends crc32c and md5 as separate headers).
func serveZipHashed(t *testing.T, eco string, zipBytes []byte, googHashes []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+eco+"/all.zip" {
			for _, h := range googHashes {
				w.Header().Add("X-Goog-Hash", h)
			}
			_, _ = w.Write(zipBytes)
			return
		}
		http.NotFound(w, r)
	}))
}

const validOSVAdvisoryJSON = `{"id":"GHSA-hash-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`

// TestRemoteFeedVerifiesGoogHash (D1.8): a download whose bytes match the bucket's published crc32c ingests.
// A deliberately-wrong md5 in the same header is ignored (only crc32c is checked).
func TestRemoteFeedVerifiesGoogHash(t *testing.T) {
	zipBytes := zipAllOf(t, map[string]string{"a.json": validOSVAdvisoryJSON})
	hdr := []string{
		"crc32c=" + base64.StdEncoding.EncodeToString(crc32Castagnoli(zipBytes)),
		"md5=" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), // wrong on purpose, must be ignored
	}
	srv := serveZipHashed(t, "Go", zipBytes, hdr)
	defer srv.Close()
	got := 0
	skipped, err := NewRemoteFeed(srv.URL, []string{"Go"}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { got++; return nil })
	if err != nil || skipped != 0 || got != 1 {
		t.Fatalf("verified feed: got=%d skipped=%d err=%v", got, skipped, err)
	}
}

// TestRemoteFeedRejectsBadCRC32C (D1.8): a download whose bytes do NOT match the published crc32c is
// fail-closed (rejected), never ingested.
func TestRemoteFeedRejectsBadCRC32C(t *testing.T) {
	zipBytes := zipAllOf(t, map[string]string{"a.json": validOSVAdvisoryJSON})
	srv := serveZipHashed(t, "Go", zipBytes, []string{"crc32c=" + base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})})
	defer srv.Close()
	_, err := NewRemoteFeed(srv.URL, []string{"Go"}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error {
		t.Fatal("a corrupted download must not be ingested")
		return nil
	})
	if err == nil {
		t.Fatal("crc32c mismatch must fail closed")
	}
}

// TestRemoteFeedProceedsWithoutHash (D1.8): a mirror that publishes no x-goog-hash cannot be verified, so
// the feed proceeds best-effort rather than failing.
func TestRemoteFeedProceedsWithoutHash(t *testing.T) {
	zipBytes := zipAllOf(t, map[string]string{"a.json": validOSVAdvisoryJSON})
	srv := serveZipHashed(t, "Go", zipBytes, nil)
	defer srv.Close()
	got := 0
	if _, err := NewRemoteFeed(srv.URL, []string{"Go"}, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { got++; return nil }); err != nil || got != 1 {
		t.Fatalf("no-hash mirror must proceed: got=%d err=%v", got, err)
	}
}

func crc32Castagnoli(b []byte) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	return out[:]
}

// TestCRC32CKnownVector pins the crc32c encoding to the standard Castagnoli check value for "123456789"
// (0xE3069283), independently of the production code, so a wrong polynomial/endianness/base64 can't pass by
// matching a same-wrong helper.
func TestCRC32CKnownVector(t *testing.T) {
	if got := base64.StdEncoding.EncodeToString(crc32Castagnoli([]byte("123456789"))); got != "4waSgw==" {
		t.Fatalf("crc32c('123456789') = %q, want 4waSgw== (0xE3069283)", got)
	}
}

// TestGCSHostRequiresDigest: a GCS-bucket source (the default) requires a published crc32c; a custom mirror
// does not.
func TestGCSHostRequiresDigest(t *testing.T) {
	if !isGCSHost(defaultOSVBulkURL) || !NewRemoteFeed("", nil, nil).requireDigest {
		t.Fatal("the default OSV bucket is a GCS host and must require a digest")
	}
	if isGCSHost("http://localhost:9999") || NewRemoteFeed("http://mirror.internal/osv", nil, nil).requireDigest {
		t.Fatal("a custom mirror must not require a digest")
	}
}

// TestVerifyGoogHashPolicy exercises verifyGoogHash directly: match passes, mismatch and a conflicting second
// digest fail closed, and an absent digest is fail-closed only when required.
func TestVerifyGoogHashPolicy(t *testing.T) {
	crc := func(b []byte) hash.Hash32 {
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		_, _ = h.Write(b)
		return h
	}
	good := base64.StdEncoding.EncodeToString(crc32Castagnoli([]byte("payload")))
	hdr := func(vals ...string) http.Header {
		h := http.Header{}
		for _, v := range vals {
			h.Add("X-Goog-Hash", v)
		}
		return h
	}
	if err := verifyGoogHash(hdr("crc32c="+good), crc([]byte("payload")), true); err != nil {
		t.Fatalf("matching digest must pass: %v", err)
	}
	if err := verifyGoogHash(hdr("crc32c=AAAAAA=="), crc([]byte("payload")), false); err == nil {
		t.Fatal("mismatched digest must fail closed")
	}
	if err := verifyGoogHash(hdr("crc32c="+good, "crc32c=AAAAAA=="), crc([]byte("payload")), false); err == nil {
		t.Fatal("a conflicting second digest must fail closed")
	}
	if err := verifyGoogHash(hdr(), crc([]byte("payload")), true); err == nil {
		t.Fatal("an absent digest must fail closed when required (GCS source)")
	}
	if err := verifyGoogHash(hdr(), crc([]byte("payload")), false); err != nil {
		t.Fatalf("an absent digest proceeds for a mirror: %v", err)
	}
}

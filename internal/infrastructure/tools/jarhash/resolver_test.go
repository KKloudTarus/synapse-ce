package jarhash

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// stubCentral returns a test server that answers the SHA-1 solr query from a fixture map sha1 -> docs.
func stubCentral(t *testing.T, bySHA1 map[string][]map[string]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		q := r.URL.Query().Get("q") // 1:"<sha1>"
		sha1 := strings.TrimSuffix(strings.TrimPrefix(q, `1:"`), `"`)
		docs := bySHA1[sha1]
		resp := map[string]any{"response": map[string]any{"docs": docs}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestResolveRecoversSingleMatch(t *testing.T) {
	sha1 := "6505a72a097d9270f7a9e7bf42c4238283247755"
	srv := stubCentral(t, map[string][]map[string]string{
		sha1: {{"g": "org.apache.commons", "a": "commons-lang3", "v": "3.8.1"}},
	}, nil)
	defer srv.Close()

	comps := []sbom.Component{
		// A shaded jar: no maven coordinate, but syft gave us its SHA-1.
		{Name: "shaded-thing", Version: "", PURL: "", SHA1: sha1},
	}
	n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps)
	if n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	got := comps[0]
	if got.PURL != "pkg:maven/org.apache.commons/commons-lang3@3.8.1" ||
		got.Name != "org.apache.commons:commons-lang3" || got.Version != "3.8.1" {
		t.Fatalf("coordinate not applied: %+v", got)
	}
}

func TestResolveSkipsAlreadyIdentified(t *testing.T) {
	var hits int32
	srv := stubCentral(t, map[string][]map[string]string{}, &hits)
	defer srv.Close()
	// A component that already has a resolved pkg:maven coordinate must NOT be queried.
	comps := []sbom.Component{
		{Name: "org.apache.commons:commons-lang3", Version: "3.10", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.10", SHA1: "abc123"},
	}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 0 {
		t.Fatalf("recovered = %d, want 0 (already identified)", n)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("must not query Central for an already-identified component (hits=%d)", hits)
	}
}

func TestResolveNoMatchLeavesUnchanged(t *testing.T) {
	srv := stubCentral(t, map[string][]map[string]string{}, nil) // every sha1 → 0 docs
	defer srv.Close()
	comps := []sbom.Component{{Name: "mystery", PURL: "", SHA1: "1111111111111111111111111111111111111111"}}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 0 {
		t.Fatalf("recovered = %d, want 0 (no match)", n)
	}
	if comps[0].PURL != "" || comps[0].Name != "mystery" {
		t.Errorf("no-match component must be left unchanged: %+v", comps[0])
	}
}

// A component without a (valid) SHA-1 is never queried – nothing to fingerprint.
func TestResolveIgnoresMissingOrBadSHA1(t *testing.T) {
	var hits int32
	srv := stubCentral(t, map[string][]map[string]string{}, &hits)
	defer srv.Close()
	comps := []sbom.Component{
		{Name: "no-hash", PURL: ""},                      // no SHA-1
		{Name: "bad-hash", PURL: "", SHA1: "not-hex-xx"}, // not a 40-char hex sha1
	}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 0 {
		t.Fatalf("recovered = %d, want 0", n)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("must not query without a valid SHA-1 (hits=%d)", hits)
	}
}

// Two components sharing a SHA-1 must hit Central only ONCE (the answer is cached, immutable per hash).
func TestResolveCachesBySHA1(t *testing.T) {
	sha1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var hits int32
	srv := stubCentral(t, map[string][]map[string]string{
		sha1: {{"g": "com.x", "a": "y", "v": "1.0"}},
	}, &hits)
	defer srv.Close()
	comps := []sbom.Component{
		{Name: "a", SHA1: sha1}, {Name: "b", SHA1: sha1},
	}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 2 {
		t.Fatalf("recovered = %d, want 2", n)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("Central queried %d times, want 1 (cached per SHA-1)", got)
	}
}

// On HTTP 429 the resolver halts (best-effort) and never fails; the component is left unchanged.
func TestResolveHaltsOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	comps := []sbom.Component{{Name: "z", SHA1: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 0 {
		t.Fatalf("recovered = %d, want 0 (throttled)", n)
	}
	if comps[0].PURL != "" {
		t.Errorf("throttled component must be unchanged: %+v", comps[0])
	}
}

// A malicious/compromised Central response with metacharacters in the coordinate must be REJECTED,
// not adopted into a PURL / advisory key (untrusted-input hardening).
func TestResolveRejectsMalformedCoordinate(t *testing.T) {
	sha1 := "cccccccccccccccccccccccccccccccccccccccc"
	for _, bad := range []map[string]string{
		{"g": "evil/../x", "a": "y", "v": "1.0"},   // slash in group
		{"g": "x", "a": "y@z", "v": "1.0"},         // @ in artifact
		{"g": "x", "a": "y", "v": "1.0 OR 2.0"},    // space in version
		{"g": "", "a": "y", "v": "1.0"},            // empty group
		{"g": "x", "a": "y", "v": "1.0/../../etc"}, // slash in version
	} {
		srv := stubCentral(t, map[string][]map[string]string{sha1: {bad}}, nil)
		comps := []sbom.Component{{Name: "shaded", PURL: "", SHA1: sha1}}
		n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps)
		srv.Close()
		if n != 0 || comps[0].PURL != "" {
			t.Errorf("malformed coord %v must be rejected, got n=%d comp=%+v", bad, n, comps[0])
		}
	}
}

// Multiple byte-identical republishes → adopt the DETERMINISTIC least by (g,a,v), regardless of
// the server's response order (Solr order is not a stable contract).
func TestResolveDeterministicOnMultiHit(t *testing.T) {
	sha1 := "dddddddddddddddddddddddddddddddddddddddd"
	// server returns them in a "wrong" order; we must pick jstl:jstl (least g).
	srv := stubCentral(t, map[string][]map[string]string{
		sha1: {{"g": "javax.servlet", "a": "jstl", "v": "1.2"}, {"g": "jstl", "a": "jstl", "v": "1.2"}},
	}, nil)
	defer srv.Close()
	comps := []sbom.Component{{Name: "shaded", SHA1: sha1}}
	if n := New(srv.URL, srv.Client()).Resolve(context.Background(), comps); n != 1 {
		t.Fatalf("recovered = %d, want 1", n)
	}
	if comps[0].Name != "javax.servlet:jstl" { // "javax.servlet" < "jstl"
		t.Errorf("multi-hit adopted %q, want deterministic least javax.servlet:jstl", comps[0].Name)
	}
}

// A transient failure (HTTP 500) must NOT be cached as a permanent miss – a later lookup can retry.
func TestResolveTransientNotCached(t *testing.T) {
	sha1 := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError) // first call: transient
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"docs": []map[string]string{{"g": "com.x", "a": "y", "v": "1.0"}}}})
	}))
	defer srv.Close()
	res := New(srv.URL, srv.Client())
	// first Resolve hits the 500 → no recovery, NOT cached
	if n := res.Resolve(context.Background(), []sbom.Component{{Name: "a", SHA1: sha1}}); n != 0 {
		t.Fatalf("first (500) recovered = %d, want 0", n)
	}
	// second Resolve for the same SHA-1 retries → succeeds (proves the 500 wasn't cached as a miss)
	comps := []sbom.Component{{Name: "b", SHA1: sha1}}
	if n := res.Resolve(context.Background(), comps); n != 1 {
		t.Fatalf("second recovered = %d, want 1 (transient must not be cached)", n)
	}
}

package ownadvisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// Alpine publishes one document per branch, and an advisory that affects several branches appears once per
// branch with that branch's own fixed version. The store keeps one row per advisory id, so the feed must union
// them: emitting one record per branch meant the last branch read replaced the rest, which recorded
// CVE-2024-56171 only for Alpine:v3.24 and left an Alpine 3.19 image matching nothing.
func TestRemoteSecdbFeedUnionsBranches(t *testing.T) {
	var hits int32
	doc := func(branch, fixed string) string {
		return `{"reponame":"main","distroversion":"` + branch + `",` +
			`"packages":[{"pkg":{"name":"libxml2","secfixes":{"` + fixed + `":["CVE-2024-56171"]}}}]}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.URL.Path {
		case "/v3.19/main.json":
			_, _ = w.Write([]byte(doc("v3.19", "2.11.8-r1")))
		case "/v3.24/main.json":
			_, _ = w.Write([]byte(doc("v3.24", "2.13.6-r0")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var got []advisory.Advisory
	skipped, err := NewRemoteSecdbFeed(srv.URL, srv.Client()).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("one advisory affecting two branches is one record, got %d (skipped %d)", len(got), skipped)
	}
	if len(got[0].Affected) != 2 {
		t.Fatalf("both branches must survive, got %+v", got[0].Affected)
	}
	fixes := map[string]string{}
	for _, p := range got[0].Affected {
		fixes[p.Ecosystem] = p.FixedVersion
	}
	if fixes["Alpine:v3.19"] != "2.11.8-r1" || fixes["Alpine:v3.24"] != "2.13.6-r0" {
		t.Errorf("each branch must keep its own fixed version, got %v", fixes)
	}
	// A branch that publishes nothing is skipped rather than fatal: Alpine does not publish every combination.
	if n := int(atomic.LoadInt32(&hits)); n < 4 {
		t.Errorf("the feed must probe more than the branches that answered, got %d requests", n)
	}
}

// An endpoint that answers every request with a 404 is not a secdb mirror. Reporting a successful sync that
// ingested nothing would be the silent gap this feed exists to close.
func TestRemoteSecdbFeedRefusesAnEmptyEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewRemoteSecdbFeed(srv.URL, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("an endpoint that publishes nothing must be an error, not an empty success")
	}
	if !strings.Contains(err.Error(), "no documents") {
		t.Errorf("the error must say the endpoint produced nothing, got %v", err)
	}
}

// A server error on a branch that DOES answer is fatal: a silently skipped branch is a hidden gap in coverage.
func TestRemoteSecdbFeedFailsOnAServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3.19/main.json" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewRemoteSecdbFeed(srv.URL, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a server error must be fatal, got %v", err)
	}
}

// A document larger than the cap is refused rather than read into memory.
func TestRemoteSecdbFeedBoundsADocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3.19/main.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		chunk := strings.Repeat("A", 1<<20)
		for i := 0; i < (maxSecdbFileBytes>>20)+2; i++ {
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	_, err := NewRemoteSecdbFeed(srv.URL, srv.Client()).Each(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("an oversized document must be refused, got %v", err)
	}
}

// The default base URL is Alpine's published secdb, so an operator needs no configuration for the ordinary case.
func TestRemoteSecdbFeedDefaultsToAlpine(t *testing.T) {
	if got := NewRemoteSecdbFeed("", nil).baseURL; got != defaultAlpineSecdbURL {
		t.Errorf("default base URL = %q, want %q", got, defaultAlpineSecdbURL)
	}
	if got := NewRemoteSecdbFeed("https://mirror.example.com/secdb/", nil).baseURL; got != "https://mirror.example.com/secdb" {
		t.Errorf("a trailing slash must be trimmed, got %q", got)
	}
}

// A secfixes entry lists every advisory ONE package version fixes. Two CVEs there are two vulnerabilities that
// share a fix, not one vulnerability with a second name: folding them together claims one identity for two,
// which the advisory writer refuses, and it rejected 13,597 of 16,707 Alpine advisories on that basis.
func TestParseSecdbSplitsMultipleCVEsPerFix(t *testing.T) {
	const doc = `{
  "reponame": "main",
  "distroversion": "v3.19",
  "packages": [
    {"pkg": {"name": "busybox", "secfixes": {"1.36.1-r16": ["CVE-2016-10140", "CVE-2017-5595"]}}}
  ]
}`
	advisories, err := ParseSecdb([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSecdb: %v", err)
	}
	ids := map[string]advisory.Advisory{}
	for _, a := range advisories {
		ids[a.ID] = a
	}
	for _, want := range []string{"CVE-2016-10140", "CVE-2017-5595"} {
		a, ok := ids[want]
		if !ok {
			t.Fatalf("expected %s to be its own advisory, got %d advisories", want, len(ids))
		}
		if len(a.Affected) != 1 || a.Affected[0].Package != "busybox" {
			t.Errorf("%s must carry the package the fix applies to, got %+v", want, a.Affected)
		}
		if a.Affected[0].Ecosystem != "Alpine:v3.19" {
			t.Errorf("%s must keep the branch, got %q", want, a.Affected[0].Ecosystem)
		}
		// Neither may claim the other as an alias: two CVEs are two identities.
		for _, alias := range a.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				t.Errorf("%s must not alias another CVE (%s)", want, alias)
			}
		}
	}
}

// A GHSA beside a CVE IS the same flaw in another namespace, so it stays an alias rather than becoming a
// second advisory.
func TestParseSecdbKeepsAGhsaAsAnAlias(t *testing.T) {
	const doc = `{
  "reponame": "main",
  "distroversion": "v3.19",
  "packages": [
    {"pkg": {"name": "curl", "secfixes": {"8.5.0-r0": ["CVE-2023-38545", "GHSA-7xvf-wr2c-xhwx"]}}}
  ]
}`
	advisories, err := ParseSecdb([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSecdb: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("a CVE plus its GHSA is one advisory, got %d", len(advisories))
	}
	if advisories[0].ID != "CVE-2023-38545" {
		t.Errorf("the CVE must be the identity, got %q", advisories[0].ID)
	}
	found := false
	for _, alias := range advisories[0].Aliases {
		if alias == "GHSA-7xvf-wr2c-xhwx" {
			found = true
		}
	}
	if !found {
		t.Errorf("the GHSA must stay an alias, got %v", advisories[0].Aliases)
	}
}

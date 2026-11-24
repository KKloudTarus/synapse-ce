package risk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

const (
	// urlSecret and bodySecret stand for a credential in the configured feed URL and one echoed in an error
	// page. Neither may reach the report.
	urlSecret  = "s3cr3t-in-url"
	bodySecret = "secret-in-body"

	emptyEPSS = `{"data":[]}`
)

func epssServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(emptyEPSS))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func log4shell() []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{{ID: "CVE-2021-44228", CVSSScore: 10}}
}

// A catalogue that cannot be read must be reported, never shown as "no known-exploited vulnerability".
func TestEnrichReportsAnUnreadableKEVCatalogue(t *testing.T) {
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "blocked "+bodySecret, code)
		}
	}
	body := func(s string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(s)) }
	}
	hang := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		refused bool // close the server first, so the dial fails
		client  *http.Client
		ctx     func() (context.Context, context.CancelFunc)
		want    string
	}{
		{name: "403 from the catalogue host", handler: status(http.StatusForbidden), want: "http 403"},
		{name: "429 throttled", handler: status(http.StatusTooManyRequests), want: "http 429"},
		{name: "500", handler: status(http.StatusInternalServerError), want: "http 500"},
		{name: "html page behind a 200", handler: body("<html>Access Denied " + bodySecret + "</html>"), want: "malformed response"},
		{name: "truncated JSON", handler: body(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2021-44228"`), want: "malformed response"},
		{name: "connection refused", handler: status(http.StatusOK), refused: true, want: "network error"},
		{name: "client timeout", handler: hang, client: &http.Client{Timeout: 50 * time.Millisecond}, want: "timeout"},
		{
			name: "scan deadline passed", handler: hang, want: "timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
		},
		{
			name: "scan cancelled", handler: hang, want: "canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			feed := srv.URL + "/kev.json?apikey=" + urlSecret
			if tc.refused {
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.User = url.UserPassword("ci", urlSecret)
				feed = u.String() + "/kev.json"
				srv.Close()
			}
			ctx := context.Background()
			if tc.ctx != nil {
				var cancel context.CancelFunc
				ctx, cancel = tc.ctx()
				defer cancel()
			}
			e := New(feed, epssServer(t).URL, tc.client)

			res := e.Enrich(ctx, log4shell())

			if got := res.Unavailable["kev"]; got != tc.want {
				t.Fatalf("Unavailable[kev] = %q, want %q (all: %+v)", got, tc.want, res.Unavailable)
			}
			if res.Vulns[0].KEV || res.Matches["kev"] != 0 {
				t.Errorf("an unread catalogue must not flag anything: kev=%v matches=%+v", res.Vulns[0].KEV, res.Matches)
			}
			if res.Versions["kev-catalog"] != "" {
				t.Errorf("no catalogue version may be recorded for an unread catalogue: %+v", res.Versions)
			}
			for _, secret := range []string{urlSecret, bodySecret, "127.0.0.1", "Access Denied"} {
				if strings.Contains(res.Unavailable["kev"], secret) {
					t.Errorf("cause %q leaks %q", res.Unavailable["kev"], secret)
				}
			}
		})
	}
}

// Reading the catalogue and finding nothing is a different statement from not reading it.
func TestEnrichKEVReadWithNoMatchIsNotUnavailable(t *testing.T) {
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2000-0001"}]}`))
	}))
	defer kev.Close()

	res := New(kev.URL, epssServer(t).URL, nil).Enrich(context.Background(), log4shell())

	if len(res.Unavailable) != 0 {
		t.Errorf("a catalogue that was read must not be reported unavailable: %+v", res.Unavailable)
	}
	if res.Versions["kev-catalog"] != "2026.06.20" || res.Matches["kev"] != 0 || res.Vulns[0].KEV {
		t.Errorf("catalogue read, nothing matched: versions=%+v matches=%+v kev=%v", res.Versions, res.Matches, res.Vulns[0].KEV)
	}
}

// With no CVE id to look up, the catalogue has nothing to say about any vulnerability, so an unread one is
// not worth a warning on every such scan.
func TestEnrichDoesNotReportKEVWhenThereIsNothingToCheck(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer down.Close()

	for name, vulns := range map[string][]vulnerability.Vulnerability{
		"no vulnerabilities":       nil,
		"only non-CVE identifiers": {{ID: "GHSA-aaaa-bbbb-cccc", CVSSScore: 9}},
	} {
		t.Run(name, func(t *testing.T) {
			res := New(down.URL, epssServer(t).URL, nil).Enrich(context.Background(), vulns)
			if len(res.Unavailable) != 0 {
				t.Errorf("nothing needed the catalogue, yet it was reported: %+v", res.Unavailable)
			}
		})
	}
}

// A refresh that fails after a catalogue was already loaded keeps serving it, as before; the feed was
// not "unavailable" for this scan, and its date is still recorded.
func TestEnrichKeepsAServedCatalogueWhenARefreshFails(t *testing.T) {
	healthy := true
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer kev.Close()
	e := New(kev.URL, epssServer(t).URL, nil)
	if first := e.Enrich(context.Background(), log4shell()); !first.Vulns[0].KEV {
		t.Fatal("setup: the first scan must flag the CVE")
	}

	healthy = false
	e.kevAt = time.Now().Add(-2 * kevTTL) // force a refresh
	res := e.Enrich(context.Background(), log4shell())

	if !res.Vulns[0].KEV || res.Versions["kev-catalog"] != "2026.06.20" {
		t.Errorf("the previously loaded catalogue must keep serving: kev=%v versions=%+v", res.Vulns[0].KEV, res.Versions)
	}
	if len(res.Unavailable) != 0 {
		t.Errorf("a served catalogue must not be reported unavailable: %+v", res.Unavailable)
	}
}

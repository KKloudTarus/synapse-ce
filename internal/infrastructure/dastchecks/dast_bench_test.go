package dastchecks

import (
	"net/url"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// dast_bench_test.go is the owned DAST accuracy gate (#1040). The owned DAST checks are deterministic PASSIVE
// evaluators over recorded observations (headers, cookies, artifact paths, body markers), so the corpus is a
// set of synthetic observations with a known expected finding — the issue's "deterministic expected
// observations", authorization-safe by construction (no target is contacted). Each vulnerable observation is
// shaped to trip exactly one check; clean observations must trip none. Owned recall and precision are gated.

// dastCase is one labeled observation: expectCheck is the check id that must fire, or "" for a clean case
// that must produce no finding.
type dastCase struct {
	name        string
	obs         ports.DASTObservation
	expectCheck string
}

const sts = "strict-transport-security: max-age=31536000"

// dastCorpus is the labeled observation corpus. Vulnerable cases carry the STS header (except the
// security-headers case itself) so they trip only their target check; clean cases carry a full set of secure
// headers or no headers at all.
var dastCorpus = []dastCase{
	{
		name:        "missing-security-header",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/sh", Status: 200, BodySHA256: hash64(), Headers: []string{"content-type: text/html"}},
		expectCheck: "security-headers",
	},
	{
		name:        "insecure-cookie",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/cookie", Status: 200, BodySHA256: hash64(), Headers: []string{sts, "set-cookie: sid=abc123"}},
		expectCheck: "cookie-security-flags",
	},
	{
		name:        "source-map-artifact",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/app/main.js.map", Status: 200, BodySHA256: hash64(), Headers: []string{sts}},
		expectCheck: "sensitive-public-artifact",
	},
	{
		name:        "auth-weakness-marker",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/login", Status: 200, BodySHA256: hash64(), BodyExcerpt: "config: synapse-auth-weakness enabled", Headers: []string{sts}},
		expectCheck: "auth-configured-weakness",
	},
	{
		// Alternate artifact trigger: a /.well-known/ path whose body exposes a "source" marker (not the .map path).
		name:        "well-known-artifact",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/.well-known/app", Status: 200, BodySHA256: hash64(), BodyExcerpt: "map source exposed", Headers: []string{sts}},
		expectCheck: "sensitive-public-artifact",
	},
	{
		// Alternate auth-weakness trigger: the configured header marker (not the body marker).
		name:        "auth-weakness-header",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/hdr", Status: 200, BodySHA256: hash64(), BodyExcerpt: "ok", Headers: []string{sts, "x-synapse-auth-weakness: on"}},
		expectCheck: "auth-configured-weakness",
	},
	// Clean cases: a full secure-header set (STS + a hardened cookie), and a headerless API response.
	{
		name:        "clean-secure-headers-and-cookie",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/ok", Status: 200, BodySHA256: hash64(), BodyExcerpt: "hello", Headers: []string{sts, "set-cookie: sid=abc123; Secure; HttpOnly; SameSite=Strict"}},
		expectCheck: "",
	},
	{
		name:        "clean-no-headers",
		obs:         ports.DASTObservation{Method: "GET", URL: "https://app.test/api", Status: 200, BodySHA256: hash64(), BodyExcerpt: "{}", Headers: nil},
		expectCheck: "",
	},
}

const (
	dastRecallFloor    = 1.0
	dastPrecisionFloor = 1.0
)

// TestDASTOwnedAccuracy runs the owned passive DAST evaluator over the labeled corpus and gates recall (each
// vulnerable observation trips its expected check) and precision (no clean observation trips a check, and no
// vulnerable observation trips a DIFFERENT check).
func TestDASTOwnedAccuracy(t *testing.T) {
	obs := make([]ports.DASTObservation, 0, len(dastCorpus))
	for _, c := range dastCorpus {
		obs = append(obs, c.obs)
	}
	findings, err := NewEvaluator().Evaluate(obs, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// Index findings by endpoint -> set of check ids.
	fired := map[string]map[string]bool{}
	for _, f := range findings {
		if fired[f.Endpoint] == nil {
			fired[f.Endpoint] = map[string]bool{}
		}
		fired[f.Endpoint][f.CheckID] = true
	}

	tp, fp, fn := 0, 0, 0
	for _, c := range dastCorpus {
		ep := endpointOf(t, c.obs.URL)
		got := fired[ep]
		if c.expectCheck != "" {
			if got[c.expectCheck] {
				tp++
			} else {
				fn++
				t.Errorf("%s: expected check %q to fire on %s, but it did not (fired: %v)", c.name, c.expectCheck, ep, keys(got))
			}
		}
		// Any check that fired but was not the expected one for this observation is a false positive.
		for id := range got {
			if id != c.expectCheck {
				fp++
				t.Errorf("%s: unexpected check %q fired on %s", c.name, id, ep)
			}
		}
	}
	recall, precision := dastRate(tp, fn), dastRate(tp, fp)
	t.Logf("dast owned: cases=%d tp=%d fp=%d fn=%d recall=%.3f precision=%.3f", len(dastCorpus), tp, fp, fn, recall, precision)
	if recall < dastRecallFloor {
		t.Errorf("dast recall %.3f below floor %.3f", recall, dastRecallFloor)
	}
	if precision < dastPrecisionFloor {
		t.Errorf("dast precision %.3f below floor %.3f", precision, dastPrecisionFloor)
	}
}

func dastRate(tp, other int) float64 {
	if tp+other == 0 {
		return 0
	}
	return float64(tp) / float64(tp+other)
}

func endpointOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Fragment = ""
	u.RawQuery = ""
	return u.String()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// hash64 is a valid-length placeholder body sha256 (the checks require a 64-char hash in the proof).
func hash64() string { return "0000000000000000000000000000000000000000000000000000000000000000" }

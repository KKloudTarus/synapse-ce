package dastchecks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func observed(url string, status int, captured bool, body string, headers ...string) ports.DASTObservation {
	return ports.DASTObservation{
		Method: "GET", URL: url, Status: status, BodySHA256: strings.Repeat("a", 64),
		BodyExcerpt: body, Headers: headers, HeadersCaptured: captured,
	}
}

func firedChecks(t *testing.T, o ports.DASTObservation) map[string]bool {
	t.Helper()
	findings, err := NewEvaluator().Evaluate([]ports.DASTObservation{o}, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	out := map[string]bool{}
	for _, finding := range findings {
		out[finding.CheckID] = true
		if err := NewEvaluator().VerifyProof(finding.Proof); err != nil {
			t.Fatalf("every emitted finding must carry a verifiable proof: %v", err)
		}
	}
	return out
}

// TestCookieAttributesAreParsedNotSearched is the regression for the audited false negative: the
// predicate searched the whole header, so a cookie whose value spelled an attribute name passed as
// if the attribute were set.
func TestCookieAttributesAreParsedNotSearched(t *testing.T) {
	const sts = "strict-transport-security: max-age=31536000"
	for _, tc := range []struct {
		name   string
		cookie string
		want   bool
	}{
		{"no attributes", "set-cookie: sid=abc123", true},
		{"value is the word secure, attribute absent", "set-cookie: sid=secure; httponly; samesite=strict", true},
		{"value is the word secure, attribute absent, mixed case", "set-cookie: sid=secure; HttpOnly; SameSite=Strict", true},
		{"value contains the words", "set-cookie: sid=secure-httponly-samesite=strict", true},
		{"secure cookie name cannot supply missing secure", "set-cookie: secure=abc123; HttpOnly; SameSite=Strict", true},
		{"httponly cookie name cannot supply missing httponly", "set-cookie: httponly=abc123; Secure; SameSite=Strict", true},
		{"samesite cookie name cannot supply missing samesite", "set-cookie: samesite=abc123; Secure; HttpOnly", true},
		{"secure cookie name with attributes", "set-cookie: secure=abc123; Secure; HttpOnly; SameSite=Strict", false},
		{"httponly cookie name with attributes", "set-cookie: httponly=abc123; Secure; HttpOnly; SameSite=Strict", false},
		{"samesite cookie name with attributes", "set-cookie: samesite=abc123; Secure; HttpOnly; SameSite=Strict", false},
		{"missing samesite", "set-cookie: sid=abc123; Secure; HttpOnly", true},
		{"missing httponly", "set-cookie: sid=abc123; Secure; SameSite=Lax", true},
		{"all three present", "set-cookie: sid=abc123; Secure; HttpOnly; SameSite=Strict", false},
		{"attribute order and spacing", "set-cookie: sid=abc123;SameSite=None;  secure ;HttpOnly", false},
		{"helper redacted form", "set-cookie: secure;httponly;samesite", false},
		{"helper redacted form missing secure", "set-cookie: httponly;samesite", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedChecks(t, observed("https://app.test/c", 200, true, "", sts, tc.cookie))
			if fired["cookie-security-flags"] != tc.want {
				t.Fatalf("cookie finding = %v, want %v for %q", fired["cookie-security-flags"], tc.want, tc.cookie)
			}
			findings, err := NewEvaluator().Evaluate([]ports.DASTObservation{observed("https://app.test/c", 200, true, "", sts, tc.cookie)}, []string{"cookie-security-flags"})
			if err != nil {
				t.Fatal(err)
			}
			if (len(findings) == 1) != tc.want {
				t.Fatalf("selected cookie finding count = %d, want finding %v", len(findings), tc.want)
			}
			for _, finding := range findings {
				if finding.CheckID != "cookie-security-flags" || NewEvaluator().VerifyProof(finding.Proof) != nil {
					t.Fatalf("invalid selected cookie proof: %+v", finding)
				}
			}
		})
	}
}

// TestPublicArtifactNeedsAServedResponse is the regression for the audited false positive: a .map
// path reported a published artifact even when the server answered 404.
func TestPublicArtifactNeedsAServedResponse(t *testing.T) {
	const sourceMap = `{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"served source map", 200, sourceMap, true},
		{"successful but empty", 200, "", false},
		{"no content", 204, "", false},
		{"reset content", 205, "", false},
		{"not found", 404, "not found", false},
		{"server error", 500, "", false},
		{"redirect", 302, "", false},
		{"served html error page", 200, "<!doctype html><html><body>app</body></html>", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedChecks(t, observed("https://app.test/app.js.map", tc.status, true, tc.body, "strict-transport-security: max-age=1"))
			if fired["sensitive-public-artifact"] != tc.want {
				t.Fatalf("artifact finding = %v, want %v (status %d)", fired["sensitive-public-artifact"], tc.want, tc.status)
			}
		})
	}
}

// TestMissingHeaderNeedsCapturedHeaders separates an observed missing header from evidence that was
// never collected. The second must not be reported, and must not be read as a secure response.
func TestMissingHeaderNeedsCapturedHeaders(t *testing.T) {
	captured := firedChecks(t, observed("https://app.test/a", 200, true, "", "content-type: text/html"))
	if !captured["security-headers"] {
		t.Fatalf("a captured response without HSTS must report the missing header")
	}
	capturedEmpty := firedChecks(t, observed("https://app.test/b", 200, true, ""))
	if !capturedEmpty["security-headers"] {
		t.Fatalf("a captured response that carried no header at all is still an observed missing header")
	}
	uncaptured := firedChecks(t, observed("https://app.test/c", 200, false, ""))
	if uncaptured["security-headers"] {
		t.Fatalf("an observation with no captured headers cannot claim a missing header")
	}
}

// TestProofVersionsStayVerifiable keeps stored evidence readable across the predicate correction: a
// version-1 proof verifies against its own recorded content, and a version-2 proof binds the
// capture fact so it cannot be flipped after sealing.
func TestProofVersionsStayVerifiable(t *testing.T) {
	evaluator := NewEvaluator()
	legacy := newVersionedFinding(1, "security-headers", "https://app.test/legacy",
		ports.DASTObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("a", 64)},
		"missing:strict-transport-security", nil)

	current := newFinding("security-headers", "https://app.test/current",
		ports.DASTObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("b", 64), HeadersCaptured: true},
		"missing:strict-transport-security", nil)
	for _, proof := range []ports.DASTProof{legacy.Proof, current.Proof} {
		sealed, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		var restored ports.DASTProof
		if err := json.Unmarshal(sealed, &restored); err != nil {
			t.Fatal(err)
		}
		if err := evaluator.VerifyProof(restored); err != nil {
			t.Fatalf("stored version-%d proof must remain verifiable after JSON decoding: %v", proof.Version, err)
		}
	}
	tampered := current.Proof
	tampered.Observation.HeadersCaptured = false
	if err := evaluator.VerifyProof(tampered); err == nil {
		t.Fatalf("flipping the capture fact after sealing must fail verification")
	}
	unserved := newFinding("sensitive-public-artifact", "https://app.test/x.js.map",
		ports.DASTObservation{Method: "GET", Status: 404, BodySHA256: strings.Repeat("c", 64), HeadersCaptured: true},
		"public_artifact", nil, "source_map_path")
	if err := evaluator.VerifyProof(unserved.Proof); err == nil {
		t.Fatalf("a current artifact proof recording an unserved response must fail verification")
	}
}

// A well-known path that was NOT served is not a published artifact. Emitting the finding anyway produced
// a version-2 proof the verifier rejects as recording an unserved response, and the consumer treats an
// unverifiable proof as a fatal error after the approved action has already been spent. firedChecks
// verifies every emitted proof, so this case also guards the emitter against drifting from the verifier.
func TestWellKnownArtifactRequiresAServedResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    ports.DASTObservation
		want bool
	}{
		{"private body, not found", observed("https://app.test/.well-known/private", 404, true, "private"), false},
		{"private body, served", observed("https://app.test/.well-known/private", 200, true, "private"), true},
		{"source body, not found", observed("https://app.test/.well-known/source", 404, true, "source"), false},
		{"source body, served", observed("https://app.test/.well-known/source", 200, true, "source"), true},
		{"private body, gone", observed("https://app.test/.well-known/private", 410, true, "private"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firedChecks(t, tc.o)["sensitive-public-artifact"]; got != tc.want {
				t.Fatalf("public-artifact reported=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestArtifactProofRequiresNonemptyServedContent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		status  int
		hash    string
		valid   bool
	}{
		{"served current proof", proofVersion, 200, strings.Repeat("a", 64), true},
		{"empty current proof", proofVersion, 200, emptyBodySHA256, false},
		{"uppercase empty digest", proofVersion, 200, strings.ToUpper(emptyBodySHA256), false},
		{"no-content current proof", proofVersion, 204, strings.Repeat("a", 64), false},
		{"reset-content current proof", proofVersion, 205, strings.Repeat("a", 64), false},
		{"legacy proof retains recorded contract", 1, 200, emptyBodySHA256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finding := newVersionedFinding(tc.version, "sensitive-public-artifact", "https://app.test/app.js.map",
				ports.DASTObservation{Method: "GET", Status: tc.status, BodySHA256: tc.hash, HeadersCaptured: true},
				"public_artifact", nil, "source_map_path")
			if err := NewEvaluator().VerifyProof(finding.Proof); (err == nil) != tc.valid {
				t.Fatalf("proof validity=%v want=%v: %v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestConfiguredAuthMarkerRequiresExactHeaderName(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{"X-Synapse-Auth-Weakness", true},
		{"x-synapse-auth-weakness: configured", true},
		{"X-Synapse-Auth-Weakness-Other: configured", false},
		{"X-Other: x-synapse-auth-weakness", false},
	} {
		t.Run(tc.header, func(t *testing.T) {
			fired := firedChecks(t, observed("https://app.test/login", 200, true, "", tc.header))
			if fired["auth-configured-weakness"] != tc.want {
				t.Fatalf("header %q configured weakness=%v want=%v", tc.header, fired["auth-configured-weakness"], tc.want)
			}
		})
	}
}

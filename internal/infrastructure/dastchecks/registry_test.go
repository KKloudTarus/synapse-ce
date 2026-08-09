package dastchecks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastcheck"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCatalogParity(t *testing.T) {
	if err := dastcheck.ValidateParity(dastcheck.Catalog, checks); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateVulnerableAndCleanFixtures(t *testing.T) {
	vulnerable := ports.DASTObservation{Method: "GET", URL: "https://app.example/.well-known/private", Status: 200, BodySHA256: strings.Repeat("a", 64), BodyExcerpt: "private synapse-auth-weakness", Headers: []string{"Set-Cookie: Secure", "X-Synapse-Auth-Weakness: configured"}}
	evaluator := NewEvaluator()
	findings, err := evaluator.Evaluate([]ports.DASTObservation{vulnerable}, nil)
	if err != nil || len(findings) != 4 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	for _, finding := range findings {
		if err := evaluator.VerifyProof(finding.Proof); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(finding.Proof)
		text := string(raw)
		for _, forbidden := range []string{"Authorization", "Cookie:", "Set-Cookie:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("proof leaked %q: %s", forbidden, text)
			}
		}
	}
	clean := ports.DASTObservation{Method: "GET", URL: "https://app.example/", Status: 200, BodySHA256: strings.Repeat("b", 64), Headers: []string{"Strict-Transport-Security: max-age=1", "Set-Cookie: Secure; HttpOnly; SameSite=Lax"}}
	findings, err = evaluator.Evaluate([]ports.DASTObservation{clean}, nil)
	if err != nil || len(findings) != 0 {
		t.Fatalf("clean findings=%+v err=%v", findings, err)
	}
}

func TestVerifyProofRejectsPredicateMismatch(t *testing.T) {
	evaluator := NewEvaluator()
	for name, finding := range map[string]ports.DASTFinding{
		"check signature": newFinding("security-headers", "https://app.example/", ports.DASTObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("a", 64)}, "configured_auth_weakness", nil),
		"artifact path":   newFinding("sensitive-public-artifact", "https://app.example/public.txt", ports.DASTObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("b", 64)}, "public_artifact", nil, "source_map_path"),
		"auth token":      newFinding("auth-configured-weakness", "https://app.example/", ports.DASTObservation{Method: "GET", Status: 200, BodySHA256: strings.Repeat("c", 64)}, "configured_auth_weakness", nil, "body:private"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := evaluator.VerifyProof(finding.Proof); err == nil {
				t.Fatal("hash-valid proof with a mismatched check predicate was accepted")
			}
		})
	}
}

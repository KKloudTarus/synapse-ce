package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestRunUsesIndependentVerifierTransportAndIdentity(t *testing.T) {
	var proposerCalls, verifierCalls int32
	provider := func(key string, calls *int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer "+key {
				t.Errorf("authorization = %q, want credential for this provider", got)
			}
			atomic.AddInt32(calls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"sound\",\"driver\":\"attacker_controlled\",\"confidence\":90}"},"finish_reason":"stop"}],"usage":{}}`))
		}))
	}
	proposer := provider("proposer-key", &proposerCalls)
	defer proposer.Close()
	verifier := provider("verifier-key", &verifierCalls)
	defer verifier.Close()

	t.Setenv("SYNAPSE_LLM_BASE_URL", proposer.URL)
	t.Setenv("SYNAPSE_LLM_API_KEY", "proposer-key")
	t.Setenv("SYNAPSE_FP_TRIAGE_PROVIDER", "openai")
	t.Setenv("SYNAPSE_FP_TRIAGE_MODEL", "gpt-4o")
	t.Setenv("SYNAPSE_VERIFIER_BASE_URL", verifier.URL)
	t.Setenv("SYNAPSE_VERIFIER_API_KEY", "verifier-key")
	t.Setenv("SYNAPSE_VERIFIER_PROVIDER", "anthropic")
	t.Setenv("SYNAPSE_VERIFIER_MODEL", "claude-sonnet-4")
	t.Setenv("SYNAPSE_FP_TRIAGE_INDEPENDENCE", "provider")
	t.Setenv("SYNAPSE_LLM_TIMEOUT", "5s")

	output := filepath.Join(t.TempDir(), "report.json")
	dataset := filepath.Join("..", "..", "internal", "usecase", "sca", "testdata", "fptriage-golden-v2.json")
	if err := run(context.Background(), dataset, output); err != nil {
		t.Fatalf("run: %v", err)
	}
	if atomic.LoadInt32(&proposerCalls) == 0 || atomic.LoadInt32(&verifierCalls) == 0 {
		t.Fatalf("both independent transports must be called: proposer=%d verifier=%d", proposerCalls, verifierCalls)
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report sca.AIEvaluationReport
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.SchemaVersion != "synapse-ai-triage-evaluation-v3" || report.Robustness.Metrics.TotalPairs == 0 ||
		report.Run.ProposerProvider != "openai" || report.Run.VerifierProvider != "anthropic" ||
		report.Run.IndependencePolicy != "provider" {
		t.Fatalf("independence metadata missing from report: %+v", report.Run)
	}
}

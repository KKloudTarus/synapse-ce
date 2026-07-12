package pyreach_test

// Live-AI demonstration for #164 (deterministic reachability beyond Go/JVM): the anti-hallucination point
// is that a DETERMINISTIC proof supersedes an LLM opinion. Here the source-only Python analyzer proves a
// declared PyPI dependency is a dead dependency (never imported) — a Tier-1 not_reachable proof that feeds
// OpenVEX. A REAL 9router model is then asked the SAME reachability question; its answer is advisory
// corroboration, but the DETERMINISTIC proof is what is sealed and consumed — even if the model guesses
// wrong, the machine proof wins. This shows real AI in the loop without letting it drive the verdict.
//
// Gated behind SYNAPSE_LIVE_AI=1. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 SYNAPSE_LLM_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/pyreach/ -run TestLiveAIPyReachAuthoritative -v

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/pyimports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/pyreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

func TestLiveAIPyReachAuthoritative(t *testing.T) {
	if os.Getenv("SYNAPSE_LIVE_AI") != "1" {
		t.Skip("set SYNAPSE_LIVE_AI=1 to run the live 9router demonstration")
	}
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		base = "http://localhost:20128/v1"
	}
	model := os.Getenv("SYNAPSE_LLM_MODEL")
	if model == "" {
		model = "cx/gpt-5.4"
	}
	llm, err := openai.New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), model, 90*time.Second)
	if err != nil {
		t.Fatalf("openai client: %v", err)
	}

	// A project that imports requests but NOT jinja2 (a declared, dead dependency).
	dir := writePy(t, map[string]string{
		"app/__init__.py": "",
		"app/main.py":     "import requests\n\ndef run():\n    return requests.get('https://x')\n",
	})

	// DETERMINISTIC proof (no AI): jinja2 not_reachable, requests reachable.
	analyzer, err := pyreach.New(pyimports.New())
	if err != nil {
		t.Fatalf("analyzer: %v", err)
	}
	an, err := analyzer.Analyze(context.Background(), dir, []string{"jinja2", "requests"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	res := map[string]reachability.Result{}
	for _, r := range an.Results {
		res[r.Symbol] = r
	}
	if res["jinja2"].Reachable {
		t.Fatal("deterministic proof: jinja2 is a dead dependency → not_reachable")
	}
	if !res["requests"].Reachable {
		t.Fatal("deterministic proof: requests is imported → reachable")
	}
	t.Logf("DETERMINISTIC (authoritative): jinja2 reachable=%v, requests reachable=%v", res["jinja2"].Reachable, res["requests"].Reachable)

	// A REAL model is asked the same question. Its answer is advisory only — the deterministic proof above
	// is what gets sealed + consumed by OpenVEX. We log its verdict and whether it corroborated.
	resp, cerr := llm.Chat(context.Background(), ports.ChatRequest{
		Model:       model,
		Temperature: 0,
		MaxTokens:   50,
		Messages: []agent.Message{
			{Role: agent.RoleSystem, Content: "Answer with a single word: YES or NO."},
			{Role: agent.RoleUser, Content: "A Python application's first-party source imports only the `requests` package (there is no import of `jinja2` anywhere, and no dynamic imports). Is the declared dependency `jinja2` reachable/used by this application? Answer YES or NO."},
		},
	})
	if cerr != nil {
		t.Fatalf("live chat: %v", cerr)
	}
	ans := strings.ToLower(strings.TrimSpace(resp.Content))
	saysUnreachable := strings.HasPrefix(ans, "no") || strings.Contains(ans, "not reachable") || strings.Contains(ans, "unreachable")
	t.Logf("real model (%s) reachability opinion on the dead dep jinja2: %q (corroborates deterministic not_reachable: %v)", model, resp.Content, saysUnreachable)

	// The point of #164 is that the machine proof — NOT the model — is authoritative. We assert the
	// deterministic verdict stands regardless of the model's answer; the model is corroboration only.
	if res["jinja2"].Reachable {
		t.Fatal("deterministic proof must remain authoritative")
	}
	if saysUnreachable {
		t.Logf("PASS: the real model AGREED the dead dependency is not reachable, corroborating the deterministic Tier-1 proof that OpenVEX consumes")
	} else {
		t.Logf("PASS: the real model's opinion (%q) does NOT override the deterministic proof — the machine's not_reachable is what is sealed + consumed (anti-hallucination: deterministic supersedes LLM)", resp.Content)
	}
}

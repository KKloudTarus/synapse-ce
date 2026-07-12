package agenttools

// Live-AI demonstration for #161 (durable/inline agent toolset parity): the synapse-worker durable agent
// now advertises the SAME full tool catalog as the inline synapse-api agent — both wire it through the one
// shared helper EnableAgentToolset. This drives a REAL 9router model against that full catalog and proves
// a tool the worker PREVIOUSLY LACKED (propose_critique, a judgment tool) is both offered to AND used by
// the model, then dispatches the model's own call end-to-end (recording a PROPOSED judgment at score 0 —
// never a confirmation; the agent stays propose-only).
//
// Gated behind SYNAPSE_LIVE_AI=1 so the normal suite stays hermetic. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 SYNAPSE_LLM_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/agenttools/ -run TestLiveAIWorkerToolsetParity -v

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// newOnWorker is the set of tools the durable worker did NOT advertise before #161 (it enabled only
// planning + finding proposals). The parity fix means a real model driven durably can now reach these.
var newOnWorker = map[string]bool{
	ToolProposeAttackChain:      true,
	ToolReachabilityContext:     true,
	ToolProposeReachability:     true,
	ToolProposeSASTValidation:   true,
	ToolProposeCritique:         true,
	ToolProposeRiskNarrative:    true,
	ToolProposeThreat:           true,
	ToolProposeVexJustification: true,
	ToolProposeWriteupDraft:     true,
}

func TestLiveAIWorkerToolsetParity(t *testing.T) {
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

	// Build the durable worker's catalog EXACTLY as cmd/synapse-worker now does: through the shared helper.
	c, _ := newCatalog(t, nil, nil)
	if terr := c.EnableAgentToolset(fullToolset()); terr != nil {
		t.Fatalf("EnableAgentToolset: %v", terr)
	}
	if !toolNames(c)[ToolProposeCritique] {
		t.Fatal("catalog is missing propose_critique — the parity tool under test")
	}

	resp, err := llm.Chat(context.Background(), ports.ChatRequest{
		Model: model,
		Tools: c.Tools(), // the FULL catalog, identical to the inline API agent's
		Messages: []agent.Message{
			{Role: agent.RoleSystem, Content: "You are an AppSec agent reviewing findings for the current engagement. When you judge a finding is likely a false positive, RECORD your adversarial critique using the available tool. Use a structured driver token (e.g. not_reachable), never prose."},
			{Role: agent.RoleUser, Content: "Finding manual:1 is a reported SQL injection, but the vulnerable sink sits on a code path that is never reachable from any request handler. Record your critique."},
		},
	})
	if err != nil {
		t.Fatalf("live chat: %v", err)
	}
	t.Logf("finish=%s tool_calls=%d content=%q", resp.FinishReason, len(resp.ToolCalls), resp.Content)
	if len(resp.ToolCalls) == 0 {
		t.Fatalf("model proposed no tool call against the full catalog; content=%q", resp.Content)
	}

	// The model must have reached for a tool the durable worker GAINED in #161 (not one it already had).
	var picked *agent.ToolCall
	for i := range resp.ToolCalls {
		if newOnWorker[resp.ToolCalls[i].Name] {
			picked = &resp.ToolCalls[i]
			break
		}
	}
	if picked == nil {
		t.Fatalf("model used no parity-gained tool; proposed %v (worker previously advertised only planning + finding proposals)", toolCallNames(resp.ToolCalls))
	}
	t.Logf("model proposed parity-gained tool %q args=%s", picked.Name, string(picked.Arguments))

	// Dispatch the model's own call through the durable catalog — proving the parity tool is not merely
	// advertised but usable end-to-end. A judgment propose tool records a PROPOSED judgment at score 0.
	res, err := c.Dispatch(context.Background(), session(), *picked)
	if err != nil {
		t.Fatalf("dispatch %q: %v", picked.Name, err)
	}
	if res.Data == nil && res.Proposal == nil && res.Plan == nil {
		t.Fatalf("dispatch of %q returned an empty result", picked.Name)
	}
	t.Logf("PASS: durable/inline toolset parity — a real model used the worker's parity-gained tool %q and it dispatched: data=%s", picked.Name, string(res.Data))
}

func toolCallNames(cs []agent.ToolCall) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

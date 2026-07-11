package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// captureProposer records that the agent's propose_critique tool reached the judgment proposer (the
// Propose-only seam – the agent can never verify/confirm).
type captureProposer struct {
	called  bool
	cap     judgment.Capability
	subject shared.ID
}

func (p *captureProposer) Propose(_ context.Context, _ string, _ shared.ID, c judgment.Capability, sk judgment.SubjectKind, sid shared.ID, _ judgment.Claim) (judgment.Judgment, error) {
	p.called, p.cap, p.subject = true, c, sid
	return judgment.Judgment{ID: "j1", Capability: c, SubjectKind: sk, SubjectID: sid, State: judgment.StateProposed}, nil
}

// TestAgentReachesSessionBuiltTool is the end-to-end proof that the AI is actually CALLED against the
// analysis-brain tools built this session: the LLM (a scripted fake) is OFFERED propose_critique in the
// ChatRequest.Tools, proposes a call, and the orchestrator DISPATCHES it into the judgment proposer. So
// the tool is not orphaned – the agent loop (llm.Chat → tool-call → catalog dispatch) reaches it.
func TestAgentReachesSessionBuiltTool(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}

	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clock, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := agenttools.New(emptyFindings{}, emptyEvidence{}, []ports.ReconTool{fakeRecon{}}, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	prop := &captureProposer{}
	cat.EnableJudgments(prop) // turns on propose_critique (+ the other propose tools)

	// The LLM proposes propose_critique on its first turn; then (out of script) it answers "done".
	llm := &scriptLLM{steps: []ports.ChatResponse{{
		ToolCalls:    []agent.ToolCall{toolCall("c1", agenttools.ToolProposeCritique, `{"subject_id":"f1","verdict":"refuted","driver":"version_mismatch"}`)},
		FinishReason: "tool_calls",
		Usage:        agent.Usage{TotalTokens: 10},
	}}}

	orch, err := orchestrator.New(llm, cat, gate, &fakeExecutor{}, ev, memory.NewAgentSessionStore(), apprStore, audit, clock, ids, orchestrator.Config{Model: "m", MaxSteps: 6})
	if err != nil {
		t.Fatal(err)
	}
	// Run = Start + drive the agent loop synchronously (the loop is what calls llm.Chat + dispatches).
	if _, err := orch.Run(context.Background(), "eng-1", "alice", "critique finding f1"); err != nil {
		t.Fatalf("run: %v", err)
	}

	// (1) the agent ADVERTISED propose_critique to the LLM (it's in the ChatRequest.Tools)
	if len(llm.reqs) == 0 {
		t.Fatal("the LLM was never called – the AI path did not run")
	}
	var advertised bool
	for _, ts := range llm.reqs[0].Tools {
		if ts.Name == agenttools.ToolProposeCritique {
			advertised = true
		}
	}
	if !advertised {
		t.Fatalf("propose_critique was not advertised to the LLM; tools = %v", toolNames(llm.reqs[0].Tools))
	}
	// (2) the orchestrator DISPATCHED the LLM's proposed call into the proposer (the tool is reached)
	if !prop.called || prop.cap != judgment.CapCritique || prop.subject != "f1" {
		t.Fatalf("propose_critique was advertised but not dispatched to the proposer: %+v", prop)
	}
}

func toolNames(ts []agent.ToolSchema) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}

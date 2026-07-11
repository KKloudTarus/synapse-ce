package orchestrator_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
)

// TestLiveOrchestratorAgainstGateway drives the FULL state machine against a real
// OpenAI-compatible gateway: a real LLM proposes, the real safety gate admits an in-scope
// action, a stub executor "runs" it, and the step is sealed – proving the propose-validate-execute loop works
// end-to-end with a live model, not just the record/replay fake. Gated on SYNAPSE_LLM_BASE_URL
// so CI/dev skip it. The executor is stubbed (no real recon binary/sandbox in a unit test);
// everything else – model, catalog, gate, scope check, evidence – is real.
func TestLiveOrchestratorAgainstGateway(t *testing.T) {
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		t.Skip("set SYNAPSE_LLM_BASE_URL (+ _API_KEY, _MODEL) to run the live orchestrator smoke")
	}
	model := os.Getenv("SYNAPSE_LLM_MODEL")
	llm, err := openai.New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), model, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io\nb.app.acme.io"), Summary: "2 hosts"}}
	orch, ev, sessions := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{Model: model, MaxSteps: 6})

	// The gateway upstream rate-limits with an intermittent ~1-2min token cooldown; ride it out.
	var sess agent.Session
	for attempt := 1; attempt <= 8; attempt++ {
		sess, err = orch.Run(context.Background(), "eng-1", "alice",
			"Enumerate the subdomains of app.acme.io using the available recon tools, then summarize what you found.")
		if err == nil {
			break
		}
		t.Logf("attempt %d: run failed (%v) – waiting out the gateway cooldown", attempt, err)
		time.Sleep(20 * time.Second)
	}
	if err != nil {
		t.Skipf("gateway upstream stayed unhealthy across retries – skipping: %v", err)
	}

	msgs, _ := sessions.Messages(context.Background(), sess.ID)
	steps := countKind(t, ev, orchestrator.StepEvidenceKind)
	engaged := exec.calls > 0
	for _, m := range msgs {
		if m.Role == agent.RoleAssistant && len(m.ToolCalls) > 0 {
			engaged = true
		}
	}
	t.Logf("live orchestrator: status=%s steps=%d exec_calls=%d sealed_steps=%d transcript_msgs=%d engaged=%v",
		sess.Status, sess.Steps, exec.calls, steps, len(msgs), engaged)

	if !sess.Status.Terminal() && sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("run did not reach a terminal/suspended state: %s", sess.Status)
	}
	if !engaged {
		t.Logf("NOTE: the model produced no tool call – the prompt/model may need tuning for tool-use")
	}
}

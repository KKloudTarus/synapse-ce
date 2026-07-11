package orchestrator_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
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

// multiEngRepo returns an in-scope engagement for ANY requested id (every engagement shares the
// app.acme.io scope + an open window + live recon) – so the load harness can drive many distinct
// engagement chains through the real gate.
type multiEngRepo struct{ now time.Time }

func (r *multiEngRepo) GetByID(_ context.Context, id shared.ID) (*engagement.Engagement, error) {
	e, _ := engagement.New(id, "", "load", "load", r.now)
	from, to := r.now.Add(-time.Hour), r.now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", r.now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	e.SetLiveRecon(true, r.now)
	return e, nil
}
func (r *multiEngRepo) GetByIDInTenant(ctx context.Context, _ shared.ID, id shared.ID) (*engagement.Engagement, error) {
	return r.GetByID(ctx, id)
}
func (r *multiEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (r *multiEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (r *multiEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (r *multiEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

// atomicExecutor counts executions race-free (the load test drives many concurrent sessions).
type atomicExecutor struct{ n int64 }

func (e *atomicExecutor) Execute(_ context.Context, _ safety.AdmittedAction) (orchestrator.Observation, error) {
	atomic.AddInt64(&e.n, 1)
	return orchestrator.Observation{Output: []byte("a.app.acme.io"), Summary: "1 host"}, nil
}

// TestLoad_ManyWorkflowsNoDoubleExecChainIntact is the PR8 load proof (a CI-runnable scaled-down
// stand-in for the 100-engagement/1000-workflow target): it drives nWorkflows one-step agent
// sessions across nEngagements concurrently (bounded), and asserts the SLOs that matter for
// correctness-at-scale: every session reaches a terminal status, the executor ran EXACTLY once
// per session (no double-run, no drop), and EVERY engagement's evidence chain stays intact.
func TestLoad_ManyWorkflowsNoDoubleExecChainIntact(t *testing.T) {
	const (
		nEngagements = 50
		perEng       = 20 // 50 × 20 = 1000 workflows
		concurrency  = 16
	)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	engRepo := &multiEngRepo{now: now}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := execution.NewGuard(engRepo, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clock, agent.ModeAuto, time.Minute)
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
	exec := &atomicExecutor{}
	orch, err := orchestrator.New(&loadLLM{}, cat, gate, exec, ev, memory.NewAgentSessionStore(), apprStore, audit, clock, ids, orchestrator.Config{Model: "m", MaxSteps: 6})
	if err != nil {
		t.Fatal(err)
	}

	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, concurrency)
		terminal int64
		failures = make(chan string, nEngagements*perEng)
	)
	for e := 0; e < nEngagements; e++ {
		engID := shared.ID(fmt.Sprintf("eng-%03d", e))
		for w := 0; w < perEng; w++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(engID shared.ID) {
				defer wg.Done()
				defer func() { <-sem }()
				sess, rerr := orch.Run(ctx, engID, "alice", "enumerate app.acme.io")
				if rerr != nil {
					failures <- fmt.Sprintf("%s: %v", engID, rerr)
					return
				}
				if sess.Status.Terminal() {
					atomic.AddInt64(&terminal, 1)
				} else {
					failures <- fmt.Sprintf("%s: non-terminal status %s", engID, sess.Status)
				}
			}(engID)
		}
	}
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Errorf("workflow failed: %s", f)
	}

	total := int64(nEngagements * perEng)
	if terminal != total {
		t.Fatalf("only %d/%d workflows reached terminal", terminal, total)
	}
	// SLO: exactly one execution per workflow – no double-run, no dropped run, under concurrency.
	if got := atomic.LoadInt64(&exec.n); got != total {
		t.Fatalf("executor ran %d times, want exactly %d (no double-run / no drop)", got, total)
	}
	// SLO: every engagement's hash chain is intact (concurrent seals stayed linear).
	for e := 0; e < nEngagements; e++ {
		engID := shared.ID(fmt.Sprintf("eng-%03d", e))
		items, lerr := ev.List(ctx, engID)
		if lerr != nil {
			t.Fatal(lerr)
		}
		if err := evdom.VerifyChain(items); err != nil {
			t.Fatalf("engagement %s chain broken under load: %v", engID, err)
		}
	}
}

// loadLLM is a stateless replay LLM: it proposes one in-scope recon then stops. Unlike scriptLLM
// it has no per-instance step cursor, so a single shared instance drives many concurrent sessions
// deterministically (turn 0 of every session = the recon proposal; any later turn = stop). It
// keys off whether the transcript already contains a tool result.
type loadLLM struct{}

func (loadLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	for _, m := range req.Messages {
		if m.Role == agent.RoleTool { // the recon already ran → produce the final answer
			return ports.ChatResponse{Content: "done", FinishReason: "stop", Usage: agent.Usage{TotalTokens: 5}}, nil
		}
	}
	return chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enumerate"}`)), nil
}

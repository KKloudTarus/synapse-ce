package httpapi

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// seedEngmiscAgent replaces the harness's empty agent stores with ones that hold tenantA's session.
// The in-memory session, plan, decision and approval stores key their rows by engagement and session
// and do not filter by tenant, so the only thing that keeps tenantB away from them is the tenant
// guard on the route. That is exactly the property the sweep needs a served row to prove.
//
// The session is terminal so the stream route writes its transcript and its closing event and
// returns, instead of polling until the stream ceiling.
func seedEngmiscAgent(w *harnessWorld) {
	ctx := engmiscTenantCtx()
	sessions := memory.NewAgentSessionStore()
	approvals := memory.NewApprovalStore()
	plans := memory.NewPlanStore()
	decisions := memory.NewDecisionStore()

	session := agent.Session{
		ID: engmiscSession, TenantID: "tenantA", EngagementID: engmiscEngagement,
		InitiatedBy: "operator", Goal: "review " + engmiscMarker, Model: "model-a", Status: agent.StatusSucceeded,
		Steps: 1, TokensUsed: 10, TokenBudgetMax: 100, CreatedAt: engmiscNow, UpdatedAt: engmiscNow,
	}
	if err := sessions.SaveSession(ctx, session); err != nil {
		w.t.Fatalf("seed agent session: %v", err)
	}
	if err := sessions.AppendMessage(ctx, session.ID, 0, agent.Message{Role: agent.RoleUser, Content: "transcript " + engmiscMarker}); err != nil {
		w.t.Fatalf("seed agent transcript: %v", err)
	}

	action := agent.ProposedAction{
		ID: "engmisc-approval", SessionID: session.ID, EngagementID: engmiscEngagement,
		Tool: "start_recon", Action: "recon.httpx", Target: engdom.Target{Kind: engdom.TargetDomain, Value: "example.test"},
		Argv: []string{"httpx", "example.test"}, EgressPreview: []string{"example.test"},
		Risk: agent.RiskRead, Rationale: "approve " + engmiscMarker, ProposedAt: engmiscNow,
	}
	if err := approvals.Enqueue(ctx, action); err != nil {
		w.t.Fatalf("seed agent approval: %v", err)
	}

	plan, err := agent.NewPlan("engmisc-plan", session.ID, engmiscEngagement, "plan "+engmiscMarker, []agent.PlanNode{
		{ID: "n1", Tool: "start_recon", Target: "example.test", Risk: agent.RiskRead, Rationale: engmiscMarker},
	}, engmiscNow)
	if err != nil {
		w.t.Fatalf("build agent plan: %v", err)
	}
	if err := plans.CreatePlan(ctx, plan); err != nil {
		w.t.Fatalf("seed agent plan: %v", err)
	}

	decision, err := agent.NewStopDecision(session.ID, engmiscEngagement, agent.StopGoalReached, "stopped "+engmiscMarker, session.AgentActor(), engmiscNow)
	if err != nil {
		w.t.Fatalf("build agent decision: %v", err)
	}
	if err := decisions.AppendDecision(ctx, decision); err != nil {
		w.t.Fatalf("seed agent decision: %v", err)
	}

	// EnableAgent is called again on purpose: the later call replaces the harness's agent wiring, and
	// the plan and decision stores hang off it, so they are set after it.
	w.rt.EnableAgent(nil, sessions, nil, approvals, nil, 1, 8)
	w.rt.SetAgentPlanStore(plans)
	w.rt.SetAgentDecisionStore(decisions)
}

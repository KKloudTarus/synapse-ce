package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestAgentDecisionStore_AppendIdempotentSeq exercises the durable decision log: monotonic seq,
// idempotent step (by action id) + single stop per session. Gated on SYNAPSE_TEST_DB_DSN.
func TestAgentDecisionStore_AppendIdempotentSeq(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	// The repositories run every statement through WithTenant, which refuses an unbound tenant so a
	// query can never silently escape RLS. Fixtures must therefore state the tenant they act as,
	// exactly like the HTTP middleware and the worker do.
	ctx = shared.WithTenant(ctx, "default")
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	stamp := time.Now().Format("150405.000000")
	eid := "eng-dec-" + stamp
	sid := "sess-dec-" + stamp
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name, status, created_at, updated_at) VALUES ($1,'default','dec','draft',now(),now())`, eid); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_sessions (id, tenant_id, engagement_id, initiated_by, goal) VALUES ($1,'default',$2,'op','g')`, sid, eid); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	st := NewAgentDecisionStore(pool)
	step := func(actionID string) agent.AgentDecision {
		d, _ := agent.NewStepDecision(shared.ID(sid), shared.ID(eid), agent.OutcomeExecuted, shared.ID(actionID), "start_recon", "recon.subfinder", "app.acme.io", agent.RiskActive, "auto", agent.AgentReason{WhyTool: "x"}, agent.AgentEvidenceRefs{StepHash: "h"}, "agent:"+sid, time.Now().UTC())
		return d
	}
	for _, a := range []string{"a1", "a2", "a1"} { // a1 twice → idempotent
		if err := st.AppendDecision(ctx, step(a)); err != nil {
			t.Fatal(err)
		}
	}
	stop, _ := agent.NewStopDecision(shared.ID(sid), shared.ID(eid), agent.StopGoalReached, "done", "agent:"+sid, time.Now().UTC())
	if err := st.AppendDecision(ctx, stop); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendDecision(ctx, stop); err != nil { // second stop → idempotent
		t.Fatal(err)
	}

	got, err := st.ListBySession(ctx, shared.ID(sid))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 decisions (a1,a2,stop dedup'd), got %d", len(got))
	}
	for i, d := range got {
		if d.Seq != i {
			t.Fatalf("decision[%d].seq=%d, want %d (monotonic)", i, d.Seq, i)
		}
	}
}

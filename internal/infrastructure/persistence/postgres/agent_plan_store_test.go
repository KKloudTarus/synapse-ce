package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestAgentPlanStore_CreateThenCAS exercises the durable plan store: create (one per session),
// get, SavePlan revision CAS, and stale-revision → ErrConflict. Gated on SYNAPSE_TEST_DB_DSN.
// It seeds an engagement + session first (FKs). Mirrors the other pg-gated store tests.
func TestAgentPlanStore_CreateThenCAS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	// The repositories run every statement through WithTenant, which refuses an unbound tenant so a
	// query can never silently escape RLS. Fixtures must therefore state the tenant they act as,
	// exactly like the HTTP middleware and the worker do.
	ctx = shared.WithTenant(ctx, "default")
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// Seed FKs: an engagement + an agent session (unique ids per run to avoid collisions).
	eid := "eng-plan-" + shared.ID(time.Now().Format("150405.000000")).String()
	sid := "sess-plan-" + shared.ID(time.Now().Format("150405.000000")).String()
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name, status, created_at, updated_at) VALUES ($1,'default','plan-test','draft',now(),now())`, eid); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_sessions (id, tenant_id, engagement_id, initiated_by, goal) VALUES ($1,'default',$2,'op','g')`, sid, eid); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	st := NewAgentPlanStore(pool)
	nodes := []agent.PlanNode{{ID: "a", Tool: "subfinder", Target: "example.com", ActionID: "act-a", Risk: agent.RiskActive}}
	p, err := agent.NewPlan(shared.ID("plan-"+sid), shared.ID(sid), shared.ID(eid), "goal", nodes, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	if err := st.CreatePlan(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreatePlan(ctx, p); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate session create must conflict, got %v", err)
	}

	got, found, err := st.GetBySession(ctx, shared.ID(sid))
	if err != nil || !found || got.Revision != 1 || len(got.Nodes) != 1 {
		t.Fatalf("get: found=%v rev=%d nodes=%d err=%v", found, got.Revision, len(got.Nodes), err)
	}

	_ = got.SetNodeStatus("a", agent.NodeDone, "")
	if err := st.SavePlan(ctx, got); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, _, _ := st.GetBySession(ctx, shared.ID(sid))
	if reloaded.Revision != 2 {
		t.Fatalf("revision after save = %d, want 2", reloaded.Revision)
	}
	if n, _ := reloaded.Node("a"); n.Status != agent.NodeDone {
		t.Fatal("node status change not persisted")
	}
	// Stale revision (got is still at rev 1) → conflict.
	if err := st.SavePlan(ctx, got); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale-revision save must conflict, got %v", err)
	}
}

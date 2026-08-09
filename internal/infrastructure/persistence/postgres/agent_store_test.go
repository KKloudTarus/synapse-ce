package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPostgresAgentStores(t *testing.T) {
	dsn := testDSN(t)
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	_, _ = pool.Exec(ctx, "TRUNCATE agent_messages, agent_sessions, agent_approvals CASCADE")
	_, _ = pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ('engA','default','t') ON CONFLICT (id) DO NOTHING`)

	ss := NewAgentSessionStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	s, _ := agent.NewSession("sA", "engA", "alice", "find subs", "m", "http://localhost:20128/v1", "h", now, 1000)
	s.TenantID = shared.DefaultTenant
	if err := ss.SaveSession(ctx, s); err != nil {
		t.Fatalf("save session: %v", err)
	}
	// upsert advances status/steps
	s.Status, s.Steps, s.TokensUsed = agent.StatusSucceeded, 3, 120
	if err := ss.SaveSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := ss.GetSession(ctx, "sA")
	if err != nil || got.Status != agent.StatusSucceeded || got.Steps != 3 || got.InitiatedBy != "alice" {
		t.Fatalf("session round-trip wrong: %+v err=%v", got, err)
	}
	tenantB := shared.WithTenant(context.Background(), "tenant-b")
	_, _ = pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('tenant-b','Tenant B') ON CONFLICT (id) DO NOTHING`)
	if _, err := ss.GetSession(tenantB, "sA"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant session lookup must be hidden, got %v", err)
	}
	if err := ss.AppendMessage(tenantB, "sA", 9, agent.Message{Role: agent.RoleUser}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant transcript append must be rejected, got %v", err)
	}
	// transcript + fork-guard
	if err := ss.AppendMessage(ctx, "sA", 0, agent.Message{Role: agent.RoleAssistant, ToolCalls: []agent.ToolCall{{ID: "c1", Name: "get_scope", Arguments: []byte(`{"engagement_id":"engA"}`)}}}); err != nil {
		t.Fatal(err)
	}
	if err := ss.AppendMessage(ctx, "sA", 0, agent.Message{Role: agent.RoleUser}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("dup seq must be ErrConflict, got %v", err)
	}
	msgs, _ := ss.Messages(ctx, "sA")
	if len(msgs) != 1 || len(msgs[0].ToolCalls) != 1 || msgs[0].ToolCalls[0].Name != "get_scope" {
		t.Fatalf("transcript/tool_calls round-trip wrong: %+v", msgs)
	}

	// approval store
	as := NewApprovalStore(pool)
	p := agent.ProposedAction{ID: "actA", SessionID: "sA", EngagementID: "engA", Tool: "start_recon", Action: "recon.naabu",
		Target: engagement.Target{Kind: engagement.TargetIP, Value: "1.1.1.1"}, Argv: []string{"naabu", "-host", "1.1.1.1"}, Risk: agent.RiskActive, ProposedAt: now}
	if err := as.Enqueue(ctx, p); err != nil {
		t.Fatal(err)
	}
	_ = as.Enqueue(ctx, p) // idempotent
	pend, _ := as.Pending(ctx, "engA")
	if len(pend) != 1 || pend[0].Target.Value != "1.1.1.1" || len(pend[0].Argv) != 3 {
		t.Fatalf("pending round-trip wrong: %+v", pend)
	}
	if err := as.Decide(ctx, agent.ApprovalDecision{ActionID: "actA", State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := as.Decide(ctx, agent.ApprovalDecision{ActionID: "actA", State: agent.ApprovalDenied, DecidedBy: "x", DecidedAt: now}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("2nd decide must be ErrConflict, got %v", err)
	}
	_, dec, _ := as.Get(ctx, "actA")
	if dec.State != agent.ApprovalApproved || dec.DecidedBy != "bob" {
		t.Fatalf("decision round-trip wrong: %+v", dec)
	}
}

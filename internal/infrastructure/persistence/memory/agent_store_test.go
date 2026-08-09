package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMemAgentSessionForkGuard(t *testing.T) {
	st := NewAgentSessionStore()
	ctx := context.Background()
	s, _ := agent.NewSession("s1", "e1", "alice", "goal", "m", "b", "h", time.Unix(1, 0), 0)
	if err := st.SaveSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendMessage(ctx, "s1", 0, agent.Message{Role: agent.RoleUser, Content: "hi"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendMessage(ctx, "s1", 0, agent.Message{Role: agent.RoleUser, Content: "dup"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate seq must be ErrConflict (fork guard), got %v", err)
	}
	msgs, _ := st.Messages(ctx, "s1")
	if len(msgs) != 1 || msgs[0].Content != "hi" {
		t.Fatalf("transcript not preserved: %+v", msgs)
	}
	if _, err := st.GetSession(ctx, "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Error("missing session must be ErrNotFound")
	}
}

func TestMemApprovalIdempotentDecide(t *testing.T) {
	st := NewApprovalStore()
	ctx := context.Background()
	p := agent.ProposedAction{ID: "a1", EngagementID: "e1", Risk: agent.RiskActive, ProposedAt: time.Unix(1, 0)}
	_ = st.Enqueue(ctx, p)
	if pend, _ := st.Pending(ctx, "e1"); len(pend) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pend))
	}
	if err := st.Decide(ctx, agent.ApprovalDecision{ActionID: "a1", State: agent.ApprovalApproved, DecidedBy: "bob"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Decide(ctx, agent.ApprovalDecision{ActionID: "a1", State: agent.ApprovalDenied, DecidedBy: "mallory"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a second decision must be ErrConflict, got %v", err)
	}
	if pend, _ := st.Pending(ctx, "e1"); len(pend) != 0 {
		t.Error("decided action must leave the pending queue")
	}
}

func TestMemApprovalConsumeIsSingleUse(t *testing.T) {
	st := NewApprovalStore()
	ctx := context.Background()
	p := agent.ProposedAction{ID: "a1", EngagementID: "e1", Risk: agent.RiskActive, ProposedAt: time.Unix(1, 0)}
	if err := st.Enqueue(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := st.Decide(ctx, agent.ApprovalDecision{ActionID: "a1", State: agent.ApprovalApproved, DecidedBy: "bob"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Consume(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Consume(ctx, "a1"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a second consume must be ErrConflict, got %v", err)
	}
	_, decision, err := st.Get(ctx, "a1")
	if err != nil || decision.State != agent.ApprovalConsumed || decision.State.Admitted() {
		t.Fatalf("consumed approval must not remain admitted: %+v err=%v", decision, err)
	}
}

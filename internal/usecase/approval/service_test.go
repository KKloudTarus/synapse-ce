package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ n int }

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error { a.n++; return nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var now = time.Unix(2_000_000, 0).UTC()

func proposal(id string, risk agent.RiskClass, proposedAt time.Time) agent.ProposedAction {
	return agent.ProposedAction{
		ID: shared.ID(id), SessionID: "s1", EngagementID: "eng-1",
		Tool: "start_recon", Action: "recon.subfinder",
		Target: engagement.Target{Kind: engagement.TargetDomain, Value: "app.acme.io"},
		Risk:   risk, ProposedAt: proposedAt,
	}
}

func newSvc(t *testing.T, mode agent.ApprovalMode) (*approval.Service, *memory.ApprovalStore) {
	t.Helper()
	store := memory.NewApprovalStore()
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, mode, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func TestRequestAutoApprovesRead(t *testing.T) {
	svc, _ := newSvc(t, agent.ModeAuto)
	dec, err := svc.Request(context.Background(), proposal("a1", agent.RiskRead, now))
	if err != nil {
		t.Fatal(err)
	}
	if dec.State != agent.ApprovalApproved {
		t.Fatalf("auto mode must auto-approve Read, got %s", dec.State)
	}
}

func TestRequestIntrusiveAlwaysManual(t *testing.T) {
	// Even in auto mode, an intrusive action must NOT auto-approve – it suspends pending.
	svc, _ := newSvc(t, agent.ModeAuto)
	dec, err := svc.Request(context.Background(), proposal("a1", agent.RiskIntrusive, now))
	if err != nil {
		t.Fatal(err)
	}
	if dec.State != agent.ApprovalPending {
		t.Fatalf("intrusive must always be manual (pending), got %s", dec.State)
	}
}

func TestRequestManualSuspends(t *testing.T) {
	svc, _ := newSvc(t, agent.ModeManual)
	dec, _ := svc.Request(context.Background(), proposal("a1", agent.RiskActive, now))
	if dec.State != agent.ApprovalPending {
		t.Fatalf("manual mode must suspend Active, got %s", dec.State)
	}
}

func TestDecideFirstWinsConcurrent(t *testing.T) {
	svc, _ := newSvc(t, agent.ModeManual)
	ctx := context.Background()
	p := proposal("a1", agent.RiskActive, now)
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, "alice", p.ID, true, "ok"); err != nil {
		t.Fatalf("first decision must succeed: %v", err)
	}
	if _, err := svc.Decide(ctx, "bob", p.ID, false, "no"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second decision must be ErrConflict (first wins), got %v", err)
	}
}

func TestSweepExpiredDeniesTimedOutPending_NeverApproves(t *testing.T) {
	svc, store := newSvc(t, agent.ModeManual)
	ctx := context.Background()
	// An intrusive action proposed 2 minutes ago, past the 1-minute timeout.
	p := proposal("a1", agent.RiskIntrusive, now.Add(-2*time.Minute))
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	n, err := svc.SweepExpired(ctx, "eng-1")
	if err != nil || n != 1 {
		t.Fatalf("expected 1 expired, got %d err=%v", n, err)
	}
	_, dec, err := store.Get(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dec.State != agent.ApprovalTimeout {
		t.Fatalf("sweep must fail-closed to timeout (deny), never approve – got %s", dec.State)
	}
}

func TestSweepExpiredLeavesFreshPending(t *testing.T) {
	svc, store := newSvc(t, agent.ModeManual)
	ctx := context.Background()
	p := proposal("a1", agent.RiskActive, now) // proposed "now" – within the window
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	n, _ := svc.SweepExpired(ctx, "eng-1")
	if n != 0 {
		t.Fatalf("a fresh pending action must not be swept, got %d", n)
	}
	_, dec, _ := store.Get(ctx, p.ID)
	if dec.State != agent.ApprovalPending {
		t.Fatalf("fresh action must stay pending, got %s", dec.State)
	}
}

func TestSweepAllExpired_FansOutAcrossEngagements(t *testing.T) {
	svc, _ := newSvc(t, agent.ModeManual)
	ctx := context.Background()
	old := now.Add(-2 * time.Minute)
	for _, p := range []agent.ProposedAction{
		{ID: "a1", SessionID: "s1", EngagementID: "e1", Risk: agent.RiskActive, ProposedAt: old},
		{ID: "a2", SessionID: "s2", EngagementID: "e2", Risk: agent.RiskActive, ProposedAt: old},
	} {
		if _, err := svc.Request(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	n, err := svc.SweepAllExpired(ctx)
	if err != nil || n != 2 {
		t.Fatalf("SweepAllExpired must fan out across engagements: n=%d err=%v", n, err)
	}
}

func TestSweepExpired_ReDrivesOnTimeout(t *testing.T) {
	svc, _ := newSvc(t, agent.ModeManual)
	ctx := context.Background()
	var resumed [][2]string
	svc.SetResumeEnqueuer(func(_ context.Context, sid, aid shared.ID) error {
		resumed = append(resumed, [2]string{sid.String(), aid.String()})
		return nil
	})
	p := agent.ProposedAction{ID: "a1", SessionID: "sess-9", EngagementID: "e1", Risk: agent.RiskActive, ProposedAt: now.Add(-2 * time.Minute)}
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SweepExpired(ctx, "e1"); err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 1 || resumed[0] != [2]string{"sess-9", "a1"} {
		t.Fatalf("a timed-out action must re-drive its session exactly once, got %v", resumed)
	}
}

func TestNewServiceValidates(t *testing.T) {
	if _, err := approval.NewService(nil, &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute); err == nil {
		t.Error("nil store must fail validation")
	}
}

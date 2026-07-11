package safety_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// --- fakes ---

type fakeEngRepo struct{ eng *engagement.Engagement }

func (f *fakeEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeAudit struct{ n int }

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error { a.n++; return nil }

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID("id-" + strconv.Itoa(g.n)) }

func engAt(now time.Time) *engagement.Engagement {
	e, _ := engagement.New(shared.ID("eng-1"), shared.ID(""), "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	return e
}

func newGate(t *testing.T, mode agent.ApprovalMode) (*safety.Gate, *approval.Service) {
	t.Helper()
	now := time.Unix(1_000_000, 0).UTC()
	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, fakeClock{now}, &fakeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approval.NewService(memory.NewApprovalStore(), &fakeAudit{}, fakeClock{now}, mode, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, &fakeAudit{}, fakeClock{now}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	return gate, appr
}

func proposal(target string, risk agent.RiskClass) agent.ProposedAction {
	return agent.ProposedAction{
		ID: "a1", SessionID: "s1", EngagementID: "eng-1", Tool: "start_recon", Action: "recon.subfinder",
		Target: engagement.Target{Kind: engagement.TargetDomain, Value: target}, Argv: []string{"subfinder", "-d", target},
		Risk: risk, ProposedAt: time.Unix(1_000_000, 0).UTC(),
	}
}

// TestAdmitForbidsOutOfScope: even in auto-approve mode, an out-of-scope target is refused
// by the guard FIRST – the AI cannot escape scope no matter what it proposes.
func TestAdmitForbidsOutOfScope(t *testing.T) {
	gate, _ := newGate(t, agent.ModeAuto)
	_, err := gate.Admit(context.Background(), proposal("evil.com", agent.RiskRead), "alice")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out-of-scope admit must be ErrForbidden, got %v", err)
	}
}

// TestAdmitAutoApproved: in-scope + auto-approvable risk → an AdmittedAction (the only way
// to obtain one is through the gate – its fields are unexported).
func TestAdmitAutoApproved(t *testing.T) {
	gate, _ := newGate(t, agent.ModeAuto)
	adm, err := gate.Admit(context.Background(), proposal("app.acme.io", agent.RiskRead), "alice")
	if err != nil {
		t.Fatalf("in-scope auto-approve should admit: %v", err)
	}
	if adm.Action().Target.Value != "app.acme.io" || adm.DecidedBy() != "auto" {
		t.Errorf("admitted action wrong: target=%s by=%s", adm.Action().Target.Value, adm.DecidedBy())
	}
}

// TestAdmitManualPendingThenApprove: manual mode suspends (ErrPendingApproval); after a
// human approves, a re-Admit succeeds.
func TestAdmitManualPendingThenApprove(t *testing.T) {
	gate, appr := newGate(t, agent.ModeManual)
	ctx := context.Background()
	p := proposal("app.acme.io", agent.RiskActive)
	if _, err := gate.Admit(ctx, p, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("manual mode must suspend with ErrPendingApproval, got %v", err)
	}
	if _, err := appr.Decide(ctx, "bob", p.ID, true, "looks fine"); err != nil {
		t.Fatalf("human approve: %v", err)
	}
	adm, err := gate.Admit(ctx, p, "alice")
	if err != nil {
		t.Fatalf("after approval, admit should succeed: %v", err)
	}
	if adm.DecidedBy() != "bob" {
		t.Errorf("admitted action should record the approver, got %q", adm.DecidedBy())
	}
}

// TestAdmitManualDenied: a denied action is ErrForbidden on re-admit (never executes).
func TestAdmitManualDenied(t *testing.T) {
	gate, appr := newGate(t, agent.ModeManual)
	ctx := context.Background()
	p := proposal("app.acme.io", agent.RiskActive)
	_, _ = gate.Admit(ctx, p, "alice") // enqueue (pending)
	if _, err := appr.Decide(ctx, "bob", p.ID, false, "too risky"); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Admit(ctx, p, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a denied action must be ErrForbidden, got %v", err)
	}
}

// TestSweepExpiredDeniesPending: an undecided action past the timeout fails closed.
func TestSweepExpiredDeniesPending(t *testing.T) {
	store := memory.NewApprovalStore()
	now := time.Unix(2_000_000, 0).UTC()
	appr, _ := approval.NewService(store, &fakeAudit{}, fakeClock{now}, agent.ModeManual, time.Minute)
	ctx := context.Background()
	p := proposal("app.acme.io", agent.RiskActive)
	p.ProposedAt = now.Add(-2 * time.Minute) // older than the 1m timeout
	if _, err := appr.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	n, err := appr.SweepExpired(ctx, "eng-1")
	if err != nil || n != 1 {
		t.Fatalf("expected 1 expired, got %d err=%v", n, err)
	}
	_, dec, _ := store.Get(ctx, p.ID)
	if dec.State != agent.ApprovalTimeout {
		t.Errorf("expired action should be timeout-denied, got %s", dec.State)
	}
}

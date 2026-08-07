package fleetwork

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{ n int }

func (g *fakeIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("wo-%d", g.n)) }

type fakeAudit struct{ n int }

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error { a.n++; return nil }

// compile-time check that the concrete signer satisfies the port (the package itself is
// deliberately stdlib-only, so the assertion lives here where ports is already imported).
var _ ports.WorkOrderSigner = (*worksign.Signer)(nil)

func newSvc(t *testing.T) *Service {
	t.Helper()
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	svc, err := NewService(memory.NewWorkOrderStore(), signer, &fakeAudit{}, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func issueInput(idem string, bucket int64) IssueInput {
	return IssueInput{
		TenantID: "t1", AssetID: "as1", AgentID: "ag1", Capability: "scan.source",
		AuthorizationID: "eng1", IdempotencyKey: idem, NotAfter: time.Unix(9999, 0).UTC(), TimeBucket: bucket,
	}
}

func TestIssueSignsAndVerifies(t *testing.T) {
	svc := newSvc(t)
	wo, err := svc.Issue(context.Background(), "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if wo.Signature == "" {
		t.Fatalf("issued order must be signed")
	}
	if !svc.Verify(wo) {
		t.Fatalf("issued order must verify")
	}
	// Tampering with an authorising field invalidates the signature.
	wo.Capability = "scan.host"
	if svc.Verify(wo) {
		t.Fatalf("tampered order must not verify")
	}
}

func TestIssueIdempotent(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	first, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent issue must return the same order: %q vs %q", first.ID, second.ID)
	}
}

func TestIssueInFlightConflict(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Issue(ctx, "actor", issueInput("idem1", 1)); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Different idempotency key, same (asset, capability, bucket) while the first is live.
	_, err := svc.Issue(ctx, "actor", issueInput("idem2", 1))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected in-flight conflict, got %v", err)
	}
}

func TestClaimIsAddressed(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Issue(ctx, "actor", issueInput("idem1", 1)); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Another agent claims nothing.
	got, err := svc.Claim(ctx, "actor", "t1", "ag2", 10)
	if err != nil {
		t.Fatalf("claim ag2: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ag2 must not claim ag1's order, got %d", len(got))
	}
	// The addressed agent claims it and it becomes claimed.
	got, err = svc.Claim(ctx, "actor", "t1", "ag1", 10)
	if err != nil {
		t.Fatalf("claim ag1: %v", err)
	}
	if len(got) != 1 || got[0].State != workorder.StateClaimed {
		t.Fatalf("ag1 should claim one order into claimed, got %+v", got)
	}
	// Re-claim returns nothing (already claimed).
	got, err = svc.Claim(ctx, "actor", "t1", "ag1", 10)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("no issued orders left to claim, got %d", len(got))
	}
}

func TestTransitionRules(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	wo, err := svc.Issue(ctx, "actor", issueInput("idem1", 1))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Illegal: issued -> succeeded.
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, workorder.StateSucceeded, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected illegal-transition validation error, got %v", err)
	}
	// Legal: issued -> claimed -> running -> succeeded.
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, workorder.StateClaimed, ""); err != nil {
		t.Fatalf("issued->claimed: %v", err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, workorder.StateRunning, ""); err != nil {
		t.Fatalf("claimed->running: %v", err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo.ID, workorder.StateSucceeded, ""); err != nil {
		t.Fatalf("running->succeeded: %v", err)
	}
	// Refusal requires a reason.
	wo2, _ := svc.Issue(ctx, "actor", issueInput("idem2", 2))
	_ = svc.Transition(ctx, "actor", "t1", wo2.ID, workorder.StateClaimed, "")
	if err := svc.Transition(ctx, "actor", "t1", wo2.ID, workorder.StateRefused, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("refusal without reason must fail, got %v", err)
	}
	if err := svc.Transition(ctx, "actor", "t1", wo2.ID, workorder.StateRefused, "unsupported capability"); err != nil {
		t.Fatalf("refusal with reason: %v", err)
	}
}

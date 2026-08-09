package fleetrolloutuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordingAudit struct{ actions []string }

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

func newService(t *testing.T) (*Service, *recordingAudit) {
	t.Helper()
	audit := &recordingAudit{}
	svc, err := NewService(memory.NewFleetRolloutStore(), audit, fixedClock{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, audit
}

// TestNoPlanOffersNothing is the resting state: a tenant that has configured no rollout must not have
// its agents offered anything, and the silence must be explainable.
func TestNoPlanOffersNothing(t *testing.T) {
	t.Parallel()

	svc, _ := newService(t)
	got := svc.DecideFor(context.Background(), "t1", "stable", "default", "1.0.0")
	if got.Offer {
		t.Fatalf("no plan must offer nothing, got %+v", got)
	}
	if got.Reason != fleetrollout.ReasonNoPlan {
		t.Fatalf("reason = %q, want %q", got.Reason, fleetrollout.ReasonNoPlan)
	}
}

// TestCanaryThenPromoteIsTwoDeliberateActions locks the shape of the control: setting a target reaches
// only the canary, and reaching everyone else requires a SECOND operator action.
func TestCanaryThenPromoteIsTwoDeliberateActions(t *testing.T) {
	t.Parallel()

	svc, audit := newService(t)
	ctx := context.Background()
	if _, err := svc.SetTarget(ctx, SetTargetInput{
		TenantID: "t1", TargetVersion: "2.0.0", CanaryGroups: []string{"canary"}, Actor: "human:alice",
	}); err != nil {
		t.Fatalf("set target: %v", err)
	}

	if got := svc.DecideFor(ctx, "t1", "stable", "canary", "1.0.0"); !got.Offer {
		t.Fatalf("the canary group must be offered the target, got %+v", got)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "prod", "1.0.0"); got.Offer {
		t.Fatalf("production must wait for promotion, got %+v", got)
	}

	if _, err := svc.Promote(ctx, "t1", "stable", "human:alice"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "prod", "1.0.0"); !got.Offer {
		t.Fatalf("after promotion production must be offered the target, got %+v", got)
	}

	// Both decisions are on the record: a rollout can replace a binary on hosts we do not own.
	if len(audit.actions) != 2 || audit.actions[0] != "fleet.rollout.target" || audit.actions[1] != "fleet.rollout.promote" {
		t.Fatalf("both actions must be audited, got %v", audit.actions)
	}
}

// TestReplacingTheTargetResetsPromotion is the subtle one. Inheriting a previous version's promotion
// would ship a NEW version to the whole fleet at once, using a decision an operator made about
// something else.
func TestReplacingTheTargetResetsPromotion(t *testing.T) {
	t.Parallel()

	svc, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.SetTarget(ctx, SetTargetInput{
		TenantID: "t1", TargetVersion: "2.0.0", CanaryGroups: []string{"canary"}, Actor: "human:alice",
	}); err != nil {
		t.Fatalf("set target: %v", err)
	}
	if _, err := svc.Promote(ctx, "t1", "stable", "human:alice"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// A new target, same canary.
	if _, err := svc.SetTarget(ctx, SetTargetInput{
		TenantID: "t1", TargetVersion: "3.0.0", CanaryGroups: []string{"canary"}, Actor: "human:alice",
	}); err != nil {
		t.Fatalf("set second target: %v", err)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "prod", "1.0.0"); got.Offer {
		t.Fatal("a replaced target must NOT inherit the previous one's promotion")
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "canary", "1.0.0"); !got.Offer || got.Target != "3.0.0" {
		t.Fatalf("the canary must receive the new target, got %+v", got)
	}
}

// A target with no canary group could only ever go to every host at once.
func TestATargetRequiresACanaryGroup(t *testing.T) {
	t.Parallel()

	svc, _ := newService(t)
	_, err := svc.SetTarget(context.Background(), SetTargetInput{
		TenantID: "t1", TargetVersion: "2.0.0", Actor: "human:alice",
	})
	if err == nil {
		t.Fatal("a target with no canary group must be refused")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error %v must wrap ErrValidation", err)
	}
}

// Pause stops every offer including the canary's, needs a reason, and resume restores exactly the
// previous state rather than advancing it.
func TestPauseStopsEverythingAndResumeDoesNotAdvance(t *testing.T) {
	t.Parallel()

	svc, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.SetTarget(ctx, SetTargetInput{
		TenantID: "t1", TargetVersion: "2.0.0", CanaryGroups: []string{"canary"}, Actor: "human:alice",
	}); err != nil {
		t.Fatalf("set target: %v", err)
	}
	if _, err := svc.Pause(ctx, "t1", "stable", "human:alice", ""); err == nil {
		t.Fatal("pausing without a reason must be refused")
	}
	if _, err := svc.Pause(ctx, "t1", "stable", "human:alice", "canary regressed"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "canary", "1.0.0"); got.Offer {
		t.Fatalf("a paused rollout must offer nothing, even to the canary: %+v", got)
	}
	// Promotion is refused while paused rather than silently queued.
	if _, err := svc.Promote(ctx, "t1", "stable", "human:alice"); err == nil {
		t.Fatal("promoting a paused rollout must be refused")
	}
	if _, err := svc.Resume(ctx, "t1", "stable", "human:alice"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "canary", "1.0.0"); !got.Offer {
		t.Fatalf("resume must restore the canary offer, got %+v", got)
	}
	if got := svc.DecideFor(ctx, "t1", "stable", "prod", "1.0.0"); got.Offer {
		t.Fatal("resume must NOT advance the rollout past where it was")
	}
}

// A store failure must decline, not read as "no rollout configured" — those are different facts and
// only one of them is a deliberate operator state.
func TestAStoreFailureDeclinesRatherThanLookingLikeNoRollout(t *testing.T) {
	t.Parallel()

	svc, err := NewService(brokenStore{}, &recordingAudit{}, fixedClock{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got := svc.DecideFor(context.Background(), "t1", "stable", "canary", "1.0.0")
	if got.Offer {
		t.Fatal("a store failure must never offer an update")
	}
	if got.Reason == fleetrollout.ReasonNoPlan {
		t.Fatal("a store failure must not be reported as a deliberate no-rollout state")
	}
}

type brokenStore struct{}

func (brokenStore) Get(context.Context, shared.ID, string) (*fleetrollout.Plan, error) {
	return nil, errors.New("store unavailable")
}
func (brokenStore) Put(context.Context, *fleetrollout.Plan) error {
	return errors.New("store unavailable")
}

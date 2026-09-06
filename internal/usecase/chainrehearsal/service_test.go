package chainrehearsal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	dpolicy "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("id-%d", g.n)) }

func harness(t *testing.T, now time.Time) (*Service, *memory.EngagementRepository) {
	t.Helper()
	register, err := dpolicy.Load()
	if err != nil {
		t.Fatalf("load register: %v", err)
	}
	sealer := offensivepolicyuc.NewEvidenceChainSealer(func(context.Context, shared.ID, string, []byte, string) (shared.ID, error) {
		return "ev", nil
	})
	gov, err := offensivepolicyuc.NewService(register, sealer, fakeAudit{})
	if err != nil {
		t.Fatalf("policy service: %v", err)
	}
	engs := memory.NewEngagementRepository()
	svc, err := NewService(engs, gov, register, exploituc.NewChainRegistry(), memory.NewExploitationChainStore(),
		fakeSealer{}, fakeAudit{}, fixedClock{now}, &seqIDs{})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return svc, engs
}

// fakeSealer records each step's proof and returns a stable evidence id.
type fakeSealer struct{}

func (fakeSealer) Seal(_ context.Context, _ shared.ID, _ string, _ []byte, _ string) (shared.ID, error) {
	return "ev-step", nil
}

func completeEngagement(t *testing.T, engs *memory.EngagementRepository, now time.Time, withRoE bool) shared.ID {
	t.Helper()
	e, err := engagement.New("eng-1", "t1", "Eng", "Client", now)
	if err != nil {
		t.Fatal(err)
	}
	e.Scope.InScope = []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.test"}}
	if withRoE {
		from, to := now.Add(-time.Hour), now.Add(time.Hour)
		_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
		if err := e.SetOffensiveRoE("Ops", "+1", "high", true, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := engs.Create(shared.WithTenant(context.Background(), "t1"), e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func TestRunChainRehearsesAGovernedChainToSuccess(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, true)

	// recon.service_banner is read_only + automatic-approval + low risk, so it is admitted under a
	// complete high-ceiling RoE, rehearsed by the no-host executor, and verified by the distinct system
	// verifier, advancing the chain to a terminal success.
	res, err := svc.RunChain(context.Background(), "t1", engID, "operator", []StepSpec{
		{Technique: "recon.service_banner", Target: "asset-1", BlastRadius: "read_only"},
	})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if !res.Simulated {
		t.Error("rehearsal result must be marked simulated")
	}
	if res.State != "succeeded" {
		t.Fatalf("chain state = %q, want succeeded", res.State)
	}
	if res.Steps != 1 {
		t.Errorf("steps = %d, want 1", res.Steps)
	}
}

func TestRunChainRefusesAStepWithoutRoE(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, false) // no RoE

	res, err := svc.RunChain(context.Background(), "t1", engID, "operator", []StepSpec{
		{Technique: "recon.service_banner", Target: "asset-1", BlastRadius: "read_only"},
	})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	// The step is refused by the offensive policy (missing RoE), so the chain never succeeds.
	if res.State == "succeeded" {
		t.Fatalf("a chain ran to success without rules of engagement: state=%q", res.State)
	}
}

func TestRunChainRequiresAStep(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, true)
	if _, err := svc.RunChain(context.Background(), "t1", engID, "operator", nil); err == nil {
		t.Fatal("an empty rehearsal was accepted")
	}
}

func TestRunChainRejectsTooManySteps(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, true)
	specs := make([]StepSpec, MaxRehearsalSteps+1)
	for i := range specs {
		specs[i] = StepSpec{Technique: "recon.service_banner", Target: "asset-1", BlastRadius: "read_only"}
	}
	if _, err := svc.RunChain(context.Background(), "t1", engID, "operator", specs); err == nil {
		t.Fatalf("a rehearsal with %d steps (over the %d cap) was accepted", len(specs), MaxRehearsalSteps)
	}
}

func TestRunChainRejectsReadOnlyStepWithCleanup(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, true)
	// A read-only step that carries a cleanup is inconsistent; the domain refuses it and the orchestrator
	// must surface that rather than silently discard the cleanup.
	_, err := svc.RunChain(context.Background(), "t1", engID, "operator", []StepSpec{
		{Technique: "recon.service_banner", Target: "asset-1", BlastRadius: "read_only", Cleanup: []string{"undo"}, CleanupVerification: "check"},
	})
	if err == nil {
		t.Fatal("a read-only step with a cleanup was accepted")
	}
}

func TestRunChainRejectsDeclaredRadiusDisagreeingWithRegister(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	svc, engs := harness(t, now)
	engID := completeEngagement(t, engs, now, true)
	// recon.service_banner is read_only in the register. Declaring it state_changing must be refused, so a
	// state-changing technique cannot be run as read-only (skipping cleanup) or vice versa.
	_, err := svc.RunChain(context.Background(), "t1", engID, "operator", []StepSpec{
		{Technique: "recon.service_banner", Target: "asset-1", BlastRadius: "state_changing", Cleanup: []string{"undo"}, CleanupVerification: "check"},
	})
	if err == nil {
		t.Fatal("a declared radius disagreeing with the register was accepted")
	}
}

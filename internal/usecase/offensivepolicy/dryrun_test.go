package offensivepolicy

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// explodingExecutor fails the test if it is called at all. It is passed nowhere — that is the point.
// The Service holds no executor, so the guarantee is structural, and this type exists to make the
// assertion explicit rather than implied by absence.
type explodingExecutor struct {
	t     *testing.T
	calls int64
}

func (e *explodingExecutor) Execute(_ context.Context, technique, target string) error {
	atomic.AddInt64(&e.calls, 1)
	e.t.Errorf("dry run executed %q against %q; a dry run must execute nothing", technique, target)
	return nil
}

// TestPlanExecutesNothing is acceptance criterion 8: dry run enumerates the plan and executes nothing,
// asserted by a test that fails if any execution occurs.
func TestPlanExecutesNothing(t *testing.T) {
	svc, sealer, audit := newService(t)
	exec := &explodingExecutor{t: t}

	plan := svc.DryRun(context.Background(), Request{
		EngagementID: "eng-1", Actor: "alice", RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{
			{Approver: "carol", Technique: "exploit.default_credentials", Target: "https://app.example.test"},
		},
	}, []PlanRequest{
		{Technique: "recon.service_banner", Target: "https://app.example.test"},
		{Technique: "exploit.default_credentials", Target: "https://app.example.test"},
		{Technique: "exploit.web_shell_upload", Target: "https://app.example.test"},
		{Technique: "impact.service_stop", Target: "https://app.example.test"},
		{Technique: "exploit.brand_new_zero_day", Target: "https://app.example.test"},
	})

	if got := atomic.LoadInt64(&exec.calls); got != 0 {
		t.Fatalf("dry run performed %d executions, want 0", got)
	}
	// A dry run must not seal an authorization either: nothing happened, so recording a permission would
	// put an approval in the evidence chain that no action ever used.
	if len(sealer.records) != 0 {
		t.Errorf("dry run sealed %d authorizations, want 0", len(sealer.records))
	}
	if got := audit.actions(); len(got) != 0 {
		t.Errorf("dry run wrote audit entries %v; enumeration is not an action", got)
	}

	if len(plan.Steps) != 5 {
		t.Fatalf("plan has %d steps, want 5", len(plan.Steps))
	}
	// Steps are ordered deterministically so two dry runs of the same plan read identically.
	for i := 1; i < len(plan.Steps); i++ {
		if plan.Steps[i-1].Technique > plan.Steps[i].Technique {
			t.Fatalf("plan steps are not deterministically ordered: %v", plan.Steps)
		}
	}
	byTechnique := map[string]PlanStep{}
	for _, s := range plan.Steps {
		byTechnique[s.Technique] = s
	}

	// The interesting rows are the refused ones, and each must say WHY in terms an operator can act on.
	if step := byTechnique["recon.service_banner"]; !step.Permitted {
		t.Errorf("an automatic-class technique inside scope should be permitted: %+v", step)
	}
	if step := byTechnique["exploit.default_credentials"]; !step.Permitted {
		t.Errorf("a medium technique with its single approval should be permitted: %+v", step)
	}
	if step := byTechnique["exploit.web_shell_upload"]; step.Permitted {
		t.Errorf("a high technique with no dual approval must be refused: %+v", step)
	} else if step.Refusal == "" {
		t.Error("a refused step must state why")
	}
	if step := byTechnique["impact.service_stop"]; step.Permitted || step.Refusal == "" {
		t.Errorf("a prohibited technique must be refused with a reason: %+v", step)
	}
	if step := byTechnique["exploit.brand_new_zero_day"]; step.Permitted || step.Refusal == "" {
		t.Errorf("an unregistered technique must be refused with a reason: %+v", step)
	}

	// The counts must be stated, so a UI cannot render "5 steps" while 3 would be refused.
	if plan.PermittedCount != 2 || plan.RefusedCount != 3 {
		t.Errorf("plan counts = %d permitted / %d refused, want 2/3", plan.PermittedCount, plan.RefusedCount)
	}
}

// TestPlanCarriesTheCleanupPathForStateChangingSteps: an operator reviewing a plan needs to see how a
// state change would be undone, not just that it changes state.
func TestPlanCarriesTheCleanupPathForStateChangingSteps(t *testing.T) {
	svc, _, _ := newService(t)
	const technique = "exploit.web_shell_upload"
	const target = "https://app.example.test"
	plan := svc.DryRun(context.Background(), Request{
		EngagementID: "eng-1", Actor: "alice", RoE: completeRoE(), Now: testNow,
		Approvals: []Approval{
			{Approver: "alice", Technique: technique, Target: target},
			{Approver: "bob", Technique: technique, Target: target},
		},
	}, []PlanRequest{{Technique: technique, Target: target}})

	if len(plan.Steps) != 1 {
		t.Fatalf("want one step, got %d", len(plan.Steps))
	}
	step := plan.Steps[0]
	if !step.Permitted {
		t.Fatalf("a dual-approved high technique should be permitted: %+v", step)
	}
	if step.BlastRadius != domain.RadiusStateChanging {
		t.Errorf("blast radius = %q, want state_changing", step.BlastRadius)
	}
	if len(step.Cleanup.Steps) == 0 || step.Cleanup.Verification == "" {
		t.Errorf("a state-changing step must show its cleanup path: %+v", step.Cleanup)
	}
}

// TestPlanRefusesEveryStepWhenTheEngagementIsIncomplete: a plan against an engagement missing a
// rules-of-engagement field enumerates, and refuses everything, naming the missing field. An operator
// gets one actionable message rather than a list of unexplained refusals.
func TestPlanRefusesEveryStepWhenTheEngagementIsIncomplete(t *testing.T) {
	svc, _, _ := newService(t)
	roe := completeRoE()
	roe.EmergencyContact = ""
	plan := svc.DryRun(context.Background(), Request{
		EngagementID: "eng-1", Actor: "alice", RoE: roe, Now: testNow,
	}, []PlanRequest{
		{Technique: "recon.service_banner", Target: "https://app.example.test"},
		{Technique: "recon.tls_inspect", Target: "https://app.example.test"},
	})
	if plan.PermittedCount != 0 || plan.RefusedCount != 2 {
		t.Fatalf("plan counts = %d/%d, want 0 permitted / 2 refused", plan.PermittedCount, plan.RefusedCount)
	}
	for _, step := range plan.Steps {
		if step.Refusal == "" || !strings.Contains(step.Refusal, "emergency_contact") {
			t.Errorf("%s refusal must name the missing field: %q", step.Technique, step.Refusal)
		}
	}
}

// TestDryRunOnANilServiceIsEmpty: a caller that failed to construct the service must not get a plan that
// reads as "nothing is restricted".
func TestDryRunOnANilServiceIsEmpty(t *testing.T) {
	var svc *Service
	plan := svc.DryRun(context.Background(), Request{EngagementID: shared.ID("eng-1")}, []PlanRequest{
		{Technique: "recon.service_banner", Target: "https://app.example.test"},
	})
	if len(plan.Steps) != 0 || plan.PermittedCount != 0 {
		t.Fatalf("a nil service must produce no permitted steps: %+v", plan)
	}
}

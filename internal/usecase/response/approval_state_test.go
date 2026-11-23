package response

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestApprovalStateUsesBoundDecisionAfterReversalDenialAndVerification(t *testing.T) {
	h := newHarness(t)
	rec, proposal := pendingApprovalRecord(act("a1"), "alice")
	rec.State = StateApplied
	rec.ReversalRequestedBy = "alice"
	proposal.ID = "revert:a1"
	proposal.Tool = "response." + string(rec.Action.Reversal.Kind)
	proposal.Action = proposal.Tool
	proposal.Argv = rec.Action.Reversal.Argv
	proposal.Rationale = "reverse response: " + rec.Action.Reversal.Description
	approvals := &fakeApprovalDecider{proposal: proposal}
	h.svc.SetApprovalDecider(approvals)
	for _, state := range []agent.ApprovalState{agent.ApprovalPending, agent.ApprovalDenied, agent.ApprovalTimeout, agent.ApprovalApproved} {
		approvals.decision = agent.ApprovalDecision{ActionID: proposal.ID, State: state}
		got, err := h.svc.ApprovalState(tctx(), rec)
		if err != nil || got != state {
			t.Fatalf("state=%s got=%s err=%v", state, got, err)
		}
	}
	if approvals.calls != 0 {
		t.Fatal("state read changed approval")
	}
	approvals.proposal.Target.Value = "another-host"
	if got, err := h.svc.ApprovalState(tctx(), rec); err != nil || got != "" {
		t.Fatalf("mismatched approval exposed: %s %v", got, err)
	}
	rec.TenantID = shared.ID("another-tenant")
	if _, err := h.svc.ApprovalState(tctx(), rec); err == nil {
		t.Fatal("cross-tenant record accepted")
	}
}

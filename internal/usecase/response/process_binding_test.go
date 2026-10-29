package response

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func TestProcessScopeAliasRejectedBeforeApprovalOrExecution(t *testing.T) {
	entity := telemetry.ProcessEntityID("asset", "boot", 123, 456)
	action, err := rdom.NewAction("stop", rdom.KindStopProcess, entity)
	if err != nil {
		t.Fatal(err)
	}
	fp := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset", ProcessEntityID: entity}
	for _, kind := range []engagement.TargetKind{engagement.TargetCloudAccount, engagement.TargetRepo, engagement.TargetImage} {
		t.Run(string(kind), func(t *testing.T) {
			h := newHarness(t)
			wrong := engagement.Target{Kind: kind, Value: entity.String()}
			if _, err := h.svc.PrepareIncidentResponse(tctx(), "eng-1", action, wrong, fp, "alice"); err == nil {
				t.Fatal("prepared wrong-kind process")
			}
			if _, err := h.svc.Apply(tctx(), "eng-1", action, wrong, fp, "alice"); err == nil {
				t.Fatal("applied wrong-kind process")
			}
			approvals := &fakeApprovalDecider{}
			h.svc.SetApprovalDecider(approvals)
			// Legacy persisted records must fail closed when resumed; history is not rewritten.
			rec := h.svc.record("t1", "eng-1", action, wrong, fp, "alice", StatePending, "", "")
			if err := h.store.Put(tctx(), rec); err != nil {
				t.Fatal(err)
			}
			if _, err := h.svc.Decide(tctx(), action.ID, "bob", true, "reviewed"); err == nil {
				t.Fatal("approved legacy wrong-kind binding")
			}
			if _, err := h.svc.Revert(tctx(), action.ID, wrong, fp, "bob"); err == nil {
				t.Fatal("reverted legacy wrong-kind binding")
			}
			if len(h.admit.calls) != 0 || len(h.exec.runs) != 0 || approvals.calls != 0 {
				t.Fatal("invalid binding reached admission, approval, or executor")
			}
			stored, found, err := h.store.Get(tctx(), action.ID)
			if err != nil || !found || stored.AuthorizationTarget != wrong || stored.State != StatePending {
				t.Fatal("legacy record mutated")
			}
		})
	}
}

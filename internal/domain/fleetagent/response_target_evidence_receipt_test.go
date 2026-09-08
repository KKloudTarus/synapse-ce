package fleetagent

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
)

func validTargetEvidenceReceipt() ResponseTargetEvidenceReceipt {
	at := time.Unix(2_000_000, 0).UTC()
	r := ResponseTargetEvidenceReceipt{
		Version: ResponseTargetEvidenceReceiptVersion, ReceiptID: "receipt-1", TenantID: "tenant-1", EngagementID: "engagement-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64),
		Target:      responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		AttemptedAt: at, WindowUntil: at.Add(time.Second), RecordedAt: at.Add(2 * time.Second),
		SourceAgentID: "agent-1", SourceAgentSessionID: "session:agent-1", SourceHostID: "host-1", TimelineComplete: true, CoverageComplete: true, Reasons: []string{"complete"},
	}
	r.Digest = ResponseTargetEvidenceReceiptDigest(r)
	return r
}

func TestResponseTargetEvidenceReceiptRejectsInconsistentCompletionFacts(t *testing.T) {
	r := validTargetEvidenceReceipt()
	r.Reasons = []string{"complete", "coverage_incomplete"}
	r.Digest = ResponseTargetEvidenceReceiptDigest(r)
	if err := r.Validate(); err == nil {
		t.Fatal("complete receipt with additional reason was accepted")
	}
	r = validTargetEvidenceReceipt()
	r.TimelineComplete, r.CoverageComplete, r.Reasons = false, false, []string{"complete"}
	r.Digest = ResponseTargetEvidenceReceiptDigest(r)
	if err := r.Validate(); err == nil {
		t.Fatal("incomplete receipt claiming complete was accepted")
	}
	r = validTargetEvidenceReceipt()
	r.TimelineComplete, r.CoverageComplete, r.Saturated, r.Reasons = false, false, true, []string{"timeline_saturated"}
	r.Digest = ResponseTargetEvidenceReceiptDigest(r)
	if err := r.Validate(); err != nil {
		t.Fatalf("saturated incomplete receipt rejected: %v", err)
	}
}

func TestResponseTargetEvidenceReceiptCloneIsDeep(t *testing.T) {
	r := validTargetEvidenceReceipt()
	clone := CloneResponseTargetEvidenceReceipt(r)
	clone.Reasons[0] = "changed"
	if r.Reasons[0] == "changed" || !SameResponseTargetEvidenceReceipt(r, r) || SameResponseTargetEvidenceReceipt(r, clone) {
		t.Fatalf("receipt clone/equality did not preserve immutable content: original=%+v clone=%+v", r, clone)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("fixture receipt invalid: %v", err)
	}
}

package fleetagent

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
)

func validTargetEvidenceReceipt() ResponseTargetEvidenceReceipt {
	at := time.Unix(2_000_000, 0).UTC()
	r := ResponseTargetEvidenceReceipt{
		Version: ResponseTargetEvidenceReceiptVersion, ReceiptID: "receipt-1", TenantID: "tenant-1", EngagementID: "engagement-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64),
		Target:      responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "pe_11111111111111111111111111111111"},
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

func TestResponseTargetEvidenceReceiptClonePreservesOriginalEvidenceDigest(t *testing.T) {
	r := validTargetEvidenceReceipt()
	r.Reversal = true
	r.ReplacementProcessEntityID = "pe_22222222222222222222222222222222"
	w := sensorstate.CoverageWindow{AssetID: r.Target.ProcessAssetID, AgentID: r.SourceAgentID, HostID: r.SourceHostID, Since: r.AttemptedAt.Add(-2 * time.Second), Until: r.AttemptedAt, CreatedAt: r.RecordedAt, InputDigest: strings.Repeat("c", 64)}
	for _, class := range detection.Classes() {
		w.States = append(w.States, detection.ClassCoverage{Class: class, HostID: r.SourceHostID, AgentID: r.SourceAgentID, State: detection.StateActive, Since: w.Since})
	}
	w.Vector = sensorstate.BuildCoverageVector(w)
	w.Vector.Reasons = []string{}
	w.Revision = sensorstate.RevisionFor(w)
	r.OriginalEvidence = &ResponseOriginalProcessEvidence{AttemptKey: "apply-attempt", AttemptedAt: w.Since, Exit: endpoint.TimelineEntry{TenantID: r.TenantID, AssetID: r.Target.ProcessAssetID, SourceAgentID: r.SourceAgentID, SourceAgentSessionID: r.SourceAgentSessionID, EntityKind: endpoint.EntityProcess, EntityID: r.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: "exit-1", OccurredAt: r.AttemptedAt.Add(-time.Second)}, Coverage: []sensorstate.CoverageWindow{w}}
	r.Digest = ResponseTargetEvidenceReceiptDigest(r)
	if err := r.Validate(); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	clone := CloneResponseTargetEvidenceReceipt(r)
	if err := clone.Validate(); err != nil {
		t.Fatalf("clone changed immutable digest: %v", err)
	}
	if !SameResponseTargetEvidenceReceipt(r, clone) || clone.OriginalEvidence.Coverage[0].Vector.Reasons == nil {
		t.Fatal("clone changed empty reason slice")
	}
	clone.OriginalEvidence.Coverage[0].States[0].State = detection.StateFailed
	if r.OriginalEvidence.Coverage[0].States[0].State != detection.StateActive {
		t.Fatal("clone shares original coverage states")
	}
	clone.OriginalEvidence.Coverage[0].GapCount = 1
	if r.OriginalEvidence.Coverage[0].GapCount != 0 {
		t.Fatal("clone shares original coverage windows")
	}
	r.OriginalEvidence.Coverage = []sensorstate.CoverageWindow{}
	clone = CloneResponseTargetEvidenceReceipt(r)
	if clone.OriginalEvidence.Coverage == nil {
		t.Fatal("clone changed empty coverage slice")
	}
}

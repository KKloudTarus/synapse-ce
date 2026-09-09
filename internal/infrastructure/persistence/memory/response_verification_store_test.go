package memory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func memoryResponseVerificationFixture(t *testing.T) ports.AcceptedResponseVerification {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(2_000_000, 0).UTC()
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, public, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "report-1", AgentID: "observer-1", HostID: "observer-1",
		AgentSessionID: fleetagent.CanonicalSessionID("observer-1"), AssetID: "asset-1", EngagementID: "eng-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", ReceiptID: "receipt", ReceiptDigest: "0000000000000000000000000000000000000000000000000000000000000000", VerificationChallenge: strings.Repeat("b", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ObservedAt: at, KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(report))
	return ports.AcceptedResponseVerification{
		Report: report, ObserverID: report.ObserverIdentity(), SignedContentDigest: hex.EncodeToString(digest[:]), RecordedAt: at.Add(time.Second),
	}
}

func memoryTargetReceiptFixture(t *testing.T, tenant shared.ID) fleetagent.ResponseTargetEvidenceReceipt {
	t.Helper()
	at := time.Unix(2_000_100, 0).UTC()
	receipt := fleetagent.ResponseTargetEvidenceReceipt{Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: "receipt-1", TenantID: tenant, EngagementID: "eng-1", ActionID: "action-1", ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64), Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"}, AttemptedAt: at, WindowUntil: at.Add(time.Second), RecordedAt: at.Add(2 * time.Second), SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), SourceHostID: "asset-1", TimelineComplete: true, CoverageComplete: true, Reasons: []string{"complete"}}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	return receipt
}

func TestResponseVerificationStoreTargetEvidenceReceiptIsolatedImmutableAndIdempotent(t *testing.T) {
	store := NewResponseVerificationStore()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	receipt := memoryTargetReceiptFixture(t, "tenant-1")
	stored, err := store.AppendResponseTargetEvidenceReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	stored.Reasons[0] = "tampered"
	loaded, found, err := store.GetResponseTargetEvidenceReceipt(ctx, receipt.AttemptKey)
	if err != nil || !found || loaded.Reasons[0] != "complete" {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, receipt); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	for _, mutate := range []func(*fleetagent.ResponseTargetEvidenceReceipt){
		func(r *fleetagent.ResponseTargetEvidenceReceipt) { r.ReceiptID = "receipt-2" },
		func(r *fleetagent.ResponseTargetEvidenceReceipt) {
			r.Reasons = []string{"coverage_incomplete"}
			r.TimelineComplete, r.CoverageComplete = false, false
		},
	} {
		candidate := fleetagent.CloneResponseTargetEvidenceReceipt(receipt)
		mutate(&candidate)
		candidate.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(candidate)
		if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, candidate); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("attempt equivocation=%+v err=%v", candidate, err)
		}
	}
	idCollision := fleetagent.CloneResponseTargetEvidenceReceipt(receipt)
	idCollision.AttemptKey, idCollision.VerificationChallenge = "attempt-2", strings.Repeat("c", 64)
	idCollision.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(idCollision)
	if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, idCollision); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("receipt id collision err=%v", err)
	}
	digestCollision := fleetagent.CloneResponseTargetEvidenceReceipt(receipt)
	digestCollision.AttemptKey, digestCollision.ReceiptID = "attempt-2", "receipt-2"
	if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, digestCollision); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered receipt digest err=%v", err)
	}
	if _, found, err := store.GetResponseTargetEvidenceReceipt(shared.WithTenant(context.Background(), "tenant-2"), receipt.AttemptKey); err != nil || found {
		t.Fatalf("tenant isolation found=%t err=%v", found, err)
	}
}

func TestResponseVerificationStoreCommitsObservationAndAuditAtomically(t *testing.T) {
	store := NewResponseVerificationStore()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	observation := memoryResponseVerificationFixture(t)
	bad := ports.FleetAuditIntent{ID: "audit-1"}
	if _, err := store.AppendResponseVerificationWithAudit(ctx, observation, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid audit intent must fail: %v", err)
	}
	if _, found, err := store.GetResponseVerification(ctx, observation.Report.AttemptKey); err != nil || found {
		t.Fatalf("invalid audit intent committed observation: found=%t err=%v", found, err)
	}

	intent := ports.FleetAuditIntent{ID: "audit-1", Entry: ports.AuditEntry{
		Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: observation.Report.ReportID.String(),
		At: observation.RecordedAt, Metadata: map[string]string{"idempotency_key": "audit-1"},
	}}
	committed, err := store.AppendResponseVerificationWithAudit(ctx, observation, intent)
	if err != nil || !ports.SameFleetAuditIntent(committed, intent) {
		t.Fatalf("append observation: intent=%+v err=%v", committed, err)
	}
	stored, found, err := store.GetResponseVerification(ctx, observation.Report.AttemptKey)
	if err != nil || !found || !ports.SameAcceptedResponseVerification(stored, observation) {
		t.Fatalf("stored observation=%+v found=%t err=%v", stored, found, err)
	}
	if _, err := store.AppendResponseVerificationWithAudit(ctx, observation, intent); err != nil {
		t.Fatalf("exact retry must be idempotent: %v", err)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil || len(pending) != 1 || !ports.SameFleetAuditIntent(pending[0], intent) {
		t.Fatalf("pending audit intents=%+v err=%v", pending, err)
	}

	equivocation := observation
	equivocation.Report.ReportID = "report-2"
	digest := sha256.Sum256(fleetagent.ResponseVerificationMessage(equivocation.Report))
	equivocation.SignedContentDigest = hex.EncodeToString(digest[:])
	if _, err := store.AppendResponseVerificationWithAudit(ctx, equivocation, intent); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second report for one attempt must conflict: %v", err)
	}
}

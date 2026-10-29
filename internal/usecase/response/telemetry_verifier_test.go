package response

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type verifierEvidenceSealer struct {
	content []byte
}

func (s *verifierEvidenceSealer) SealOnce(_ context.Context, engagementID shared.ID, kind, _ string, content []byte, actor string) (evdom.Evidence, error) {
	s.content = append([]byte(nil), content...)
	return evdom.Evidence{ID: "evidence-1", EngagementID: engagementID, Kind: kind, Content: content, CreatedBy: actor}, nil
}

func telemetryVerificationRequest(t *testing.T) VerificationRequest {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "pe_11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return VerificationRequest{
		TenantID: "tenant-1", EngagementID: "eng-1", Action: action,
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "pe_11111111111111111111111111111111"},
		ExecutorID: "agent:response-executor", ExecutorAgentID: "response-executor", AttemptKey: "attempt-1",
		VerificationChallenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AttemptedAt:           time.Unix(1_000, 0).UTC(),
		DeadlineAt:            time.Unix(1_060, 0).UTC(),
	}
}

func TestTelemetryEffectVerifierSealsAcceptedObservation(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	req := telemetryVerificationRequest(t)
	source, _, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewResponseVerificationStore()
	observation := ports.AcceptedResponseVerification{
		Report: source.Report, ObserverID: source.Report.ObserverIdentity(),
		SignedContentDigest: source.SignedContentDigest, RecordedAt: source.RecordedAt,
	}
	intent := ports.FleetAuditIntent{ID: "audit-1", Entry: ports.AuditEntry{
		Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: source.Report.ReportID.String(),
		At: source.RecordedAt, Metadata: map[string]string{"idempotency_key": "audit-1"},
	}}
	if _, err := store.AppendResponseVerificationWithAudit(ctx, observation, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, source.Receipt); err != nil {
		t.Fatal(err)
	}
	timeline := memory.NewEndpointTimelineStore()
	if err := timeline.AppendTimeline(ctx, source.Timeline); err != nil {
		t.Fatal(err)
	}
	coverage := memory.NewCoverageWindowStore()
	for _, window := range source.Coverage {
		if _, err := coverage.AppendCoverageWindow(ctx, window); err != nil {
			t.Fatal(err)
		}
	}
	sealer := &verifierEvidenceSealer{}
	verifier, err := NewTelemetryEffectVerifier("control-plane:response-verifier", store, store, timeline, coverage, sealer)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.Verify(ctx, req)
	if err != nil {
		t.Fatalf("verify accepted observation: %v", err)
	}
	if receipt.Outcome != VerificationSucceeded || receipt.EvidenceID != "evidence-1" || receipt.Source == nil {
		t.Fatalf("receipt=%+v", receipt)
	}
	if len(sealer.content) == 0 {
		t.Fatal("accepted observation was not sealed into evidence")
	}
}

func TestTelemetryEffectVerifierLeavesMissingReportPending(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	sealer := &verifierEvidenceSealer{}
	verifier, err := NewTelemetryEffectVerifier(
		"control-plane:response-verifier", memory.NewResponseVerificationStore(), memory.NewResponseVerificationStore(),
		memory.NewEndpointTimelineStore(), memory.NewCoverageWindowStore(), sealer,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.Verify(ctx, telemetryVerificationRequest(t))
	if !errors.Is(err, ErrVerificationPending) || receipt.Outcome != VerificationPending || !receipt.EvidenceID.IsZero() {
		t.Fatalf("missing observation receipt=%+v err=%v", receipt, err)
	}
}

func TestTelemetryEffectVerifierSealsExplicitCoverageGapAsUnknown(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	req := telemetryVerificationRequest(t)
	source, _, err := newE2EVerificationSource(req, VerificationUnknown)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewResponseVerificationStore()
	observation := ports.AcceptedResponseVerification{
		Report: source.Report, ObserverID: source.Report.ObserverIdentity(),
		SignedContentDigest: source.SignedContentDigest, RecordedAt: source.RecordedAt,
	}
	if _, err := store.AppendResponseVerificationWithAudit(ctx, observation, ports.FleetAuditIntent{
		ID: "audit-gap", Entry: ports.AuditEntry{
			Actor: observation.ObserverID, Action: "fleet.response_verification.ingest", Target: source.Report.ReportID.String(),
			At: source.RecordedAt, Metadata: map[string]string{"idempotency_key": "audit-gap"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendResponseTargetEvidenceReceipt(ctx, source.Receipt); err != nil {
		t.Fatal(err)
	}
	timeline := memory.NewEndpointTimelineStore()
	if err := timeline.AppendTimeline(ctx, source.Timeline); err != nil {
		t.Fatal(err)
	}
	coverage := memory.NewCoverageWindowStore()
	for _, window := range source.Coverage {
		if _, err := coverage.AppendCoverageWindow(ctx, window); err != nil {
			t.Fatal(err)
		}
	}
	sealer := &verifierEvidenceSealer{}
	verifier, err := NewTelemetryEffectVerifier("control-plane:response-verifier", store, store, timeline, coverage, sealer)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifier.Verify(ctx, req)
	if err != nil || receipt.Outcome != VerificationUnknown || receipt.Source == nil {
		t.Fatalf("explicit coverage gap receipt=%+v err=%v", receipt, err)
	}
}

func TestDeriveTelemetryVerificationRejectsDifferentSourceAgent(t *testing.T) {
	req := telemetryVerificationRequest(t)
	source, _, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	source.Receipt.Timeline[0].SourceAgentID = "response-executor"
	if _, err := deriveTelemetryVerification(req, source.Receipt); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("executor-origin timeline must not verify its own effect, got %v", err)
	}
	source.Receipt.Timeline[0].SourceAgentID = source.Report.AgentID
	source.Receipt.Timeline[0].SourceAgentSessionID = "different-session"
	if _, err := deriveTelemetryVerification(req, source.Receipt); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("timeline from another observer session must be rejected, got %v", err)
	}
}

func TestVerificationSourceRejectsLateObservationOrReceipt(t *testing.T) {
	req := telemetryVerificationRequest(t)
	source, _, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	source.Report.ObservedAt = req.DeadlineAt
	if err := source.validateBinding(req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("observation at deadline error=%v, want validation", err)
	}
	source, _, err = newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	source.RecordedAt = req.DeadlineAt
	if err := source.validateBinding(req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("receipt at deadline error=%v, want validation", err)
	}
}

func TestReversalVerificationRequiresExactReplacement(t *testing.T) {
	req := telemetryVerificationRequest(t)
	req.Reversal = true
	req.OriginalAttemptKey = "original-attempt"
	req.OriginalAttemptedAt = req.AttemptedAt.Add(-time.Second)
	req.ReplacementProcessEntityID = "pe_22222222222222222222222222222222"
	source, _, err := newE2EVerificationSource(req, VerificationSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := deriveTelemetryVerification(req, source.Receipt)
	if err != nil || outcome != VerificationSucceeded {
		t.Fatalf("valid outcome=%s err=%v", outcome, err)
	}
	source.Receipt.Timeline[0].EntityID = "pe_33333333333333333333333333333333"
	source.Receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(source.Receipt)
	outcome, err = deriveTelemetryVerification(req, source.Receipt)
	if err != nil || outcome != VerificationUnknown {
		t.Fatalf("unrelated replacement outcome=%s err=%v", outcome, err)
	}
}

type pendingEvidenceDispatcher struct{}

func (pendingEvidenceDispatcher) EnsureObservation(context.Context, ports.ResponseVerificationRequest) error {
	return fmt.Errorf("late projection: %w", ports.ErrResponseTargetEvidencePending)
}
func TestTelemetryEffectVerifierTreatsLateEvidenceAsOrdinaryPending(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	verifier, err := NewTelemetryEffectVerifier("control-plane:response-verifier", memory.NewResponseVerificationStore(), memory.NewResponseVerificationStore(), memory.NewEndpointTimelineStore(), memory.NewCoverageWindowStore(), &verifierEvidenceSealer{})
	if err != nil {
		t.Fatal(err)
	}
	verifier.SetObservationDispatcher(pendingEvidenceDispatcher{})
	_, err = verifier.Verify(ctx, telemetryVerificationRequest(t))
	if !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("late evidence error=%v", err)
	}
	if !onlyVerificationPending(verificationPendingError("action-1", "waiting", err)) {
		t.Fatal("late evidence reported as an operational failure")
	}
}

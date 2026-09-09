package responseverificationingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ingestClock struct{ at time.Time }

func (c ingestClock) Now() time.Time { return c.at }

type ingestBindings struct {
	asset shared.ID
	err   error
}

func (b *ingestBindings) ResolveResponseObservationAsset(context.Context, shared.ID) (shared.ID, error) {
	if b.err != nil {
		return "", b.err
	}
	return b.asset, nil
}

type ingestKeys struct {
	key fleetagent.AgentSigningKey
	err error
}

type ingestOrders struct {
	order *workorder.WorkOrder
	err   error
}

func (o *ingestOrders) GetByID(context.Context, shared.ID, shared.ID) (*workorder.WorkOrder, error) {
	if o.err != nil {
		return nil, o.err
	}
	return o.order, nil
}

func (k *ingestKeys) ResolveSigningKey(context.Context, shared.ID, string) (fleetagent.AgentSigningKey, error) {
	if k.err != nil {
		return fleetagent.AgentSigningKey{}, k.err
	}
	return k.key, nil
}

type ingestAudit struct{ entries []ports.AuditEntry }

func (a *ingestAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}
func (a *ingestAudit) RecordOnce(ctx context.Context, entry ports.AuditEntry) error {
	return a.Record(ctx, entry)
}

type ingestHarness struct {
	ctx          context.Context
	service      *Service
	report       fleetagent.ResponseVerificationReport
	private      ed25519.PrivateKey
	responses    *memory.ResponseStore
	observations *memory.ResponseVerificationStore
	orders       *ingestOrders
	audit        *ingestAudit
}

func newIngestHarness(t *testing.T, state responsesaga.SagaState) ingestHarness {
	t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	at := time.Unix(2_000_000, 0).UTC()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	responses := memory.NewResponseStore()
	if err := responses.Put(ctx, rdom.Record{
		ID: action.ID, TenantID: "tenant-1", EngagementID: "eng-1", Action: action,
		State: rdom.StatePending, ApprovedBy: "alice", UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("a", 64)
	attempt := responsesaga.ResponseAttempt{
		ActionID: action.ID, Attempt: 1, IdempotencyKey: "attempt-1",
		Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		State:  state, CommandOutcome: "applied", VerificationChallenge: challenge,
		ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1,
		ExecutorID: "agent:response-executor", ExecutorAgentID: "response-executor", At: at, DeadlineAt: at.Add(time.Hour),
	}
	if _, _, err := responses.StartAttempt(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, public, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "report-1", AgentID: "observer-1", HostID: "observer-1",
		AgentSessionID: fleetagent.CanonicalSessionID("observer-1"), AssetID: "asset-1", EngagementID: "eng-1", ActionID: action.ID,
		ActionDigest: digest, AttemptKey: attempt.IdempotencyKey, ReceiptID: "receipt", ReceiptDigest: "0000000000000000000000000000000000000000000000000000000000000000", VerificationChallenge: challenge, Target: attempt.Target,
		ObservedAt: at.Add(time.Second), KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	request := fleetagent.ResponseObservationRequest{
		ProtocolVersion: fleetagent.ResponseObservationProtocolVersion, RequestID: report.ReportID,
		TenantID: "tenant-1", ObserverAgentID: report.AgentID, AssetID: report.AssetID,
		EngagementID: report.EngagementID, ActionID: report.ActionID, ActionDigest: report.ActionDigest,
		AttemptKey: report.AttemptKey, ReceiptID: "receipt", ReceiptDigest: "0000000000000000000000000000000000000000000000000000000000000000", VerificationChallenge: report.VerificationChallenge, Target: report.Target,
		Reversal: report.Reversal, AttemptedAt: at, IssuedAt: at.Add(500 * time.Millisecond), NotAfter: at.Add(time.Hour),
	}
	order := &workorder.WorkOrder{
		ID: report.ReportID, TenantID: "tenant-1", AssetID: report.AssetID, AgentID: report.AgentID,
		Capability: workorder.CapabilityResponseObserve, AuthorizationID: report.EngagementID,
		IdempotencyKey: "response-observation:v1:" + report.AttemptKey + ":" + report.AgentID.String(),
		NotAfter:       request.NotAfter, LeaseID: "lease-1", LeaseUntil: at.Add(time.Hour), State: workorder.StateRunning,
		Priority: workorder.ResponseObservePriority, ResponseObserve: &request,
	}
	orders := &ingestOrders{order: order}
	observations := memory.NewResponseVerificationStore()
	receipt := fleetagent.ResponseTargetEvidenceReceipt{
		Version: fleetagent.ResponseTargetEvidenceReceiptVersion, ReceiptID: report.ReceiptID, TenantID: "tenant-1", EngagementID: report.EngagementID,
		ActionID: report.ActionID, ActionDigest: report.ActionDigest, AttemptKey: report.AttemptKey, VerificationChallenge: report.VerificationChallenge,
		Target: report.Target, Reversal: report.Reversal, AttemptedAt: at, WindowUntil: report.ObservedAt, RecordedAt: report.ObservedAt,
		SourceAgentID: "target-agent", SourceAgentSessionID: "session:target-agent", SourceHostID: "target-agent", TimelineComplete: false, CoverageComplete: false, Reasons: []string{"coverage_incomplete"},
	}
	receipt.Digest = fleetagent.ResponseTargetEvidenceReceiptDigest(receipt)
	report.ReceiptDigest, request.ReceiptDigest = receipt.Digest, receipt.Digest
	report.Signature = fleetagent.SignResponseVerification(private, report)
	if _, err := observations.AppendResponseTargetEvidenceReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	audit := &ingestAudit{}
	service, err := NewService(observations, observations, responses, orders, &ingestBindings{asset: "asset-1"}, &ingestKeys{key: key}, audit, ingestClock{at: at.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return ingestHarness{ctx: ctx, service: service, report: report, private: private, responses: responses, observations: observations, orders: orders, audit: audit}
}

func TestIngestAcceptsPurposeSignedAttemptBoundObservation(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	result, err := h.service.Ingest(h.ctx, "observer-1", h.report)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.ReportID != h.report.ReportID {
		t.Fatalf("report id=%s", result.ReportID)
	}
	if _, found, err := h.observations.GetResponseVerification(h.ctx, h.report.AttemptKey); err != nil || !found {
		t.Fatalf("accepted observation found=%t err=%v", found, err)
	}
	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); err != nil {
		t.Fatalf("exact retry must be idempotent: %v", err)
	}
}

func TestIngestRejectsPreCommandOrMismatchedChallenge(t *testing.T) {
	t.Run("attempt_not_verifying", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateCommandApplied)
		if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("pre-verifying observation must fail: %v", err)
		}
	})
	t.Run("challenge_mismatch", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateVerifying)
		h.report.VerificationChallenge = strings.Repeat("b", 64)
		h.report.Signature = fleetagent.SignResponseVerification(h.private, h.report)
		if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("mismatched challenge must fail: %v", err)
		}
	})
}

func TestIngestRejectsCrossPurposeKeyAndTransportIdentity(t *testing.T) {
	t.Run("wrong_purpose", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateVerifying)
		h.service.keys.(*ingestKeys).key.Purpose = fleetagent.PurposeTelemetryBatch
		if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("cross-purpose key must fail: %v", err)
		}
	})
	t.Run("wrong_transport_identity", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateVerifying)
		if _, err := h.service.Ingest(h.ctx, "another-agent", h.report); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("transport identity mismatch must fail: %v", err)
		}
	})
}

func TestIngestRejectsExecutorAgentUnderDifferentRoleAndKey(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	h.report.AgentID = "response-executor"
	h.report.HostID = "response-executor"
	h.report.AgentSessionID = fleetagent.CanonicalSessionID("response-executor")
	h.service.keys.(*ingestKeys).key.AgentID = "response-executor"
	h.report.Signature = fleetagent.SignResponseVerification(h.private, h.report)

	if _, err := h.service.Ingest(h.ctx, "response-executor", h.report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("executor agent self-verification must fail across role/key labels: %v", err)
	}
}

func TestIngestRejectsCrossAssetObservation(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	h.report.AssetID = "asset-2"
	h.report.Signature = fleetagent.SignResponseVerification(h.private, h.report)
	h.service.observers = &ingestBindings{asset: "asset-2"}

	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); err == nil {
		t.Fatal("cross-asset observation must fail even when its target resolver accepts the altered asset")
	}
}

func TestIngestRejectsObserverWithoutLiveTargetBinding(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	h.service.observers = &ingestBindings{err: shared.ErrNotFound}

	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unassigned observer error=%v, want forbidden", err)
	}
}

func TestIngestRejectsMissingOrInactiveObservationOrder(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateVerifying)
		h.orders.err = shared.ErrNotFound
		if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("report without its issued observation order must fail: %v", err)
		}
	})
	t.Run("not_running", func(t *testing.T) {
		h := newIngestHarness(t, responsesaga.StateVerifying)
		h.orders.order.State = workorder.StateClaimed
		if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("report outside a running observation order must fail: %v", err)
		}
	})
}

func TestIngestRejectsObservationOutsideIssuedBinding(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	h.orders.order.ResponseObserve.ActionDigest = strings.Repeat("b", 64)
	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("report disagreeing with its observation order must fail: %v", err)
	}
}

func TestIngestRejectsObservationReceivedAtAttemptDeadline(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	attempt, found, err := h.responses.GetAttempt(h.ctx, h.report.AttemptKey)
	if err != nil || !found {
		t.Fatalf("load response attempt: found=%v err=%v", found, err)
	}
	h.service.clock = ingestClock{at: attempt.DeadlineAt}
	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("late response observation error=%v, want forbidden", err)
	}
	if _, found, err := h.observations.GetResponseVerification(h.ctx, h.report.AttemptKey); err != nil || found {
		t.Fatalf("late response observation persisted: found=%v err=%v", found, err)
	}
}

func TestIngestRejectsReportReceivedAfterSigningKeyRevocation(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	key := &h.service.keys.(*ingestKeys).key
	key.RevokedAt = h.report.ObservedAt.Add(time.Millisecond)
	if _, err := h.service.Ingest(h.ctx, "observer-1", h.report); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("report signed before revocation but received after it must fail, got %v", err)
	}
	if _, found, err := h.observations.GetResponseVerification(h.ctx, h.report.AttemptKey); err != nil || found {
		t.Fatalf("revoked-key report persisted: found=%v err=%v", found, err)
	}
}

func TestIngestPreservesSigningKeyInfrastructureErrors(t *testing.T) {
	h := newIngestHarness(t, responsesaga.StateVerifying)
	outage := errors.New("key store unavailable")
	h.service.keys.(*ingestKeys).err = outage

	_, err := h.service.Ingest(h.ctx, "observer-1", h.report)
	if !errors.Is(err, outage) || errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("key-store outage must remain retryable, got %v", err)
	}
}

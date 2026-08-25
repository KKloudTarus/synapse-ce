package telemetryingest

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func signedGapForHarness(t *testing.T, h *harness, id shared.ID) fleetagent.TelemetryGapReport {
	t.Helper()
	priority := fleetagent.PriorityP3
	stream, err := fleetagent.TelemetryDeliveryStreamID("agent-1", h.session, priority)
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.TelemetryGapReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		GapID:           id, AgentID: "agent-1", HostID: "agent-1", AgentSessionID: h.session,
		AssetID: "asset-1", StreamID: stream, Priority: priority, Epoch: 1,
		Count: 2, Reason: fleetagent.TelemetryGapQuotaEviction,
		FromAt: h.now.Add(-time.Minute), ToAt: h.now,
		KeyID: h.key.KeyID,
	}
	report.Signature = fleetagent.SignTelemetryGap(h.priv, report)
	return report
}

func TestIngestGapPersistsQueryableLossAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	report := signedGapForHarness(t, h, "gap-1")
	res, err := h.svc.IngestGap(h.ctx, "agent-1", report)
	if err != nil {
		t.Fatalf("ingest gap: %v", err)
	}
	if res.GapID != report.GapID {
		t.Fatalf("gap ACK = %q, want %q", res.GapID, report.GapID)
	}
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", report); err != nil {
		t.Fatalf("exact gap replay: %v", err)
	}
	priority := fleetagent.PriorityP3
	gaps, err := h.transport.QueryDeliveryGaps(h.ctx, ports.TelemetryGapQuery{
		AgentID: "agent-1", AssetID: "asset-1", Priority: &priority,
		Since: h.now.Add(-30 * time.Second), Until: h.now.Add(30 * time.Second),
	})
	if err != nil || len(gaps) != 1 {
		t.Fatalf("query persisted agent gap = %+v, %v; want one", gaps, err)
	}
	if gaps[0].FromSequence != 0 || gaps[0].ToSequence != 0 || !gaps[0].FromAt.Equal(report.FromAt) || !gaps[0].ToAt.Equal(report.ToAt) {
		t.Fatalf("persisted unknown-coordinate gap = %+v", gaps[0])
	}
}

func TestIngestKnownWALGapDoesNotAdvanceTransportBatchACK(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatalf("seed transport batch: %v", err)
	}

	report := signedGapForHarness(t, h, "gap-known-wal")
	report.Priority = fleetagent.PriorityP1
	report.StreamID = h.stream
	report.KnownSequence = true
	report.FromSequence = 2
	report.ToSequence = 3
	report.Count = 2
	report.Signature = fleetagent.SignTelemetryGap(h.priv, report)
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", report); err != nil {
		t.Fatalf("ingest known-coordinate WAL gap: %v", err)
	}

	state, err := h.transport.StreamState(h.ctx, "agent-1", h.stream, 1)
	if err != nil {
		t.Fatal(err)
	}
	if state.Contiguous != 1 {
		t.Fatalf("known WAL gap advanced transport-batch ACK to %d; want 1", state.Contiguous)
	}
}

func TestIngestGapRejectsForgedIdentityAndSignature(t *testing.T) {
	h := newHarness(t)
	identity := signedGapForHarness(t, h, "gap-identity")
	identity.AgentID = "attacker"
	identity.Signature = fleetagent.SignTelemetryGap(h.priv, identity)
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", identity); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("forged identity error = %v, want forbidden", err)
	}

	forged := signedGapForHarness(t, h, "gap-signature")
	forged.Signature = "not-a-signature"
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", forged); err == nil {
		t.Fatal("forged telemetry gap signature was accepted")
	}
	if h.audit.count() < 2 {
		t.Fatalf("rejections were not audited, count=%d", h.audit.count())
	}
}

func TestIngestGapAcceptsOnlyMonotonicCoalescingExtension(t *testing.T) {
	h := newHarness(t)
	report := signedGapForHarness(t, h, "gap-extension")
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", report); err != nil {
		t.Fatal(err)
	}
	extended := report
	extended.Count = 4
	extended.ToAt = report.ToAt.Add(2 * time.Minute)
	extended.Signature = fleetagent.SignTelemetryGap(h.priv, extended)
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", extended); err != nil {
		t.Fatalf("monotonic coalescing extension rejected: %v", err)
	}

	conflict := extended
	conflict.Reason = fleetagent.TelemetryGapIOFailure
	conflict.Signature = fleetagent.SignTelemetryGap(h.priv, conflict)
	if _, err := h.svc.IngestGap(h.ctx, "agent-1", conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("gap-id equivocation error = %v, want conflict", err)
	}
}

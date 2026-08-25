package main

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBuildTelemetryGapReportUsesCanonicalIdentityAndVerifies(t *testing.T) {
	signer := testTelemetrySigner(t, "agent-gap")
	now := time.Unix(1_700_001_000, 0).UTC()
	gap := ports.SpoolGap{
		ID: "gap-1", Priority: fleetagent.PriorityP3, Epoch: 4,
		KnownSequence: true, FromSequence: 11, ToSequence: 13, Count: 3,
		Reason:     ports.SpoolGapCorruptFrame,
		OccurredAt: now, FromAt: now.Add(-time.Minute), ToAt: now,
	}
	report, err := buildTelemetryGapReport(fleetclient.Credential{
		AgentID: "agent-gap", AssetID: "asset-gap", Token: "token",
	}, signer, gap)
	if err != nil {
		t.Fatal(err)
	}
	if report.GapID != gap.ID || report.AgentID != "agent-gap" || report.HostID != "agent-gap" || report.AssetID != "asset-gap" {
		t.Fatalf("report identity = %+v", report)
	}
	if report.AgentSessionID != fleetagent.CanonicalSessionID("agent-gap") {
		t.Fatalf("session = %q", report.AgentSessionID)
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID("agent-gap", report.AgentSessionID, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	if report.StreamID != wantStream || report.Reason != fleetagent.TelemetryGapCorruptFrame {
		t.Fatalf("stream/reason = %q/%q", report.StreamID, report.Reason)
	}
	if err := fleetagent.VerifyTelemetryGapWithKey(signer.Key, time.Unix(1_700_000_000, 0).UTC(), report); err != nil {
		t.Fatalf("signed gap report did not verify: %v", err)
	}
}

func TestBuildTelemetryGapReportPreservesUnknownCoordinates(t *testing.T) {
	signer := testTelemetrySigner(t, "agent-gap")
	now := time.Unix(1_700_001_000, 0).UTC()
	gap := ports.SpoolGap{
		ID: "gap-unknown", Priority: fleetagent.PriorityP3, Epoch: 2,
		Count: 5, Reason: ports.SpoolGapQuotaEviction,
		OccurredAt: now, FromAt: now.Add(-5 * time.Minute), ToAt: now,
	}
	report, err := buildTelemetryGapReport(fleetclient.Credential{AgentID: "agent-gap", AssetID: "asset-gap"}, signer, gap)
	if err != nil {
		t.Fatal(err)
	}
	if report.KnownSequence || report.FromSequence != 0 || report.ToSequence != 0 || report.Count != 5 {
		t.Fatalf("unknown-coordinate report = %+v", report)
	}
	if report.Reason != fleetagent.TelemetryGapQuotaEviction {
		t.Fatalf("reason = %q", report.Reason)
	}
}

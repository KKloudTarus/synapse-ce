package responsefleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type receiptClock struct{ now time.Time }

func (c receiptClock) Now() time.Time { return c.now }

type receiptBindings struct{ rows []ports.TelemetryAssetBinding }

func (b receiptBindings) ListTelemetryAssetBindings(context.Context) ([]ports.TelemetryAssetBinding, error) {
	return append([]ports.TelemetryAssetBinding(nil), b.rows...), nil
}

type receiptTimeline struct{ rows []endpoint.TimelineEntry }

func (s receiptTimeline) AppendTimeline(context.Context, []endpoint.TimelineEntry) error { return nil }
func (s receiptTimeline) QueryTimeline(context.Context, ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	return append([]endpoint.TimelineEntry(nil), s.rows...), nil
}
func (s receiptTimeline) LoadTimelineEntries(context.Context, shared.ID, []shared.ID) ([]endpoint.TimelineEntry, error) {
	return nil, nil
}

type receiptCoverage struct{ rows []sensorstate.CoverageWindow }

func (s receiptCoverage) ListCoverageWindowsBounded(context.Context, ports.CoverageWindowQuery, int) ([]sensorstate.CoverageWindow, error) {
	return append([]sensorstate.CoverageWindow(nil), s.rows...), nil
}

func receiptRequest(t *testing.T, at time.Time) ports.ResponseVerificationRequest {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	return ports.ResponseVerificationRequest{TenantID: "tenant-1", EngagementID: "eng-1", Action: action,
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		ExecutorID: "agent:executor", ExecutorAgentID: "executor", AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("a", 64), AttemptedAt: at, DeadlineAt: at.Add(time.Minute)}
}

func receiptWindow(t *testing.T, at time.Time, revisionSeed string) sensorstate.CoverageWindow {
	t.Helper()
	seed := 0
	for _, char := range revisionSeed {
		seed = seed*31 + int(char)
	}
	w := sensorstate.CoverageWindow{AssetID: "asset-1", AgentID: "agent-1", HostID: "asset-1", Since: at, Until: at.Add(time.Second), InputDigest: fmt.Sprintf("%064x", seed), CreatedAt: at.Add(2 * time.Second), BatchCount: 1,
		States: []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "asset-1", AgentID: "agent-1", State: detection.StateActive, Since: at}}}
	w.Vector = sensorstate.BuildCoverageVector(w)
	w.Revision = sensorstate.RevisionFor(w)
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	return w
}

func receiptBuilder(t *testing.T, at time.Time, bindings []ports.TelemetryAssetBinding, timeline []endpoint.TimelineEntry, coverage []sensorstate.CoverageWindow) (*TargetEvidenceReceiptBuilder, *memory.ResponseVerificationStore, context.Context) {
	t.Helper()
	store := memory.NewResponseVerificationStore()
	builder, err := NewTargetEvidenceReceiptBuilder(receiptBindings{bindings}, receiptTimeline{timeline}, receiptCoverage{coverage}, store, receiptClock{at.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return builder, store, shared.WithTenant(context.Background(), "tenant-1")
}

func TestTargetEvidenceReceiptBuilderCompletenessAndSources(t *testing.T) {
	at := time.Unix(2_100_000, 0).UTC()
	req := receiptRequest(t, at)
	active := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at}
	cases := []struct {
		name       string
		bindings   []ports.TelemetryAssetBinding
		wantReason string
	}{
		{"missing", nil, "source_missing"},
		{"ambiguous", []ports.TelemetryAssetBinding{active, {TenantID: req.TenantID, AgentID: "agent-2", AssetID: "asset-1", UpdatedAt: at}}, "source_ambiguous"},
		{"stale", []ports.TelemetryAssetBinding{{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at.Add(-10 * time.Minute)}}, "source_stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder, _, ctx := receiptBuilder(t, at, tc.bindings, nil, nil)
			receipt, err := builder.Build(ctx, req)
			if err != nil || receipt.TimelineComplete || receipt.CoverageComplete || receipt.Saturated || len(receipt.Reasons) != 1 || receipt.Reasons[0] != tc.wantReason {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
	t.Run("complete", func(t *testing.T) {
		event := endpoint.TimelineEntry{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "process-1", Kind: endpoint.TimelineProcessExit, EventID: "event-1"}
		builder, _, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{active}, []endpoint.TimelineEntry{event}, []sensorstate.CoverageWindow{receiptWindow(t, at, "one")})
		receipt, err := builder.Build(ctx, req)
		if err != nil || !receipt.TimelineComplete || !receipt.CoverageComplete || receipt.Saturated || receipt.SourceHostID != "asset-1" || len(receipt.Reasons) != 1 || receipt.Reasons[0] != "complete" {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	})
}

func TestTargetEvidenceReceiptBuilderOrdersSaturatesAndValidatesReplay(t *testing.T) {
	at := time.Unix(2_100_100, 0).UTC()
	req := receiptRequest(t, at)
	binding := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at}
	windows := make([]sensorstate.CoverageWindow, 0, ports.MaxCoverageWindowLimit+1)
	for i := 0; i <= ports.MaxCoverageWindowLimit; i++ {
		windows = append(windows, receiptWindow(t, at, fmt.Sprintf("%d", i)))
	}
	timeline := []endpoint.TimelineEntry{
		{OccurredAt: at.Add(700 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "process-1", Kind: endpoint.TimelineProcessExit, EventID: "z"},
		{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "process-1", Kind: endpoint.TimelineProcessExec, EventID: "a"},
	}
	builder, _, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{binding}, timeline, windows)
	receipt, err := builder.Build(ctx, req)
	if err != nil || !receipt.Saturated || receipt.CoverageComplete || len(receipt.Coverage) != ports.MaxCoverageWindowLimit || !contains(receipt.Reasons, "coverage_saturated") || receipt.Timeline[0].EventID != "a" {
		t.Fatalf("saturated receipt=%+v err=%v", receipt, err)
	}
	if replay, err := builder.Build(ctx, req); err != nil || !fleetagent.SameResponseTargetEvidenceReceipt(receipt, replay) {
		t.Fatalf("exact replay=%+v err=%v", replay, err)
	}
	mismatch := req
	mismatch.VerificationChallenge = strings.Repeat("b", 64)
	if _, err := builder.Build(ctx, mismatch); err == nil {
		t.Fatal("replay with different challenge was accepted")
	}
}

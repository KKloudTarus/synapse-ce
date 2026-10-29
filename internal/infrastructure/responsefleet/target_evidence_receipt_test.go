package responsefleet

import (
	"context"
	"errors"
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

func (s receiptCoverage) ListCoverageWindowsBounded(_ context.Context, q ports.CoverageWindowQuery, _ int) ([]sensorstate.CoverageWindow, error) {
	var rows []sensorstate.CoverageWindow
	for _, row := range s.rows {
		if row.AgentID == q.AgentID && row.AssetID == q.AssetID && row.HostID == q.HostID {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func receiptRequest(t *testing.T, at time.Time) ports.ResponseVerificationRequest {
	t.Helper()
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "pe_11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return ports.ResponseVerificationRequest{TenantID: "tenant-1", EngagementID: "eng-1", Action: action,
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "pe_11111111111111111111111111111111"},
		ExecutorID: "agent:agent-1", ExecutorAgentID: "agent-1", AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("a", 64), AttemptedAt: at, DeadlineAt: at.Add(time.Minute)}
}

func receiptWindow(t *testing.T, at time.Time, revisionSeed string) sensorstate.CoverageWindow {
	t.Helper()
	seed := 0
	for _, char := range revisionSeed {
		seed = seed*31 + int(char)
	}
	w := sensorstate.CoverageWindow{AssetID: "asset-1", AgentID: "agent-1", HostID: "agent-1", Since: at, Until: at.Add(time.Second), InputDigest: fmt.Sprintf("%064x", seed), CreatedAt: at.Add(2 * time.Second), BatchCount: 1,
		States: []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "agent-1", AgentID: "agent-1", State: detection.StateActive, Since: at}}}
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
	agents := memory.NewFleetAgentStore()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	for _, binding := range bindings {
		agent, err := fleetagent.NewAgent(binding.AgentID, "tenant-1", binding.AgentID.String(), "linux", "test", "test", nil, "token-hash", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := agents.CreateAgent(ctx, agent); err != nil {
			t.Fatal(err)
		}
	}
	builder, err := NewTargetEvidenceReceiptBuilder(receiptBindings{bindings}, agents, receiptTimeline{timeline}, receiptCoverage{coverage}, store, receiptClock{at.Add(time.Second)}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return builder, store, ctx
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder, store, ctx := receiptBuilder(t, at, tc.bindings, nil, nil)
			_, err := builder.Build(ctx, req)
			if !errors.Is(err, ErrTargetEvidencePending) || !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("err=%v", err)
			}
			if _, found, err := store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); err != nil || found {
				t.Fatalf("receipt persisted: found=%v err=%v", found, err)
			}
		})
	}
	t.Run("complete", func(t *testing.T) {
		event := endpoint.TimelineEntry{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "pe_11111111111111111111111111111111", Kind: endpoint.TimelineProcessExit, EventID: "event-1"}
		active.UpdatedAt = at.Add(-time.Hour) // Inventory age is not a liveness signal.
		builder, _, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{active}, []endpoint.TimelineEntry{event}, []sensorstate.CoverageWindow{receiptWindow(t, at, "one")})
		receipt, err := builder.Build(ctx, req)
		if err != nil || !receipt.TimelineComplete || !receipt.CoverageComplete || receipt.Saturated || receipt.SourceHostID != "agent-1" || len(receipt.Reasons) != 1 || receipt.Reasons[0] != "complete" {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	})
}

func TestTargetEvidenceReceiptBuilderDoesNotUseAssetIDAsAuthenticatedHost(t *testing.T) {
	at := time.Unix(2_100_050, 0).UTC()
	req := receiptRequest(t, at)
	binding := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: req.ExecutorAgentID, AssetID: req.Target.ProcessAssetID, UpdatedAt: at}
	event := endpoint.TimelineEntry{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: binding.AssetID, SourceAgentID: binding.AgentID, SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID(binding.AgentID)), EntityKind: endpoint.EntityProcess, EntityID: req.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: "exit"}
	window := receiptWindow(t, at, "wrong-host")
	window.HostID = binding.AssetID
	for i := range window.States {
		window.States[i].HostID = binding.AssetID
	}
	window.Revision = sensorstate.RevisionFor(window)
	builder, store, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{binding}, []endpoint.TimelineEntry{event}, []sensorstate.CoverageWindow{window})
	if _, err := builder.Build(ctx, req); !errors.Is(err, ErrTargetEvidencePending) {
		t.Fatalf("non-authenticated host coverage accepted: %v", err)
	}
	if _, found, err := store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); err != nil || found {
		t.Fatalf("receipt persisted: found=%v err=%v", found, err)
	}
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
		{OccurredAt: at.Add(700 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "pe_11111111111111111111111111111111", Kind: endpoint.TimelineProcessExit, EventID: "z"},
		{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: "pe_11111111111111111111111111111111", Kind: endpoint.TimelineProcessExec, EventID: "a"},
	}
	builder, _, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{binding}, timeline, windows)
	_, err := builder.Build(ctx, req)
	if !errors.Is(err, ErrTargetEvidencePending) || !strings.Contains(err.Error(), "coverage_saturated") {
		t.Fatalf("err=%v", err)
	}
}

type mutableReceiptTimeline struct{ rows []endpoint.TimelineEntry }

func (s *mutableReceiptTimeline) AppendTimeline(_ context.Context, rows []endpoint.TimelineEntry) error {
	s.rows = append(s.rows, rows...)
	return nil
}
func (s *mutableReceiptTimeline) QueryTimeline(context.Context, ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	return append([]endpoint.TimelineEntry(nil), s.rows...), nil
}
func (s *mutableReceiptTimeline) LoadTimelineEntries(context.Context, shared.ID, []shared.ID) ([]endpoint.TimelineEntry, error) {
	return nil, nil
}

func TestTargetEvidenceReceiptWaitsForLateExitThenReplays(t *testing.T) {
	at := time.Unix(2_100_200, 0).UTC()
	req := receiptRequest(t, at)
	binding := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at.Add(-time.Hour)}
	builder, store, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{binding}, nil, []sensorstate.CoverageWindow{receiptWindow(t, at, "late")})
	timeline := &mutableReceiptTimeline{}
	builder.timeline = timeline
	if _, err := builder.Build(ctx, req); !errors.Is(err, ErrTargetEvidencePending) {
		t.Fatalf("missing exit: %v", err)
	}
	if _, found, err := store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); err != nil || found {
		t.Fatalf("pending receipt stored: found=%v err=%v", found, err)
	}
	timeline.rows = []endpoint.TimelineEntry{{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: req.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: "exit"}}
	first, err := builder.Build(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.WindowUntil.After(at.Add(501 * time.Millisecond)) {
		t.Fatalf("cutoff chased clock: %v", first.WindowUntil)
	}
	second, err := builder.Build(ctx, req)
	if err != nil || !fleetagent.SameResponseTargetEvidenceReceipt(first, second) {
		t.Fatalf("replay=%+v err=%v", second, err)
	}
	mismatch := req
	mismatch.VerificationChallenge = strings.Repeat("b", 64)
	if _, err := builder.Build(ctx, mismatch); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mismatch err=%v", err)
	}
}

type filteredReceiptTimeline struct{ rows []endpoint.TimelineEntry }

func (s filteredReceiptTimeline) AppendTimeline(context.Context, []endpoint.TimelineEntry) error {
	return nil
}
func (s filteredReceiptTimeline) LoadTimelineEntries(context.Context, shared.ID, []shared.ID) ([]endpoint.TimelineEntry, error) {
	return nil, nil
}
func (s filteredReceiptTimeline) QueryTimeline(_ context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	var out []endpoint.TimelineEntry
	for _, e := range s.rows {
		if !e.OccurredAt.Before(q.From) && !e.OccurredAt.After(q.To) {
			out = append(out, e)
		}
	}
	return out, nil
}

type filteredReceiptCoverage struct{ rows []sensorstate.CoverageWindow }

func (s filteredReceiptCoverage) ListCoverageWindowsBounded(_ context.Context, q ports.CoverageWindowQuery, _ int) ([]sensorstate.CoverageWindow, error) {
	var out []sensorstate.CoverageWindow
	for _, w := range s.rows {
		if w.Until.After(q.Since) && w.Since.Before(q.Until) {
			out = append(out, w)
		}
	}
	return out, nil
}

func TestReversalReceiptRequiresOriginalExitAndExactReplacement(t *testing.T) {
	at := time.Unix(2_200_000, 0).UTC()
	req := receiptRequest(t, at.Add(2*time.Second))
	req.Reversal = true
	req.OriginalAttemptKey, req.OriginalAttemptedAt = "original", at
	req.OriginalDeadlineAt, req.OriginalChallenge = at.Add(time.Minute), strings.Repeat("c", 64)
	req.ReplacementProcessEntityID = "pe_22222222222222222222222222222222"
	binding := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at}
	builder, store, ctx := receiptBuilder(t, at.Add(2*time.Second), []ports.TelemetryAssetBinding{binding}, nil, nil)
	base := endpoint.TimelineEntry{TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess}
	exit := base
	exit.OccurredAt, exit.EntityID, exit.Kind, exit.EventID = at.Add(500*time.Millisecond), req.Target.ProcessEntityID, endpoint.TimelineProcessExit, "original-exit"
	unrelated := base
	unrelated.OccurredAt, unrelated.EntityID, unrelated.Kind, unrelated.EventID = at.Add(2500*time.Millisecond), "pe_33333333333333333333333333333333", endpoint.TimelineProcessExec, "unrelated-exec"
	builder.timeline = filteredReceiptTimeline{[]endpoint.TimelineEntry{exit, unrelated}}
	builder.coverage = filteredReceiptCoverage{[]sensorstate.CoverageWindow{receiptWindow(t, at, "original"), receiptWindow(t, at.Add(2*time.Second), "reversal")}}
	if _, err := builder.Build(ctx, req); !errors.Is(err, ErrTargetEvidencePending) {
		t.Fatalf("unrelated exec err=%v", err)
	}
	if _, found, _ := store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); found {
		t.Fatal("unrelated exec sealed a receipt")
	}
	exec := unrelated
	exec.EntityID, exec.EventID = req.ReplacementProcessEntityID, "replacement-exec"
	builder.timeline = filteredReceiptTimeline{[]endpoint.TimelineEntry{exit, unrelated, exec}}
	receipt, err := builder.Build(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.OriginalEvidence == nil || receipt.OriginalEvidence.Exit.EventID != exit.EventID || receipt.ReplacementProcessEntityID != exec.EntityID {
		t.Fatalf("unbound receipt=%+v", receipt)
	}
	if receipt.OriginalEvidence.Exit.OccurredAt.After(receipt.AttemptedAt) {
		t.Fatal("original exit was moved into reversal")
	}
}

func TestContinuousCoverageUsesNewestMaterializationAndFailsClosedOnTie(t *testing.T) {
	at := time.Unix(2_300_000, 0).UTC()
	good := receiptWindow(t, at, "good")
	bad := good
	bad.GapCount = 1
	bad.Vector = sensorstate.BuildCoverageVector(bad)
	bad.Revision = sensorstate.RevisionFor(bad)
	bad.CreatedAt = good.CreatedAt.Add(time.Second)
	if continuousCoverage(at, at.Add(time.Second), []sensorstate.CoverageWindow{good, bad}) {
		t.Fatal("newer gap was ignored")
	}
	bad.CreatedAt = good.CreatedAt
	if continuousCoverage(at, at.Add(time.Second), []sensorstate.CoverageWindow{bad, good}) {
		t.Fatal("tied conflicting revisions did not fail closed")
	}
	good.CreatedAt = bad.CreatedAt.Add(time.Second)
	if !continuousCoverage(at, at.Add(time.Second), []sensorstate.CoverageWindow{bad, good}) {
		t.Fatal("newer repaired coverage was ignored")
	}
}

func TestReceiptWaitsForCompleteCoverageAndFreshHeartbeat(t *testing.T) {
	at := time.Unix(2_400_000, 0).UTC()
	req := receiptRequest(t, at)
	binding := ports.TelemetryAssetBinding{TenantID: req.TenantID, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: at}
	event := endpoint.TimelineEntry{OccurredAt: at.Add(500 * time.Millisecond), TenantID: req.TenantID, AssetID: "asset-1", SourceAgentID: "agent-1", SourceAgentSessionID: shared.ID(fleetagent.CanonicalSessionID("agent-1")), EntityKind: endpoint.EntityProcess, EntityID: req.Target.ProcessEntityID, Kind: endpoint.TimelineProcessExit, EventID: "exit"}
	gap := receiptWindow(t, at, "gap")
	gap.GapCount = 1
	gap.Vector = sensorstate.BuildCoverageVector(gap)
	gap.Revision = sensorstate.RevisionFor(gap)
	builder, store, ctx := receiptBuilder(t, at, []ports.TelemetryAssetBinding{binding}, []endpoint.TimelineEntry{event}, []sensorstate.CoverageWindow{gap})
	if _, err := builder.Build(ctx, req); !errors.Is(err, ErrTargetEvidencePending) || !strings.Contains(err.Error(), "coverage_incomplete") {
		t.Fatalf("gap err=%v", err)
	}
	if _, found, _ := store.GetResponseTargetEvidenceReceipt(ctx, req.AttemptKey); found {
		t.Fatal("coverage gap sealed receipt")
	}
	builder.clock = receiptClock{at.Add(6 * time.Minute)}
	if _, err := builder.Build(ctx, req); !errors.Is(err, ErrTargetEvidencePending) || !strings.Contains(err.Error(), "source_stale") {
		t.Fatalf("stale heartbeat err=%v", err)
	}
}

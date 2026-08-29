package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coveragewindow"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
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

func TestP3QuotaGapSurvivesRestartAndDegradesComposedCoverage(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg := telemetryGapSpoolConfig(t, now)
	wal, err := spool.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(map[uint64]struct{})
	for index := range 12 {
		position, enqueueErr := wal.Enqueue(ctx, telemetryGapP3Item(index, now))
		if enqueueErr == nil {
			accepted[position.Sequence] = struct{}{}
		}
	}
	if len(accepted) == 0 {
		t.Fatal("spool accepted no P3 records")
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := spool.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := recovered.Close(); err != nil {
			t.Errorf("close recovered spool: %v", err)
		}
	})
	records, err := recovered.Peek(ctx, ports.PeekSpoolRequest{MaxRecords: 100, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	present := make(map[uint64]struct{}, len(records))
	for _, record := range records {
		if record.Position.Priority == fleetagent.PriorityP3 {
			present[record.Position.Sequence] = struct{}{}
		}
	}
	gaps, err := recovered.Gaps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var quotaGap ports.SpoolGap
	for _, gap := range gaps {
		if gap.Priority == fleetagent.PriorityP3 && gap.KnownSequence && gap.Reason == ports.SpoolGapQuotaEviction {
			quotaGap = gap
			break
		}
	}
	if quotaGap.ID.IsZero() {
		t.Fatalf("durable gaps = %+v, want a known P3 quota-eviction gap", gaps)
	}
	for sequence := range accepted {
		if _, ok := present[sequence]; ok {
			continue
		}
		if sequence < quotaGap.FromSequence || sequence > quotaGap.ToSequence {
			t.Fatalf("accepted sequence %d is neither present nor covered by durable gap %+v", sequence, quotaGap)
		}
	}

	const (
		tenantID = shared.ID("tenant-gap")
		agentID  = shared.ID("agent-gap")
		assetID  = shared.ID("asset-gap")
	)
	tenantCtx := shared.WithTenant(ctx, tenantID)
	signer := testTelemetrySigner(t, agentID.String())
	report, err := buildTelemetryGapReport(fleetclient.Credential{
		AgentID: agentID.String(), AssetID: assetID.String(),
	}, signer, quotaGap)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleetagent.VerifyTelemetryGapWithKey(signer.Key, now, report); err != nil {
		t.Fatalf("verify durable quota gap report: %v", err)
	}

	keys := memory.NewAgentSigningKeyStore()
	if err := keys.Register(tenantCtx, signer.Key); err != nil {
		t.Fatal(err)
	}
	transport := memory.NewTelemetryTransportStore()
	if err := transport.BindTelemetryAsset(tenantCtx, ports.TelemetryAssetBinding{
		TenantID: tenantID, AgentID: agentID, AssetID: assetID, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	ingest, err := telemetryingest.NewService(
		transport,
		keys,
		memory.NewPrivacyPolicyStore(),
		telemetryGapAudit{},
		telemetryGapClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.IngestGap(tenantCtx, agentID, report); err != nil {
		t.Fatalf("ingest signed quota gap: %v", err)
	}

	since := now.Add(-time.Minute)
	until := now.Add(time.Minute)
	facts, err := transport.ListCoverageGapFacts(tenantCtx, ports.CoverageGapQuery{
		AgentID: agentID, AssetID: assetID, Since: since, Until: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("coverage gap facts = %+v, want one agent-origin fact", facts)
	}
	fact := facts[0]
	if fact.Source != ports.CoverageGapAgent || fact.FactID != quotaGap.ID || !fact.KnownSequence ||
		fact.FromSequence != quotaGap.FromSequence || fact.ToSequence != quotaGap.ToSequence ||
		fact.Count != quotaGap.Count || fact.Reason != string(fleetagent.TelemetryGapQuotaEviction) {
		t.Fatalf("persisted coverage gap fact = %+v, want exact durable spool gap identity", fact)
	}

	states := memory.NewSensorStateStore()
	observation := sensorstate.Observation{
		ReportID: "report-active-process", AgentID: agentID, HostID: agentID, AssetID: assetID,
		Kind: sensorstate.RecordSensorState, ObservedAt: since.Add(-time.Minute), RecordedAt: now,
		PayloadDigest: strings.Repeat("a", 64), SignedContentDigest: strings.Repeat("b", 64), SchemaVersion: 1,
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: agentID, AgentID: agentID,
			State: detection.StateActive, Since: since.Add(-time.Minute),
		}},
	}
	if err := states.AppendSensorState(tenantCtx, observation); err != nil {
		t.Fatal(err)
	}

	withGap, err := coveragewindow.NewService(
		states, transport, transport, memory.NewCoverageWindowStore(), telemetryGapClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	window, err := withGap.Compose(tenantCtx, coveragewindow.ComposeRequest{
		AgentID: agentID, AssetID: assetID, HostID: agentID, Since: since, Until: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	if window.GapCount != 1 || window.SampledCount != 0 || window.TruncatedCount != 0 || window.DroppedCount != 0 {
		t.Fatalf("coverage dispositions = sampled:%d truncated:%d dropped:%d gaps:%d, want 0/0/0/1",
			window.SampledCount, window.TruncatedCount, window.DroppedCount, window.GapCount)
	}
	if window.Vector.Process != 80 || !containsString(window.Vector.Reasons, "telemetry_gap:1") {
		t.Fatalf("process coverage/reasons = %d/%v, want 80 with telemetry_gap:1", window.Vector.Process, window.Vector.Reasons)
	}
	for _, reason := range window.Vector.Reasons {
		if strings.HasPrefix(reason, "telemetry_dropped:") {
			t.Fatalf("quota gap fabricated dropped telemetry reason %q", reason)
		}
	}

	withoutGapTransport := memory.NewTelemetryTransportStore()
	withoutGap, err := coveragewindow.NewService(
		states, withoutGapTransport, withoutGapTransport, memory.NewCoverageWindowStore(), telemetryGapClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := withoutGap.Compose(tenantCtx, coveragewindow.ComposeRequest{
		AgentID: agentID, AssetID: assetID, HostID: agentID, Since: since, Until: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Vector.Process != 100 || baseline.GapCount != 0 {
		t.Fatalf("baseline process coverage/gaps = %d/%d, want 100/0", baseline.Vector.Process, baseline.GapCount)
	}
	if window.InputDigest == baseline.InputDigest || window.Revision == baseline.Revision {
		t.Fatal("durable gap did not participate in immutable coverage input identity")
	}
}

type telemetryGapClock struct{ now time.Time }

func (c telemetryGapClock) Now() time.Time { return c.now }

type telemetryGapAudit struct{}

func (telemetryGapAudit) Record(context.Context, ports.AuditEntry) error     { return nil }
func (telemetryGapAudit) RecordOnce(context.Context, ports.AuditEntry) error { return nil }

func telemetryGapSpoolConfig(t *testing.T, now time.Time) spool.Config {
	t.Helper()
	return spool.Config{
		Dir: t.TempDir(), Session: "session-gap", Boot: "boot-gap",
		MaxBytes: 6 << 10, MaxGapBytes: 4 << 10, SegmentBytes: 1200, MaxRecordBytes: 600,
		PeekRecords: 128, PeekBytes: 1 << 20, BatchInterval: time.Hour, BatchBytes: 1 << 20,
		Sync: map[fleetagent.DeliveryPriority]spool.SyncPolicy{
			fleetagent.PriorityP0: spool.SyncAlways,
			fleetagent.PriorityP1: spool.SyncAlways,
			fleetagent.PriorityP2: spool.SyncAlways,
			fleetagent.PriorityP3: spool.SyncAlways,
		},
		Now: func() time.Time { return now },
	}
}

func telemetryGapP3Item(index int, now time.Time) ports.SpoolItem {
	id := shared.ID("raw-gap-" + time.Unix(int64(index), 0).UTC().Format("150405"))
	return ports.SpoolItem{
		Kind: ports.SpoolRecordTelemetry, Priority: fleetagent.PriorityP3,
		EventID: id, EventClass: detection.ClassProcess, ContentType: "application/json",
		Payload: bytes.Repeat([]byte(id.String()+"|"), 32), ObservedAt: now,
		SchemaVersion: 1,
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

package memory

import (
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCoverageGapReaderPreservesOriginsAndHalfOpenBounds(t *testing.T) {
	store := NewTelemetryTransportStore()
	tenant := shared.ID("tenant-coverage-gaps")
	ctx := coverageTenant(tenant)
	at := time.Date(2026, 8, 27, 12, 0, 0, 123456000, time.UTC)
	agentID := shared.ID("agent-1")
	assetID := shared.ID("asset-1")
	streamID := shared.ID("stream-1")

	if err := store.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
		TenantID: tenant, AgentID: agentID, AssetID: assetID, UpdatedAt: at,
	}); err != nil {
		t.Fatalf("BindTelemetryAsset() error = %v", err)
	}
	for _, batch := range []ports.TelemetryEventBatch{
		coverageGapBatch(agentID, assetID, streamID, 1, at),
		coverageGapBatch(agentID, assetID, streamID, 3, at.Add(2*time.Minute)),
	} {
		if err := store.CommitBatch(ctx, batch); err != nil {
			t.Fatalf("CommitBatch() error = %v", err)
		}
	}
	if err := store.SaveStreamState(ctx, ports.TelemetryStreamState{
		AgentID: agentID, StreamID: streamID, Epoch: 1, Contiguous: 1, Pending: []uint64{3}, UpdatedAt: at.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveStreamState() error = %v", err)
	}
	if err := store.RecordAgentGap(ctx, ports.TelemetryAgentGap{
		GapID: "agent-gap-1", AgentID: agentID, AssetID: assetID, StreamID: streamID,
		Priority: fleetagent.PriorityP3, Epoch: 1, KnownSequence: true,
		FromSequence: 2, ToSequence: 2, Count: 1, Reason: fleetagent.TelemetryGapQuotaBackpressure,
		FromAt: at.Add(time.Minute), ToAt: at.Add(time.Minute),
		FirstReportedAt: at.Add(3 * time.Minute), UpdatedAt: at.Add(3 * time.Minute),
	}); err != nil {
		t.Fatalf("RecordAgentGap() error = %v", err)
	}
	if err := store.RecordAgentGap(ctx, ports.TelemetryAgentGap{
		GapID: "at-until", AgentID: agentID, AssetID: assetID, StreamID: streamID,
		Priority: fleetagent.PriorityP3, Epoch: 1, Count: 1, Reason: fleetagent.TelemetryGapIOFailure,
		FromAt: at.Add(10 * time.Minute), ToAt: at.Add(10 * time.Minute),
		FirstReportedAt: at.Add(11 * time.Minute), UpdatedAt: at.Add(11 * time.Minute),
	}); err != nil {
		t.Fatalf("RecordAgentGap(at Until) error = %v", err)
	}

	facts, err := store.ListCoverageGapFacts(ctx, ports.CoverageGapQuery{
		AgentID: agentID, AssetID: assetID, Since: at, Until: at.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ListCoverageGapFacts() error = %v", err)
	}
	if len(facts) != 2 {
		t.Fatalf("facts = %#v, want separate inferred and agent-origin facts", facts)
	}
	if facts[0].Source == facts[1].Source {
		t.Fatalf("sources = %q, %q, want distinct origins", facts[0].Source, facts[1].Source)
	}
	for _, fact := range facts {
		if !fact.KnownSequence || fact.FromSequence != 2 || fact.ToSequence != 2 {
			t.Fatalf("fact coordinates = %#v, want sequence 2", fact)
		}
	}
	wantInferredID := ports.InferredCoverageGapFactID(agentID, streamID, 1, 2, 2, at.Add(2*time.Minute))
	for _, fact := range facts {
		if fact.Source == ports.CoverageGapInferred && fact.FactID != wantInferredID {
			t.Fatalf("inferred FactID = %q, want %q", fact.FactID, wantInferredID)
		}
	}
	other, err := store.ListCoverageGapFacts(coverageTenant("tenant-other"), ports.CoverageGapQuery{
		AgentID: agentID, AssetID: assetID, Since: at, Until: at.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("other tenant ListCoverageGapFacts() error = %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other tenant saw %d gap facts", len(other))
	}
}

func coverageGapBatch(agentID, assetID, streamID shared.ID, sequence uint64, observedAt time.Time) ports.TelemetryEventBatch {
	return ports.TelemetryEventBatch{
		BatchID: shared.ID(fmt.Sprintf("batch-%d", sequence)), PayloadDigest: "payload",
		AgentID: agentID, StreamID: streamID, AssetID: assetID,
		Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: sequence, SchemaVersion: 1,
		EventTimeMin: observedAt, EventTimeMax: observedAt,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "policy",
		Events: []ports.StoredTelemetryEvent{{
			EventID: shared.ID(fmt.Sprintf("event-%d", sequence)), Class: detection.ClassProcess,
			Digest: "digest", RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("payload"), ObservedAt: observedAt,
		}},
	}
}

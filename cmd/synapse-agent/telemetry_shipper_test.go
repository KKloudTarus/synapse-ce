package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeTelemetryTransport struct {
	response fleetclient.TelemetryShipResponse
	err      error
	calls    int
	last     fleetclient.TelemetryIngestRequest
}

func (f *fakeTelemetryTransport) RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error {
	return nil
}

func (f *fakeTelemetryTransport) ShipTelemetry(_ context.Context, _ string, req fleetclient.TelemetryIngestRequest) (fleetclient.TelemetryShipResponse, error) {
	f.calls++
	f.last = req
	return f.response, f.err
}

func testTelemetrySigner(t *testing.T, agent string) fleetclient.TelemetrySigner {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	key, err := fleetclient.BuildTelemetrySigningKey(agent, private, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return fleetclient.TelemetrySigner{PrivateKey: private, Key: key}
}

// testTelemetrySpoolItem builds an enqueue item whose payload is a real telemetry envelope with
// the envelope content type. The shipper refuses to ship a WAL record of any other content type,
// so a fixture that writes raw JSON never reaches the behaviour under test.
func testTelemetrySpoolItem(agent string, sequence uint64, schema int) ports.SpoolItem {
	record := testTelemetryRecord(agent, sequence, schema)
	return ports.SpoolItem{
		Kind:          record.Kind,
		Priority:      record.Position.Priority,
		EventID:       record.EventID,
		EventClass:    record.EventClass,
		ContentType:   record.ContentType,
		Payload:       record.Payload,
		ObservedAt:    record.ObservedAt,
		MustNotShed:   record.MustNotShed,
		SchemaVersion: record.SchemaVersion,
	}
}

func testTelemetryRecord(agent string, sequence uint64, schema int) ports.SpoolRecord {
	now := time.Unix(1_700_000_000+int64(sequence), 0).UTC()
	eventID := shared.ID("event-" + strconv.FormatUint(sequence, 10))
	envelope := telemetry.TelemetryEnvelope{
		SchemaVersion:   schema,
		EventID:         eventID,
		EventType:       "process.exec",
		EventClass:      detection.ClassProcess,
		AgentID:         shared.ID(agent),
		AgentSessionID:  shared.ID(fleetagent.CanonicalSessionID(shared.ID(agent))),
		AssetID:         "asset-1",
		BootID:          "boot-1",
		StreamID:        "source-stream-1",
		OccurredAt:      now,
		ObservedAt:      now,
		Sequence:        sequence,
		DataQuality:     telemetry.QualityMissingPPID,
		ResourceContext: telemetry.ResourceContext{},
		Event: telemetry.TelemetryEvent{
			Class: detection.ClassProcess,
			Process: &telemetry.ProcessObservation{
				Kind: "exec", PID: 10, EntityID: "process-1", Comm: "curl",
			},
		},
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		panic(err)
	}
	return ports.SpoolRecord{
		Kind: ports.SpoolRecordTelemetry,
		Position: fleetagent.StreamPosition{
			Priority: fleetagent.PriorityP3,
			Epoch:    4,
			Sequence: sequence,
			Session:  fleetagent.CanonicalSessionID(shared.ID(agent)),
			Boot:     "boot-1",
		},
		EventID:       eventID,
		EventClass:    detection.ClassProcess,
		ContentType:   telemetryEnvelopeContentType,
		Payload:       payload,
		ObservedAt:    now,
		EnqueuedAt:    now,
		MustNotShed:   false,
		SchemaVersion: schema,
	}
}

func TestBuildTelemetryIngestRequestUsesBatchSequenceNotWALSequence(t *testing.T) {
	signer := testTelemetrySigner(t, "agent-1")
	records := []ports.SpoolRecord{
		testTelemetryRecord("agent-1", 11, 2),
		testTelemetryRecord("agent-1", 12, 2),
	}
	req, err := buildTelemetryIngestRequest(fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"}, signer, records, 7)
	if err != nil {
		t.Fatal(err)
	}
	m := req.Manifest
	if m.Position.Sequence != 7 || m.PreviousSequence != 6 {
		t.Fatalf("manifest used WAL coordinates instead of batch sequence: seq=%d prev=%d", m.Position.Sequence, m.PreviousSequence)
	}
	if m.Position.Epoch != 4 || m.Position.Priority != fleetagent.PriorityP3 {
		t.Fatalf("manifest lane/incarnation = %+v", m.Position)
	}
	if len(req.Events) != 2 || len(m.Events) != 2 || m.KeptCount != 2 {
		t.Fatalf("batch membership = events:%d refs:%d kept:%d", len(req.Events), len(m.Events), m.KeptCount)
	}
	if err := fleetagent.VerifyTelemetryManifestWithKey(signer.Key, time.Unix(1_700_000_000, 0).UTC(), m); err != nil {
		t.Fatalf("signed manifest did not verify: %v", err)
	}
	req2, err := buildTelemetryIngestRequest(fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"}, signer, records, 7)
	if err != nil {
		t.Fatal(err)
	}
	if req2.Manifest.BatchID != m.BatchID {
		t.Fatalf("same delivery coordinates/content must derive stable batch id: %q != %q", req2.Manifest.BatchID, m.BatchID)
	}
}

func TestBuildTelemetryIngestRequestCommitsRetainedTruncation(t *testing.T) {
	signer := testTelemetrySigner(t, "agent-1")
	clean := testTelemetryRecord("agent-1", 11, 2)
	truncatedArgv := testTelemetryRecord("agent-1", 12, 2)
	truncatedPath := testTelemetryRecord("agent-1", 13, 2)
	both := testTelemetryRecord("agent-1", 14, 2)
	setQuality := func(record *ports.SpoolRecord, quality telemetry.DataQuality) {
		t.Helper()
		var envelope telemetry.TelemetryEnvelope
		if err := json.Unmarshal(record.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.DataQuality = quality
		payload, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		record.Payload = payload
	}
	setQuality(&truncatedArgv, telemetry.QualityTruncatedArgv)
	setQuality(&truncatedPath, telemetry.QualityTruncatedPath)
	setQuality(&both, telemetry.QualityTruncatedArgv.With(telemetry.QualityTruncatedPath))

	req, err := buildTelemetryIngestRequest(
		fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"},
		signer,
		[]ports.SpoolRecord{clean, truncatedArgv, truncatedPath, both},
		7,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := req.Manifest.TruncatedCount, 3; got != want {
		t.Fatalf("truncated count = %d, want %d retained events", got, want)
	}
	if req.Manifest.SampledOutCount != 0 || req.Manifest.DroppedCount != 0 {
		t.Fatalf("retained truncation changed loss dispositions: sampled=%d dropped=%d", req.Manifest.SampledOutCount, req.Manifest.DroppedCount)
	}
	wantPolicy, err := fleetagent.SamplingPolicyDigest(
		fleetagent.NoSamplingAlgorithm,
		fleetagent.NoSamplingPolicyID,
		"",
		fleetagent.NoSamplingVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if req.Manifest.SamplingPolicyDigest != wantPolicy {
		t.Fatalf("sampling policy digest = %q, want stable no-sampling policy %q", req.Manifest.SamplingPolicyDigest, wantPolicy)
	}
	if err := fleetagent.VerifyTelemetryManifestWithKey(signer.Key, time.Unix(1_700_000_000, 0).UTC(), req.Manifest); err != nil {
		t.Fatalf("signed manifest did not verify: %v", err)
	}
}

func TestBuildTelemetryIngestRequestRejectsUnverifiableTruncation(t *testing.T) {
	signer := testTelemetrySigner(t, "agent-1")
	valid := testTelemetryRecord("agent-1", 11, 2)
	wrongType := valid
	wrongType.ContentType = "application/json"
	malformed := valid
	malformed.Payload = []byte(`{"event":"not-an-envelope"}`)

	for _, tc := range []struct {
		name   string
		record ports.SpoolRecord
	}{
		{name: "unexpected content type", record: wrongType},
		{name: "malformed envelope", record: malformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildTelemetryIngestRequest(
				fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"},
				signer,
				[]ports.SpoolRecord{tc.record},
				7,
			); err == nil {
				t.Fatal("build request succeeded without trustworthy truncation metadata")
			}
		})
	}
}

func TestTelemetryBatchPrefixStopsAtSchemaBoundary(t *testing.T) {
	records := []ports.SpoolRecord{
		testTelemetryRecord("agent-1", 1, 1),
		testTelemetryRecord("agent-1", 2, 1),
		testTelemetryRecord("agent-1", 3, 2),
	}
	prefix, err := telemetryBatchPrefix(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefix) != 2 {
		t.Fatalf("schema boundary should end batch at two records, got %d", len(prefix))
	}
}

func TestTelemetryBatchJournalRoundTrip(t *testing.T) {
	store := newTelemetryBatchJournalStore(t.TempDir())
	signer := testTelemetrySigner(t, "agent-1")
	records := []ports.SpoolRecord{testTelemetryRecord("agent-1", 5, 2)}
	req, err := buildTelemetryIngestRequest(fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1"}, signer, records, 3)
	if err != nil {
		t.Fatal(err)
	}
	state := telemetryBatchLaneState{
		Version:       telemetryBatchJournalVersion,
		Priority:      fleetagent.PriorityP3,
		Epoch:         4,
		LastCommitted: 2,
		Pending:       &telemetryPendingBatch{Epoch: 4, Sequence: 3, WALFrom: 5, WALThrough: 5, Request: req},
	}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pending == nil || got.Pending.Sequence != 3 || got.Pending.WALThrough != 5 || got.Pending.Request.Manifest.BatchID != req.Manifest.BatchID {
		t.Fatalf("journal round trip = %+v", got)
	}
}

func TestTelemetryACKedJournalFinalizesWithoutNetworkReplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live telemetry spool is paired with the Linux-only eBPF sensor")
	}
	ctx := context.Background()
	stateDir := t.TempDir()
	r := &runner{cfg: config{stateDir: stateDir, spoolBytes: 4 << 20}}
	cred := fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1", Token: "token"}
	durable, _, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	position, err := durable.Enqueue(ctx, testTelemetrySpoolItem("agent-1", 1, 2))
	if err != nil {
		t.Fatal(err)
	}
	records, err := durable.PeekPriority(ctx, fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil || len(records) != 1 {
		t.Fatalf("peek: records=%d err=%v", len(records), err)
	}
	signer := testTelemetrySigner(t, "agent-1")
	req, err := buildTelemetryIngestRequest(cred, signer, records, 1)
	if err != nil {
		t.Fatal(err)
	}
	journal := newTelemetryBatchJournalStore(stateDir)
	state := telemetryBatchLaneState{
		Version: telemetryBatchJournalVersion, Priority: fleetagent.PriorityP3, Epoch: position.Epoch,
		Pending: &telemetryPendingBatch{Epoch: position.Epoch, Sequence: 1, WALFrom: position.Sequence, WALThrough: position.Sequence, Acked: true, Request: req},
	}
	if err := journal.Save(state); err != nil {
		t.Fatal(err)
	}
	api := &fakeTelemetryTransport{response: fleetclient.TelemetryShipResponse{ACK: 1}}
	shipped, _, err := r.shipTelemetryPriority(ctx, durable, api, cred, signer, journal, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	if !shipped || api.calls != 0 {
		t.Fatalf("acked journal should finalize locally without network: shipped=%t calls=%d", shipped, api.calls)
	}
	left, err := durable.PeekPriority(ctx, fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil || len(left) != 0 {
		t.Fatalf("WAL not reclaimed after ack recovery: left=%d err=%v", len(left), err)
	}
	final, err := journal.Load(fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	if final.Pending != nil || final.LastCommitted != 1 {
		t.Fatalf("journal did not finalize ACK: %+v", final)
	}
}

func TestTelemetry429RetainsPendingJournalAndWAL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live telemetry spool is paired with the Linux-only eBPF sensor")
	}
	ctx := context.Background()
	stateDir := t.TempDir()
	r := &runner{cfg: config{stateDir: stateDir, spoolBytes: 4 << 20}}
	cred := fleetclient.Credential{AgentID: "agent-1", AssetID: "asset-1", Token: "token"}
	durable, _, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	if _, err := durable.Enqueue(ctx, testTelemetrySpoolItem("agent-1", 1, 2)); err != nil {
		t.Fatal(err)
	}
	signer := testTelemetrySigner(t, "agent-1")
	api := &fakeTelemetryTransport{err: &fleetclient.HTTPStatusError{StatusCode: 429, RetryAfter: 3 * time.Second}}
	journal := newTelemetryBatchJournalStore(stateDir)
	shipped, retryAfter, err := r.shipTelemetryPriority(ctx, durable, api, cred, signer, journal, fleetagent.PriorityP3)
	if shipped || err == nil || retryAfter != 3*time.Second {
		t.Fatalf("429 result: shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	var status *fleetclient.HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != 429 {
		t.Fatalf("want retained 429 status, got %v", err)
	}
	state, err := journal.Load(fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || state.Pending.Acked {
		t.Fatalf("retryable failure must retain unacked pending request: %+v", state)
	}
	left, err := durable.PeekPriority(ctx, fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil || len(left) != 1 {
		t.Fatalf("retryable failure must retain WAL: left=%d err=%v", len(left), err)
	}
}

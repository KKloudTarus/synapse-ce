package detectionship

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var shipNow = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

type memoryState struct {
	mu      sync.Mutex
	state   ports.DetectionDeliveryState
	ok      bool
	saves   int
	saveErr error
}

func (m *memoryState) Load() (ports.DetectionDeliveryState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneState(m.state), m.ok, nil
}

func (m *memoryState) Save(state ports.DetectionDeliveryState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.state, m.ok = cloneState(state), true
	m.saves++
	return nil
}

func cloneState(in ports.DetectionDeliveryState) ports.DetectionDeliveryState {
	body, _ := json.Marshal(in)
	var out ports.DetectionDeliveryState
	_ = json.Unmarshal(body, &out)
	return out
}

type memorySpool struct {
	mu           sync.Mutex
	records      []ports.SpoolRecord
	acked        uint64
	epoch        uint64
	currentEpoch uint64
	peeks        []ports.PeekSpoolRequest
}

func (s *memorySpool) Enqueue(context.Context, ports.SpoolItem) (fleetagent.StreamPosition, error) {
	return fleetagent.StreamPosition{}, errors.New("unused")
}
func (s *memorySpool) Peek(_ context.Context, req ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peeks = append(s.peeks, req)
	limit := len(s.records)
	if req.MaxRecords > 0 && limit > req.MaxRecords {
		limit = req.MaxRecords
	}
	out := append([]ports.SpoolRecord(nil), s.records[:limit]...)
	return out, nil
}
func (s *memorySpool) Ack(_ context.Context, ack ports.SpoolACK) (ports.SpoolACKResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.records[:0]
	removed := 0
	for _, record := range s.records {
		if record.Position.Priority == ack.Priority && record.Position.Epoch == ack.Epoch && record.Position.Sequence <= ack.Through {
			removed++
			continue
		}
		kept = append(kept, record)
	}
	s.records = kept
	s.acked, s.epoch = ack.Through, ack.Epoch
	return ports.SpoolACKResult{RemovedRecords: removed, HighestACKed: ack.Through}, nil
}
func (*memorySpool) Flush(context.Context) error                    { return nil }
func (*memorySpool) Gaps(context.Context) ([]ports.SpoolGap, error) { return nil, nil }
func (s *memorySpool) Stats(context.Context) (ports.SpoolStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	currentEpoch := s.currentEpoch
	if currentEpoch == 0 {
		currentEpoch = s.epoch
	}
	stats := ports.SpoolStats{Priorities: []ports.SpoolPriorityStats{{Priority: fleetagent.PriorityP1,
		CurrentEpoch: currentEpoch}}}
	if s.acked > 0 {
		stats.EpochACKs = []ports.SpoolEpochACK{{Priority: fleetagent.PriorityP1, Epoch: s.epoch, HighestACKed: s.acked}}
	}
	return stats, nil
}
func (*memorySpool) Close() error { return nil }

type captureTransport struct {
	registerErrs []error
	sendErrs     []error
	keys         []fleetagent.AgentSigningKey
	proofs       []string
	batches      []fleetagent.AgentBatch
	items        [][]fleetagent.DetectionBatchItem
	onSend       func(int)
}

func (c *captureTransport) RegisterDetectionKey(_ context.Context, _ string, key fleetagent.AgentSigningKey, proof string) error {
	c.keys, c.proofs = append(c.keys, key), append(c.proofs, proof)
	index := len(c.keys) - 1
	if index < len(c.registerErrs) {
		return c.registerErrs[index]
	}
	return nil
}
func (c *captureTransport) SendDetectionBatch(_ context.Context, _ string, batch fleetagent.AgentBatch, items []fleetagent.DetectionBatchItem) error {
	c.batches = append(c.batches, batch)
	c.items = append(c.items, append([]fleetagent.DetectionBatchItem(nil), items...))
	index := len(c.batches) - 1
	if c.onSend != nil {
		c.onSend(index)
	}
	if index < len(c.sendErrs) {
		return c.sendErrs[index]
	}
	return nil
}

type statusError struct{ status int }

func (e statusError) Error() string                 { return fmt.Sprintf("status %d", e.status) }
func (e statusError) ResponseStatus() (int, string) { return e.status, "" }

func testConfig() Config {
	return Config{AgentID: "agent-1", EngagementID: "eng-1", Token: "secret", Now: func() time.Time { return shipNow },
		IdleInterval: time.Millisecond, Retry: func(error, uint) (bool, time.Duration) { return false, 0 }}
}

func TestDeliverOnceRegistersSignsBatchesAndACKsP1(t *testing.T) {
	spool := &memorySpool{records: []ports.SpoolRecord{spoolDetection(1, "det-1"), spoolDetection(2, "det-2")}}
	state := &memoryState{}
	transport := &captureTransport{}
	service, err := NewService(spool, transport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := service.DeliverOnce(context.Background())
	if err != nil || !delivered {
		t.Fatalf("delivered=%v err=%v", delivered, err)
	}
	if len(transport.keys) != 1 || len(transport.batches) != 1 || len(transport.items[0]) != 2 {
		t.Fatalf("keys=%d batches=%d items=%d", len(transport.keys), len(transport.batches), len(transport.items[0]))
	}
	if err := fleetagent.VerifyKeyPossession(transport.keys[0], transport.proofs[0]); err != nil {
		t.Fatalf("registration proof: %v", err)
	}
	batch := transport.batches[0]
	if batch.Sequence != 1 || batch.AgentID != "agent-1" || batch.EngagementID != "eng-1" || batch.KeyID != transport.keys[0].KeyID {
		t.Fatalf("batch identity = %#v", batch)
	}
	if err := fleetagent.VerifyBatch(transport.keys[0].PublicKey, batch); err != nil {
		t.Fatalf("batch signature: %v", err)
	}
	for i, item := range transport.items[0] {
		body, _ := json.Marshal(item.Detection)
		if got := fleetagent.DetectionContentHash(body, item.AssetID); got != batch.Detections[i].ContentSHA256 {
			t.Fatalf("item %d content digest = %s, want %s", i, got, batch.Detections[i].ContentSHA256)
		}
	}
	if spool.acked != 2 || len(spool.records) != 0 {
		t.Fatalf("WAL ack=%d records=%d", spool.acked, len(spool.records))
	}
	if state.state.Pending != nil || state.state.NextSequence != 2 || state.state.Key == nil {
		t.Fatalf("state after delivery = %#v", state.state)
	}
	if len(spool.peeks) == 0 || spool.peeks[0].OnlyPriority == nil || *spool.peeks[0].OnlyPriority != fleetagent.PriorityP1 {
		t.Fatalf("shipper did not isolate the P1 lane: %#v", spool.peeks)
	}
}

func TestLostResponseRestartsWithSameSequenceMembershipAndKey(t *testing.T) {
	spool := &memorySpool{records: []ports.SpoolRecord{spoolDetection(1, "det-1")}}
	state := &memoryState{}
	firstTransport := &captureTransport{sendErrs: []error{errors.New("connection reset")}}
	first, err := NewService(spool, firstTransport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := first.DeliverOnce(context.Background()); err == nil || delivered {
		t.Fatalf("lost response delivered=%v err=%v", delivered, err)
	}
	if state.state.Pending == nil || state.state.Pending.Sequence != 1 || state.state.Pending.EngagementID != "eng-1" || spool.acked != 0 {
		t.Fatalf("pending state not preserved: %#v ack=%d", state.state, spool.acked)
	}

	secondTransport := &captureTransport{}
	second, err := NewService(spool, secondTransport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := second.DeliverOnce(context.Background()); err != nil || !delivered {
		t.Fatalf("restart delivered=%v err=%v", delivered, err)
	}
	if len(secondTransport.keys) != 0 {
		t.Fatal("already-registered key was redundantly registered after restart")
	}
	if got := secondTransport.batches[0]; got.Sequence != firstTransport.batches[0].Sequence || got.Detections[0].ID != firstTransport.batches[0].Detections[0].ID || got.KeyID != firstTransport.batches[0].KeyID {
		t.Fatalf("retry changed signed batch identity: first=%#v second=%#v", firstTransport.batches[0], got)
	}
}

func TestDuplicateSpoolRecordsCollapseIntoOneSignedItemAndACKBoth(t *testing.T) {
	spool := &memorySpool{records: []ports.SpoolRecord{spoolDetection(1, "det-1"), spoolDetection(2, "det-1")}}
	state := &memoryState{}
	transport := &captureTransport{}
	service, err := NewService(spool, transport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := service.DeliverOnce(context.Background()); err != nil || !delivered {
		t.Fatalf("delivered=%v err=%v", delivered, err)
	}
	if len(transport.items) != 1 || len(transport.items[0]) != 1 || len(transport.batches[0].Detections) != 1 {
		t.Fatalf("duplicate WAL records were not collapsed: items=%#v batch=%#v", transport.items, transport.batches[0])
	}
	if spool.acked != 2 || len(spool.records) != 0 {
		t.Fatalf("collapsed batch did not ACK both WAL records: ack=%d records=%d", spool.acked, len(spool.records))
	}
}

func TestRunRotatesRejectedKeyOnceAndRetriesPendingBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spool := &memorySpool{records: []ports.SpoolRecord{spoolDetection(1, "det-1")}}
	state := &memoryState{}
	transport := &captureTransport{sendErrs: []error{statusError{status: 403}, nil}, onSend: func(index int) {
		if index == 1 {
			cancel()
		}
	}}
	service, err := NewService(spool, transport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	err = service.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if len(transport.keys) != 2 || transport.keys[0].KeyID == transport.keys[1].KeyID {
		t.Fatalf("rejected key was not rotated: %#v", transport.keys)
	}
	if len(transport.batches) != 2 || transport.batches[0].Sequence != transport.batches[1].Sequence {
		t.Fatalf("rotation must retry the same pending sequence: %#v", transport.batches)
	}
	if spool.acked != 1 || state.state.Pending != nil || state.state.NextSequence != 2 {
		t.Fatalf("delivery not committed after rotation: ack=%d state=%#v", spool.acked, state.state)
	}
}

func TestRecoveredACKCompletesPendingStateWithoutResending(t *testing.T) {
	key := localKey(t)
	state := &memoryState{ok: true, state: ports.DetectionDeliveryState{Version: 1, NextSequence: 4, Key: &key,
		RegisteredKeyID: key.Key.KeyID, Pending: &ports.DetectionPendingBatch{EngagementID: "eng-1",
			Sequence: 4, Epoch: 2, Through: 9, EventIDs: []shared.ID{"det-9"}}}}
	spool := &memorySpool{acked: 9, epoch: 2}
	transport := &captureTransport{}
	service, err := NewService(spool, transport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := service.DeliverOnce(context.Background()); err != nil || !delivered {
		t.Fatalf("recover delivered=%v err=%v", delivered, err)
	}
	if len(transport.batches) != 0 || state.state.Pending != nil || state.state.NextSequence != 5 {
		t.Fatalf("acked pending batch was resent or not advanced: sends=%d state=%#v", len(transport.batches), state.state)
	}
}

func TestRecoveredACKFromPastEpochCompletesPendingStateAfterReboot(t *testing.T) {
	key := localKey(t)
	state := &memoryState{ok: true, state: ports.DetectionDeliveryState{Version: 1, NextSequence: 4, Key: &key,
		RegisteredKeyID: key.Key.KeyID, Pending: &ports.DetectionPendingBatch{EngagementID: "eng-1",
			Sequence: 4, Epoch: 2, Through: 9, EventIDs: []shared.ID{"det-9"}}}}
	spool := &memorySpool{acked: 9, epoch: 2, currentEpoch: 3}
	transport := &captureTransport{}
	service, err := NewService(spool, transport, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := service.DeliverOnce(context.Background()); err != nil || !delivered {
		t.Fatalf("reboot recovery delivered=%v err=%v", delivered, err)
	}
	if len(transport.batches) != 0 || state.state.Pending != nil || state.state.NextSequence != 5 {
		t.Fatalf("past-epoch ACK was not recovered: sends=%d state=%#v", len(transport.batches), state.state)
	}
}

func TestPendingEngagementMismatchFailsClosed(t *testing.T) {
	key := localKey(t)
	state := &memoryState{ok: true, state: ports.DetectionDeliveryState{Version: 1, NextSequence: 1, Key: &key,
		RegisteredKeyID: key.Key.KeyID, Pending: &ports.DetectionPendingBatch{EngagementID: "eng-original",
			Sequence: 1, Epoch: 1, Through: 1, EventIDs: []shared.ID{"det-1"}}}}
	if _, err := NewService(&memorySpool{}, &captureTransport{}, state, testConfig()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("engagement mismatch error = %v", err)
	}
	cfg := testConfig()
	cfg.EngagementID = "eng-original"
	service, err := NewService(&memorySpool{}, &captureTransport{}, state, cfg)
	if err != nil {
		t.Fatal(err)
	}
	service.cfg.EngagementID = "eng-changed" // exercise the per-delivery guard independently of construction
	if _, err := service.DeliverOnce(context.Background()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("delivery engagement mismatch error = %v", err)
	}
}

func TestPendingMembershipMismatchFailsClosed(t *testing.T) {
	key := localKey(t)
	state := &memoryState{ok: true, state: ports.DetectionDeliveryState{Version: 1, NextSequence: 1, Key: &key,
		RegisteredKeyID: key.Key.KeyID, Pending: &ports.DetectionPendingBatch{EngagementID: "eng-1",
			Sequence: 1, Epoch: 1, Through: 1, EventIDs: []shared.ID{"expected"}}}}
	spool := &memorySpool{records: []ports.SpoolRecord{spoolDetection(1, "different")}, epoch: 1}
	service, err := NewService(spool, &captureTransport{}, state, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeliverOnce(context.Background()); !errors.Is(err, ErrDeliveryState) {
		t.Fatalf("membership mismatch error = %v", err)
	}
	if spool.acked != 0 {
		t.Fatal("inconsistent pending state ACKed the WAL")
	}
}

func TestNewServiceRejectsCorruptPrivateKeyAndBadConfig(t *testing.T) {
	bad := localKey(t)
	bad.PrivateKey[0] ^= 0xff
	state := &memoryState{ok: true, state: ports.DetectionDeliveryState{Version: 1, NextSequence: 1, Key: &bad}}
	if _, err := NewService(&memorySpool{}, &captureTransport{}, state, testConfig()); err == nil {
		t.Fatal("corrupt private key accepted")
	}
	cfg := testConfig()
	cfg.EngagementID = ""
	if _, err := NewService(&memorySpool{}, &captureTransport{}, &memoryState{}, cfg); err == nil {
		t.Fatal("empty engagement accepted")
	}
}

func spoolDetection(sequence uint64, id shared.ID) ports.SpoolRecord {
	value := validDetection()
	body, _ := json.Marshal(value)
	return ports.SpoolRecord{Kind: ports.SpoolRecordDetection,
		Position: fleetagent.StreamPosition{Priority: fleetagent.PriorityP1, Epoch: 1, Sequence: sequence, Session: "session", Boot: "boot"},
		EventID:  id, EventClass: value.Class, ContentType: "application/vnd.synapse.detection+json;version=1",
		Payload: body, ObservedAt: value.Observed, EnqueuedAt: shipNow, MustNotShed: true, SchemaVersion: 1}
}

func validDetection() detection.Detection {
	event := detection.Event{Class: detection.ClassProcess, At: shipNow, Host: "asset-1",
		Process: &detection.ProcessEvent{PID: 42, PPID: 1, Comm: "curl", Path: "/usr/bin/curl", UID: 1000}}
	return detection.Detection{RuleID: "proc.curl", RuleVersion: 1, Class: detection.ClassProcess,
		Severity: shared.SeverityHigh, HostID: "asset-1", AgentID: "agent-1",
		Evidence: []detection.Event{event}, ObservedCount: 1, Observed: shipNow}
}

func localKey(t *testing.T) ports.DetectionSigningKeyState {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeDetectionBatch, pub, shipNow.Add(-time.Hour), shipNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ports.DetectionSigningKeyState{Key: key, PrivateKey: privateKey}
}

package sensorstateship

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testSpool struct {
	records  []ports.SpoolRecord
	ackCalls int
	lastACK  ports.SpoolACK
}

func (s *testSpool) PeekPriority(_ context.Context, priority fleetagent.DeliveryPriority, _ ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	if priority != fleetagent.PriorityP0 {
		return nil, errors.New("unexpected priority")
	}
	return append([]ports.SpoolRecord(nil), s.records...), nil
}

func (s *testSpool) Ack(_ context.Context, ack ports.SpoolACK) (ports.SpoolACKResult, error) {
	s.ackCalls++
	s.lastACK = ack
	s.records = nil
	return ports.SpoolACKResult{RemovedRecords: 1, HighestACKed: ack.Through}, nil
}

type testTransport struct {
	ack   ACK
	err   error
	calls int
	sent  []fleetagent.SensorStateReport
}

func (t *testTransport) ShipSensorState(_ context.Context, _ string, report fleetagent.SensorStateReport) (ACK, error) {
	t.calls++
	t.sent = append(t.sent, report)
	return t.ack, t.err
}

type testStateStore struct {
	state DeliveryState
	saves int
}

func (s *testStateStore) Load(context.Context) (DeliveryState, error) {
	return cloneState(s.state), nil
}

func (s *testStateStore) Save(_ context.Context, state DeliveryState) error {
	s.saves++
	s.state = cloneState(state)
	return nil
}

func cloneState(state DeliveryState) DeliveryState {
	if state.Pending == nil {
		return state
	}
	pending := *state.Pending
	pending.Report.States = append([]detection.ClassCoverage(nil), pending.Report.States...)
	state.Pending = &pending
	return state
}

func TestBuildReportBindsP0CoverageRecord(t *testing.T) {
	agent := shared.ID("agent-state-1")
	record := testCoverageRecord(t, agent)
	report, err := BuildReport(agent, "asset-state-1", testSigner(t), record)
	if err != nil {
		t.Fatal(err)
	}
	if report.Kind != "coverage" || report.ReportID != record.EventID || len(report.States) != 1 || report.States[0].AgentID != report.AgentID {
		t.Fatalf("report = %+v", report)
	}
}

func TestACKedStateFinalizesWithoutNetworkReplay(t *testing.T) {
	agent := shared.ID("agent-state-1")
	record := testCoverageRecord(t, agent)
	signer := testSigner(t)
	report, err := BuildReport(agent, "asset-state-1", signer, record)
	if err != nil {
		t.Fatal(err)
	}
	spool := &testSpool{records: []ports.SpoolRecord{record}}
	transport := &testTransport{}
	state := &testStateStore{state: DeliveryState{Version: DeliveryStateVersion, Pending: &PendingReport{
		Epoch: record.Position.Epoch, WALThrough: record.Position.Sequence, Acked: true, Report: report,
	}}}
	service := newTestService(t, spool, transport, state, signer)
	delivered, err := service.DeliverOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !delivered || transport.calls != 0 || spool.ackCalls != 1 || state.state.Pending != nil {
		t.Fatalf("ACK recovery delivered=%t transport=%d WAL ACKs=%d state=%+v", delivered, transport.calls, spool.ackCalls, state.state)
	}
}

func TestRetryRetainsExactPendingReportAndP0WAL(t *testing.T) {
	agent := shared.ID("agent-state-1")
	record := testCoverageRecord(t, agent)
	signer := testSigner(t)
	spool := &testSpool{records: []ports.SpoolRecord{record}}
	transport := &testTransport{err: errors.New("temporarily unavailable")}
	state := &testStateStore{state: DeliveryState{Version: DeliveryStateVersion}}
	service := newTestService(t, spool, transport, state, signer)
	if delivered, err := service.DeliverOnce(context.Background()); delivered || err == nil {
		t.Fatalf("first delivery = %t, %v; want retained failure", delivered, err)
	}
	if state.state.Pending == nil || state.state.Pending.Acked || spool.ackCalls != 0 || len(spool.records) != 1 {
		t.Fatalf("retryable failure lost pending report or WAL: state=%+v ACKs=%d records=%d", state.state, spool.ackCalls, len(spool.records))
	}
	first := state.state.Pending.Report
	transport.err = nil
	transport.ack = ACK{Acknowledged: true, ReportID: first.ReportID}
	if delivered, err := service.DeliverOnce(context.Background()); err != nil || !delivered {
		t.Fatalf("retry delivery = %t, %v", delivered, err)
	}
	if len(transport.sent) != 2 || !sameReport(transport.sent[0], transport.sent[1]) {
		t.Fatalf("retry changed exact signed report: first=%+v retry=%+v", transport.sent[0], transport.sent[1])
	}
	if spool.ackCalls != 1 || state.state.Pending != nil {
		t.Fatalf("successful retry did not finalize WAL/state: ACKs=%d state=%+v", spool.ackCalls, state.state)
	}
}

func TestMismatchedACKRetainsPendingReportAndWAL(t *testing.T) {
	agent := shared.ID("agent-state-1")
	record := testCoverageRecord(t, agent)
	signer := testSigner(t)
	spool := &testSpool{records: []ports.SpoolRecord{record}}
	transport := &testTransport{ack: ACK{Acknowledged: true, ReportID: "other-report"}}
	state := &testStateStore{state: DeliveryState{Version: DeliveryStateVersion}}
	service := newTestService(t, spool, transport, state, signer)
	if delivered, err := service.DeliverOnce(context.Background()); delivered || !errors.Is(err, ErrProtocol) {
		t.Fatalf("mismatched ACK = %t, %v; want protocol error", delivered, err)
	}
	if state.state.Pending == nil || state.state.Pending.Acked || spool.ackCalls != 0 || len(spool.records) != 1 {
		t.Fatalf("mismatched ACK changed durable state: state=%+v ACKs=%d records=%d", state.state, spool.ackCalls, len(spool.records))
	}
}

func newTestService(t *testing.T, spool PrioritySpool, transport Transport, state StateStore, signer Signer) *Service {
	t.Helper()
	service, err := NewService(spool, transport, state, Config{
		AgentID: "agent-state-1", AssetID: "asset-state-1", Token: "token", Signer: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testCoverageRecord(t *testing.T, agent shared.ID) ports.SpoolRecord {
	t.Helper()
	at := time.Unix(1_700_000_000, 0).UTC()
	payload, err := json.Marshal(struct {
		SchemaVersion int                       `json:"schema_version"`
		ObservedAt    time.Time                 `json:"observed_at"`
		Classes       []detection.ClassCoverage `json:"classes"`
	}{
		SchemaVersion: 1,
		ObservedAt:    at,
		Classes:       []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: agent, State: detection.StateActive, Since: at}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ports.SpoolRecord{
		Kind: ports.SpoolRecordCoverage,
		Position: fleetagent.StreamPosition{Priority: fleetagent.PriorityP0, Epoch: 1, Sequence: 1,
			Session: fleetagent.CanonicalSessionID(agent), Boot: "boot-1"},
		EventID: "coverage-1", ContentType: "application/json", Payload: payload,
		ObservedAt: at, EnqueuedAt: at, MustNotShed: true, SchemaVersion: 1,
	}
}

func testSigner(t *testing.T) Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Signer{PrivateKey: privateKey, KeyID: "sensor-state-key"}
}

func sameReport(left, right fleetagent.SensorStateReport) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

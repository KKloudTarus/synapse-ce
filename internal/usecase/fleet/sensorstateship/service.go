package sensorstateship

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const DeliveryStateVersion = 1

var ErrProtocol = errors.New("sensor-state delivery protocol error")

// PrioritySpool is the narrow P0 WAL contract needed by sensor-state delivery.
type PrioritySpool interface {
	PeekPriority(context.Context, fleetagent.DeliveryPriority, ports.PeekSpoolRequest) ([]ports.SpoolRecord, error)
	Ack(context.Context, ports.SpoolACK) (ports.SpoolACKResult, error)
}

// Transport ships one exact signed report and returns a transport-neutral ACK.
type Transport interface {
	ShipSensorState(context.Context, string, fleetagent.SensorStateReport) (ACK, error)
}

type ACK struct {
	Acknowledged bool
	ReportID     shared.ID
}

type StateStore interface {
	Load(context.Context) (DeliveryState, error)
	Save(context.Context, DeliveryState) error
}

type Signer struct {
	PrivateKey ed25519.PrivateKey
	KeyID      string
}

type Config struct {
	AgentID shared.ID
	AssetID shared.ID
	Token   string
	Signer  Signer
}

type DeliveryState struct {
	Version int            `json:"version"`
	Pending *PendingReport `json:"pending,omitempty"`
}

type PendingReport struct {
	Epoch      uint64                       `json:"epoch"`
	WALThrough uint64                       `json:"wal_through"`
	Acked      bool                         `json:"acked"`
	Report     fleetagent.SensorStateReport `json:"report"`
}

type Service struct {
	spool     PrioritySpool
	transport Transport
	state     StateStore
	cfg       Config
}

func NewService(spool PrioritySpool, transport Transport, state StateStore, cfg Config) (*Service, error) {
	if spool == nil || transport == nil || state == nil {
		return nil, fmt.Errorf("%w: sensor-state delivery dependencies are required", shared.ErrValidation)
	}
	if cfg.AgentID.IsZero() || cfg.AssetID.IsZero() || cfg.Token == "" || cfg.Signer.KeyID == "" || len(cfg.Signer.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: sensor-state delivery configuration is incomplete", shared.ErrValidation)
	}
	return &Service{spool: spool, transport: transport, state: state, cfg: cfg}, nil
}

// DeliverOnce advances the durable report -> server ACK -> WAL ACK saga once.
// The exact signed report is saved before transmission, and server acknowledgement
// is saved before the corresponding P0 WAL record can be reclaimed.
func (s *Service) DeliverOnce(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	state, err := s.state.Load(ctx)
	if err != nil {
		return false, protocolError(err)
	}
	if err := ValidateDeliveryState(state); err != nil {
		return false, protocolError(err)
	}
	if pending := state.Pending; pending != nil {
		if pending.Acked {
			return true, s.finalize(ctx, &state)
		}
		return s.sendPending(ctx, &state)
	}

	priority := fleetagent.PriorityP0
	records, err := s.spool.PeekPriority(ctx, priority, ports.PeekSpoolRequest{MaxRecords: 1, OnlyPriority: &priority})
	if err != nil || len(records) == 0 {
		return false, err
	}
	report, err := BuildReport(s.cfg.AgentID, s.cfg.AssetID, s.cfg.Signer, records[0])
	if err != nil {
		return false, protocolError(err)
	}
	state.Pending = &PendingReport{
		Epoch: records[0].Position.Epoch, WALThrough: records[0].Position.Sequence, Report: report,
	}
	if err := s.state.Save(ctx, state); err != nil {
		return false, fmt.Errorf("persist pending sensor-state report: %w", err)
	}
	return s.sendPending(ctx, &state)
}

func (s *Service) sendPending(ctx context.Context, state *DeliveryState) (bool, error) {
	pending := state.Pending
	if pending == nil {
		return false, protocolError(errors.New("sensor-state state has no pending report"))
	}
	ack, err := s.transport.ShipSensorState(ctx, s.cfg.Token, pending.Report)
	if err != nil {
		return false, fmt.Errorf("ship sensor-state report: %w", err)
	}
	if !ack.Acknowledged || ack.ReportID != pending.Report.ReportID {
		return false, protocolError(fmt.Errorf("server ACK %q does not match report %q", ack.ReportID, pending.Report.ReportID))
	}
	state.Pending.Acked = true
	if err := s.state.Save(ctx, *state); err != nil {
		return false, fmt.Errorf("persist sensor-state ACK: %w", err)
	}
	if err := s.finalize(ctx, state); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) finalize(ctx context.Context, state *DeliveryState) error {
	pending := state.Pending
	if pending == nil || !pending.Acked {
		return protocolError(errors.New("sensor-state state has no acknowledged report"))
	}
	if _, err := s.spool.Ack(ctx, ports.SpoolACK{
		Priority: fleetagent.PriorityP0, Epoch: pending.Epoch, Through: pending.WALThrough,
	}); err != nil {
		return fmt.Errorf("apply sensor-state WAL ACK: %w", err)
	}
	state.Pending = nil
	if err := s.state.Save(ctx, *state); err != nil {
		return fmt.Errorf("clear pending sensor-state report: %w", err)
	}
	return nil
}

func BuildReport(agentID, assetID shared.ID, signer Signer, record ports.SpoolRecord) (fleetagent.SensorStateReport, error) {
	if err := record.Validate(); err != nil {
		return fleetagent.SensorStateReport{}, err
	}
	if record.Position.Priority != fleetagent.PriorityP0 {
		return fleetagent.SensorStateReport{}, fmt.Errorf("sensor-state record must be P0, got %s", record.Position.Priority)
	}
	if agentID.IsZero() || assetID.IsZero() || signer.KeyID == "" || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return fleetagent.SensorStateReport{}, fmt.Errorf("%w: sensor-state report identity or signer is incomplete", shared.ErrValidation)
	}
	kind, states, observedAt, schema, err := decodeRecord(record)
	if err != nil {
		return fleetagent.SensorStateReport{}, err
	}
	for i := range states {
		if states[i].HostID != agentID || (!states[i].AgentID.IsZero() && states[i].AgentID != agentID) {
			return fleetagent.SensorStateReport{}, fmt.Errorf("sensor-state record class identity does not match agent %q", agentID)
		}
		states[i].AgentID = agentID
	}
	digest := sha256.Sum256(record.Payload)
	report := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		ReportID:        record.EventID, AgentID: agentID, HostID: agentID,
		AgentSessionID: fleetagent.CanonicalSessionID(agentID), AssetID: assetID,
		Kind: kind, ObservedAt: observedAt.UTC(), SchemaVersion: schema,
		PayloadDigest: hex.EncodeToString(digest[:]), States: states, KeyID: signer.KeyID,
	}
	report.Signature = fleetagent.SignSensorState(signer.PrivateKey, report)
	if err := report.Validate(); err != nil {
		return fleetagent.SensorStateReport{}, err
	}
	return report, nil
}

func ValidateDeliveryState(state DeliveryState) error {
	if state.Version != DeliveryStateVersion {
		return fmt.Errorf("unsupported sensor-state delivery state version %d", state.Version)
	}
	if state.Pending == nil {
		return nil
	}
	if state.Pending.Epoch == 0 || state.Pending.WALThrough == 0 {
		return errors.New("pending sensor-state WAL coordinates are invalid")
	}
	if err := state.Pending.Report.Validate(); err != nil {
		return fmt.Errorf("pending sensor-state report: %w", err)
	}
	return nil
}

type coveragePayload struct {
	SchemaVersion int                       `json:"schema_version"`
	ObservedAt    time.Time                 `json:"observed_at"`
	Classes       []detection.ClassCoverage `json:"classes"`
}

type classStatePayload struct {
	SchemaVersion int                     `json:"schema_version"`
	ObservedAt    time.Time               `json:"observed_at"`
	State         detection.ClassCoverage `json:"state"`
}

func decodeRecord(record ports.SpoolRecord) (string, []detection.ClassCoverage, time.Time, int, error) {
	switch record.Kind {
	case ports.SpoolRecordCoverage:
		var snapshot coveragePayload
		if err := json.Unmarshal(record.Payload, &snapshot); err != nil {
			return "", nil, time.Time{}, 0, fmt.Errorf("decode coverage P0 record: %w", err)
		}
		if snapshot.SchemaVersion <= 0 || snapshot.ObservedAt.IsZero() || len(snapshot.Classes) == 0 {
			return "", nil, time.Time{}, 0, errors.New("coverage P0 record is incomplete")
		}
		return "coverage", append([]detection.ClassCoverage(nil), snapshot.Classes...), snapshot.ObservedAt, snapshot.SchemaVersion, nil
	case ports.SpoolRecordSensorState:
		var state classStatePayload
		if err := json.Unmarshal(record.Payload, &state); err != nil {
			return "", nil, time.Time{}, 0, fmt.Errorf("decode sensor-state P0 record: %w", err)
		}
		if state.SchemaVersion <= 0 || state.ObservedAt.IsZero() {
			return "", nil, time.Time{}, 0, errors.New("sensor-state P0 record is incomplete")
		}
		return "sensor_state", []detection.ClassCoverage{state.State}, state.ObservedAt, state.SchemaVersion, nil
	default:
		return "", nil, time.Time{}, 0, fmt.Errorf("P0 spool record kind %q is not a sensor-state record", record.Kind)
	}
}

func protocolError(err error) error {
	return fmt.Errorf("%w: %v", ErrProtocol, err)
}

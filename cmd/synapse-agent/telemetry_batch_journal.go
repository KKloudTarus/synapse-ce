package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

const telemetryBatchJournalVersion = 1

// telemetryBatchLaneState is the durable bridge between A2's per-record WAL
// coordinates and A3's per-batch delivery sequence. Only one batch per priority
// lane may be pending: that makes server ACK -> local WAL deletion unambiguous.
type telemetryBatchLaneState struct {
	Version       int                         `json:"version"`
	Priority      fleetagent.DeliveryPriority `json:"priority"`
	Epoch         uint64                      `json:"epoch"`
	LastCommitted uint64                      `json:"last_committed"`
	Pending       *telemetryPendingBatch      `json:"pending,omitempty"`
}

// telemetryPendingBatch stores the exact signed request before it is put on the
// network. Keeping the payload in the journal means a P3 quota eviction cannot
// make an already-issued batch sequence impossible to retransmit; the batch can
// still converge at the server, after which the WAL ACK is applied idempotently.
type telemetryPendingBatch struct {
	Epoch      uint64                             `json:"epoch"`
	Sequence   uint64                             `json:"sequence"`
	WALFrom    uint64                             `json:"wal_from"`
	WALThrough uint64                             `json:"wal_through"`
	Acked      bool                               `json:"acked"`
	Request    fleetclient.TelemetryIngestRequest `json:"request"`
}

type telemetryBatchJournalStore struct {
	dir string
}

func newTelemetryBatchJournalStore(stateDir string) *telemetryBatchJournalStore {
	return &telemetryBatchJournalStore{dir: filepath.Join(stateDir, "telemetry-batches")}
}

func (s *telemetryBatchJournalStore) path(priority fleetagent.DeliveryPriority) string {
	return filepath.Join(s.dir, fmt.Sprintf("lane-%d.json", int(priority)))
}

func (s *telemetryBatchJournalStore) Load(priority fleetagent.DeliveryPriority) (telemetryBatchLaneState, error) {
	if !priority.Valid() {
		return telemetryBatchLaneState{}, fmt.Errorf("telemetry batch journal: invalid priority %d", int(priority))
	}
	state := telemetryBatchLaneState{Version: telemetryBatchJournalVersion, Priority: priority}
	data, err := os.ReadFile(s.path(priority))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return telemetryBatchLaneState{}, fmt.Errorf("telemetry batch journal: read %s: %w", priority, err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return telemetryBatchLaneState{}, fmt.Errorf("telemetry batch journal: decode %s: %w", priority, err)
	}
	if err := validateTelemetryBatchLaneState(state, priority); err != nil {
		return telemetryBatchLaneState{}, err
	}
	return state, nil
}

func (s *telemetryBatchJournalStore) Save(state telemetryBatchLaneState) error {
	if err := validateTelemetryBatchLaneState(state, state.Priority); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("telemetry batch journal: marshal %s: %w", state.Priority, err)
	}
	if err := writeTelemetryJournalFile(s.path(state.Priority), data); err != nil {
		return fmt.Errorf("telemetry batch journal: persist %s: %w", state.Priority, err)
	}
	return nil
}

func validateTelemetryBatchLaneState(state telemetryBatchLaneState, priority fleetagent.DeliveryPriority) error {
	if state.Version != telemetryBatchJournalVersion {
		return fmt.Errorf("telemetry batch journal: unsupported version %d", state.Version)
	}
	if !priority.Valid() || state.Priority != priority {
		return fmt.Errorf("telemetry batch journal: lane priority mismatch: got %d want %d", int(state.Priority), int(priority))
	}
	if state.LastCommitted > 0 && state.Epoch == 0 {
		return fmt.Errorf("telemetry batch journal: committed sequence has no epoch")
	}
	if state.Pending == nil {
		return nil
	}
	pending := state.Pending
	if pending.Epoch == 0 || pending.Sequence == 0 || pending.WALFrom == 0 || pending.WALThrough < pending.WALFrom {
		return fmt.Errorf("telemetry batch journal: pending coordinates are invalid")
	}
	if state.Epoch != pending.Epoch {
		return fmt.Errorf("telemetry batch journal: pending epoch %d disagrees with lane epoch %d", pending.Epoch, state.Epoch)
	}
	if pending.Sequence != state.LastCommitted+1 {
		return fmt.Errorf("telemetry batch journal: pending sequence %d does not follow committed %d", pending.Sequence, state.LastCommitted)
	}
	if pending.Request.Manifest.Position.Priority != priority ||
		pending.Request.Manifest.Position.Epoch != pending.Epoch ||
		pending.Request.Manifest.Position.Sequence != pending.Sequence ||
		pending.Request.Manifest.PreviousSequence != state.LastCommitted {
		return fmt.Errorf("telemetry batch journal: pending request coordinates disagree with journal")
	}
	if err := pending.Request.Manifest.Validate(); err != nil {
		return fmt.Errorf("telemetry batch journal: pending manifest: %w", err)
	}
	if len(pending.Request.Events) != pending.Request.Manifest.KeptCount {
		return fmt.Errorf("telemetry batch journal: pending event count disagrees with manifest")
	}
	return nil
}

// writeTelemetryJournalFile is an atomic, fsync-backed replace. The pending
// request is the crash-recovery authority for a batch sequence, so a successful
// return must survive a process or host crash before any HTTP request is sent.
func writeTelemetryJournalFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".telemetry-batch-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

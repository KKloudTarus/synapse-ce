package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportStore is the in-memory twin of the A3 transport-sequencing store: per-stream ACK
// state (with an optimistic-concurrency version) and the durable raw batch events — tenant-bucketed and
// keyed by the authenticated agent id, upholding the same contract as the Postgres tier. Transport gaps
// are derived on read from the ACK snapshot, never stored. Reached only through
// ports.TelemetryTransportStore.
type TelemetryTransportStore struct {
	mu     sync.Mutex
	states map[shared.ID]map[streamEpoch]ports.TelemetryStreamState
	events map[shared.ID]map[eventKey]storedTransportEvent
}

// streamEpoch and eventKey carry agent so an agent-chosen StreamID can never address another agent's
// stream space within the tenant (see migration 0109).
type streamEpoch struct {
	agent  shared.ID
	stream shared.ID
	epoch  uint64
}

type eventKey struct {
	agent    shared.ID
	stream   shared.ID
	epoch    uint64
	sequence uint64
	eventID  shared.ID
}

type storedTransportEvent struct {
	asset         shared.ID
	class         string
	digest        string
	payload       []byte
	schemaVersion int
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportStore)(nil)

// NewTelemetryTransportStore constructs an empty in-memory transport store.
func NewTelemetryTransportStore() *TelemetryTransportStore {
	return &TelemetryTransportStore{
		states: map[shared.ID]map[streamEpoch]ports.TelemetryStreamState{},
		events: map[shared.ID]map[eventKey]storedTransportEvent{},
	}
}

func (s *TelemetryTransportStore) StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (ports.TelemetryStreamState, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.TelemetryStreamState{}, err
	}
	if agentID.IsZero() || streamID.IsZero() || epoch == 0 {
		return ports.TelemetryStreamState{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[tenant][streamEpoch{agentID, streamID, epoch}]; ok {
		return cloneStreamState(st), nil
	}
	// A stream/epoch never seen is a zero state (Version 0), not an error.
	return ports.TelemetryStreamState{AgentID: agentID, StreamID: streamID, Epoch: epoch}, nil
}

func (s *TelemetryTransportStore) SaveStreamState(ctx context.Context, state ports.TelemetryStreamState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[tenant] == nil {
		s.states[tenant] = map[streamEpoch]ports.TelemetryStreamState{}
	}
	key := streamEpoch{state.AgentID, state.StreamID, state.Epoch}
	// Optimistic concurrency: accept the write only if the stored version still matches the one the caller
	// read; otherwise a concurrent batch advanced the stream and the caller must retry.
	if cur, ok := s.states[tenant][key]; ok {
		if cur.Version != state.Version {
			return shared.ErrConflict
		}
	} else if state.Version != 0 {
		return shared.ErrConflict
	}
	next := cloneStreamState(state)
	next.Version = state.Version + 1
	s.states[tenant][key] = next
	return nil
}

func (s *TelemetryTransportStore) MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var highest uint64
	for key := range s.states[tenant] {
		if key.agent == agentID && key.stream == streamID && key.epoch > highest {
			highest = key.epoch
		}
	}
	return highest, nil
}

func (s *TelemetryTransportStore) ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.TelemetryGap
	for key, st := range s.states[tenant] {
		if key.agent == agentID && key.stream == streamID {
			out = append(out, st.GapsFrom()...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch != out[j].Epoch {
			return out[i].Epoch < out[j].Epoch
		}
		return out[i].FromSequence < out[j].FromSequence
	})
	return out, nil
}

func (s *TelemetryTransportStore) IngestBatchEvents(ctx context.Context, batch ports.TelemetryEventBatch) (int, error) {
	if err := batch.Validate(); err != nil {
		return 0, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.events[tenant] == nil {
		s.events[tenant] = map[eventKey]storedTransportEvent{}
	}
	stored := 0
	for _, e := range batch.Events {
		key := eventKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence, e.EventID}
		if _, exists := s.events[tenant][key]; exists {
			continue // idempotent
		}
		s.events[tenant][key] = storedTransportEvent{
			asset: batch.AssetID, class: string(e.Class),
			digest: e.Digest, payload: append([]byte(nil), e.Payload...), schemaVersion: batch.SchemaVersion,
		}
		stored++
	}
	return stored, nil
}

func (s *TelemetryTransportStore) CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key := range s.events[tenant] {
		if key.agent == agentID && key.stream == streamID && key.epoch == epoch && key.sequence == sequence {
			n++
		}
	}
	return n, nil
}

func cloneStreamState(s ports.TelemetryStreamState) ports.TelemetryStreamState {
	c := s
	c.Pending = append([]uint64(nil), s.Pending...)
	return c
}

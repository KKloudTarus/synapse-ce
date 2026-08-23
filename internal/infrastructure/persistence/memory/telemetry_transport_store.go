package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportStore is the in-memory twin of the A3 transport-sequencing store.
type TelemetryTransportStore struct {
	mu        sync.Mutex
	states    map[shared.ID]map[streamEpoch]ports.TelemetryStreamState
	commits   map[shared.ID]map[batchKey]storedBatchCommit
	events    map[shared.ID]map[eventKey]storedTransportEvent
	gaps      map[shared.ID]map[streamEpoch][]ports.TelemetryGap
	agentGaps map[shared.ID]map[shared.ID]ports.TelemetryAgentGap
	bindings  map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding
}

type streamEpoch struct {
	agent  shared.ID
	stream shared.ID
	epoch  uint64
}

type batchKey struct {
	agent    shared.ID
	stream   shared.ID
	epoch    uint64
	sequence uint64
}

type eventKey struct {
	agent    shared.ID
	stream   shared.ID
	epoch    uint64
	sequence uint64
	eventID  shared.ID
}

type storedBatchCommit struct {
	batchID       shared.ID
	payloadDigest string
	asset         shared.ID
	schemaVersion int
	eventCount    int
	priority      fleetagent.DeliveryPriority
	fromAt        time.Time
	toAt          time.Time
}

type storedTransportEvent struct {
	asset         shared.ID
	class         string
	digest        string
	payload       []byte
	schemaVersion int
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportStore)(nil)

func NewTelemetryTransportStore() *TelemetryTransportStore {
	return &TelemetryTransportStore{
		states:    map[shared.ID]map[streamEpoch]ports.TelemetryStreamState{},
		commits:   map[shared.ID]map[batchKey]storedBatchCommit{},
		events:    map[shared.ID]map[eventKey]storedTransportEvent{},
		gaps:      map[shared.ID]map[streamEpoch][]ports.TelemetryGap{},
		agentGaps: map[shared.ID]map[shared.ID]ports.TelemetryAgentGap{},
		bindings:  map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding{},
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
	if s.gaps[tenant] == nil {
		s.gaps[tenant] = map[streamEpoch][]ports.TelemetryGap{}
	}
	key := streamEpoch{state.AgentID, state.StreamID, state.Epoch}
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
	materialized := next.GapsFrom()
	for i := range materialized {
		materialized[i].DetectedAt = next.UpdatedAt.UTC()
	}
	s.gaps[tenant][key] = materialized
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

func (s *TelemetryTransportStore) enrichGapLocked(tenant shared.ID, gap ports.TelemetryGap) (ports.TelemetryGap, bool) {
	next, ok := s.commits[tenant][batchKey{gap.AgentID, gap.StreamID, gap.Epoch, gap.ToSequence + 1}]
	if !ok || next.fromAt.IsZero() {
		return gap, false
	}
	gap.AssetID = next.asset
	gap.Priority = next.priority
	gap.ToAt = next.fromAt.UTC()
	if gap.FromSequence > 1 {
		if prev, ok := s.commits[tenant][batchKey{gap.AgentID, gap.StreamID, gap.Epoch, gap.FromSequence - 1}]; ok && !prev.toAt.IsZero() {
			gap.FromAt = prev.toAt.UTC()
		}
	}
	if gap.FromAt.IsZero() {
		gap.FromAt = time.Unix(0, 0).UTC()
	}
	if gap.FromAt.After(gap.ToAt) {
		gap.FromAt, gap.ToAt = gap.ToAt, gap.FromAt
	}
	return gap, true
}

func (s *TelemetryTransportStore) ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.TelemetryGap
	for key, materialized := range s.gaps[tenant] {
		if key.agent != agentID || key.stream != streamID {
			continue
		}
		for _, gap := range materialized {
			if enriched, ok := s.enrichGapLocked(tenant, gap); ok {
				gap = enriched
			}
			out = append(out, gap)
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

func agentGapCompatibleExtension(current, next ports.TelemetryAgentGap) bool {
	if current.GapID != next.GapID || current.AgentID != next.AgentID || current.AssetID != next.AssetID ||
		current.StreamID != next.StreamID || current.Priority != next.Priority || current.Epoch != next.Epoch ||
		current.KnownSequence != next.KnownSequence || current.Reason != next.Reason || next.Count < current.Count ||
		next.FromAt.After(current.FromAt) || next.ToAt.Before(current.ToAt) {
		return false
	}
	if current.KnownSequence {
		return next.FromSequence <= current.FromSequence && next.ToSequence >= current.ToSequence
	}
	return next.FromSequence == 0 && next.ToSequence == 0
}

func (s *TelemetryTransportStore) RecordAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agentGaps[tenant] == nil {
		s.agentGaps[tenant] = map[shared.ID]ports.TelemetryAgentGap{}
	}
	current, ok := s.agentGaps[tenant][gap.GapID]
	if !ok {
		s.agentGaps[tenant][gap.GapID] = gap
		return nil
	}
	if !agentGapCompatibleExtension(current, gap) {
		return fmt.Errorf("%w: telemetry agent gap id is already committed to incompatible or larger evidence", shared.ErrConflict)
	}
	gap.FirstReportedAt = current.FirstReportedAt
	if gap.UpdatedAt.Before(current.UpdatedAt) {
		gap.UpdatedAt = current.UpdatedAt
	}
	s.agentGaps[tenant][gap.GapID] = gap
	return nil
}

func (s *TelemetryTransportStore) QueryDeliveryGaps(ctx context.Context, q ports.TelemetryGapQuery) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	if q.Priority != nil && !q.Priority.Valid() {
		return nil, fmt.Errorf("%w: invalid telemetry gap priority", shared.ErrValidation)
	}
	if !q.Since.IsZero() && !q.Until.IsZero() && q.Until.Before(q.Since) {
		return nil, fmt.Errorf("%w: telemetry gap query until precedes since", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.TelemetryGap
	for _, materialized := range s.gaps[tenant] {
		for _, raw := range materialized {
			gap, ok := s.enrichGapLocked(tenant, raw)
			if !ok {
				continue
			}
			if !q.AgentID.IsZero() && gap.AgentID != q.AgentID {
				continue
			}
			if !q.AssetID.IsZero() && gap.AssetID != q.AssetID {
				continue
			}
			if q.Priority != nil && gap.Priority != *q.Priority {
				continue
			}
			if !q.Since.IsZero() && gap.ToAt.Before(q.Since.UTC()) {
				continue
			}
			if !q.Until.IsZero() && gap.FromAt.After(q.Until.UTC()) {
				continue
			}
			out = append(out, gap)
		}
	}
	for _, source := range s.agentGaps[tenant] {
		if !q.AgentID.IsZero() && source.AgentID != q.AgentID {
			continue
		}
		if !q.AssetID.IsZero() && source.AssetID != q.AssetID {
			continue
		}
		if q.Priority != nil && source.Priority != *q.Priority {
			continue
		}
		if !q.Since.IsZero() && source.ToAt.Before(q.Since.UTC()) {
			continue
		}
		if !q.Until.IsZero() && source.FromAt.After(q.Until.UTC()) {
			continue
		}
		out = append(out, ports.TelemetryGap{
			AgentID: source.AgentID, AssetID: source.AssetID, StreamID: source.StreamID, Priority: source.Priority,
			Epoch: source.Epoch, FromSequence: source.FromSequence, ToSequence: source.ToSequence,
			FromAt: source.FromAt, ToAt: source.ToAt, DetectedAt: source.FirstReportedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromAt.Equal(out[j].FromAt) {
			if out[i].Epoch != out[j].Epoch {
				return out[i].Epoch < out[j].Epoch
			}
			return out[i].FromSequence < out[j].FromSequence
		}
		return out[i].FromAt.Before(out[j].FromAt)
	})
	return out, nil
}

func (s *TelemetryTransportStore) IngestBatchEvents(ctx context.Context, batch ports.TelemetryEventBatch) (int, error) {
	wantCommit, err := memoryBatchCommit(batch)
	if err != nil {
		return 0, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commits[tenant] == nil {
		s.commits[tenant] = map[batchKey]storedBatchCommit{}
	}
	if s.events[tenant] == nil {
		s.events[tenant] = map[eventKey]storedTransportEvent{}
	}
	coord := batchKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence}
	if existing, ok := s.commits[tenant][coord]; ok && existing != wantCommit {
		return 0, fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
	}
	stored := 0
	for _, e := range batch.Events {
		key := eventKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence, e.EventID}
		if existing, exists := s.events[tenant][key]; exists {
			if existing.asset != batch.AssetID || existing.class != string(e.Class) || existing.digest != e.Digest || existing.schemaVersion != batch.SchemaVersion || string(existing.payload) != string(e.Payload) {
				return 0, fmt.Errorf("%w: telemetry event coordinate is already committed to different content", shared.ErrConflict)
			}
			continue
		}
		stored++
	}
	if _, ok := s.commits[tenant][coord]; !ok {
		s.commits[tenant][coord] = wantCommit
	}
	for _, e := range batch.Events {
		key := eventKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence, e.EventID}
		if _, exists := s.events[tenant][key]; exists {
			continue
		}
		s.events[tenant][key] = storedTransportEvent{asset: batch.AssetID, class: string(e.Class), digest: e.Digest, payload: append([]byte(nil), e.Payload...), schemaVersion: batch.SchemaVersion}
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

func (s *TelemetryTransportStore) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	if tenant != binding.TenantID {
		return fmt.Errorf("%w: telemetry asset binding tenant disagrees with context", shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bindings[tenant] == nil {
		s.bindings[tenant] = map[shared.ID]ports.TelemetryAssetBinding{}
	}
	if current, ok := s.bindings[tenant][binding.AgentID]; ok && binding.UpdatedAt.Before(current.UpdatedAt) {
		return fmt.Errorf("%w: stale telemetry asset binding update", shared.ErrConflict)
	}
	s.bindings[tenant][binding.AgentID] = binding
	return nil
}

func (s *TelemetryTransportStore) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return "", err
	}
	if agentID.IsZero() {
		return "", fmt.Errorf("%w: telemetry asset resolution requires agent id", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.bindings[tenant][agentID]
	if !ok || binding.AssetID.IsZero() {
		return "", shared.ErrNotFound
	}
	return binding.AssetID, nil
}

func cloneStreamState(s ports.TelemetryStreamState) ports.TelemetryStreamState {
	c := s
	c.Pending = append([]uint64(nil), s.Pending...)
	return c
}

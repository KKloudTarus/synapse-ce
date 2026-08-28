package memory

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportStore is the in-memory twin of the A3 transport-sequencing store.
type TelemetryTransportStore struct {
	mu                sync.Mutex
	states            map[shared.ID]map[streamEpoch]ports.TelemetryStreamState
	commits           map[shared.ID]map[batchKey]storedBatchCommit
	events            map[shared.ID]map[eventKey]storedTransportEvent
	gaps              map[shared.ID]map[streamEpoch][]ports.TelemetryGap
	gapHistory        map[shared.ID]map[streamEpoch][]ports.TelemetryGap
	agentGaps         map[shared.ID]map[shared.ID]ports.TelemetryAgentGap
	agentGapRevisions map[shared.ID]map[shared.ID][]ports.TelemetryAgentGapRevision
	agentGapDigests   map[shared.ID]map[string]shared.ID
	bindings          map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding
	auditIntents      map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete     map[fleetAuditKey]bool
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
	batchID              shared.ID
	payloadDigest        string
	asset                shared.ID
	schemaVersion        int
	eventCount           int
	observedCount        int
	keptCount            int
	sampledOutCount      int
	truncatedCount       int
	droppedCount         int
	samplingPolicyDigest string
	priority             fleetagent.DeliveryPriority
	fromAt               time.Time
	toAt                 time.Time
}

type storedTransportEvent struct {
	asset                 shared.ID
	class                 string
	digest                string
	redactionPolicyDigest string
	payload               []byte
	schemaVersion         int
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAuditStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAgentGapStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryBatchAccountingReader = (*TelemetryTransportStore)(nil)
var _ ports.CoverageGapReader = (*TelemetryTransportStore)(nil)

func NewTelemetryTransportStore() *TelemetryTransportStore {
	return &TelemetryTransportStore{
		states:            map[shared.ID]map[streamEpoch]ports.TelemetryStreamState{},
		commits:           map[shared.ID]map[batchKey]storedBatchCommit{},
		events:            map[shared.ID]map[eventKey]storedTransportEvent{},
		gaps:              map[shared.ID]map[streamEpoch][]ports.TelemetryGap{},
		gapHistory:        map[shared.ID]map[streamEpoch][]ports.TelemetryGap{},
		agentGaps:         map[shared.ID]map[shared.ID]ports.TelemetryAgentGap{},
		agentGapRevisions: map[shared.ID]map[shared.ID][]ports.TelemetryAgentGapRevision{},
		agentGapDigests:   map[shared.ID]map[string]shared.ID{},
		bindings:          map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding{},
		auditIntents:      make(map[fleetAuditKey]ports.FleetAuditIntent),
		auditComplete:     make(map[fleetAuditKey]bool),
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
	if s.gapHistory[tenant] == nil {
		s.gapHistory[tenant] = map[streamEpoch][]ports.TelemetryGap{}
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
	previous := s.gaps[tenant][key]
	materialized := next.GapsFrom()
	for i := range materialized {
		materialized[i].DetectedAt = next.UpdatedAt.UTC()
	}
	for _, old := range previous {
		stillOpen := false
		for i := range materialized {
			if old.FromSequence == materialized[i].FromSequence && old.ToSequence == materialized[i].ToSequence {
				materialized[i].DetectedAt = old.DetectedAt
				stillOpen = true
				break
			}
		}
		if !stillOpen {
			s.gapHistory[tenant][key] = append(s.gapHistory[tenant][key], old)
		}
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
		// Without a predecessor commitment the gap has no honest historical lower
		// bound. Represent it as a point at the known successor rather than
		// fabricating a span back to the Unix epoch.
		gap.FromAt = gap.ToAt
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

// ListGapChanges returns enriched inferred-gap history affected by one sequence.
// Resolved entries remain available so source retries can repair coverage windows.
func (s *TelemetryTransportStore) ListGapChanges(
	ctx context.Context,
	agentID, streamID shared.ID,
	epoch, sequence uint64,
) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := streamEpoch{agentID, streamID, epoch}
	var out []ports.TelemetryGap
	for _, raw := range s.gapHistory[tenant][key] {
		if sequence < raw.FromSequence || sequence > raw.ToSequence {
			continue
		}
		gap, ok := s.enrichGapLocked(tenant, raw)
		if ok {
			out = append(out, gap)
		}
	}
	for _, raw := range s.gaps[tenant][key] {
		startsAfter := sequence != ^uint64(0) && sequence+1 == raw.FromSequence
		endsBefore := raw.ToSequence != ^uint64(0) && sequence == raw.ToSequence+1
		if !startsAfter && !endsBefore {
			continue
		}
		gap, ok := s.enrichGapLocked(tenant, raw)
		if ok {
			out = append(out, gap)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FromAt.Equal(out[j].FromAt) {
			return out[i].FromAt.Before(out[j].FromAt)
		}
		if out[i].FromSequence != out[j].FromSequence {
			return out[i].FromSequence < out[j].FromSequence
		}
		return out[i].ToSequence < out[j].ToSequence
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

// AcceptAgentGapRevision atomically preserves the exact signed report and advances
// the current agent-gap projection under the same store lock.
func (s *TelemetryTransportStore) AcceptAgentGapRevision(ctx context.Context, revision ports.TelemetryAgentGapRevision) error {
	_, err := s.acceptAgentGapRevisionWithAudit(ctx, revision, nil)
	return err
}

func (s *TelemetryTransportStore) AcceptAgentGapRevisionWithAudit(
	ctx context.Context,
	revision ports.TelemetryAgentGapRevision,
	intent ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	return s.acceptAgentGapRevisionWithAudit(ctx, revision, &intent)
}

func (s *TelemetryTransportStore) acceptAgentGapRevisionWithAudit(
	ctx context.Context,
	revision ports.TelemetryAgentGapRevision,
	intent *ports.FleetAuditIntent,
) (ports.FleetAuditIntent, error) {
	if err := revision.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	gap := revision.Projection()
	if err := gap.Validate(); err != nil {
		return ports.FleetAuditIntent{}, err
	}
	if intent != nil {
		normalized, err := validateMemoryFleetAuditIntent(*intent)
		if err != nil {
			return ports.FleetAuditIntent{}, err
		}
		intent = &normalized
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agentGaps[tenant] == nil {
		s.agentGaps[tenant] = map[shared.ID]ports.TelemetryAgentGap{}
	}
	if s.agentGapRevisions[tenant] == nil {
		s.agentGapRevisions[tenant] = map[shared.ID][]ports.TelemetryAgentGapRevision{}
	}
	if s.agentGapDigests[tenant] == nil {
		s.agentGapDigests[tenant] = map[string]shared.ID{}
	}
	if existingGapID, ok := s.agentGapDigests[tenant][revision.SignedContentDigest]; ok {
		if existingGapID != revision.GapID {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: telemetry agent gap signed content is bound to another gap", shared.ErrConflict)
		}
	} else {
		current, ok := s.agentGaps[tenant][gap.GapID]
		if ok && !agentGapCompatibleExtension(current, gap) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: telemetry agent gap id is already committed to incompatible or larger evidence", shared.ErrConflict)
		}
		revision.Revision = uint64(len(s.agentGapRevisions[tenant][gap.GapID]) + 1)
		if ok {
			gap.FirstReportedAt = current.FirstReportedAt
			if gap.UpdatedAt.Before(current.UpdatedAt) {
				gap.UpdatedAt = current.UpdatedAt
			}
		}
		s.agentGapRevisions[tenant][gap.GapID] = append(s.agentGapRevisions[tenant][gap.GapID], revision)
		s.agentGapDigests[tenant][revision.SignedContentDigest] = gap.GapID
		s.agentGaps[tenant][gap.GapID] = gap
	}
	if intent == nil {
		return ports.FleetAuditIntent{}, nil
	}
	auditKey := fleetAuditKey{tenant: tenant, id: intent.ID}
	candidate := *intent
	if existing, ok := s.auditIntents[auditKey]; ok {
		candidate.Entry.At = existing.Entry.At
		if !memoryFleetAuditIntentEqual(existing, candidate) {
			return ports.FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id already has different immutable content", shared.ErrConflict)
		}
	}
	if _, ok := s.auditIntents[auditKey]; !ok {
		s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(candidate)
	}
	return cloneMemoryFleetAuditIntent(candidate), nil
}

func (s *TelemetryTransportStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenant && !s.auditComplete[key] {
			out = append(out, cloneMemoryFleetAuditIntent(intent))
		}
	}
	slices.SortFunc(out, func(left, right ports.FleetAuditIntent) int {
		if order := left.Entry.At.Compare(right.Entry.At); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	return out, nil
}

func (s *TelemetryTransportStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: fleet audit intention id is required", shared.ErrValidation)
	}
	key := fleetAuditKey{tenant: tenant, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.auditIntents[key]; !ok {
		return shared.ErrNotFound
	}
	s.auditComplete[key] = true
	return nil
}

// AgentGapRevisions returns tenant-scoped immutable revisions for focused
// persistence verification, ordered by acceptance in this store.
func (s *TelemetryTransportStore) AgentGapRevisions(ctx context.Context, gapID shared.ID) ([]ports.TelemetryAgentGapRevision, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	if gapID.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ports.TelemetryAgentGapRevision(nil), s.agentGapRevisions[tenant][gapID]...), nil
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
			if !q.Until.IsZero() && !gap.FromAt.Before(q.Until.UTC()) {
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
		if !q.Until.IsZero() && !source.FromAt.Before(q.Until.UTC()) {
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

// ListCoverageGapFacts returns each auditable loss fact independently. The
// existing QueryDeliveryGaps projection intentionally remains collapsed for its
// older consumers; coverage revision identity needs the source and fact ID.
func (s *TelemetryTransportStore) ListCoverageGapFacts(ctx context.Context, q ports.CoverageGapQuery) ([]ports.CoverageGapFact, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: coverage gap query has invalid identity or half-open interval", shared.ErrValidation)
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	facts := make([]ports.CoverageGapFact, 0)
	for _, materialized := range s.gaps[tenant] {
		for _, raw := range materialized {
			gap, ok := s.enrichGapLocked(tenant, raw)
			if !ok || gap.AgentID != q.AgentID || gap.AssetID != q.AssetID ||
				gap.ToAt.Before(q.Since.UTC()) || !gap.FromAt.Before(q.Until.UTC()) {
				continue
			}
			fact := ports.CoverageGapFact{
				Source: ports.CoverageGapInferred, FactID: inferredCoverageGapID(gap),
				AgentID: gap.AgentID, AssetID: gap.AssetID, StreamID: gap.StreamID,
				Priority: gap.Priority, Epoch: gap.Epoch, KnownSequence: true,
				FromSequence: gap.FromSequence, ToSequence: gap.ToSequence,
				Count:  gap.ToSequence - gap.FromSequence + 1,
				Reason: "missing_delivery_sequence", FromAt: gap.FromAt.UTC(),
				ToAt: gap.ToAt.UTC(), RecordedAt: gap.DetectedAt.UTC(),
			}
			if err := fact.Validate(); err != nil {
				return nil, fmt.Errorf("read inferred coverage gap: %w", err)
			}
			facts = append(facts, fact)
		}
	}
	for _, gap := range s.agentGaps[tenant] {
		if gap.AgentID != q.AgentID || gap.AssetID != q.AssetID ||
			gap.ToAt.Before(q.Since.UTC()) || !gap.FromAt.Before(q.Until.UTC()) {
			continue
		}
		fact := ports.CoverageGapFact{
			Source: ports.CoverageGapAgent, FactID: gap.GapID,
			AgentID: gap.AgentID, AssetID: gap.AssetID, StreamID: gap.StreamID,
			Priority: gap.Priority, Epoch: gap.Epoch, KnownSequence: gap.KnownSequence,
			FromSequence: gap.FromSequence, ToSequence: gap.ToSequence, Count: gap.Count,
			Reason: string(gap.Reason), FromAt: gap.FromAt.UTC(), ToAt: gap.ToAt.UTC(),
			RecordedAt: gap.FirstReportedAt.UTC(),
		}
		if err := fact.Validate(); err != nil {
			return nil, fmt.Errorf("read agent-origin coverage gap: %w", err)
		}
		facts = append(facts, fact)
	}
	sort.Slice(facts, func(i, j int) bool { return coverageGapFactLess(facts[i], facts[j]) })
	return facts, nil
}

func inferredCoverageGapID(gap ports.TelemetryGap) shared.ID {
	return ports.InferredCoverageGapFactID(
		gap.AgentID, gap.StreamID, gap.Epoch, gap.FromSequence, gap.ToSequence, gap.DetectedAt,
	)
}

func coverageGapFactLess(a, b ports.CoverageGapFact) bool {
	if !a.FromAt.Equal(b.FromAt) {
		return a.FromAt.Before(b.FromAt)
	}
	if a.StreamID != b.StreamID {
		return a.StreamID < b.StreamID
	}
	if a.Epoch != b.Epoch {
		return a.Epoch < b.Epoch
	}
	if a.FromSequence != b.FromSequence {
		return a.FromSequence < b.FromSequence
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.FactID < b.FactID
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
			if existing.asset != batch.AssetID || existing.class != string(e.Class) || existing.digest != e.Digest || existing.redactionPolicyDigest != e.RedactionPolicyDigest || existing.schemaVersion != batch.SchemaVersion || string(existing.payload) != string(e.Payload) {
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
		s.events[tenant][key] = storedTransportEvent{
			asset: batch.AssetID, class: string(e.Class), digest: e.Digest,
			redactionPolicyDigest: e.RedactionPolicyDigest,
			payload:               append([]byte(nil), e.Payload...), schemaVersion: batch.SchemaVersion,
		}
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

func (s *TelemetryTransportStore) QueryTelemetryBatchAccounting(ctx context.Context, q ports.TelemetryBatchAccountingQuery) ([]ports.TelemetryBatchAccounting, error) {
	if !q.Valid() {
		return nil, fmt.Errorf("%w: telemetry batch accounting query has invalid identity or half-open interval", shared.ErrValidation)
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ports.TelemetryBatchAccounting, 0)
	for key, commit := range s.commits[tenant] {
		if key.agent != q.AgentID || commit.asset != q.AssetID ||
			commit.toAt.Before(q.Since.UTC()) || !commit.fromAt.Before(q.Until.UTC()) {
			continue
		}
		accounting := ports.TelemetryBatchAccounting{
			AgentID: key.agent, StreamID: key.stream, BatchID: commit.batchID, AssetID: commit.asset,
			Priority: commit.priority, Epoch: key.epoch, Sequence: key.sequence,
			ObservedCount: commit.observedCount, KeptCount: commit.keptCount,
			SampledOutCount: commit.sampledOutCount, TruncatedCount: commit.truncatedCount,
			DroppedCount: commit.droppedCount, SamplingPolicyDigest: commit.samplingPolicyDigest,
			FromAt: commit.fromAt, ToAt: commit.toAt,
		}
		if err := accounting.Validate(); err != nil {
			return nil, fmt.Errorf("read telemetry batch accounting: %w", err)
		}
		out = append(out, accounting)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromAt.Equal(out[j].FromAt) {
			if out[i].StreamID != out[j].StreamID {
				return out[i].StreamID < out[j].StreamID
			}
			if out[i].Epoch != out[j].Epoch {
				return out[i].Epoch < out[j].Epoch
			}
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].FromAt.Before(out[j].FromAt)
	})
	return out, nil
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
	for agentID, current := range s.bindings[tenant] {
		if agentID != binding.AgentID && current.AssetID == binding.AssetID {
			return fmt.Errorf("%w: telemetry asset %s is already bound to agent %s", shared.ErrConflict, binding.AssetID, agentID)
		}
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

// ResolveTelemetryReferences resolves causal references from the existing accepted-event facts.
func (s *TelemetryTransportStore) ResolveTelemetryReferences(ctx context.Context, agentID, assetID shared.ID, redactionPolicyDigest string, refs []fleetagent.TelemetryReference) (ports.TelemetryReferenceStatus, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return "", err
	}
	if agentID.IsZero() || assetID.IsZero() || strings.TrimSpace(redactionPolicyDigest) == "" || len(refs) == 0 {
		return "", fmt.Errorf("%w: agent, asset, redaction policy digest and telemetry references are required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status := ports.TelemetryReferencesDurable
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return "", err
		}
		stored, ok := s.events[tenant][eventKey{agent: agentID, stream: ref.StreamID, epoch: ref.Epoch, sequence: ref.Sequence, eventID: ref.EventID}]
		if !ok {
			status = ports.TelemetryReferencesMissing
			continue
		}
		if stored.asset != assetID || stored.digest != ref.Digest || stored.redactionPolicyDigest != redactionPolicyDigest {
			return ports.TelemetryReferencesContradictory, nil
		}
	}
	return status, nil
}

func cloneStreamState(s ports.TelemetryStreamState) ports.TelemetryStreamState {
	c := s
	c.Pending = append([]uint64(nil), s.Pending...)
	return c
}

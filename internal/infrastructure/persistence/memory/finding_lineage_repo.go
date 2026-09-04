package memory

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type lineageKey struct {
	tenantID shared.ID
	cycleID  shared.ID
	id       shared.ID
}

type FindingLineageRepository struct {
	mu           sync.RWMutex
	identities   map[lineageKey]findinglineage.Identity
	observations map[lineageKey]findinglineage.Observation
	aliases      map[lineageKey]findinglineage.Alias
	candidates   map[lineageKey]findinglineage.MatchCandidate
	resolutions  map[lineageKey]findinglineage.ResolutionEvent
	overrides    map[lineageKey]findinglineage.OverrideEvent
	skips        map[lineageKey]findinglineage.SkipRecord
}

func NewFindingLineageRepository() *FindingLineageRepository {
	return &FindingLineageRepository{
		identities: map[lineageKey]findinglineage.Identity{}, observations: map[lineageKey]findinglineage.Observation{},
		aliases: map[lineageKey]findinglineage.Alias{}, candidates: map[lineageKey]findinglineage.MatchCandidate{},
		resolutions: map[lineageKey]findinglineage.ResolutionEvent{}, overrides: map[lineageKey]findinglineage.OverrideEvent{},
		skips: map[lineageKey]findinglineage.SkipRecord{},
	}
}

var _ ports.FindingLineageRepository = (*FindingLineageRepository)(nil)

func (repository *FindingLineageRepository) CreateIdentityWithObservation(ctx context.Context, identity findinglineage.Identity, observation findinglineage.Observation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	identity.TenantID = shared.TenantOrDefault(identity.TenantID)
	observation.TenantID = shared.TenantOrDefault(observation.TenantID)
	if err := identity.Validate(); err != nil {
		return err
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	if identity.TenantID != observation.TenantID || identity.CycleID != observation.CycleID || identity.ID != observation.IdentityID ||
		identity.FirstSeenSnapshotID != observation.SnapshotID || identity.ProducerKind != observation.ProducerKind ||
		identity.FindingKind != observation.FindingKind || identity.TargetIdentityCanonical != observation.TargetCanonical {
		return fmt.Errorf("%w: identity and first observation do not share ownership", shared.ErrValidation)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	identityKey := key(identity.TenantID, identity.CycleID, identity.ID)
	observationKey := key(observation.TenantID, observation.CycleID, observation.ID)
	if _, exists := repository.identities[identityKey]; exists {
		return fmt.Errorf("%w: finding identity already exists", shared.ErrConflict)
	}
	if _, exists := repository.observations[observationKey]; exists || repository.observationSourceExistsLocked(observation) {
		return fmt.Errorf("%w: finding observation already exists", shared.ErrConflict)
	}
	repository.identities[identityKey] = cloneLineageIdentity(identity)
	repository.observations[observationKey] = cloneLineageObservation(observation)
	return nil
}

func (repository *FindingLineageRepository) AppendObservation(ctx context.Context, observation findinglineage.Observation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	observation.TenantID = shared.TenantOrDefault(observation.TenantID)
	if err := observation.Validate(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	identity, exists := repository.identities[key(observation.TenantID, observation.CycleID, observation.IdentityID)]
	if !exists {
		return shared.ErrNotFound
	}
	if identity.ProducerKind != observation.ProducerKind || identity.FindingKind != observation.FindingKind || identity.TargetIdentityCanonical != observation.TargetCanonical {
		return fmt.Errorf("%w: observation does not match identity namespace", shared.ErrValidation)
	}
	observationKey := key(observation.TenantID, observation.CycleID, observation.ID)
	if existing, exists := repository.observations[observationKey]; exists {
		if reflect.DeepEqual(existing, observation) {
			return nil
		}
		return fmt.Errorf("%w: observation id was reused", shared.ErrConflict)
	}
	if repository.observationSourceExistsLocked(observation) {
		return fmt.Errorf("%w: source observation already exists in snapshot", shared.ErrConflict)
	}
	repository.observations[observationKey] = cloneLineageObservation(observation)
	return nil
}

func (repository *FindingLineageRepository) AppendAlias(ctx context.Context, alias findinglineage.Alias) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	alias.TenantID = shared.TenantOrDefault(alias.TenantID)
	if err := alias.Validate(); err != nil {
		return false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.identities[key(alias.TenantID, alias.CycleID, alias.IdentityID)]; !exists {
		return false, shared.ErrNotFound
	}
	for _, existing := range repository.aliases {
		if sameAlias(existing, alias) {
			return false, nil
		}
	}
	aliasKey := key(alias.TenantID, alias.CycleID, alias.ID)
	if _, exists := repository.aliases[aliasKey]; exists {
		return false, fmt.Errorf("%w: alias id was reused", shared.ErrConflict)
	}
	repository.aliases[aliasKey] = alias
	return true, nil
}

func (repository *FindingLineageRepository) GetIdentity(ctx context.Context, tenantID, cycleID, identityID shared.ID) (findinglineage.Identity, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.Identity{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	identity, exists := repository.identities[key(tenantID, cycleID, identityID)]
	if !exists {
		return findinglineage.Identity{}, shared.ErrNotFound
	}
	return cloneLineageIdentity(identity), nil
}

func (repository *FindingLineageRepository) GetObservation(ctx context.Context, tenantID, cycleID, observationID shared.ID) (findinglineage.Observation, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.Observation{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	observation, exists := repository.observations[key(tenantID, cycleID, observationID)]
	if !exists {
		return findinglineage.Observation{}, shared.ErrNotFound
	}
	return cloneLineageObservation(observation), nil
}

func (repository *FindingLineageRepository) GetObservationBySource(ctx context.Context, tenantID, cycleID, snapshotID shared.ID, producerKind, findingKind, targetCanonical, sourceFindingID, sourceOccurrenceID string) (findinglineage.Observation, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.Observation{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	for _, observation := range repository.observations {
		if observation.TenantID == tenantID && observation.CycleID == cycleID && observation.SnapshotID == snapshotID &&
			observation.ProducerKind == producerKind && observation.FindingKind == findingKind && observation.TargetCanonical == targetCanonical &&
			observation.SourceFindingID == sourceFindingID && observation.SourceOccurrenceID == sourceOccurrenceID {
			return cloneLineageObservation(observation), nil
		}
	}
	return findinglineage.Observation{}, shared.ErrNotFound
}

func (repository *FindingLineageRepository) FindIdentitiesByProducerID(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind, targetCanonical, sourceID string) ([]findinglineage.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	seen := map[shared.ID]struct{}{}
	identities := make([]findinglineage.Identity, 0)
	for _, observation := range repository.observations {
		if observation.TenantID != tenantID || observation.CycleID != cycleID || observation.ProducerKind != producerKind || observation.FindingKind != findingKind || observation.TargetCanonical != targetCanonical ||
			(observation.SourceFindingID != sourceID && observation.SourceOccurrenceID != sourceID) {
			continue
		}
		if _, exists := seen[observation.IdentityID]; exists {
			continue
		}
		seen[observation.IdentityID] = struct{}{}
		identities = append(identities, cloneLineageIdentity(repository.identities[key(tenantID, cycleID, observation.IdentityID)]))
	}
	sortLineageIdentities(identities)
	return identities, nil
}

func (repository *FindingLineageRepository) FindIdentitiesByFingerprint(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind string, schemaVersion int, targetCanonical, fingerprint string) ([]findinglineage.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	identities := make([]findinglineage.Identity, 0)
	for _, identity := range repository.identities {
		if identity.TenantID == tenantID && identity.CycleID == cycleID && identity.ProducerKind == producerKind && identity.FindingKind == findingKind &&
			identity.FingerprintSchemaVersion == schemaVersion && identity.TargetIdentityCanonical == targetCanonical && identity.LineageFingerprint == fingerprint {
			identities = append(identities, cloneLineageIdentity(identity))
		}
	}
	sortLineageIdentities(identities)
	return identities, nil
}

func (repository *FindingLineageRepository) FindIdentitiesByAlias(ctx context.Context, tenantID, cycleID shared.ID, producerKind, findingKind string, schemaVersion int, targetCanonical, fingerprint string) ([]findinglineage.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	seen := map[shared.ID]struct{}{}
	identities := make([]findinglineage.Identity, 0)
	for _, alias := range repository.aliases {
		if alias.TenantID != tenantID || alias.CycleID != cycleID || alias.ProducerKind != producerKind || alias.FindingKind != findingKind ||
			alias.SchemaVersion != schemaVersion || alias.TargetCanonical != targetCanonical || alias.Fingerprint != fingerprint {
			continue
		}
		if _, exists := seen[alias.IdentityID]; exists {
			continue
		}
		seen[alias.IdentityID] = struct{}{}
		identities = append(identities, cloneLineageIdentity(repository.identities[key(tenantID, cycleID, alias.IdentityID)]))
	}
	sortLineageIdentities(identities)
	return identities, nil
}

func (repository *FindingLineageRepository) ListObservationsBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.Observation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	observations := make([]findinglineage.Observation, 0)
	for _, observation := range repository.observations {
		if observation.TenantID == tenantID && observation.CycleID == cycleID && observation.SnapshotID == snapshotID {
			observations = append(observations, cloneLineageObservation(observation))
		}
	}
	sort.Slice(observations, func(left, right int) bool { return observations[left].ID < observations[right].ID })
	return observations, nil
}

func (repository *FindingLineageRepository) ListOpenCandidatesBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.MatchCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	candidates := make([]findinglineage.MatchCandidate, 0)
	for _, candidate := range repository.candidates {
		if candidate.TenantID == tenantID && candidate.CycleID == cycleID && candidate.SnapshotID == snapshotID && candidate.Status == findinglineage.CandidateOpen {
			candidates = append(candidates, cloneMatchCandidate(candidate))
		}
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].ID < candidates[right].ID })
	return candidates, nil
}

func (repository *FindingLineageRepository) ListActiveOverridesBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.OverrideEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	latest := map[shared.ID]findinglineage.OverrideEvent{}
	for _, event := range repository.overrides {
		observation, exists := repository.observations[key(tenantID, cycleID, event.SourceObservationID)]
		if !exists || observation.SnapshotID != snapshotID {
			continue
		}
		if current, exists := latest[event.SourceObservationID]; !exists || event.Version > current.Version {
			latest[event.SourceObservationID] = event
		}
	}
	events := make([]findinglineage.OverrideEvent, 0, len(latest))
	for _, event := range latest {
		events = append(events, event)
	}
	sort.Slice(events, func(left, right int) bool {
		return events[left].SourceObservationID < events[right].SourceObservationID
	})
	return events, nil
}

func (repository *FindingLineageRepository) CreateCandidate(ctx context.Context, candidate findinglineage.MatchCandidate, supersessionEventID shared.ID) (findinglineage.MatchCandidate, bool, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.MatchCandidate{}, false, err
	}
	candidate.TenantID = shared.TenantOrDefault(candidate.TenantID)
	if err := candidate.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, existing := range repository.candidates {
		if sameCandidateIdempotency(existing, candidate) {
			return cloneMatchCandidate(existing), false, nil
		}
	}
	candidateKey := key(candidate.TenantID, candidate.CycleID, candidate.ID)
	if _, exists := repository.candidates[candidateKey]; exists {
		return findinglineage.MatchCandidate{}, false, fmt.Errorf("%w: candidate id was reused", shared.ErrConflict)
	}
	for existingKey, existing := range repository.candidates {
		if !sameOpenCandidateSubject(existing, candidate) {
			continue
		}
		if supersessionEventID.IsZero() {
			return findinglineage.MatchCandidate{}, false, fmt.Errorf("%w: supersession event id is required", shared.ErrValidation)
		}
		prior := repository.latestResolutionIDLocked(existing.TenantID, existing.CycleID, existing.ID)
		updated, event, err := findinglineage.ResolveCandidate(existing, supersessionEventID, findinglineage.ResolutionSupersede,
			"system:finding-lineage", "candidate_ref_set_changed", candidate.Refs, candidate.ID, existing.Version, prior, candidate.CreatedAt)
		if err != nil {
			return findinglineage.MatchCandidate{}, false, err
		}
		if _, exists := repository.resolutions[key(event.TenantID, event.CycleID, event.ID)]; exists {
			return findinglineage.MatchCandidate{}, false, fmt.Errorf("%w: supersession event id was reused", shared.ErrConflict)
		}
		repository.candidates[existingKey] = cloneMatchCandidate(updated)
		repository.resolutions[key(event.TenantID, event.CycleID, event.ID)] = cloneResolutionEvent(event)
		break
	}
	repository.candidates[candidateKey] = cloneMatchCandidate(candidate)
	return cloneMatchCandidate(candidate), true, nil
}

func (repository *FindingLineageRepository) GetCandidate(ctx context.Context, tenantID, cycleID, candidateID shared.ID) (findinglineage.MatchCandidate, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.MatchCandidate{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	candidate, exists := repository.candidates[key(tenantID, cycleID, candidateID)]
	if !exists {
		return findinglineage.MatchCandidate{}, shared.ErrNotFound
	}
	return cloneMatchCandidate(candidate), nil
}

func (repository *FindingLineageRepository) ResolveCandidateCAS(ctx context.Context, updated findinglineage.MatchCandidate, event findinglineage.ResolutionEvent) (findinglineage.MatchCandidate, findinglineage.ResolutionEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	updated.TenantID = shared.TenantOrDefault(updated.TenantID)
	event.TenantID = shared.TenantOrDefault(event.TenantID)
	if err := updated.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	if err := event.Validate(); err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	eventKey := key(event.TenantID, event.CycleID, event.ID)
	if existing, exists := repository.resolutions[eventKey]; exists {
		if existing.ContentHash != event.ContentHash {
			return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, fmt.Errorf("%w: resolution event id was reused", shared.ErrConflict)
		}
		current := repository.candidates[key(event.TenantID, event.CycleID, event.CandidateID)]
		return cloneMatchCandidate(current), cloneResolutionEvent(existing), false, nil
	}
	candidateKey := key(event.TenantID, event.CycleID, event.CandidateID)
	current, exists := repository.candidates[candidateKey]
	if !exists {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, shared.ErrNotFound
	}
	if repository.latestResolutionIDLocked(event.TenantID, event.CycleID, event.CandidateID) != event.PriorEventID {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, fmt.Errorf("%w: resolution prior event changed", shared.ErrConflict)
	}
	wantUpdated, wantEvent, err := findinglineage.ResolveCandidate(current, event.ID, event.Action, event.Actor, event.Reason,
		event.AfterRefs, event.SuccessorCandidateID, event.ExpectedVersion, event.PriorEventID, event.CreatedAt)
	if err != nil {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, err
	}
	if !sameCandidateResolution(wantUpdated, updated) || wantEvent.ContentHash != event.ContentHash {
		return findinglineage.MatchCandidate{}, findinglineage.ResolutionEvent{}, false, fmt.Errorf("%w: resolution event does not match candidate", shared.ErrValidation)
	}
	repository.candidates[candidateKey] = cloneMatchCandidate(wantUpdated)
	repository.resolutions[eventKey] = cloneResolutionEvent(wantEvent)
	return cloneMatchCandidate(wantUpdated), cloneResolutionEvent(wantEvent), true, nil
}

func (repository *FindingLineageRepository) ListCandidateResolutions(ctx context.Context, tenantID, cycleID, candidateID shared.ID) ([]findinglineage.ResolutionEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	events := make([]findinglineage.ResolutionEvent, 0)
	for _, event := range repository.resolutions {
		if event.TenantID == tenantID && event.CycleID == cycleID && event.CandidateID == candidateID {
			events = append(events, cloneResolutionEvent(event))
		}
	}
	sort.Slice(events, func(left, right int) bool { return events[left].Version < events[right].Version })
	return events, nil
}

func (repository *FindingLineageRepository) GetActiveOverride(ctx context.Context, tenantID, cycleID, sourceObservationID shared.ID) (findinglineage.OverrideEvent, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.OverrideEvent{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	var active findinglineage.OverrideEvent
	for _, event := range repository.overrides {
		if event.TenantID == tenantID && event.CycleID == cycleID && event.SourceObservationID == sourceObservationID && event.Version > active.Version {
			active = event
		}
	}
	if active.ID.IsZero() {
		return findinglineage.OverrideEvent{}, shared.ErrNotFound
	}
	return active, nil
}

func (repository *FindingLineageRepository) AppendOverrideCAS(ctx context.Context, event findinglineage.OverrideEvent) (findinglineage.OverrideEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return findinglineage.OverrideEvent{}, false, err
	}
	event.TenantID = shared.TenantOrDefault(event.TenantID)
	if err := event.Validate(); err != nil {
		return findinglineage.OverrideEvent{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	eventKey := key(event.TenantID, event.CycleID, event.ID)
	if existing, exists := repository.overrides[eventKey]; exists {
		if existing.ContentHash != event.ContentHash {
			return findinglineage.OverrideEvent{}, false, fmt.Errorf("%w: override event id was reused", shared.ErrConflict)
		}
		return existing, false, nil
	}
	if _, exists := repository.observations[key(event.TenantID, event.CycleID, event.SourceObservationID)]; !exists {
		return findinglineage.OverrideEvent{}, false, shared.ErrNotFound
	}
	if _, exists := repository.identities[key(event.TenantID, event.CycleID, event.TargetIdentityID)]; !exists {
		return findinglineage.OverrideEvent{}, false, shared.ErrNotFound
	}
	if !event.SourceIdentityID.IsZero() {
		if _, exists := repository.identities[key(event.TenantID, event.CycleID, event.SourceIdentityID)]; !exists {
			return findinglineage.OverrideEvent{}, false, shared.ErrNotFound
		}
	}
	if !event.TargetObservationID.IsZero() {
		if _, exists := repository.observations[key(event.TenantID, event.CycleID, event.TargetObservationID)]; !exists {
			return findinglineage.OverrideEvent{}, false, shared.ErrNotFound
		}
	}
	var active findinglineage.OverrideEvent
	for _, existing := range repository.overrides {
		if existing.TenantID == event.TenantID && existing.CycleID == event.CycleID && existing.SourceObservationID == event.SourceObservationID && existing.Version > active.Version {
			active = existing
		}
	}
	if active.Version != event.ExpectedVersion || active.ID != event.PriorEventID {
		return findinglineage.OverrideEvent{}, false, fmt.Errorf("%w: override version changed", shared.ErrConflict)
	}
	repository.overrides[eventKey] = event
	return event, true, nil
}

func (repository *FindingLineageRepository) ListOverrideEvents(ctx context.Context, tenantID, cycleID, sourceObservationID shared.ID) ([]findinglineage.OverrideEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	events := make([]findinglineage.OverrideEvent, 0)
	for _, event := range repository.overrides {
		if event.TenantID == tenantID && event.CycleID == cycleID && event.SourceObservationID == sourceObservationID {
			events = append(events, event)
		}
	}
	sort.Slice(events, func(left, right int) bool { return events[left].Version < events[right].Version })
	return events, nil
}

func (repository *FindingLineageRepository) AppendSkip(ctx context.Context, record findinglineage.SkipRecord) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	record.TenantID = shared.TenantOrDefault(record.TenantID)
	if err := record.Validate(); err != nil {
		return false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, existing := range repository.skips {
		if existing.TenantID == record.TenantID && existing.CycleID == record.CycleID && existing.SnapshotID == record.SnapshotID &&
			existing.ProducerKind == record.ProducerKind && existing.Reason == record.Reason && existing.SourceReferenceHash == record.SourceReferenceHash {
			return false, nil
		}
	}
	recordKey := key(record.TenantID, record.CycleID, record.ID)
	if _, exists := repository.skips[recordKey]; exists {
		return false, fmt.Errorf("%w: skip record id was reused", shared.ErrConflict)
	}
	repository.skips[recordKey] = record
	return true, nil
}

func (repository *FindingLineageRepository) ListSkipsBySnapshot(ctx context.Context, tenantID, cycleID, snapshotID shared.ID) ([]findinglineage.SkipRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	records := make([]findinglineage.SkipRecord, 0)
	for _, record := range repository.skips {
		if record.TenantID == tenantID && record.CycleID == cycleID && record.SnapshotID == snapshotID {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(left, right int) bool { return records[left].ID < records[right].ID })
	return records, nil
}

func (repository *FindingLineageRepository) observationSourceExistsLocked(observation findinglineage.Observation) bool {
	for _, existing := range repository.observations {
		if existing.TenantID == observation.TenantID && existing.CycleID == observation.CycleID && existing.SnapshotID == observation.SnapshotID &&
			existing.ProducerKind == observation.ProducerKind && existing.FindingKind == observation.FindingKind && existing.TargetCanonical == observation.TargetCanonical &&
			existing.SourceFindingID == observation.SourceFindingID && existing.SourceOccurrenceID == observation.SourceOccurrenceID {
			return true
		}
	}
	return false
}

func (repository *FindingLineageRepository) latestResolutionIDLocked(tenantID, cycleID, candidateID shared.ID) shared.ID {
	var latest findinglineage.ResolutionEvent
	for _, event := range repository.resolutions {
		if event.TenantID == tenantID && event.CycleID == cycleID && event.CandidateID == candidateID && event.Version > latest.Version {
			latest = event
		}
	}
	return latest.ID
}

func sameAlias(left, right findinglineage.Alias) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID && left.IdentityID == right.IdentityID &&
		left.ProducerKind == right.ProducerKind && left.FindingKind == right.FindingKind && left.TargetCanonical == right.TargetCanonical &&
		left.SchemaVersion == right.SchemaVersion && left.Fingerprint == right.Fingerprint
}

func sameCandidateIdempotency(left, right findinglineage.MatchCandidate) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID && left.SnapshotID == right.SnapshotID &&
		left.ProducerKind == right.ProducerKind && left.Reason == right.Reason && left.CandidateSetHash == right.CandidateSetHash
}

func sameOpenCandidateSubject(left, right findinglineage.MatchCandidate) bool {
	return left.Status == findinglineage.CandidateOpen && left.TenantID == right.TenantID && left.CycleID == right.CycleID &&
		left.SnapshotID == right.SnapshotID && left.ProducerKind == right.ProducerKind && left.Reason == right.Reason &&
		left.SourceReferenceHash == right.SourceReferenceHash
}

func key(tenantID, cycleID, id shared.ID) lineageKey {
	return lineageKey{tenantID: tenantID, cycleID: cycleID, id: id}
}

func cloneLineageIdentity(identity findinglineage.Identity) findinglineage.Identity {
	identity.CanonicalIdentityFields = append([]byte(nil), identity.CanonicalIdentityFields...)
	return identity
}

func cloneLineageObservation(observation findinglineage.Observation) findinglineage.Observation {
	if observation.RiskScoreMilli != nil {
		value := *observation.RiskScoreMilli
		observation.RiskScoreMilli = &value
	}
	return observation
}

func cloneMatchCandidate(candidate findinglineage.MatchCandidate) findinglineage.MatchCandidate {
	candidate.Refs = cloneLineageRefs(candidate.Refs)
	if candidate.ResolvedAt != nil {
		value := *candidate.ResolvedAt
		candidate.ResolvedAt = &value
	}
	if candidate.SupersededAt != nil {
		value := *candidate.SupersededAt
		candidate.SupersededAt = &value
	}
	return candidate
}

func cloneResolutionEvent(event findinglineage.ResolutionEvent) findinglineage.ResolutionEvent {
	event.BeforeRefs = cloneLineageRefs(event.BeforeRefs)
	event.AfterRefs = cloneLineageRefs(event.AfterRefs)
	return event
}

func cloneLineageRefs(input []findinglineage.CandidateRef) []findinglineage.CandidateRef {
	output := make([]findinglineage.CandidateRef, len(input))
	for index, reference := range input {
		output[index] = reference
		if reference.ReasonPayload != nil {
			output[index].ReasonPayload = make(map[string]string, len(reference.ReasonPayload))
			for key, value := range reference.ReasonPayload {
				output[index].ReasonPayload[key] = value
			}
		}
	}
	return output
}

func sortLineageIdentities(identities []findinglineage.Identity) {
	sort.Slice(identities, func(left, right int) bool { return identities[left].ID < identities[right].ID })
}

func sameCandidateResolution(left, right findinglineage.MatchCandidate) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID && left.ID == right.ID &&
		left.Status == right.Status && left.Version == right.Version && left.SupersededByCandidateID == right.SupersededByCandidateID &&
		sameOptionalTime(left.ResolvedAt, right.ResolvedAt) && sameOptionalTime(left.SupersededAt, right.SupersededAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysource"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type advisoryRevision struct {
	canonical advisory.Canonical
	hash      string
	fields    []advisory.ChangedField
	syncRuns  []advisoryRevisionSyncRun
	createdAt time.Time
}

type advisoryRevisionSyncRun struct {
	ID       shared.ID
	TenantID shared.ID
}

type sourceSnapshotPublication struct {
	TenantID       shared.ID
	SourceID       string
	AdapterType    string
	NextCheckpoint []byte
	Results        []advisory.MaterializationResult
}

type evaluationCheckpoint struct {
	revision    int64
	evaluatedAt time.Time
}

// AdvisoryMaterializer is an in-memory implementation of the global advisory
// observation history and canonical projection.
type AdvisoryMaterializer struct {
	mu                   sync.Mutex
	observations         map[string]advisory.ObservationRecord
	current              map[string]string
	identityIndex        map[string]map[string]struct{}
	sourceIndex          map[string]map[string]struct{}
	activeSourceIndex    map[string]map[string]struct{}
	canonicals           map[string]advisory.Canonical
	aliases              map[string]string
	revisions            map[string][]advisoryRevision
	snapshotPublications map[shared.ID]sourceSnapshotPublication
	evaluated            map[shared.ID]map[string]evaluationCheckpoint
	// now stamps each revision's createdAt. It defaults to the wall clock; tests inject a controlled
	// clock so revision-pinning is deterministic regardless of the host clock resolution (Windows'
	// ~15ms tick otherwise lets two closely-spaced Materialize calls share a createdAt).
	now func() time.Time
}

func NewAdvisoryMaterializer() *AdvisoryMaterializer {
	return &AdvisoryMaterializer{
		observations:         map[string]advisory.ObservationRecord{},
		current:              map[string]string{},
		identityIndex:        map[string]map[string]struct{}{},
		sourceIndex:          map[string]map[string]struct{}{},
		activeSourceIndex:    map[string]map[string]struct{}{},
		canonicals:           map[string]advisory.Canonical{},
		aliases:              map[string]string{},
		revisions:            map[string][]advisoryRevision{},
		snapshotPublications: map[shared.ID]sourceSnapshotPublication{},
		evaluated:            map[shared.ID]map[string]evaluationCheckpoint{},
		now:                  func() time.Time { return time.Now().UTC() },
	}
}

// WithClock overrides the revision-createdAt clock (tests only). A nil clock is ignored.
func (m *AdvisoryMaterializer) WithClock(now func() time.Time) *AdvisoryMaterializer {
	if now != nil {
		m.mu.Lock()
		m.now = now
		m.mu.Unlock()
	}
	return m
}

var _ ports.AdvisoryMaterializer = (*AdvisoryMaterializer)(nil)
var _ ports.SourceSnapshotPublisher = (*AdvisoryMaterializer)(nil)
var _ ports.PublishedSourceSnapshotReader = (*AdvisoryMaterializer)(nil)
var _ ports.BoundedCurrentSourceRecordIDs = (*AdvisoryMaterializer)(nil)
var _ ports.AuthoritativeSourceSnapshotStore = (*AdvisoryMaterializer)(nil)
var _ ports.AdvisoryStore = (*AdvisoryMaterializer)(nil)
var _ ports.AdvisoryEvaluationCheckpointStore = (*AdvisoryMaterializer)(nil)
var _ ports.VulnerabilityAdvisoryReadStore = (*AdvisoryMaterializer)(nil)
var _ ports.VulnerabilityAdvisoryImpactReadStore = (*AdvisoryMaterializer)(nil)

func (m *AdvisoryMaterializer) CurrentSourceRecordIDs(ctx context.Context, sourceID string, yield func(string) error) error {
	return m.currentSourceRecordIDs(ctx, sourceID, 0, true, yield)
}

func (m *AdvisoryMaterializer) CurrentSourceRecordIDsBounded(ctx context.Context, sourceID string, limit int, yield func(string) error) error {
	if limit <= 0 {
		return fmt.Errorf("%w: source record limit is required", shared.ErrValidation)
	}
	return m.currentSourceRecordIDs(ctx, sourceID, limit, false, yield)
}

func (m *AdvisoryMaterializer) currentSourceRecordIDs(ctx context.Context, sourceID string, limit int, includeAbsenceRetirements bool, yield func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" || yield == nil {
		return fmt.Errorf("%w: source id and callback are required", shared.ErrValidation)
	}
	index := m.activeSourceIndex
	if includeAbsenceRetirements {
		index = m.sourceIndex
	}
	capacity := len(index[sourceID])
	if limit > 0 && limit < capacity {
		capacity = limit
	}
	result := make([]string, 0, capacity)
	for currentKey := range index[sourceID] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, ok := m.current[currentKey]; !ok {
			continue
		}
		parts := strings.SplitN(currentKey, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		if limit > 0 && len(result) == limit {
			return fmt.Errorf("%w: current source records exceed %d", shared.ErrValidation, limit)
		}
		result = append(result, parts[1])
	}
	sort.Strings(result)
	for _, recordID := range result {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(recordID); err != nil {
			return err
		}
	}
	return nil
}

func (m *AdvisoryMaterializer) Materialize(ctx context.Context, records []advisory.ObservationRecord) (advisory.MaterializationResult, error) {
	if err := advisory.ValidateBatch(records); err != nil {
		return advisory.MaterializationResult{}, fmt.Errorf("validate advisory batch: %w", err)
	}
	tenantID, hasTenant := shared.TenantFrom(ctx)
	for _, record := range records {
		if strings.TrimSpace(record.SyncRunID) != "" && !hasTenant {
			return advisory.MaterializationResult{}, fmt.Errorf("%w: sync run provenance requires tenant context", shared.ErrValidation)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	working, err := m.clone()
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	result, err := working.materializeLocked(tenantID, records)
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	m.observations = working.observations
	m.current = working.current
	m.identityIndex = working.identityIndex
	m.sourceIndex = working.sourceIndex
	m.activeSourceIndex = working.activeSourceIndex
	m.canonicals = working.canonicals
	m.aliases = working.aliases
	m.revisions = working.revisions
	return result, nil
}

// MaterializeSourceSnapshot applies a complete source view through one copy-on-write
// swap. Each record is materialized independently because unrelated source records do
// not share an advisory identity, but an error leaves every live projection unchanged.
func (m *AdvisoryMaterializer) MaterializeSourceSnapshot(ctx context.Context, records []advisory.ObservationRecord) ([]advisory.MaterializationResult, error) {
	return m.materializeSourceSnapshot(ctx, ports.SourceSnapshotPublication{}, records)
}

// PublishSourceSnapshot atomically commits a complete source view with a receipt that
// preserves its provider checkpoint and exact revision results for durable recovery.
func (m *AdvisoryMaterializer) PublishSourceSnapshot(ctx context.Context, publication ports.SourceSnapshotPublication, records []advisory.ObservationRecord) ([]advisory.MaterializationResult, error) {
	if publication.SyncRunID.IsZero() {
		return nil, fmt.Errorf("%w: source snapshot publication requires a sync run", shared.ErrValidation)
	}
	return m.materializeSourceSnapshot(ctx, publication, records)
}

func (m *AdvisoryMaterializer) materializeSourceSnapshot(ctx context.Context, publication ports.SourceSnapshotPublication, records []advisory.ObservationRecord) ([]advisory.MaterializationResult, error) {
	normalized, err := normalizeSourceSnapshot(records)
	if err != nil {
		return nil, err
	}
	tenantID, hasTenant := shared.TenantFrom(ctx)
	if !publication.SyncRunID.IsZero() {
		if !hasTenant {
			return nil, fmt.Errorf("%w: source snapshot publication requires tenant context", shared.ErrValidation)
		}
		for _, record := range normalized {
			if shared.ID(strings.TrimSpace(record.SyncRunID)) != publication.SyncRunID {
				return nil, fmt.Errorf("%w: source snapshot record does not match its publication run", shared.ErrValidation)
			}
		}
	}
	for _, record := range normalized {
		if strings.TrimSpace(record.SyncRunID) != "" && !hasTenant {
			return nil, fmt.Errorf("%w: sync run provenance requires tenant context", shared.ErrValidation)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sourceType := normalized[0].Observation.SourceType
	if sourceType != string(vulnerabilitysource.AdapterOVAL) && sourceType != string(vulnerabilitysource.AdapterCSAF) {
		return nil, fmt.Errorf("%w: unsupported authoritative source adapter %q", shared.ErrValidation, sourceType)
	}
	if !publication.SyncRunID.IsZero() {
		if _, exists := m.snapshotPublications[publication.SyncRunID]; exists {
			return nil, fmt.Errorf("%w: source snapshot publication already exists", shared.ErrConflict)
		}
	}
	for _, record := range normalized {
		key := record.Observation.SourceID + "\x00" + record.Observation.RecordID
		hash, ok := m.current[key]
		if !ok {
			continue
		}
		previous := m.observations[recordKey(record.Observation.SourceID, record.Observation.RecordID, hash)]
		if previous.Observation.SourceType != record.Observation.SourceType {
			return nil, fmt.Errorf("%w: authoritative source contains an observation from another adapter", shared.ErrValidation)
		}
		identities := previous.IdentityIDs()
		if len(identities) != 1 || identities[0] != record.Observation.RecordID {
			return nil, fmt.Errorf("%w: authoritative source record has legacy aliases", shared.ErrValidation)
		}
	}
	working, err := m.clone()
	if err != nil {
		return nil, err
	}
	results := make([]advisory.MaterializationResult, 0, len(normalized))
	for _, record := range normalized {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := working.materializeLocked(tenantID, []advisory.ObservationRecord{record})
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !publication.SyncRunID.IsZero() {
		clonedResults, err := cloneMaterializationResults(results)
		if err != nil {
			return nil, err
		}
		working.snapshotPublications[publication.SyncRunID] = sourceSnapshotPublication{
			TenantID:       tenantID,
			SourceID:       normalized[0].Observation.SourceID,
			AdapterType:    normalized[0].Observation.SourceType,
			NextCheckpoint: append([]byte(nil), publication.NextCheckpoint...),
			Results:        clonedResults,
		}
	}
	m.observations = working.observations
	m.current = working.current
	m.identityIndex = working.identityIndex
	m.sourceIndex = working.sourceIndex
	m.activeSourceIndex = working.activeSourceIndex
	m.canonicals = working.canonicals
	m.aliases = working.aliases
	m.revisions = working.revisions
	m.snapshotPublications = working.snapshotPublications
	return results, nil
}

func (m *AdvisoryMaterializer) PublishedSourceSnapshot(ctx context.Context, syncRunID shared.ID) (ports.PublishedSourceSnapshot, bool, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return ports.PublishedSourceSnapshot{}, false, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	if syncRunID.IsZero() {
		return ports.PublishedSourceSnapshot{}, false, fmt.Errorf("%w: sync run id is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	m.mu.Lock()
	defer m.mu.Unlock()
	publication, ok := m.snapshotPublications[syncRunID]
	if !ok || publication.TenantID != tenantID {
		return ports.PublishedSourceSnapshot{}, false, nil
	}
	results, err := cloneMaterializationResults(publication.Results)
	if err != nil {
		return ports.PublishedSourceSnapshot{}, false, err
	}
	return ports.PublishedSourceSnapshot{
		SourceID:       shared.ID(publication.SourceID),
		AdapterType:    publication.AdapterType,
		NextCheckpoint: append([]byte(nil), publication.NextCheckpoint...),
		Results:        results,
	}, true, nil
}

func normalizeSourceSnapshot(records []advisory.ObservationRecord) ([]advisory.ObservationRecord, error) {
	if err := advisory.ValidateSourceSnapshot(records); err != nil {
		return nil, fmt.Errorf("validate advisory source snapshot: %w", err)
	}
	normalized := make([]advisory.ObservationRecord, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	var sourceID, sourceType string
	for _, record := range records {
		normalizedRecord, err := record.Normalize()
		if err != nil {
			return nil, err
		}
		if sourceID == "" {
			sourceID = normalizedRecord.Observation.SourceID
			sourceType = normalizedRecord.Observation.SourceType
		}
		if normalizedRecord.Observation.SourceID != sourceID || normalizedRecord.Observation.SourceType != sourceType {
			return nil, fmt.Errorf("%w: source snapshot contains multiple sources", shared.ErrValidation)
		}
		identities := normalizedRecord.IdentityIDs()
		if len(identities) != 1 || identities[0] != normalizedRecord.Observation.RecordID {
			return nil, fmt.Errorf("%w: authoritative source snapshot records must use their record id as the sole identity", shared.ErrValidation)
		}
		if normalizedRecord.Observation.AbsenceRetirement {
			if normalizedRecord.Observation.Status != advisory.StatusActive || len(normalizedRecord.Observation.Advisory.Affected) != 0 {
				return nil, fmt.Errorf("%w: authoritative source absence must be active with no affected packages", shared.ErrValidation)
			}
		} else if normalizedRecord.Observation.Status != advisory.StatusActive {
			return nil, fmt.Errorf("%w: authoritative source records must be active", shared.ErrValidation)
		}
		key := normalizedRecord.Observation.SourceID + "\x00" + normalizedRecord.Observation.RecordID
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate provider record %s", shared.ErrConflict, key)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, normalizedRecord)
	}
	sort.Slice(normalized, func(i, j int) bool {
		left := normalized[i].Observation.SourceID + "\x00" + normalized[i].Observation.RecordID
		right := normalized[j].Observation.SourceID + "\x00" + normalized[j].Observation.RecordID
		return left < right
	})
	return normalized, nil
}

func (m *AdvisoryMaterializer) materializeLocked(tenantID shared.ID, records []advisory.ObservationRecord) (advisory.MaterializationResult, error) {
	normalized := make([]advisory.ObservationRecord, 0, len(records))
	seenRecord := map[string]string{}
	identitySet := map[string]struct{}{}
	for _, record := range records {
		record, err := record.Normalize()
		if err != nil {
			return advisory.MaterializationResult{}, err
		}
		hash, err := record.ContentHash()
		if err != nil {
			return advisory.MaterializationResult{}, err
		}
		key := record.Observation.SourceID + "\x00" + record.Observation.RecordID
		if previous, ok := seenRecord[key]; ok && previous != hash {
			return advisory.MaterializationResult{}, fmt.Errorf("%w: duplicate provider record", shared.ErrConflict)
		}
		seenRecord[key] = hash
		for _, id := range record.IdentityIDs() {
			identitySet[id] = struct{}{}
		}
		normalized = append(normalized, record)
	}

	for _, record := range normalized {
		if err := m.replaceCurrentObservation(record); err != nil {
			return advisory.MaterializationResult{}, err
		}
	}

	observations := m.connectedObservations(identitySet)
	canonical, err := advisory.Merge(observations)
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	for _, id := range append([]string{canonical.Advisory.ID}, canonical.Advisory.Aliases...) {
		if existing, ok := m.aliases[id]; ok && existing != canonical.Advisory.ID {
			return advisory.MaterializationResult{}, fmt.Errorf("%w: alias %s maps to %s", advisory.ErrAliasConflict, id, existing)
		}
	}

	previous, hasPrevious := m.canonicals[canonical.Advisory.ID]
	hash, err := canonical.ContentHash()
	if err != nil {
		return advisory.MaterializationResult{}, err
	}
	result := advisory.MaterializationResult{Canonical: canonical, ContentHash: hash}
	if hasPrevious {
		result.ChangedFields = advisory.Diff(previous, canonical)
	}
	if revisions := m.revisions[canonical.Advisory.ID]; len(revisions) > 0 && revisions[len(revisions)-1].hash == hash {
		result.Revision = int64(len(revisions))
		m.canonicals[canonical.Advisory.ID] = canonical
		return result, nil
	}
	m.canonicals[canonical.Advisory.ID] = canonical
	for _, id := range append([]string{canonical.Advisory.ID}, canonical.Advisory.Aliases...) {
		m.aliases[id] = canonical.Advisory.ID
	}
	m.revisions[canonical.Advisory.ID] = append(m.revisions[canonical.Advisory.ID], advisoryRevision{canonical: canonical, hash: hash, fields: append([]advisory.ChangedField(nil), result.ChangedFields...), syncRuns: observationSyncRuns(tenantID, normalized), createdAt: m.now()})
	result.Revision = int64(len(m.revisions[canonical.Advisory.ID]))
	result.CreatedRevision = true
	return result, nil
}

func (m *AdvisoryMaterializer) clone() (*AdvisoryMaterializer, error) {
	clone := NewAdvisoryMaterializer()
	for key, record := range m.observations {
		record.RawPayload = append([]byte(nil), record.RawPayload...)
		clone.observations[key] = record
	}
	for key, value := range m.current {
		clone.current[key] = value
	}
	clone.rebuildCurrentIndexes()
	for key, value := range m.canonicals {
		clone.canonicals[key] = value
	}
	for key, value := range m.aliases {
		clone.aliases[key] = value
	}
	for key, revisions := range m.revisions {
		clone.revisions[key] = make([]advisoryRevision, len(revisions))
		for index, revision := range revisions {
			revision.fields = append([]advisory.ChangedField(nil), revision.fields...)
			revision.syncRuns = append([]advisoryRevisionSyncRun(nil), revision.syncRuns...)
			clone.revisions[key][index] = revision
		}
	}
	for runID, publication := range m.snapshotPublications {
		results, err := cloneMaterializationResults(publication.Results)
		if err != nil {
			return nil, err
		}
		publication.NextCheckpoint = append([]byte(nil), publication.NextCheckpoint...)
		publication.Results = results
		clone.snapshotPublications[runID] = publication
	}
	for tenantID, checkpoints := range m.evaluated {
		clone.evaluated[tenantID] = make(map[string]evaluationCheckpoint, len(checkpoints))
		for advisoryID, checkpoint := range checkpoints {
			clone.evaluated[tenantID][advisoryID] = checkpoint
		}
	}
	clone.now = m.now
	return clone, nil
}

func cloneMaterializationResults(results []advisory.MaterializationResult) ([]advisory.MaterializationResult, error) {
	cloned := make([]advisory.MaterializationResult, len(results))
	for index, result := range results {
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("encode source snapshot result: %w", err)
		}
		if err := json.Unmarshal(encoded, &cloned[index]); err != nil {
			return nil, fmt.Errorf("decode source snapshot result: %w", err)
		}
	}
	return cloned, nil
}

func recordKey(sourceID, recordID, hash string) string {
	return strings.Join([]string{sourceID, recordID, hash}, "\x00")
}

func (m *AdvisoryMaterializer) replaceCurrentObservation(record advisory.ObservationRecord) error {
	hash, err := record.ContentHash()
	if err != nil {
		return fmt.Errorf("hash observation: %w", err)
	}
	currentKey := record.Observation.SourceID + "\x00" + record.Observation.RecordID
	if oldHash, ok := m.current[currentKey]; ok {
		if oldHash == hash {
			return nil
		}
		if previous, ok := m.observations[recordKey(record.Observation.SourceID, record.Observation.RecordID, oldHash)]; ok {
			m.unindexObservation(currentKey, previous)
		}
	}
	m.observations[recordKey(record.Observation.SourceID, record.Observation.RecordID, hash)] = record
	m.current[currentKey] = hash
	m.indexObservation(currentKey, record)
	return nil
}

func (m *AdvisoryMaterializer) indexObservation(currentKey string, record advisory.ObservationRecord) {
	if m.sourceIndex[record.Observation.SourceID] == nil {
		m.sourceIndex[record.Observation.SourceID] = map[string]struct{}{}
	}
	m.sourceIndex[record.Observation.SourceID][currentKey] = struct{}{}
	if !record.Observation.AbsenceRetirement {
		if m.activeSourceIndex[record.Observation.SourceID] == nil {
			m.activeSourceIndex[record.Observation.SourceID] = map[string]struct{}{}
		}
		m.activeSourceIndex[record.Observation.SourceID][currentKey] = struct{}{}
	}
	for _, identityID := range record.IdentityIDs() {
		if m.identityIndex[identityID] == nil {
			m.identityIndex[identityID] = map[string]struct{}{}
		}
		m.identityIndex[identityID][currentKey] = struct{}{}
	}
}

func (m *AdvisoryMaterializer) unindexObservation(currentKey string, record advisory.ObservationRecord) {
	currentKeys := m.sourceIndex[record.Observation.SourceID]
	delete(currentKeys, currentKey)
	if len(currentKeys) == 0 {
		delete(m.sourceIndex, record.Observation.SourceID)
	}
	if !record.Observation.AbsenceRetirement {
		activeKeys := m.activeSourceIndex[record.Observation.SourceID]
		delete(activeKeys, currentKey)
		if len(activeKeys) == 0 {
			delete(m.activeSourceIndex, record.Observation.SourceID)
		}
	}
	for _, identityID := range record.IdentityIDs() {
		currentKeys := m.identityIndex[identityID]
		delete(currentKeys, currentKey)
		if len(currentKeys) == 0 {
			delete(m.identityIndex, identityID)
		}
	}
}

func (m *AdvisoryMaterializer) rebuildCurrentIndexes() {
	m.identityIndex = map[string]map[string]struct{}{}
	m.sourceIndex = map[string]map[string]struct{}{}
	m.activeSourceIndex = map[string]map[string]struct{}{}
	for currentKey, hash := range m.current {
		parts := strings.SplitN(currentKey, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		record, ok := m.observations[recordKey(parts[0], parts[1], hash)]
		if !ok {
			continue
		}
		m.indexObservation(currentKey, record)
	}
}

func (m *AdvisoryMaterializer) connectedObservations(ids map[string]struct{}) []advisory.Observation {
	known := make(map[string]struct{}, len(ids))
	queue := make([]string, 0, len(ids))
	for id := range ids {
		known[id] = struct{}{}
		queue = append(queue, id)
	}
	seenRecords := map[string]struct{}{}
	out := make([]advisory.Observation, 0)
	for len(queue) > 0 {
		identityID := queue[0]
		queue = queue[1:]
		for currentKey := range m.identityIndex[identityID] {
			if _, ok := seenRecords[currentKey]; ok {
				continue
			}
			hash, ok := m.current[currentKey]
			if !ok {
				continue
			}
			parts := strings.SplitN(currentKey, "\x00", 2)
			if len(parts) != 2 {
				continue
			}
			record, ok := m.observations[recordKey(parts[0], parts[1], hash)]
			if !ok {
				continue
			}
			seenRecords[currentKey] = struct{}{}
			out = append(out, record.Observation)
			for _, nextIdentityID := range record.IdentityIDs() {
				if _, ok := known[nextIdentityID]; ok {
					continue
				}
				known[nextIdentityID] = struct{}{}
				queue = append(queue, nextIdentityID)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceID+"\x00"+out[i].RecordID < out[j].SourceID+"\x00"+out[j].RecordID
	})
	return out
}

func (m *AdvisoryMaterializer) GetCanonical(_ context.Context, id string) (advisory.Canonical, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.ToUpper(strings.TrimSpace(id))
	if canonicalID, ok := m.aliases[id]; ok {
		id = canonicalID
	}
	canonical, ok := m.canonicals[id]
	if !ok {
		return advisory.Canonical{}, errors.Join(shared.ErrNotFound, fmt.Errorf("advisory %s", id))
	}
	return canonical, nil
}

func (m *AdvisoryMaterializer) GetCanonicalAtRevision(_ context.Context, id string, revision int64) (advisory.Canonical, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.ToUpper(strings.TrimSpace(id))
	if canonicalID, ok := m.aliases[id]; ok {
		id = canonicalID
	}
	revisions := m.revisions[id]
	if revision <= 0 || revision > int64(len(revisions)) {
		return advisory.Canonical{}, fmt.Errorf("advisory %s revision %d: %w", id, revision, shared.ErrNotFound)
	}
	return revisions[revision-1].canonical, nil
}

func (m *AdvisoryMaterializer) CurrentRevision(_ context.Context, id string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.ToUpper(strings.TrimSpace(id))
	if canonicalID, ok := m.aliases[id]; ok {
		id = canonicalID
	}
	if revision := int64(len(m.revisions[id])); revision > 0 {
		return revision, nil
	}
	return 0, fmt.Errorf("advisory %s: %w", id, shared.ErrNotFound)
}

func (m *AdvisoryMaterializer) ByPackage(_ context.Context, ecosystem, packageName string) ([]advisory.Advisory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]advisory.Advisory, 0)
	for _, canonical := range m.canonicals {
		for _, affected := range canonical.Advisory.Affected {
			if affected.Ecosystem == ecosystem && affected.Package == packageName {
				out = append(out, canonical.Project()) // carry Withdrawn + KEV/EPSS, matching the postgres store
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *AdvisoryMaterializer) ByCPE(_ context.Context, part, vendor, product string) ([]advisory.Advisory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	part, vendor, product = strings.ToLower(strings.TrimSpace(part)), strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product))
	out := make([]advisory.Advisory, 0)
	for _, canonical := range m.canonicals {
		for _, current := range canonical.Advisory.CPEs {
			parsed, err := sbom.ParseCPE23(current.Criteria)
			if err == nil && parsed.Part == part && parsed.Vendor == vendor && parsed.Product == product {
				out = append(out, canonical.Project()) // carry Withdrawn + KEV/EPSS, matching the postgres store
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *AdvisoryMaterializer) ListAdvisoryRevisions(_ context.Context, after string, snapshotAt time.Time, limit int) (ports.AdvisoryRevisionPage, error) {
	if snapshotAt.IsZero() {
		return ports.AdvisoryRevisionPage{}, fmt.Errorf("%w: advisory corpus snapshot time is required", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.revisions))
	for id := range m.revisions {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	page := ports.AdvisoryRevisionPage{}
	for _, id := range ids {
		revisions := m.revisions[id]
		var revision int64
		for i := range revisions {
			if revisions[i].createdAt.IsZero() || !revisions[i].createdAt.After(snapshotAt) {
				revision = int64(i + 1)
			}
		}
		if revision == 0 {
			continue
		}
		page.Items = append(page.Items, ports.AdvisoryRevisionRef{ID: id, Revision: revision, CreatedAt: revisions[revision-1].createdAt})
		if len(page.Items) == limit+1 {
			break
		}
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.Next = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

func (m *AdvisoryMaterializer) AdvisoryRevisionAt(_ context.Context, advisoryID string, snapshotAt time.Time) (ports.AdvisoryRevisionRef, error) {
	advisoryID = strings.ToUpper(strings.TrimSpace(advisoryID))
	if advisoryID == "" || snapshotAt.IsZero() {
		return ports.AdvisoryRevisionRef{}, fmt.Errorf("%w: advisory corpus snapshot identity is required", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if canonicalID, ok := m.aliases[advisoryID]; ok {
		advisoryID = canonicalID
	}
	revisions := m.revisions[advisoryID]
	for index := len(revisions) - 1; index >= 0; index-- {
		if revisions[index].createdAt.IsZero() || !revisions[index].createdAt.After(snapshotAt) {
			return ports.AdvisoryRevisionRef{ID: advisoryID, Revision: int64(index + 1), CreatedAt: revisions[index].createdAt}, nil
		}
	}
	return ports.AdvisoryRevisionRef{}, fmt.Errorf("advisory %s at snapshot: %w", advisoryID, shared.ErrNotFound)
}

func (m *AdvisoryMaterializer) MarkAdvisoryEvaluated(ctx context.Context, tenantID shared.ID, advisoryID string, revision int64, evaluatedAt time.Time) error {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	advisoryID = strings.ToUpper(strings.TrimSpace(advisoryID))
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || advisoryID == "" || revision <= 0 || evaluatedAt.IsZero() {
		return fmt.Errorf("%w: advisory evaluation checkpoint is invalid", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if revision > int64(len(m.revisions[advisoryID])) {
		return fmt.Errorf("advisory %s revision %d: %w", advisoryID, revision, shared.ErrNotFound)
	}
	if m.evaluated[tenantID] == nil {
		m.evaluated[tenantID] = map[string]evaluationCheckpoint{}
	}
	if current := m.evaluated[tenantID][advisoryID]; revision > current.revision {
		m.evaluated[tenantID][advisoryID] = evaluationCheckpoint{revision: revision, evaluatedAt: evaluatedAt.UTC()}
	}
	return nil
}

func (m *AdvisoryMaterializer) OldestUnevaluatedAdvisory(ctx context.Context, tenantID shared.ID) (*vulnerabilityintel.EvaluationLag, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var oldest *vulnerabilityintel.EvaluationLag
	for advisoryID, revisions := range m.revisions {
		checkpoint := m.evaluated[tenantID][advisoryID]
		if checkpoint.revision >= int64(len(revisions)) {
			continue
		}
		candidate := vulnerabilityintel.EvaluationLag{
			AdvisoryID: advisoryID, CurrentRevision: int64(len(revisions)),
			EvaluatedRevision: checkpoint.revision, ChangedAt: revisions[checkpoint.revision].createdAt,
		}
		if oldest == nil || candidate.ChangedAt.Before(oldest.ChangedAt) || candidate.ChangedAt.Equal(oldest.ChangedAt) && candidate.AdvisoryID < oldest.AdvisoryID {
			copy := candidate
			oldest = &copy
		}
	}
	return oldest, nil
}

func (m *AdvisoryMaterializer) ListVulnerabilityAdvisories(ctx context.Context, tenantID shared.ID, query vulnerabilityintel.AdvisoryQuery) (vulnerabilityintel.AdvisoryPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return vulnerabilityintel.AdvisoryPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	query = query.Normalize()
	if err := validateAdvisoryQuery(query); err != nil {
		return vulnerabilityintel.AdvisoryPage{}, err
	}
	wantedStatuses := make(map[advisory.Status]struct{}, len(query.Statuses))
	for _, status := range query.Statuses {
		wantedStatuses[status] = struct{}{}
	}
	search := strings.ToLower(query.Search)
	source := strings.ToLower(query.Source)
	m.mu.Lock()
	items := make([]vulnerabilityintel.AdvisoryItem, 0)
	for advisoryID, revisions := range m.revisions {
		if advisoryID <= query.AfterID || len(revisions) == 0 {
			continue
		}
		latest := revisions[len(revisions)-1]
		canonical := latest.canonical
		if len(wantedStatuses) > 0 {
			if _, ok := wantedStatuses[canonical.Status]; !ok {
				continue
			}
		}
		if query.KEV != nil && (canonical.KEV == nil || *canonical.KEV != *query.KEV) || query.MinCVSS != nil && canonical.Advisory.CVSSScore < *query.MinCVSS || query.MaxCVSS != nil && canonical.Advisory.CVSSScore > *query.MaxCVSS {
			continue
		}
		if search != "" && !canonicalContains(canonical, search) || source != "" && !stringSliceContains(canonical.Sources, source) {
			continue
		}
		items = append(items, vulnerabilityintel.AdvisoryItem{Canonical: canonical, Revision: int64(len(revisions)), ChangedFields: append([]advisory.ChangedField(nil), latest.fields...), ChangedAt: latest.createdAt})
	}
	m.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Canonical.Advisory.ID < items[j].Canonical.Advisory.ID })
	page := vulnerabilityintel.AdvisoryPage{}
	if len(items) > query.Limit {
		items = items[:query.Limit]
		page.Next = items[len(items)-1].Canonical.Advisory.ID
	}
	page.Items = items
	return page, nil
}

func (m *AdvisoryMaterializer) CountVulnerabilityAdvisoriesChangedSince(ctx context.Context, since time.Time) (int64, error) {
	if _, ok := shared.TenantFrom(ctx); !ok || since.IsZero() {
		return 0, fmt.Errorf("%w: tenant context and since are required", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for _, revisions := range m.revisions {
		if len(revisions) > 0 && !revisions[len(revisions)-1].createdAt.Before(since) {
			count++
		}
	}
	return count, nil
}

func (m *AdvisoryMaterializer) CountVulnerabilityAdvisoryDailyImpact(ctx context.Context, since time.Time) (vulnerabilityintel.AdvisoryDailyImpact, error) {
	if _, ok := shared.TenantFrom(ctx); !ok || since.IsZero() {
		return vulnerabilityintel.AdvisoryDailyImpact{}, fmt.Errorf("%w: tenant context and since are required", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var impact vulnerabilityintel.AdvisoryDailyImpact
	for _, revisions := range m.revisions {
		if len(revisions) == 0 {
			continue
		}
		if !revisions[0].createdAt.Before(since) {
			impact.NewlyIngested++
		}
		if !revisions[len(revisions)-1].canonical.PublishedAt.IsZero() && !revisions[len(revisions)-1].canonical.PublishedAt.Before(since) {
			impact.NewlyDisclosed++
		}
	}
	return impact, nil
}

func (m *AdvisoryMaterializer) ListVulnerabilityAdvisoryRevisions(ctx context.Context, query vulnerabilityintel.AdvisoryRevisionQuery) (vulnerabilityintel.AdvisoryRevisionPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	query.AdvisoryID = strings.ToUpper(strings.TrimSpace(query.AdvisoryID))
	query.Limit = vulnerabilityintel.NormalizeLimit(query.Limit)
	if query.AdvisoryID == "" || query.BeforeRevision < 0 {
		return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("%w: advisory revision query is invalid", shared.ErrValidation)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if canonicalID, ok := m.aliases[query.AdvisoryID]; ok {
		query.AdvisoryID = canonicalID
	}
	revisions := m.revisions[query.AdvisoryID]
	if len(revisions) == 0 {
		return vulnerabilityintel.AdvisoryRevisionPage{}, fmt.Errorf("advisory %s: %w", query.AdvisoryID, shared.ErrNotFound)
	}
	before := query.BeforeRevision
	if before == 0 || before > int64(len(revisions))+1 {
		before = int64(len(revisions)) + 1
	}
	page := vulnerabilityintel.AdvisoryRevisionPage{}
	for revision := before - 1; revision >= 1 && len(page.Items) < query.Limit+1; revision-- {
		item := revisions[revision-1]
		syncRunIDs := make([]shared.ID, 0, len(item.syncRuns))
		for _, syncRun := range item.syncRuns {
			if syncRun.TenantID == tenantID {
				syncRunIDs = append(syncRunIDs, syncRun.ID)
			}
		}
		page.Items = append(page.Items, vulnerabilityintel.AdvisoryRevisionItem{Canonical: item.canonical, Revision: revision, ChangedFields: append([]advisory.ChangedField(nil), item.fields...), SyncRunIDs: syncRunIDs, ChangedAt: item.createdAt})
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		page.Next = page.Items[len(page.Items)-1].Revision
	}
	return page, nil
}

func (m *AdvisoryMaterializer) ListVulnerabilitySyncRunRevisions(ctx context.Context, runIDs []shared.ID, limitPerRun int) (map[shared.ID]vulnerabilityintel.AdvisoryRevisionLinkPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if limitPerRun <= 0 || limitPerRun > vulnerabilityintel.MaxPageSize {
		return nil, fmt.Errorf("%w: invalid sync run revision limit", shared.ErrValidation)
	}
	wanted := make(map[shared.ID]struct{}, len(runIDs))
	for _, runID := range runIDs {
		if !runID.IsZero() {
			wanted[runID] = struct{}{}
		}
	}
	out := make(map[shared.ID]vulnerabilityintel.AdvisoryRevisionLinkPage, len(wanted))
	m.mu.Lock()
	defer m.mu.Unlock()
	for advisoryID, revisions := range m.revisions {
		for index, revision := range revisions {
			for _, syncRun := range revision.syncRuns {
				if syncRun.TenantID != tenantID {
					continue
				}
				if _, ok := wanted[syncRun.ID]; !ok {
					continue
				}
				page := out[syncRun.ID]
				page.Items = append(page.Items, vulnerabilityintel.AdvisoryRevisionLink{AdvisoryID: advisoryID, Revision: int64(index + 1), ChangedAt: revision.createdAt})
				out[syncRun.ID] = page
			}
		}
	}
	for runID, page := range out {
		sort.Slice(page.Items, func(i, j int) bool {
			if page.Items[i].ChangedAt.Equal(page.Items[j].ChangedAt) {
				if page.Items[i].AdvisoryID == page.Items[j].AdvisoryID {
					return page.Items[i].Revision > page.Items[j].Revision
				}
				return page.Items[i].AdvisoryID < page.Items[j].AdvisoryID
			}
			return page.Items[i].ChangedAt.After(page.Items[j].ChangedAt)
		})
		if len(page.Items) > limitPerRun {
			page.Items = page.Items[:limitPerRun]
			page.Truncated = true
		}
		out[runID] = page
	}
	return out, nil
}

func observationSyncRuns(tenantID shared.ID, records []advisory.ObservationRecord) []advisoryRevisionSyncRun {
	seen := map[shared.ID]struct{}{}
	for _, record := range records {
		runID := shared.ID(strings.TrimSpace(record.SyncRunID))
		if !runID.IsZero() {
			seen[runID] = struct{}{}
		}
	}
	out := make([]advisoryRevisionSyncRun, 0, len(seen))
	for runID := range seen {
		out = append(out, advisoryRevisionSyncRun{ID: runID, TenantID: tenantID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func validateAdvisoryQuery(query vulnerabilityintel.AdvisoryQuery) error {
	for _, status := range query.Statuses {
		if !status.Valid() {
			return fmt.Errorf("%w: invalid advisory status", shared.ErrValidation)
		}
	}
	if query.MinCVSS != nil && (*query.MinCVSS < 0 || *query.MinCVSS > 10) || query.MaxCVSS != nil && (*query.MaxCVSS < 0 || *query.MaxCVSS > 10) || query.MinCVSS != nil && query.MaxCVSS != nil && *query.MinCVSS > *query.MaxCVSS {
		return fmt.Errorf("%w: invalid CVSS range", shared.ErrValidation)
	}
	return nil
}

func canonicalContains(canonical advisory.Canonical, search string) bool {
	if strings.Contains(strings.ToLower(canonical.Advisory.ID), search) || strings.Contains(strings.ToLower(canonical.Advisory.Summary), search) {
		return true
	}
	return stringSliceContains(canonical.Advisory.Aliases, search)
}

func stringSliceContains(values []string, search string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	return false
}

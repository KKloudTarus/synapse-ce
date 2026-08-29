package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// recKey identifies a projection row by (engagement, detection id) — the SAME namespace the per-engagement
// seal uses. Keying on this (not the id alone) is what lets the same detection id in two engagements be two
// distinct rows instead of one silently overwriting the other, mirroring the Postgres PRIMARY KEY
// (tenant_id, engagement_id, id).
type recKey struct{ eng, id shared.ID }

// DetectionRecordStore is the in-memory detection-ledger projection used inline/in dev. Records are
// bucketed per tenant, so a read under one tenant can never observe another's — the same isolation the
// Postgres store gets from RLS. Within a tenant, a row is keyed by (engagement, id) to match the Postgres
// uniqueness key. It keeps deep copies so a caller mutating a returned record cannot corrupt stored state.
type DetectionRecordStore struct {
	mu       sync.Mutex
	byTenant map[shared.ID]map[recKey]detection.Record // tenant -> (engagement, record id) -> record
	now      func() time.Time
}

var _ ports.DetectionRecordStore = (*DetectionRecordStore)(nil)

// NewDetectionRecordStore constructs the store.
func NewDetectionRecordStore() *DetectionRecordStore {
	return &DetectionRecordStore{byTenant: map[shared.ID]map[recKey]detection.Record{}, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the store's clock (tests only), so expiry-on-read is deterministic.
func (s *DetectionRecordStore) SetClock(now func() time.Time) { s.now = now }

// AppendDetection stores one record, idempotent on (engagement, id), bucketed by the record's TenantID.
func (s *DetectionRecordStore) AppendDetection(ctx context.Context, r detection.Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	tenant := shared.TenantOrDefault(r.TenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[recKey]detection.Record{}
	}
	// Idempotent on (engagement, id), matching the Postgres ON CONFLICT (tenant_id, engagement_id, id):
	// a re-delivery of the same detection in the same engagement is a no-op, while the same id in a
	// DIFFERENT engagement is a distinct row and must not overwrite the first.
	k := recKey{eng: r.EngagementID, id: r.ID}
	if _, exists := s.byTenant[tenant][k]; exists {
		return nil
	}
	s.byTenant[tenant][k] = cloneRecord(r)
	return nil
}

// ListDetections returns the non-expired records for an engagement under the ctx tenant, oldest first.
func (s *DetectionRecordStore) ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error) {
	tenant := shared.TenantOrDefault(tenantFromCtx(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []detection.Record
	for _, r := range s.byTenant[tenant] {
		// Hide expired rows, mirroring the Postgres store's `expires_at IS NULL OR expires_at > now()`
		// predicate, so both backends return the same non-expired projection.
		if r.EngagementID == engagementID && !r.Expired(now) {
			out = append(out, cloneRecord(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RecordedAt.Equal(out[j].RecordedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].RecordedAt.Before(out[j].RecordedAt)
	})
	return out, nil
}

// HasDetection reports whether a record with this id already exists in the given engagement under the ctx tenant, so ingest can
// skip an already-sealed detection on a retry (idempotent resume) rather than sealing it twice.
func (s *DetectionRecordStore) HasDetection(ctx context.Context, engagementID, id shared.ID) (bool, error) {
	tenant := shared.TenantOrDefault(tenantFromCtx(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byTenant[tenant][recKey{eng: engagementID, id: id}]
	return ok, nil
}

// LastBatchSequence returns the highest batch sequence recorded for an agent under the ctx tenant.
func (s *DetectionRecordStore) LastBatchSequence(ctx context.Context, agentID shared.ID) (uint64, error) {
	tenant := shared.TenantOrDefault(tenantFromCtx(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	var highest uint64
	for _, r := range s.byTenant[tenant] {
		if r.AgentID == agentID && r.BatchSeq > highest {
			highest = r.BatchSeq
		}
	}
	return highest, nil
}

// ListExpiredDetections returns eligible record ids without mutating the projection.
func (s *DetectionRecordStore) ListExpiredDetections(ctx context.Context, engagementID shared.ID, cutoff time.Time) ([]shared.ID, error) {
	tenant := shared.TenantOrDefault(tenantFromCtx(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []shared.ID
	for _, r := range s.byTenant[tenant] {
		if r.EngagementID == engagementID && r.Expired(cutoff) {
			expired = append(expired, r.ID)
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i] < expired[j] })
	return expired, nil
}

// DeleteDetection removes one exact projection row. Repeating a successful deletion is a no-op.
func (s *DetectionRecordStore) DeleteDetection(ctx context.Context, engagementID, detectionID shared.ID) (bool, error) {
	tenant := shared.TenantOrDefault(tenantFromCtx(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	key := recKey{eng: engagementID, id: detectionID}
	if _, exists := s.byTenant[tenant][key]; !exists {
		return false, nil
	}
	delete(s.byTenant[tenant], key)
	return true, nil
}

func cloneRecord(r detection.Record) detection.Record {
	cp := r
	cp.Detection.Evidence = append([]detection.Event(nil), r.Detection.Evidence...)
	return cp
}

// tenantFromCtx resolves the tenant for a read; a missing tenant maps to the default bucket (the same
// default the write path uses), keeping reads and writes consistent in the in-memory twin.
func tenantFromCtx(ctx context.Context) shared.ID {
	if t, ok := shared.TenantFrom(ctx); ok {
		return t
	}
	return ""
}

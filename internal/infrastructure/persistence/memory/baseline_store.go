package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BaselineStore is the in-memory twin of the behavioral-baseline projection (Phase D / D5). It is
// tenant-bucketed and upholds the same upsert-by-(tenant,group) contract as the Postgres tier. Reached
// only through ports.BaselineStore.
type BaselineStore struct {
	mu   sync.Mutex
	recs map[shared.ID]map[string]ports.BaselineRecord // tenant -> group -> record
}

var _ ports.BaselineStore = (*BaselineStore)(nil)

// NewBaselineStore creates an empty in-memory baseline store.
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{recs: make(map[shared.ID]map[string]ports.BaselineRecord)}
}

func requireBaselineTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: baseline store operation requires a tenant in context", shared.ErrValidation)
}

// validateRecord enforces the record is well-formed and its key's tenant matches the context tenant (no
// cross-tenant write via a mismatched key).
func validateBaselineRecord(tenant shared.ID, rec ports.BaselineRecord) error {
	if err := rec.Key.Validate(); err != nil {
		return err
	}
	if rec.Key.Tenant != tenant {
		return fmt.Errorf("%w: baseline key tenant %q does not match context tenant %q", shared.ErrValidation, rec.Key.Tenant, tenant)
	}
	if !rec.State.Valid() {
		return fmt.Errorf("%w: unknown baseline state %q", shared.ErrValidation, rec.State)
	}
	// Rehydrate to validate the summaries/accumulator integrity uniformly with the Postgres tier.
	if _, err := baseline.NewBaselineFrom(rec.Key, rec.State, rec.Summaries); err != nil {
		return err
	}
	if rec.DriftRun < 0 {
		return fmt.Errorf("%w: drift run must be non-negative", shared.ErrValidation)
	}
	return nil
}

// Save upserts a baseline record for its key.
func (s *BaselineStore) Save(ctx context.Context, rec ports.BaselineRecord) error {
	tenant, err := requireBaselineTenant(ctx)
	if err != nil {
		return err
	}
	if err := validateBaselineRecord(tenant, rec); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byGroup := s.recs[tenant]
	if byGroup == nil {
		byGroup = make(map[string]ports.BaselineRecord)
		s.recs[tenant] = byGroup
	}
	byGroup[rec.Key.Group] = cloneBaselineRecord(rec)
	return nil
}

// Load returns the record for a key, or shared.ErrNotFound.
func (s *BaselineStore) Load(ctx context.Context, key baseline.Key) (ports.BaselineRecord, error) {
	tenant, err := requireBaselineTenant(ctx)
	if err != nil {
		return ports.BaselineRecord{}, err
	}
	if err := key.Validate(); err != nil {
		return ports.BaselineRecord{}, err
	}
	if key.Tenant != tenant {
		return ports.BaselineRecord{}, fmt.Errorf("%w: baseline key tenant %q does not match context tenant %q", shared.ErrValidation, key.Tenant, tenant)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[tenant][key.Group]
	if !ok {
		return ports.BaselineRecord{}, fmt.Errorf("%w: baseline %s/%s", shared.ErrNotFound, key.Tenant, key.Group)
	}
	// Re-validate on read (defense-in-depth + parity with the Postgres tier): a stored record must always
	// rehydrate to a valid baseline.
	if _, err := baseline.NewBaselineFrom(rec.Key, rec.State, rec.Summaries); err != nil {
		return ports.BaselineRecord{}, err
	}
	return cloneBaselineRecord(rec), nil
}

// cloneBaselineRecord deep-copies the summaries slice so a stored record never aliases the caller's.
func cloneBaselineRecord(rec ports.BaselineRecord) ports.BaselineRecord {
	cp := rec
	cp.Summaries = append([]baseline.FeatureSummary(nil), rec.Summaries...)
	return cp
}

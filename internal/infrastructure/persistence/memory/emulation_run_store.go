package memory

import (
	"context"
	"sync"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EmulationRunStore is the in-memory emulation-run persistence used inline/in dev. It keeps a deep copy
// of each run's coverage so a caller mutating the returned slice cannot corrupt stored state.
type EmulationRunStore struct {
	mu   sync.Mutex
	runs map[string]demu.Run // keyed by tenant\x00id
}

// NewEmulationRunStore constructs the store.
func NewEmulationRunStore() *EmulationRunStore {
	return &EmulationRunStore{runs: map[string]demu.Run{}}
}

func emuRunKey(tenantID, id shared.ID) string {
	return shared.TenantOrDefault(tenantID).String() + "\x00" + id.String()
}

// SaveRun persists a run and its coverage records.
func (s *EmulationRunStore) SaveRun(_ context.Context, run demu.Run) error {
	if run.ID == "" || run.TenantID == "" {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := run
	cp.Coverage = append([]demu.CoverageRecord(nil), run.Coverage...)
	s.runs[emuRunKey(run.TenantID, run.ID)] = cp
	return nil
}

// GetRun returns a copy of a stored run scoped to the tenant; a cross-tenant read sees ErrNotFound.
func (s *EmulationRunStore) GetRun(_ context.Context, tenantID, id shared.ID) (demu.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[emuRunKey(tenantID, id)]
	if !ok {
		return demu.Run{}, shared.ErrNotFound
	}
	cp := run
	cp.Coverage = append([]demu.CoverageRecord(nil), run.Coverage...)
	return cp, nil
}

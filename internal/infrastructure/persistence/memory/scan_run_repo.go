package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunStore is an in-memory store of scan-run manifests.
type ScanRunStore struct {
	mu   sync.RWMutex
	runs []ports.ScanRun
}

// NewScanRunStore returns an empty in-memory scan-run store.
func NewScanRunStore() *ScanRunStore { return &ScanRunStore{} }

var _ ports.ScanRunStore = (*ScanRunStore)(nil)

func (s *ScanRunStore) Begin(_ context.Context, run ports.ScanRun) error {
	if err := run.ValidateBegin(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.runs {
		if existing.ID != run.ID {
			continue
		}
		if existing.TenantID == run.TenantID && existing.EngagementID == run.EngagementID && existing.TerminalStatus == run.TerminalStatus && existing.CreatedAt.Equal(run.CreatedAt) {
			return nil
		}
		return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrConflict)
	}
	s.runs = append(s.runs, run)
	return nil
}

func (s *ScanRunStore) Seal(_ context.Context, run ports.ScanRun) error {
	if err := run.ValidateSealed(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, existing := range s.runs {
		if existing.ID != run.ID || existing.TenantID != run.TenantID {
			continue
		}
		if existing.SealedAt != nil {
			if existing.ManifestHash == run.ManifestHash {
				return nil
			}
			return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrConflict)
		}
		if existing.EngagementID != run.EngagementID {
			return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrConflict)
		}
		s.runs[index] = run
		return nil
	}
	return fmt.Errorf("scan run %s: %w", run.ID, shared.ErrNotFound)
}

func (s *ScanRunStore) List(_ context.Context, tenantID, engagementID shared.ID) ([]ports.ScanRun, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ports.ScanRun
	for _, r := range s.runs {
		if r.TenantID == tenantID.String() && r.EngagementID == engagementID.String() {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *ScanRunStore) Get(_ context.Context, tenantID shared.ID, runID string) (ports.ScanRun, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.runs {
		if r.TenantID == tenantID.String() && r.ID == runID {
			return r, nil
		}
	}
	return ports.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
}

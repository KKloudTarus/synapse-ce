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

func (s *ScanRunStore) Save(_ context.Context, run ports.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, run)
	return nil
}

func (s *ScanRunStore) List(_ context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ports.ScanRun
	for _, r := range s.runs {
		if r.EngagementID == engagementID.String() {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *ScanRunStore) Get(_ context.Context, runID string) (ports.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.runs {
		if r.ID == runID {
			return r, nil
		}
	}
	return ports.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
}

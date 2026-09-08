package memory

import (
	"bytes"
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ScanRunEvidenceStore = (*ScanRunStore)(nil)

func (s *ScanRunStore) SaveScanRunEvidence(ctx context.Context, item ports.ScanRunEvidence) error {
	if err := item.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scanRunKey{TenantID: item.TenantID, ID: item.RunID}
	run, exists := s.runs[key]
	if !exists {
		return shared.ErrNotFound
	}
	if prior, exists := s.evidence[key]; exists {
		if prior.ContentHash != item.ContentHash || !bytes.Equal(prior.Payload, item.Payload) {
			return fmt.Errorf("%w: scan evidence replay differs", shared.ErrConflict)
		}
		return nil
	}
	if run.IsSealed() {
		return fmt.Errorf("%w: cannot append evidence to a sealed run", shared.ErrConflict)
	}
	s.registerRollback(ctx)
	item.Payload = bytes.Clone(item.Payload)
	s.evidence[key] = item
	return nil
}

func (s *ScanRunStore) GetScanRunEvidence(ctx context.Context, tenantID shared.ID, runID string) (ports.ScanRunEvidence, error) {
	if err := ctx.Err(); err != nil {
		return ports.ScanRunEvidence{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, exists := s.evidence[scanRunKey{TenantID: tenantID, ID: runID}]
	if !exists {
		return ports.ScanRunEvidence{}, shared.ErrNotFound
	}
	item.Payload = bytes.Clone(item.Payload)
	return item, item.Validate()
}

func (s *ScanRunStore) registerRollback(ctx context.Context) {
	registerTenantCheckpoint(ctx, s, func(tenantID shared.ID) func() {
		runs := captureTenantEntries(s.runs, func(k scanRunKey, _ scanrun.ScanRun) bool { return k.TenantID == tenantID })
		evidence := captureTenantEntries(s.evidence, func(k scanRunKey, _ ports.ScanRunEvidence) bool { return k.TenantID == tenantID })
		return func() { s.mu.Lock(); defer s.mu.Unlock(); runs(); evidence() }
	})
}

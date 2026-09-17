package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ImportReceiptStore is the in-memory conformance adapter for durable import receipts.
// It is intentionally not wired into production; the PostgreSQL implementation is the durable adapter.
type ImportReceiptStore struct {
	mu       sync.RWMutex
	byTenant map[shared.ID]map[string]importreceipt.Receipt
}

var _ ports.ImportReceiptStore = (*ImportReceiptStore)(nil)

// NewImportReceiptStore returns an empty receipt store.
func NewImportReceiptStore() *ImportReceiptStore {
	return &ImportReceiptStore{byTenant: map[shared.ID]map[string]importreceipt.Receipt{}}
}

// CreateOrGet atomically creates a receipt or resolves the receipt already owning the idempotency key.
func (s *ImportReceiptStore) CreateOrGet(_ context.Context, tenantID shared.ID, receipt importreceipt.Receipt) (importreceipt.Receipt, bool, error) {
	if err := receipt.Validate(); err != nil {
		return importreceipt.Receipt{}, false, err
	}
	if receipt.TenantID != tenantID {
		return importreceipt.Receipt{}, false, fmt.Errorf("%w: import receipt %s is stamped with tenant %q but was saved into %q",
			shared.ErrValidation, receipt.ID, receipt.TenantID, tenantID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := importreceipt.IdempotencyKey(receipt)
	if existing, ok := s.byTenant[tenantID][key]; ok {
		return existing, false, nil
	}
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]importreceipt.Receipt{}
	}
	s.byTenant[tenantID][key] = receipt
	return receipt, true, nil
}

// Finalize atomically performs the sole receipt mutation.
func (s *ImportReceiptStore) Finalize(_ context.Context, tenantID, receiptID shared.ID, outcome importreceipt.Outcome, counters importreceipt.Counters, updatedAt time.Time) (importreceipt.Receipt, error) {
	if tenantID.IsZero() || receiptID.IsZero() || !outcome.Terminal() || updatedAt.IsZero() {
		return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt finalization needs tenant, receipt, terminal outcome and time", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, receipt := range s.byTenant[tenantID] {
		if receipt.ID != receiptID {
			continue
		}
		if receipt.Outcome.Terminal() {
			if receipt.Outcome == outcome && receipt.Counters == counters {
				return receipt, nil
			}
			return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt %s is already finalized as %s", shared.ErrConflict, receiptID, receipt.Outcome)
		}
		if receipt.Outcome != importreceipt.OutcomePending {
			return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt %s cannot finalize from %s", shared.ErrConflict, receiptID, receipt.Outcome)
		}
		if updatedAt.Before(receipt.CreatedAt) {
			return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt finalization precedes creation", shared.ErrValidation)
		}
		if err := counters.Validate(); err != nil {
			return importreceipt.Receipt{}, err
		}
		if outcome == importreceipt.OutcomeComplete && counters.Refused != 0 {
			return importreceipt.Receipt{}, fmt.Errorf("%w: a complete import receipt cannot contain refused results", shared.ErrValidation)
		}
		receipt.Outcome = outcome
		receipt.Counters = counters
		receipt.UpdatedAt = updatedAt
		s.byTenant[tenantID][key] = receipt
		return receipt, nil
	}
	return importreceipt.Receipt{}, shared.ErrNotFound
}

// GetByIdentity returns only a receipt visible in the requested tenant partition.
func (s *ImportReceiptStore) GetByIdentity(_ context.Context, tenantID, engagementID shared.ID, sourceIdentity, digest string) (importreceipt.Receipt, error) {
	if tenantID.IsZero() || engagementID.IsZero() || strings.TrimSpace(sourceIdentity) == "" || strings.TrimSpace(digest) == "" {
		return importreceipt.Receipt{}, fmt.Errorf("%w: import receipt lookup needs tenant, engagement, source identity and digest", shared.ErrValidation)
	}
	probe := importreceipt.Receipt{TenantID: tenantID, EngagementID: engagementID, SourceIdentity: sourceIdentity, Digest: digest}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if found, ok := s.byTenant[tenantID][importreceipt.IdempotencyKey(probe)]; ok {
		return found, nil
	}
	return importreceipt.Receipt{}, shared.ErrNotFound
}

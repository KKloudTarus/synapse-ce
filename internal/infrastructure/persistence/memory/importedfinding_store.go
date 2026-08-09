package memory

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ImportedFindingStore is the in-memory third-party finding store.
type ImportedFindingStore struct {
	mu sync.RWMutex
	// byTenant holds each tenant's findings keyed by the idempotency key, so re-ingesting an identical
	// document cannot duplicate a finding.
	byTenant map[shared.ID]map[string]importedfinding.ImportedFinding
	// digests records which documents an engagement has already ingested.
	digests map[string]bool
}

var _ ports.ImportedFindingStore = (*ImportedFindingStore)(nil)

// NewImportedFindingStore returns an empty store.
func NewImportedFindingStore() *ImportedFindingStore {
	return &ImportedFindingStore{
		byTenant: map[shared.ID]map[string]importedfinding.ImportedFinding{},
		digests:  map[string]bool{},
	}
}

// idempotencyKey mirrors the persistent unique constraint: one finding per document, rule and location.
func idempotencyKey(f importedfinding.ImportedFinding) string {
	return strings.Join([]string{
		f.EngagementID.String(),
		f.Provenance.SourceDigest,
		f.Provenance.RuleID,
		f.Location.Path,
		shared.ID(strings.TrimSpace(f.Location.LogicalName)).String(),
		itoa(f.Location.StartLine),
	}, "\x00")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func digestKey(engagementID shared.ID, digest string) string {
	return engagementID.String() + "\x00" + digest
}

// Save persists a batch, skipping any finding whose idempotency key already exists.
func (s *ImportedFindingStore) Save(_ context.Context, tenantID shared.ID, findings []importedfinding.ImportedFinding) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]importedfinding.ImportedFinding{}
	}
	stored, existing := 0, 0
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			return stored, existing, err
		}
		key := idempotencyKey(f)
		if _, taken := s.byTenant[tenantID][key]; taken {
			existing++
			continue
		}
		s.byTenant[tenantID][key] = f
		s.digests[digestKey(f.EngagementID, f.Provenance.SourceDigest)] = true
		stored++
	}
	return stored, existing, nil
}

// ListByEngagement returns one engagement's imported findings, deterministically ordered.
func (s *ImportedFindingStore) ListByEngagement(_ context.Context, tenantID, engagementID shared.ID) ([]importedfinding.ImportedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []importedfinding.ImportedFinding
	for _, f := range s.byTenant[tenantID] {
		if f.EngagementID == engagementID {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provenance.RuleID != out[j].Provenance.RuleID {
			return out[i].Provenance.RuleID < out[j].Provenance.RuleID
		}
		if out[i].Location.Path != out[j].Location.Path {
			return out[i].Location.Path < out[j].Location.Path
		}
		if out[i].Location.StartLine != out[j].Location.StartLine {
			return out[i].Location.StartLine < out[j].Location.StartLine
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ExistsDigest reports whether this engagement already ingested a document with this digest.
func (s *ImportedFindingStore) ExistsDigest(_ context.Context, _ shared.ID, engagementID shared.ID, digest string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.digests[digestKey(engagementID, digest)], nil
}

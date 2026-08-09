package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ImportedFindingStore is the in-memory third-party finding store.
//
// It is EPHEMERAL: everything it holds is lost on restart. It backs tests and the CLI's validate mode;
// the server uses the Postgres store, which is what makes the audit entry for an ingest true.
type ImportedFindingStore struct {
	mu sync.RWMutex
	// byTenant holds each tenant's findings keyed by the idempotency key, so re-ingesting an identical
	// document cannot duplicate a finding.
	byTenant map[shared.ID]map[string]importedfinding.ImportedFinding
	// digests records which documents a (tenant, engagement) pair has already ingested. The tenant is
	// part of the key even though the HTTP path already proves the engagement belongs to the caller's
	// tenant: a caller that reaches the store another way (a worker, a bulk job) must not be able to
	// observe or collide with another tenant's ingest history.
	digests map[shared.ID]map[string]bool
}

var _ ports.ImportedFindingStore = (*ImportedFindingStore)(nil)

// NewImportedFindingStore returns an empty store.
func NewImportedFindingStore() *ImportedFindingStore {
	return &ImportedFindingStore{
		byTenant: map[shared.ID]map[string]importedfinding.ImportedFinding{},
		digests:  map[shared.ID]map[string]bool{},
	}
}

func digestKey(engagementID shared.ID, digest string) string {
	return engagementID.String() + "\x00" + digest
}

// Save persists a batch ATOMICALLY: the whole delta is built and validated first, so a finding that
// fails validation aborts the batch without leaving earlier findings — and without recording the
// document digest, which would make a retry look like a clean deduplicated ingest while the un-persisted
// tail was permanently lost.
func (s *ImportedFindingStore) Save(_ context.Context, tenantID shared.ID, findings []importedfinding.ImportedFinding) (int, int, error) {
	type entry struct {
		key string
		f   importedfinding.ImportedFinding
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existingForTenant := s.byTenant[tenantID]
	pending := make([]entry, 0, len(findings))
	seen := map[string]bool{}
	existing := 0
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			return 0, 0, err
		}
		// The partition and the row must agree. A finding stamped with one tenant but saved into
		// another's partition would be returned by a read it does not belong to.
		if f.TenantID != tenantID {
			return 0, 0, fmt.Errorf("%w: imported finding %s is stamped with tenant %q but was saved into %q",
				shared.ErrValidation, f.ID, f.TenantID, tenantID)
		}
		key := importedfinding.IdempotencyKey(f)
		if seen[key] {
			existing++
			continue
		}
		if _, taken := existingForTenant[key]; taken {
			existing++
			continue
		}
		seen[key] = true
		pending = append(pending, entry{key: key, f: f})
	}

	if existingForTenant == nil && len(pending) > 0 {
		existingForTenant = map[string]importedfinding.ImportedFinding{}
		s.byTenant[tenantID] = existingForTenant
	}
	for _, e := range pending {
		existingForTenant[e.key] = e.f
		s.recordDigestLocked(tenantID, e.f.EngagementID, e.f.Provenance.SourceDigest)
	}
	return len(pending), existing, nil
}

func (s *ImportedFindingStore) recordDigestLocked(tenantID, engagementID shared.ID, digest string) {
	if s.digests[tenantID] == nil {
		s.digests[tenantID] = map[string]bool{}
	}
	s.digests[tenantID][digestKey(engagementID, digest)] = true
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

// ExistsDigest reports whether this tenant's engagement already ingested a document with this digest.
func (s *ImportedFindingStore) ExistsDigest(_ context.Context, tenantID, engagementID shared.ID, digest string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.digests[tenantID][digestKey(engagementID, digest)], nil
}

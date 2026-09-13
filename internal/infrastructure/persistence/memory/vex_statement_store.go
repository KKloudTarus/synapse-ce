package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// VEXStatementStore is the in-memory VEX-statement store. It is EPHEMERAL (lost on restart); the server uses
// the Postgres store. It backs tests and the CLI. Statements are partitioned by tenant, then by engagement,
// then keyed by content digest so re-ingesting an identical assertion cannot duplicate a row.
type VEXStatementStore struct {
	mu       sync.RWMutex
	byTenant map[shared.ID]map[string]map[string]storedRow // tenant -> engagement -> digest -> row
	seq      int64                                          // monotonic insertion counter, mirroring the Postgres identity column
}

// storedRow pairs a statement with its monotonic insertion order, so re-apply replays in import order
// (newest wins per finding), matching the Postgres `seq` identity column rather than relying on clock ties.
type storedRow struct {
	seq int64
	st  vex.StoredStatement
}

var _ ports.VEXStatementRepository = (*VEXStatementStore)(nil)

// NewVEXStatementStore returns an empty store.
func NewVEXStatementStore() *VEXStatementStore {
	return &VEXStatementStore{byTenant: map[shared.ID]map[string]map[string]storedRow{}}
}

// Save persists the statements idempotently by digest; an identical assertion already stored is left as-is
// (keeping its original insertion order). New statements take the next insertion sequence.
func (s *VEXStatementStore) Save(_ context.Context, tenantID, engagementID shared.ID, statements []vex.StoredStatement) error {
	if len(statements) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byEng := s.byTenant[tenantID]
	if byEng == nil {
		byEng = map[string]map[string]storedRow{}
		s.byTenant[tenantID] = byEng
	}
	eng := engagementID.String()
	byDigest := byEng[eng]
	if byDigest == nil {
		byDigest = map[string]storedRow{}
		byEng[eng] = byDigest
	}
	for _, st := range statements {
		if _, exists := byDigest[st.Digest]; exists {
			continue // idempotent: an identical assertion already stands
		}
		s.seq++
		byDigest[st.Digest] = storedRow{seq: s.seq, st: st}
	}
	return nil
}

// ListByEngagement returns the engagement's statements in insertion order, so a re-apply walking them applies
// the most-recent assertion last (newest wins per finding).
func (s *VEXStatementStore) ListByEngagement(_ context.Context, tenantID, engagementID shared.ID) ([]vex.StoredStatement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byDigest := s.byTenant[tenantID][engagementID.String()]
	rows := make([]storedRow, 0, len(byDigest))
	for _, r := range byDigest {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].seq < rows[j].seq })
	out := make([]vex.StoredStatement, len(rows))
	for i, r := range rows {
		out[i] = r.st
	}
	return out, nil
}

package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AdvisoryStore is the in-memory owned-advisory store (dev/tests, mirrors the Postgres adapter). It
// is GLOBAL reference data – NOT tenant-scoped. Advisories are indexed by every affected (ecosystem,
// package) so ByPackage is a map lookup, and Upsert is idempotent by advisory id (re-syncable reference
// data, replaced in place – not append-only). The stored ecosystem+package keys are the ingester-normalized,
// OSV-canonical ids per the ports.AdvisoryStore KEY CONTRACT.
type AdvisoryStore struct {
	mu    sync.RWMutex
	byID  map[string]advisory.Advisory
	byKey map[string][]string // "ecosystem\x00package" -> advisory ids (resolved via byID); NUL separator is collision-proof (excluded from canonical names), matching the pg adapter
}

// NewAdvisoryStore returns an empty in-memory advisory store.
func NewAdvisoryStore() *AdvisoryStore {
	return &AdvisoryStore{byID: map[string]advisory.Advisory{}, byKey: map[string][]string{}}
}

var (
	_ ports.AdvisoryStore  = (*AdvisoryStore)(nil)
	_ ports.AdvisoryWriter = (*AdvisoryStore)(nil) // the ingester loads via the narrow writer port
)

// Upsert inserts or replaces an advisory by id and (re)builds its (ecosystem, package) index entries. A
// re-sync may change the affected set, so the prior index entries for the id are dropped first. Idempotent.
func (s *AdvisoryStore) Upsert(_ context.Context, a advisory.Advisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, existed := s.byID[a.ID]; existed {
		s.removeFromIndex(a.ID)
	}
	s.byID[a.ID] = a
	seen := map[string]bool{}
	for _, ap := range a.Affected {
		if ap.Ecosystem == "" || ap.Package == "" {
			continue
		}
		k := ap.Ecosystem + "\x00" + ap.Package
		if seen[k] {
			continue // one advisory, multiple blocks for the same package -> index once
		}
		seen[k] = true
		s.byKey[k] = append(s.byKey[k], a.ID)
	}
	return nil
}

// removeFromIndex drops every byKey entry pointing at id (caller holds the write lock).
func (s *AdvisoryStore) removeFromIndex(id string) {
	for k, ids := range s.byKey {
		out := ids[:0]
		for _, x := range ids {
			if x != id {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			delete(s.byKey, k)
		} else {
			s.byKey[k] = out
		}
	}
}

// ByPackage returns the advisories that list (ecosystem, name) as affected, in deterministic id order
// (matching the Postgres adapter's ORDER BY id COLLATE "C"); the caller runs advisory.Match to decide which
// actually hit the component's version.
func (s *AdvisoryStore) ByPackage(_ context.Context, ecosystem, name string) ([]advisory.Advisory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byKey[ecosystem+"\x00"+name]
	out := make([]advisory.Advisory, 0, len(ids))
	for _, id := range ids {
		if a, ok := s.byID[id]; ok {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID }) // byte order, parity with the pg adapter
	return out, nil
}

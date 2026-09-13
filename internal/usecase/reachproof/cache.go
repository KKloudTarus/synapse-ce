package reachproof

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// ReachabilityCache memoizes a whole-graph reachability Analysis under a verdict-complete fingerprint
// (see CacheKey). It is a read-through cache for the expensive analyzer run: the coordinator always
// re-derives per-subject verdicts from the Analysis, so caching the graph result never changes a verdict,
// it only skips recomputing the graph when every verdict-affecting input is unchanged.
//
// The #1-bar (never hide a real vulnerability) is upheld OUTSIDE this interface, by the caller: the
// coordinator reads/writes the cache only under a CacheKey.Complete() fingerprint, so a partial key can
// never map to a stored negative. An implementation therefore does not need to reason about staleness; it
// only needs to be a correct content-addressed store. Get returns (analysis, true) on a hit and
// (nil, false) on a miss; a hit that returns a nil analysis is treated by the caller as a miss.
type ReachabilityCache interface {
	Get(ctx context.Context, fingerprint string) (*reachability.Analysis, bool, error)
	Put(ctx context.Context, fingerprint string, analysis *reachability.Analysis) error
}

// DefaultCacheCapacity bounds the process-local cache by entry count so a long-running server that scans many
// distinct source trees does not grow without limit. DefaultCacheResultBudget additionally bounds it by
// content size (total reachability.Result entries across all cached Analyses), so a few engagements with
// thousands of affected symbols cannot dominate RSS the way a pure entry-count bound would. Eviction under
// either bound only ever forces a recompute, never an unsound verdict.
const (
	DefaultCacheCapacity     = 256
	DefaultCacheResultBudget = 200_000 // ~ a few hundred MB worst case of Result+Path slices
)

// InMemoryCache is a process-local ReachabilityCache backed by a map guarded by a RWMutex, with FIFO
// eviction once it exceeds either its entry-count capacity or its total-Result budget. It is the sound core
// adapter: correct for a single process and for tests. A cross-process persistent adapter (postgres or file)
// is the follow-on and implements this same interface. It deep-copies on Put and on Get so a caller mutating
// a returned Analysis can never corrupt a stored entry, and a later mutation of the argument can never reach
// back into the store.
//
// It is one process-global instance shared across all tenants and engagements, keyed only by the
// content-addressed fingerprint (source hash + symbols + tier + versions + env), with no tenant component.
// This is sound: the cached Analysis is a pure function of those inputs, and per-subject verdicts are
// re-derived after every read from tenant-scoped prior judgments, so no tenant state is baked into a cached
// graph and a hit changes wall-clock only. The residual is a weak cross-tenant timing oracle (a fast hit
// reveals that some tenant already scanned a byte-identical tree with the same symbol set); no verdict, path,
// or source content crosses, since a key match means the trees are byte-identical. A persistent adapter that
// wants to close even that oracle can fold a per-tenant salt into the key at the cost of cross-tenant reuse.
type InMemoryCache struct {
	mu           sync.RWMutex
	entries      map[string]reachability.Analysis
	order        []string // insertion order, for FIFO eviction
	capacity     int
	resultBudget int
	results      int // running sum of len(Results) across cached entries
}

// NewInMemoryCache returns an empty in-memory cache bounded by DefaultCacheCapacity and DefaultCacheResultBudget.
func NewInMemoryCache() *InMemoryCache {
	return NewInMemoryCacheWithCapacity(DefaultCacheCapacity, DefaultCacheResultBudget)
}

// NewInMemoryCacheWithCapacity returns an empty in-memory cache holding at most capacity entries and
// resultBudget total Result entries (a non-positive value falls back to the corresponding default).
func NewInMemoryCacheWithCapacity(capacity, resultBudget int) *InMemoryCache {
	if capacity <= 0 {
		capacity = DefaultCacheCapacity
	}
	if resultBudget <= 0 {
		resultBudget = DefaultCacheResultBudget
	}
	return &InMemoryCache{entries: map[string]reachability.Analysis{}, capacity: capacity, resultBudget: resultBudget}
}

// Get returns a deep copy of the stored Analysis for fingerprint, or (nil, false) on a miss.
func (c *InMemoryCache) Get(_ context.Context, fingerprint string) (*reachability.Analysis, bool, error) {
	if fingerprint == "" {
		return nil, false, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	a, ok := c.entries[fingerprint]
	if !ok {
		return nil, false, nil
	}
	cp := cloneAnalysis(a)
	return &cp, true, nil
}

// Put stores a deep copy of analysis under fingerprint, evicting oldest entries until both the entry-count
// capacity and the total-Result budget hold. A nil analysis or empty fingerprint is a no-op, so only a real
// result under a real key is ever cached. A single Analysis larger than the whole budget is still stored (it
// is the only entry), because refusing to cache it would just recompute it every time.
func (c *InMemoryCache) Put(_ context.Context, fingerprint string, analysis *reachability.Analysis) error {
	if fingerprint == "" || analysis == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, exists := c.entries[fingerprint]; exists {
		c.results -= len(prev.Results) // overwriting: drop the old size before adding the new
		c.removeFromOrder(fingerprint) // move it to the back so eviction never removes the just-written key
	}
	c.order = append(c.order, fingerprint)
	stored := cloneAnalysis(*analysis)
	c.entries[fingerprint] = stored
	c.results += len(stored.Results)
	// Evict oldest until within both bounds. The just-written key is now at the back of order, so it is only
	// evicted when it is the sole entry (guarded by len > 1), never spuriously.
	for len(c.order) > 1 && (len(c.entries) > c.capacity || c.results > c.resultBudget) {
		oldest := c.order[0]
		c.order = c.order[1:]
		if ev, ok := c.entries[oldest]; ok {
			c.results -= len(ev.Results)
			delete(c.entries, oldest)
		}
	}
	return nil
}

// removeFromOrder deletes the first occurrence of fingerprint from the insertion-order slice (called on an
// overwrite so the key can be re-appended at the back). O(n) in the number of entries; overwrites are rare
// (only concurrent double-misses of the same key), so this is not on the hot path.
func (c *InMemoryCache) removeFromOrder(fingerprint string) {
	for i, fp := range c.order {
		if fp == fingerprint {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// cloneAnalysis deep-copies an Analysis (its Results, each Result's Path, and Entrypoints) so no slice is
// shared between a caller and the store.
func cloneAnalysis(a reachability.Analysis) reachability.Analysis {
	out := reachability.Analysis{}
	if a.Results != nil {
		out.Results = make([]reachability.Result, len(a.Results))
		for i, r := range a.Results {
			cp := reachability.Result{Symbol: r.Symbol, Reachable: r.Reachable}
			if r.Path != nil {
				cp.Path = append([]string(nil), r.Path...)
			}
			out.Results[i] = cp
		}
	}
	if a.Entrypoints != nil {
		out.Entrypoints = append([]string(nil), a.Entrypoints...)
	}
	return out
}

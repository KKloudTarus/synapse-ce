package reachproof

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// countingAnalyzer records how many times Analyze ran, so a test can prove a cache hit skipped the run.
type countingAnalyzer struct {
	mu    sync.Mutex
	calls int
	res   []reachability.Result
}

func (a *countingAnalyzer) Analyze(context.Context, string, []string) (*reachability.Analysis, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	return &reachability.Analysis{Results: a.res, Entrypoints: []string{"app.main"}}, nil
}

// fakeFingerprinter returns a fixed source hash + environment per target, or an error for a chosen target.
type fakeFingerprinter struct {
	sourceHash string
	env        string
	errFor     string // targetRef that should fail (empty = never)
}

func (f fakeFingerprinter) FingerprintSource(_ context.Context, targetRef string) (string, string, error) {
	if f.errFor != "" && targetRef == f.errFor {
		return "", "", errors.New("cannot hash source")
	}
	return f.sourceHash, f.env, nil
}

const (
	analyzerV = "callgraph-2.1"
	coverageV = "cov-3"
)

func newCachedCoord(t *testing.T, a analyzer, cache ReachabilityCache, fp ports.ReachabilitySourceFingerprinter) *Coordinator {
	t.Helper()
	c, err := NewCoordinator(a, &fakeRecorder{}, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	return c.WithCache(cache, fp, analyzerV, coverageV)
}

func completeFP() fakeFingerprinter {
	return fakeFingerprinter{sourceHash: "srchash-v1", env: "env-abc"}
}

func recordTarget(t *testing.T, c *Coordinator, target string) {
	t.Helper()
	if _, err := c.Record(context.Background(), "eng-1", target,
		[]ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func recordOnce(t *testing.T, c *Coordinator) { t.Helper(); recordTarget(t, c, "/work") }

// A second Record with identical verdict-affecting inputs reuses the cached Analysis (one analyzer run).
func TestCacheHitSkipsRecompute(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}}}}
	c := newCachedCoord(t, a, NewInMemoryCache(), completeFP())
	recordOnce(t, c)
	recordOnce(t, c)
	if a.calls != 1 {
		t.Fatalf("identical inputs must hit the cache: analyzer ran %d times, want 1", a.calls)
	}
}

// A changed source-tree hash is a different key, so the cache misses and the analyzer re-runs: a stale-key
// negative can never be served after the source changed (the #1-bar).
func TestCacheChangedSourceMisses(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}}}}
	cache := NewInMemoryCache()
	recordOnce(t, newCachedCoord(t, a, cache, completeFP()))
	changed := fakeFingerprinter{sourceHash: "srchash-v2", env: "env-abc"} // source tree changed
	recordOnce(t, newCachedCoord(t, a, cache, changed))
	if a.calls != 2 {
		t.Fatalf("a changed source hash must miss: analyzer ran %d times, want 2", a.calls)
	}
}

// Two DIFFERENT targets with an identical symbol set must NOT collide: the per-target source hash keeps their
// graphs separate (a static key would serve one repo's graph for another).
func TestCacheDistinctTargetsSameSymbolsDoNotCollide(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
	cache := NewInMemoryCache()
	// A fingerprinter that returns a per-target hash (its target IS the hash here).
	fp := perTargetFingerprinter{}
	c := newCachedCoord(t, a, cache, fp)
	recordTarget(t, c, "/repo-a")
	recordTarget(t, c, "/repo-b")
	if a.calls != 2 {
		t.Fatalf("distinct targets must not share a cached graph: analyzer ran %d, want 2", a.calls)
	}
}

type perTargetFingerprinter struct{}

func (perTargetFingerprinter) FingerprintSource(_ context.Context, targetRef string) (string, string, error) {
	return "hash:" + targetRef, "env:" + targetRef, nil
}

// Each remaining verdict-affecting field, when changed, must miss the cache.
func TestCacheEveryKeyFieldChangeMisses(t *testing.T) {
	cases := map[string]struct {
		fp            ports.ReachabilitySourceFingerprinter
		analyzerV, cV string
	}{
		"env fingerprint":  {fakeFingerprinter{sourceHash: "srchash-v1", env: "env-other"}, analyzerV, coverageV},
		"analyzer version": {completeFP(), "other", coverageV},
		"coverage model":   {completeFP(), analyzerV, "other"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
			cache := NewInMemoryCache()
			recordOnce(t, newCachedCoord(t, a, cache, completeFP()))
			c2, _ := NewCoordinator(a, &fakeRecorder{}, &fakeAudit{}, fakeClock{})
			c2 = c2.WithCache(cache, tc.fp, tc.analyzerV, tc.cV)
			recordOnce(t, c2)
			if a.calls != 2 {
				t.Fatalf("changing %s must miss: analyzer ran %d, want 2", name, a.calls)
			}
		})
	}
}

// A changed symbol set is a different query and must miss (the cached Analysis answered a different set).
func TestCacheChangedSymbolSetMisses(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
	c := newCachedCoord(t, a, NewInMemoryCache(), completeFP())
	recordOnce(t, c)
	if _, err := c.Record(context.Background(), "eng-1", "/work",
		[]ports.ReachabilitySubject{{FindingID: "f2", Symbols: []string{"dep.vuln", "other.sym"}}}); err != nil {
		t.Fatal(err)
	}
	if a.calls != 2 {
		t.Fatalf("a changed symbol set must miss: analyzer ran %d, want 2", a.calls)
	}
}

// A fingerprinter error must NEVER cache: the run recomputes rather than risk a stale key.
func TestFingerprintErrorNeverCaches(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
	fp := fakeFingerprinter{sourceHash: "srchash-v1", env: "env-abc", errFor: "/work"}
	c := newCachedCoord(t, a, NewInMemoryCache(), fp)
	recordOnce(t, c)
	recordOnce(t, c)
	if a.calls != 2 {
		t.Fatalf("a fingerprint error must never cache: analyzer ran %d, want 2", a.calls)
	}
}

// An incomplete fingerprint (empty source hash) must NEVER cache: an unbound field means recompute.
func TestIncompleteKeyNeverCaches(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
	fp := fakeFingerprinter{sourceHash: "", env: "env-abc"} // could not hash the source -> incomplete
	c := newCachedCoord(t, a, NewInMemoryCache(), fp)
	recordOnce(t, c)
	recordOnce(t, c)
	if a.calls != 2 {
		t.Fatalf("an incomplete key must never cache: analyzer ran %d, want 2", a.calls)
	}
}

// With no cache attached (the default), every Record recomputes.
func TestNoCacheAlwaysRecomputes(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true}}}
	c := newCoord(t, a, &fakeRecorder{})
	recordOnce(t, c)
	recordOnce(t, c)
	if a.calls != 2 {
		t.Fatalf("no cache must recompute: analyzer ran %d, want 2", a.calls)
	}
}

// A cache hit still produces the same minted verdict: the coordinator re-derives from the cached Analysis.
func TestCacheHitStillMintsSameVerdict(t *testing.T) {
	a := &countingAnalyzer{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: true, Path: []string{"app.main", "dep.vuln"}}}}
	rec := &fakeRecorder{}
	c, err := NewCoordinator(a, rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	c = c.WithCache(NewInMemoryCache(), completeFP(), analyzerV, coverageV)
	subs := []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}}
	if _, err := c.Record(context.Background(), "eng-1", "/work", subs); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Record(context.Background(), "eng-1", "/work", subs); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 {
		t.Fatalf("analyzer should have run once, ran %d", a.calls)
	}
	if len(rec.proposes) != 2 {
		t.Fatalf("both records must mint from the (cached) analysis, got %d proposes", len(rec.proposes))
	}
	for i, p := range rec.proposes {
		if p.claim.Reachable != judgment.Reachable || p.claim.Tier != judgment.Tier2 {
			t.Fatalf("propose %d wrong claim: %+v", i, p.claim)
		}
	}
}

// A cache hit must re-derive the SAME fail-open behavior for a not-reachable analysis: a Tier-2 not-reachable
// with no entry points is soft no-coverage, so BOTH the first (miss) and second (hit) Record must mint
// nothing (the prior tier stands). This is the direction that matters for the #1 bar: a cache hit must never
// turn a fail-open into a served negative.
func TestCacheHitPreservesFailOpenNotReachable(t *testing.T) {
	// noEntrypoints via a bespoke analyzer: not reachable AND zero entry points -> Tier-2 soft no-coverage.
	a := &countingAnalyzerNoEntry{res: []reachability.Result{{Symbol: "dep.vuln", Reachable: false}}}
	rec := &fakeRecorder{}
	c, err := NewCoordinator(a, rec, &fakeAudit{}, fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	c = c.WithCache(NewInMemoryCache(), completeFP(), analyzerV, coverageV)
	subs := []ports.ReachabilitySubject{{FindingID: "f1", Symbols: []string{"dep.vuln"}}}
	for i := 0; i < 2; i++ {
		n, rerr := c.Record(context.Background(), "eng-1", "/work", subs)
		if rerr != nil {
			t.Fatalf("record %d: %v", i, rerr)
		}
		if n != 0 {
			t.Fatalf("record %d: fail-open must mint nothing, minted %d", i, n)
		}
	}
	if a.calls != 1 {
		t.Fatalf("second record must hit the cache: analyzer ran %d, want 1", a.calls)
	}
	if len(rec.proposes) != 0 {
		t.Fatalf("no not_reachable claim may be minted on a fail-open, got %d proposes", len(rec.proposes))
	}
}

type countingAnalyzerNoEntry struct {
	mu    sync.Mutex
	calls int
	res   []reachability.Result
}

func (a *countingAnalyzerNoEntry) Analyze(context.Context, string, []string) (*reachability.Analysis, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	return &reachability.Analysis{Results: a.res, Entrypoints: nil}, nil // zero entry points -> fail open
}

// Overwriting an existing key does not corrupt the entry-count or the running Result budget, and does not
// spuriously evict other entries.
func TestInMemoryCachePutOverwriteConsistent(t *testing.T) {
	cache := NewInMemoryCacheWithCapacity(4, 0)
	mk := func(n int) *reachability.Analysis {
		res := make([]reachability.Result, n)
		return &reachability.Analysis{Results: res}
	}
	_ = cache.Put(context.Background(), "a", mk(3))
	_ = cache.Put(context.Background(), "b", mk(3))
	_ = cache.Put(context.Background(), "a", mk(1)) // overwrite a: results should drop 3 then add 1
	for _, fp := range []string{"a", "b"} {
		if _, hit, _ := cache.Get(context.Background(), fp); !hit {
			t.Fatalf("overwrite must not evict %q", fp)
		}
	}
	if cache.results != 4 { // b:3 + a:1
		t.Fatalf("result budget accounting wrong after overwrite: got %d, want 4", cache.results)
	}
	if len(cache.order) != 2 {
		t.Fatalf("overwrite must not append to order: got %d entries, want 2", len(cache.order))
	}
}

// Codex finding 4: overwriting the OLDEST key with a large value must not evict the key being written; it is
// moved to the back, so an eviction pass removes another entry instead.
func TestInMemoryCachePutOverwriteOldestNotEvicted(t *testing.T) {
	cache := NewInMemoryCacheWithCapacity(100, 10) // tight result budget
	mk := func(n int) *reachability.Analysis {
		return &reachability.Analysis{Results: make([]reachability.Result, n)}
	}
	_ = cache.Put(context.Background(), "a", mk(4)) // oldest
	_ = cache.Put(context.Background(), "b", mk(4)) // total 8, within budget
	_ = cache.Put(context.Background(), "a", mk(8)) // overwrite oldest: 8(a)+4(b)=12 > 10 -> must evict b, keep a
	if _, hit, _ := cache.Get(context.Background(), "a"); !hit {
		t.Fatal("the just-overwritten key a must survive its own Put")
	}
	if _, hit, _ := cache.Get(context.Background(), "b"); hit {
		t.Fatal("overflow after overwrite must evict the other (now-oldest) entry b")
	}
}

// The result-budget bound evicts oldest entries even when the entry count is under capacity.
func TestInMemoryCacheResultBudgetEvicts(t *testing.T) {
	cache := NewInMemoryCacheWithCapacity(100, 10) // generous entry cap, tight result budget
	mk := func(n int) *reachability.Analysis {
		return &reachability.Analysis{Results: make([]reachability.Result, n)}
	}
	_ = cache.Put(context.Background(), "a", mk(6))
	_ = cache.Put(context.Background(), "b", mk(6)) // 12 > 10 -> evict a
	if _, hit, _ := cache.Get(context.Background(), "a"); hit {
		t.Fatal("result-budget overflow must evict the oldest entry a")
	}
	if _, hit, _ := cache.Get(context.Background(), "b"); !hit {
		t.Fatal("the most recent entry b must survive")
	}
}

// The bounded cache evicts the oldest entry past capacity; an evicted key simply misses (recompute), which
// is always sound. The most recent entries survive.
func TestInMemoryCacheEvictsOldest(t *testing.T) {
	cache := NewInMemoryCacheWithCapacity(2, 0)
	put := func(fp string) {
		if err := cache.Put(context.Background(), fp, &reachability.Analysis{Results: []reachability.Result{{Symbol: fp}}}); err != nil {
			t.Fatal(err)
		}
	}
	put("a")
	put("b")
	put("c") // evicts "a"
	if _, hit, _ := cache.Get(context.Background(), "a"); hit {
		t.Fatal("oldest entry a should have been evicted")
	}
	for _, fp := range []string{"b", "c"} {
		if _, hit, _ := cache.Get(context.Background(), fp); !hit {
			t.Fatalf("recent entry %q should survive", fp)
		}
	}
}

// The in-memory adapter deep-copies, so a caller mutating a returned Analysis cannot corrupt the store.
func TestInMemoryCacheIsolatesEntries(t *testing.T) {
	cache := NewInMemoryCache()
	orig := &reachability.Analysis{Results: []reachability.Result{{Symbol: "s", Reachable: true, Path: []string{"a", "b"}}}, Entrypoints: []string{"root"}}
	if err := cache.Put(context.Background(), "fp", orig); err != nil {
		t.Fatal(err)
	}
	orig.Results[0].Path[0] = "mutated" // mutate the source after Put
	got, hit, err := cache.Get(context.Background(), "fp")
	if err != nil || !hit {
		t.Fatalf("want hit, got hit=%v err=%v", hit, err)
	}
	if got.Results[0].Path[0] != "a" {
		t.Fatalf("Put must deep-copy: stored path was mutated to %q", got.Results[0].Path[0])
	}
	got.Results[0].Symbol = "corrupt" // mutate the returned copy
	got2, _, _ := cache.Get(context.Background(), "fp")
	if got2.Results[0].Symbol != "s" {
		t.Fatalf("Get must deep-copy: returned copy mutated the store to %q", got2.Results[0].Symbol)
	}
}

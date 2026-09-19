package benchperf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAllocCeilingRatchet(t *testing.T) {
	const base = 1_000_000
	ceil := AllocCeiling(base, 0.30) // 1,300,000
	cases := []struct {
		name    string
		median  uint64
		regress bool
	}{
		{"well under", 900_000, false},
		{"at ceiling", ceil, false}, // strict '>' at the call site: exactly at the ceiling passes
		{"just over ceiling", ceil + 1, true},
		{"gross regression", 2_000_000, true},
	}
	for _, c := range cases {
		if got := c.median > ceil; got != c.regress {
			t.Errorf("%s: median %d vs ceiling %d, regressed=%v want %v", c.name, c.median, ceil, got, c.regress)
		}
	}
}

func TestLoadValidatesSchemaAndSamples(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Missing file -> found=false, no error (the caller reports the disabled-gate error itself).
	if _, found, err := Load(filepath.Join(dir, "nope.json"), 20); found || err != nil {
		t.Errorf("missing baseline: found=%v err=%v, want found=false err=nil", found, err)
	}
	// Wrong schema -> error.
	if _, _, err := Load(write("bad-schema.json", `{"schema":"old-v1","samples":20,"alloc_bytes_median":1}`), 20); err == nil {
		t.Error("wrong schema must error")
	}
	// Sample mismatch -> error.
	if _, _, err := Load(write("bad-samples.json", `{"schema":"`+Schema+`","samples":10,"alloc_bytes_median":1}`), 20); err == nil {
		t.Error("sample-count mismatch must error")
	}
	// Zero alloc -> error.
	if _, _, err := Load(write("zero.json", `{"schema":"`+Schema+`","samples":20,"alloc_bytes_median":0}`), 20); err == nil {
		t.Error("zero alloc_bytes_median must error")
	}
	// Valid -> loads.
	b, found, err := Load(write("ok.json", `{"schema":"`+Schema+`","samples":20,"alloc_bytes_median":5}`), 20)
	if !found || err != nil || b.AllocBytes != 5 {
		t.Errorf("valid baseline: found=%v err=%v alloc=%d", found, err, b.AllocBytes)
	}
}

func TestDatasetDigestStableAndCollisionResistant(t *testing.T) {
	first := DatasetDigest("ab", "c")
	again := DatasetDigest("ab", "c")
	if first != again {
		t.Error("digest must be stable for the same input")
	}
	// Length-prefixing must keep ("ab","c") distinct from ("a","bc").
	if DatasetDigest("ab", "c") == DatasetDigest("a", "bc") {
		t.Error("length-prefixing must prevent a boundary collision")
	}
	if DatasetDigest("x") == DatasetDigest("y") {
		t.Error("different content must digest differently")
	}
}

// measureSink escapes allocations in the Measure test so the compiler cannot elide them as dead stores.
var measureSink []byte

func TestMeasureRunsWarmupAndSamples(t *testing.T) {
	calls := 0
	res := Measure(3, 5, func() {
		calls++
		measureSink = make([]byte, 4096) // escapes to a package var, so the alloc delta is real
	})
	if calls != 8 {
		t.Errorf("op called %d times, want 3 warmup + 5 samples = 8", calls)
	}
	if res.MedianAllocBytes == 0 {
		t.Error("an allocating op must record non-zero median alloc")
	}
	_ = res.PeakMemoryBytes
	if res.LatencyP95 < res.LatencyP50 {
		// p95 >= p50 by definition of the percentile picker.
		t.Errorf("p95 %s must be >= p50 %s", res.LatencyP95, res.LatencyP50)
	}
}

func TestLoadDistinguishesUnreadableFromMissing(t *testing.T) {
	// A path that exists but is a directory is present-but-unreadable: it must error, not report "missing".
	dir := t.TempDir()
	if _, found, err := Load(dir, 20); err == nil || found {
		t.Errorf("an unreadable baseline path must error (found=%v err=%v)", found, err)
	}
}

func TestMedianAndPercentileEmptyIsZero(t *testing.T) {
	if got := MedianU64(nil); got != 0 {
		t.Errorf("median of empty = %d, want 0", got)
	}
	if got := PercentileDur(nil, 95); got != 0 {
		t.Errorf("percentile of empty = %v, want 0", got)
	}
}

func TestMedianAndPercentile(t *testing.T) {
	if got := MedianU64([]uint64{5, 1, 3, 2, 4}); got != 3 {
		t.Errorf("median = %d, want 3", got)
	}
	xs := []time.Duration{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if got := PercentileDur(xs, 50); got != 6 {
		t.Errorf("p50 = %v, want 6", got)
	}
	if got := PercentileDur(xs, 95); got != 10 {
		t.Errorf("p95 = %v, want 10", got)
	}
}

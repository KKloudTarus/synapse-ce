package benchperf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

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
	if _, found, err := Load(filepath.Join(dir, "nope.json"), 3, 20); found || err != nil {
		t.Errorf("missing baseline: found=%v err=%v, want found=false err=nil", found, err)
	}
	// Wrong schema -> error.
	if _, _, err := Load(write("bad-schema.json", `{"schema":"old-v1","samples":20,"alloc_bytes_median":1}`), 3, 20); err == nil {
		t.Error("wrong schema must error")
	}
	// Sample mismatch -> error.
	if _, _, err := Load(write("bad-samples.json", `{"schema":"`+Schema+`","samples":10,"alloc_bytes_median":1}`), 3, 20); err == nil {
		t.Error("sample-count mismatch must error")
	}
	// Zero alloc -> error.
	if _, _, err := Load(write("zero.json", `{"schema":"`+Schema+`","samples":20,"alloc_bytes_median":0}`), 3, 20); err == nil {
		t.Error("zero alloc_bytes_median must error")
	}
	// Valid -> loads.
	b, found, err := Load(write("ok.json", `{"schema":"`+Schema+`","release_digest":"7105fde8c2a9186803861275f3f5dd287293f3e5","dataset_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","environment_digest":"env:fixture","go_version":"go1.27.0","warmup_samples":3,"samples":20,"alloc_bytes_median":5,"alloc_ceiling_bytes":6,"peak_memory_bytes":6,"throughput_ops_per_second":7.5}`), 3, 20)
	if !found || err != nil || b.AllocBytes != 5 {
		t.Errorf("valid baseline: found=%v err=%v alloc=%d", found, err, b.AllocBytes)
	}
}

func TestLoadRejectsNonReproducibleIdentityAndMissingMeasurements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	valid := `{"schema":"` + Schema + `","release_digest":"7105fde8c2a9186803861275f3f5dd287293f3e5","dataset_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","environment_digest":"env:fixture","go_version":"go1.27.0","warmup_samples":3,"samples":20,"alloc_bytes_median":5,"alloc_ceiling_bytes":6,"peak_memory_bytes":6,"throughput_ops_per_second":7.5}`
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path, 3, 20); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}
	if _, _, err := Load(path, 4, 20); err == nil || !strings.Contains(err.Error(), "warmup samples") {
		t.Fatalf("changed live warmup must reject the baseline: %v", err)
	}
	for _, replacement := range []string{
		`"release_digest":"(devel)"`,
		`"peak_memory_bytes":0`,
		`"alloc_ceiling_bytes":0`,
		`"throughput_ops_per_second":0`,
	} {
		body := strings.Replace(valid, `"release_digest":"7105fde8c2a9186803861275f3f5dd287293f3e5"`, replacement, 1)
		if replacement == `"peak_memory_bytes":0` {
			body = strings.Replace(valid, `"peak_memory_bytes":6`, replacement, 1)
		} else if replacement == `"alloc_ceiling_bytes":0` {
			body = strings.Replace(valid, `"alloc_ceiling_bytes":6`, replacement, 1)
		} else if replacement == `"throughput_ops_per_second":0` {
			body = strings.Replace(valid, `"throughput_ops_per_second":7.5`, replacement, 1)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(path, 3, 20); err == nil {
			t.Errorf("Load accepted malformed baseline %s", replacement)
		}
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

func TestParseLinuxPeakResidentBytes(t *testing.T) {
	got, ok := parseLinuxPeakResidentBytes("Name:\ttest\nVmHWM:\t  123 kB\n")
	if !ok || got != 123*1024 {
		t.Fatalf("peak = %d, ok=%t", got, ok)
	}
	if _, ok := parseLinuxPeakResidentBytes("VmHWM:\tbroken kB\n"); ok {
		t.Fatal("malformed VmHWM accepted")
	}
}

func TestCheckPeakEvidence(t *testing.T) {
	if err := CheckPeakEvidence(Result{PeakMemoryBytes: 4096}); err != nil {
		t.Fatalf("nonzero peak evidence: %v", err)
	}
	if runtime.GOOS == "linux" {
		if err := CheckPeakEvidence(Result{}); err == nil {
			t.Fatal("Linux result without peak evidence must fail")
		}
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
	if res.ThroughputOpsPerSecond <= 0 {
		t.Errorf("five timed operations must yield positive throughput, got %v", res.ThroughputOpsPerSecond)
	}
}

func TestLoadDistinguishesUnreadableFromMissing(t *testing.T) {
	// A path that exists but is a directory is present-but-unreadable: it must error, not report "missing".
	dir := t.TempDir()
	if _, found, err := Load(dir, 3, 20); err == nil || found {
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

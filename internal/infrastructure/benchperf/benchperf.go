// Package benchperf is the shared contract for the owned-scanner performance gates (#1040 A6). Every gate
// measures repeated scans of a pinned workload and ratchets on BYTES ALLOCATED per scan against a committed
// baseline JSON under docs/benchmarks. Allocation is deterministic for a given Go toolchain and input (it does
// not depend on CPU count or clock speed), so it gives a stable cross-machine regression signal; latency is
// CPU-dependent and only recorded. Before this package each gate carried its own copy of the baseline struct,
// loader, ratchet, and measurement loop; centralizing them removes that duplication and lets every baseline
// record the same identity and statistics fields the #1040 amendment requires.
package benchperf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"time"
)

// Schema tags a committed baseline so it is never compared across an incompatible shape. v2 adds the amendment
// identity/statistics fields (release_digest, dataset_digest, warmup_samples, peak_memory_bytes) to v1.
const Schema = "synapse-scan-perf-v2"

// Baseline is the committed reference measurement for one performance gate. It records the measurement identity
// and statistics the #1040 amendment requires, so a checked-in baseline is self-describing and reproducible:
//   - EnvironmentDigest / GoVersion: where it was measured (latency is only comparable within the same env).
//   - ReleaseDigest: the module version of the code under test (debug.ReadBuildInfo), so a baseline measured
//     against a stale build is identifiable.
//   - DatasetDigest: a content hash of the pinned workload; a gate asserts its live workload matches, so a
//     regression can never be masked by the fixture silently drifting.
//   - WarmupSamples / Samples: the sampling and warm-up policy.
//   - AllocBytes: the gated statistic (median bytes allocated). PeakMemoryBytes and the latencies are recorded
//     for context, not gated (they are GC- and CPU-dependent).
type Baseline struct {
	Schema            string `json:"schema"`
	Target            string `json:"target"`
	ReleaseDigest     string `json:"release_digest"`
	DatasetDigest     string `json:"dataset_digest"`
	EnvironmentDigest string `json:"environment_digest"`
	GoVersion         string `json:"go_version"`
	WarmupSamples     int    `json:"warmup_samples"`
	Samples           int    `json:"samples"`
	AllocBytes        uint64 `json:"alloc_bytes_median"`
	PeakMemoryBytes   uint64 `json:"peak_memory_bytes"`
	LatencyP50Millis  int64  `json:"latency_p50_millis"`
	LatencyP95Millis  int64  `json:"latency_p95_millis"`
}

// Load reads the committed baseline at path. found is false when the file is absent (the caller reports the
// disabled-gate error). It fails with an error on a wrong schema or a sample count that does not match the
// gate's, because a baseline measured under a different schema or sample count is not comparable, so ratcheting
// against it would be a stale, meaningless gate.
func Load(path string, expectedSamples int) (b Baseline, found bool, err error) {
	data, rerr := os.ReadFile(path)
	if errors.Is(rerr, fs.ErrNotExist) {
		// Absent baseline: the caller reports the disabled-gate error.
		return Baseline{}, false, nil
	}
	if rerr != nil {
		// Present but unreadable (permission, is-a-directory, transient I/O): a real error, not "missing", so
		// the operator sees the true cause rather than a misleading "commit the baseline" message.
		return Baseline{}, false, fmt.Errorf("read perf baseline %s: %w", path, rerr)
	}
	if uerr := json.Unmarshal(data, &b); uerr != nil {
		return Baseline{}, true, fmt.Errorf("decode perf baseline %s: %w", path, uerr)
	}
	if b.Schema != Schema {
		return Baseline{}, true, fmt.Errorf("perf baseline %s has schema %q, want %q (not comparable)", path, b.Schema, Schema)
	}
	if b.Samples != expectedSamples {
		return Baseline{}, true, fmt.Errorf("perf baseline %s was measured with %d samples, gate uses %d (re-baseline)", path, b.Samples, expectedSamples)
	}
	if b.AllocBytes == 0 {
		return Baseline{}, true, fmt.Errorf("malformed baseline %s: alloc_bytes_median is zero", path)
	}
	return b, true, nil
}

// AllocCeiling is the ratchet's upper bound: the baseline allocation plus the tolerance fraction. Factored out
// so the gate's decision is unit-tested without running a scan.
func AllocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// Result is one measurement run's statistics.
type Result struct {
	MedianAllocBytes uint64
	PeakMemoryBytes  uint64 // max heap-in-use observed after an operation across the samples (informational)
	LatencyP50       time.Duration
	LatencyP95       time.Duration
}

// Measure warms op up warmup times, then times it samples times, recording per-sample allocated bytes
// (TotalAlloc delta) and latency, plus the peak heap-in-use across the run. It GCs before each sample so the
// TotalAlloc delta reflects only op's allocations, deterministic per toolchain and input.
func Measure(warmup, samples int, op func()) Result {
	for i := 0; i < warmup; i++ {
		op()
	}
	latencies := make([]time.Duration, 0, samples)
	allocBytes := make([]uint64, 0, samples)
	var peak uint64
	for i := 0; i < samples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		op()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
		if after.HeapInuse > peak {
			peak = after.HeapInuse
		}
	}
	return Result{
		MedianAllocBytes: MedianU64(allocBytes),
		PeakMemoryBytes:  peak,
		LatencyP50:       PercentileDur(latencies, 50),
		LatencyP95:       PercentileDur(latencies, 95),
	}
}

// EnvironmentDigest identifies the measurement environment without asserting cross-hardware comparability.
func EnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// ReleaseDigest is the module version of the code under test, from the embedded build info. It is "(devel)" for
// an untagged working tree and "unknown" when build info is unavailable; either way it records which build a
// baseline was measured against.
func ReleaseDigest() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}

// DatasetDigest hashes the pinned workload's deterministic parts into a stable content digest, so a gate can
// assert its live workload matches the committed baseline's dataset. Order matters: pass the parts in a fixed
// order (e.g. sorted path then content) so the digest is reproducible.
func DatasetDigest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		// Length-prefix each part so ("ab","c") and ("a","bc") never collide. sha256's Write never errors.
		h.Write([]byte(strconv.Itoa(len(p)) + ":"))
		h.Write([]byte(p))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// MedianU64 returns the median of xs (upper-middle for even counts), or 0 for an empty slice. xs is not mutated.
func MedianU64(xs []uint64) uint64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

// PercentileDur returns the p-th percentile of xs, or 0 for an empty slice. xs is not mutated.
func PercentileDur(xs []time.Duration, p int) time.Duration {
	if len(xs) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

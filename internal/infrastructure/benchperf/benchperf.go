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
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schema tags a committed baseline so it is never compared across an incompatible shape. v2 adds the amendment
// identity/statistics fields (release_digest, dataset_digest, warmup_samples, peak_memory_bytes) to v1.
const Schema = "synapse-scan-perf-v2"

// Baseline is the committed reference measurement for one performance gate. It records the measurement identity
// and statistics the #1040 amendment requires, so a checked-in baseline is self-describing and reproducible:
//   - EnvironmentDigest / GoVersion: where it was measured (latency is only comparable within the same env).
//   - ReleaseDigest: the immutable source revision that produced the baseline, so a stale build is identifiable.
//   - DatasetDigest: a content hash of the pinned workload; a gate asserts its live workload matches, so a
//     regression can never be masked by the fixture silently drifting.
//   - WarmupSamples / Samples: the sampling and warm-up policy.
//   - AllocBytes: the cross-environment gated statistic (median bytes allocated). PeakMemoryBytes and
//     latencies are recorded for context. VmHWM is process-wide and depends on other tests in the process.
type Baseline struct {
	Schema                 string  `json:"schema"`
	Target                 string  `json:"target"`
	ReleaseDigest          string  `json:"release_digest"`
	DatasetDigest          string  `json:"dataset_digest"`
	EnvironmentDigest      string  `json:"environment_digest"`
	GoVersion              string  `json:"go_version"`
	WarmupSamples          int     `json:"warmup_samples"`
	Samples                int     `json:"samples"`
	AllocBytes             uint64  `json:"alloc_bytes_median"`
	PeakMemoryBytes        uint64  `json:"peak_memory_bytes"`
	LatencyP50Millis       int64   `json:"latency_p50_millis"`
	LatencyP95Millis       int64   `json:"latency_p95_millis"`
	ThroughputOpsPerSecond float64 `json:"throughput_ops_per_second"`
}

// Load reads the committed baseline at path. found is false when the file is absent (the caller reports the
// disabled-gate error). It fails with an error on a wrong schema or a warmup/sample count that does not match the
// gate's, because a baseline measured under a different schema or sampling policy is not comparable, so ratcheting
// against it would be a stale, meaningless gate.
func Load(path string, expectedWarmup, expectedSamples int) (b Baseline, found bool, err error) {
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
	if b.WarmupSamples != expectedWarmup {
		return Baseline{}, true, fmt.Errorf("perf baseline %s was measured with %d warmup samples, gate uses %d (re-baseline)", path, b.WarmupSamples, expectedWarmup)
	}
	if err := validateBaseline(b); err != nil {
		return Baseline{}, true, fmt.Errorf("malformed baseline %s: %w", path, err)
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
	// PeakMemoryBytes is the Linux kernel's VmHWM (maximum resident set size) for the
	// benchmark test process. It is zero where that operating-system measurement is unavailable.
	PeakMemoryBytes uint64
	LatencyP50      time.Duration
	LatencyP95      time.Duration
	// ThroughputOpsPerSecond is serial completed operations divided by their
	// total timed duration; warmups and per-sample GC are excluded.
	ThroughputOpsPerSecond float64
}

// CheckPeakEvidence requires a Linux peak-resident measurement for the published result.
// VmHWM is process-wide, so it is recorded but not used as a per-operation regression ratchet.
func CheckPeakEvidence(result Result) error {
	if runtime.GOOS == "linux" && result.PeakMemoryBytes == 0 {
		return fmt.Errorf("linux peak resident memory measurement is unavailable")
	}
	return nil
}

// Measure warms op up warmup times, then times it samples times, recording per-sample allocated bytes
// (TotalAlloc delta), latency, and the kernel-maintained high-water resident memory mark. It GCs before each
// sample so the TotalAlloc delta reflects only op's allocations, deterministic per toolchain and input.
func Measure(warmup, samples int, op func()) Result {
	for i := 0; i < warmup; i++ {
		op()
	}
	latencies := make([]time.Duration, 0, samples)
	allocBytes := make([]uint64, 0, samples)
	var peak uint64
	var timedDuration time.Duration
	for i := 0; i < samples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		op()
		elapsed := time.Since(start)
		if elapsed <= 0 {
			// Fast operations can fall below the timer resolution on Windows.
			elapsed = time.Nanosecond
		}
		latencies = append(latencies, elapsed)
		timedDuration += elapsed
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
		if hwm, ok := linuxPeakResidentBytes(); ok && hwm > peak {
			peak = hwm
		}
	}
	var throughput float64
	if timedDuration > 0 {
		throughput = float64(samples) / timedDuration.Seconds()
	}
	return Result{
		MedianAllocBytes:       MedianU64(allocBytes),
		PeakMemoryBytes:        peak,
		LatencyP50:             PercentileDur(latencies, 50),
		LatencyP95:             PercentileDur(latencies, 95),
		ThroughputOpsPerSecond: throughput,
	}
}

// EnvironmentDigest identifies the measurement environment without asserting cross-hardware comparability.
func EnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// ReleaseDigest returns the immutable source revision supplied by the benchmark runner. Test binaries normally
// embed "(devel)", so build info cannot bind a measurement to the checked-out source. The hosted workflow sets
// SYNAPSE_BENCH_RELEASE_DIGEST from the exact revision it checked out; local measurements can set it explicitly.
func ReleaseDigest() string {
	if digest := strings.TrimSpace(os.Getenv("SYNAPSE_BENCH_RELEASE_DIGEST")); isGitSHA(digest) {
		return digest
	}
	return "unidentified"
}

func validateBaseline(b Baseline) error {
	if !isGitSHA(b.ReleaseDigest) {
		return fmt.Errorf("release_digest must be a full lowercase Git SHA")
	}
	if !strings.HasPrefix(b.DatasetDigest, "sha256:") || len(b.DatasetDigest) != len("sha256:")+64 {
		return fmt.Errorf("dataset_digest must be a SHA-256 digest")
	}
	if strings.TrimSpace(b.EnvironmentDigest) == "" || strings.TrimSpace(b.GoVersion) == "" {
		return fmt.Errorf("environment_digest and go_version are required")
	}
	if b.WarmupSamples < 0 {
		return fmt.Errorf("warmup_samples must not be negative")
	}
	if b.AllocBytes == 0 || b.PeakMemoryBytes == 0 {
		return fmt.Errorf("alloc_bytes_median and peak_memory_bytes must be non-zero")
	}
	if b.ThroughputOpsPerSecond <= 0 || math.IsInf(b.ThroughputOpsPerSecond, 0) || math.IsNaN(b.ThroughputOpsPerSecond) {
		return fmt.Errorf("throughput_ops_per_second must be a positive finite measurement")
	}
	return nil
}

func isGitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func linuxPeakResidentBytes() (uint64, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	return parseLinuxPeakResidentBytes(string(status))
}

func parseLinuxPeakResidentBytes(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "VmHWM:" || fields[2] != "kB" {
			continue
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kilobytes * 1024, true
	}
	return 0, false
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

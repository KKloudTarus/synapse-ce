package telemetry

import "strings"

// Coverage and data-quality honesty for a single raw event (A1). These are the per-event twin of the
// batch-level loss semantics in loss.go: they let a downstream reader tell a whole observation from one
// that was capped or is missing a field, so a rule or a hunt never treats a truncated event as complete.

// DataQuality is a bitset of per-event defects the normalizer discovered (a capped argv, a missing PPID,
// no kernel timestamp, …). Zero means the event is fully-formed. It is deliberately additive: new defects
// get a new bit without changing the wire meaning of the old ones.
type DataQuality uint32

const (
	// QualityTruncatedArgv — the process argv was cut by the sensor's per-arg / arg-count cap; the args
	// present are a prefix, not the whole command line.
	QualityTruncatedArgv DataQuality = 1 << iota
	// QualityTruncatedPath — an executable or file path was cut by the sensor's path buffer.
	QualityTruncatedPath
	// QualityMissingPPID — the parent pid was not recoverable, so ParentProcessEntityID is empty.
	QualityMissingPPID
	// QualityMissingStartTime — the kernel process start time was unavailable, so the ProcessEntityID is
	// derived without it and is therefore weaker against PID reuse.
	QualityMissingStartTime
	// QualityMissingParentStartTime — the PARENT's kernel start time was unavailable, so a reliable
	// ParentProcessEntityID could not be derived. The normalizer leaves ParentEntityID empty rather than
	// synthesize a start=0 id that would silently fail to match the parent's real entity (and could alias
	// the wrong process under parent-PID reuse — the D4 failure mode); this flag records the gap honestly.
	QualityMissingParentStartTime
	// QualityKernelTimestampUnavailable — OccurredAt could not be taken from the kernel event and fell
	// back to the collector's ObservedAt; the two are equal for this event.
	QualityKernelTimestampUnavailable
	// QualityRedacted — source-side privacy redaction (A6, #627) changed at least one field of this event
	// (a secret scrubbed, a value hashed, or a field dropped) before it entered the spool. The reader knows
	// a redacted value is not the raw observation; the applied policy is named by RedactionPolicyDigest.
	QualityRedacted
)

// Has reports whether flag f is set.
func (q DataQuality) Has(f DataQuality) bool { return q&f != 0 }

// With returns q with flag f set (value-style; DataQuality is a small immutable value).
func (q DataQuality) With(f DataQuality) DataQuality { return q | f }

// IsClean reports whether the event carries no quality defects.
func (q DataQuality) IsClean() bool { return q == 0 }

// String renders the set flags for logs/tests; "clean" when none are set.
func (q DataQuality) String() string {
	if q.IsClean() {
		return "clean"
	}
	names := []struct {
		f DataQuality
		n string
	}{
		{QualityTruncatedArgv, "truncated_argv"},
		{QualityTruncatedPath, "truncated_path"},
		{QualityMissingPPID, "missing_ppid"},
		{QualityMissingStartTime, "missing_start_time"},
		{QualityMissingParentStartTime, "missing_parent_start_time"},
		{QualityKernelTimestampUnavailable, "kernel_ts_unavailable"},
		{QualityRedacted, "redacted"},
	}
	var set []string
	for _, e := range names {
		if q.Has(e.f) {
			set = append(set, e.n)
		}
	}
	return strings.Join(set, "|")
}

// CoverageFlags is a bitset describing the coverage posture of the sensor path this event came through —
// distinct from DataQuality (which is about THIS event's fields). Zero means full, healthy coverage.
type CoverageFlags uint32

const (
	// CoverageSensorDegraded — the emitting sensor was in a degraded state (e.g. partial attach) when this
	// event was produced, so absence of sibling events is not proof of absence of activity.
	CoverageSensorDegraded CoverageFlags = 1 << iota
	// CoverageBackfilled — the event was recovered from a durable spool after a gap, not observed live.
	CoverageBackfilled
)

// Has reports whether flag f is set.
func (c CoverageFlags) Has(f CoverageFlags) bool { return c&f != 0 }

// With returns c with flag f set.
func (c CoverageFlags) With(f CoverageFlags) CoverageFlags { return c | f }

// IsComplete reports whether the event came through a fully-covered, live sensor path.
func (c CoverageFlags) IsComplete() bool { return c == 0 }

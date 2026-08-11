// Package detection is the pure domain for the agent-side blue-team detection engine (issue #422): the
// typed event classes an eBPF sensor observes, the clean-room rules that match over them, the detection
// a match emits, and the coverage honesty that says a class the agent could not observe is a GAP, never
// a clean host.
//
// It has no I/O, no clock, and no eBPF: the kernel programs, their loaders and the agent-side engine
// live in internal/infrastructure/ebpf and internal/usecase/fleet/detect, which depend on this domain.
// A rule Matcher is TYPED DATA evaluated by Go — never a shell expression or an eval'd string (golden
// rule 1): the engine observes and matches, it never executes anything.
//
// Milestone one ships DETECTIONS, not raw events. This package models the detection and the bounded
// evidence window that travels with it; the raw event stream stays on the host (issue #424).
package detection

// Class is a category of host activity the engine observes. Each class is backed by its own eBPF program
// with its own bounded map and can be loaded, disabled and fail INDEPENDENTLY — a missing kernel feature
// takes out one class with a coverage report, never the whole engine (#422 requirement 6).
//
// The set mirrors the telemetry classes the emulation catalogue (#421) expects a detection for, so the
// purple ledger (#426) can reconcile "what we executed" against "what we detected" by detection id.
type Class string

const (
	ClassProcess   Class = "process"   // process execution (exec/fork)
	ClassNetwork   Class = "network"   // outbound/inbound connect
	ClassFile      Class = "file"      // file access to sensitive paths
	ClassPrivilege Class = "privilege" // privilege / capability change
)

// Valid reports whether c is a known event class.
func (c Class) Valid() bool {
	switch c {
	case ClassProcess, ClassNetwork, ClassFile, ClassPrivilege:
		return true
	default:
		return false
	}
}

// Classes returns every event class in a stable order, so a per-class coverage report and its trend are
// comparable across runs and across hosts.
func Classes() []Class {
	return []Class{ClassProcess, ClassNetwork, ClassFile, ClassPrivilege}
}

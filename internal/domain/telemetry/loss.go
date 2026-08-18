// Package telemetry is the pure domain for the raw-telemetry tier's HONESTY semantics (#611, A0.4/A0.6):
// how a batch's fidelity is classified so coverage/confidence never lie. It owns no I/O and no store — the
// columnar tier lives behind ports.TelemetryStore — only the vocabulary both sides reason about.
package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// LossDisposition names WHY a stored window is less than the full truth. The whole point of A0.6 (fixing
// D2) is that these are DISTINCT and never collapsed into a single "sample rate": keeping a prefix and
// calling it a sample hides that the tail — where a late malicious sequence lives — was dropped.
type LossDisposition string

const (
	// Complete — nothing was lost; the window is the full truth for what the agent shipped.
	Complete LossDisposition = "complete"
	// Sampled — an INTENTIONAL policy kept one event per N observed, under a named algorithm. A sample is
	// representative by construction; it is not a truncation.
	Sampled LossDisposition = "sampled"
	// Truncated — a batch was cut by a hard limit (e.g. the ingest budget). Unlike a sample, a truncation
	// is NOT representative — it keeps a prefix and drops a contiguous tail — so it must be recorded as its
	// own thing with a reason, never as an elevated sample rate.
	Truncated LossDisposition = "truncated"
	// Dropped — events were observed and then lost under pressure or failure (never stored at all). This is
	// the most severe: the window is missing signal that was seen but could not be kept.
	Dropped LossDisposition = "dropped"
)

// Valid reports whether d is a known disposition.
func (d LossDisposition) Valid() bool {
	switch d {
	case Complete, Sampled, Truncated, Dropped:
		return true
	default:
		return false
	}
}

// Lossy reports whether the disposition means the window is less than complete — i.e. a hunt over it must
// NOT be presented as the whole truth. Everything but Complete is lossy (a Sample included: a sampled
// window is representative but still not every event).
func (d LossDisposition) Lossy() bool { return d != Complete }

// MustNotShed reports whether a telemetry class carries signal that must NEVER be sampled or truncated
// (the hard "never-sample" list of #611 applied to the raw-telemetry classes): losing part of it would
// corrupt a security decision, so an over-budget batch of such a class is refused (back-pressured) rather
// than stored as a lossy prefix. Privilege transitions and sensitive-file activity qualify; high-volume
// process/network background telemetry is sheddable.
//
// The broader never-sample list (confirmed detections, response-verification, sensor-state, coverage
// gaps, key/config tampering, agent stop/update/decommission) rides the evidence/detection path, not this
// lossy columnar tier, so it is enforced there — here we gate the two raw classes that are never-shed.
func MustNotShed(c detection.Class) bool {
	switch c {
	case detection.ClassPrivilege, detection.ClassFile:
		return true
	default:
		return false
	}
}

// ValidateLossCounts checks the honest-accounting invariant shared by every loss record: the counts add
// up (kept + dropped == observed) and are non-negative, and each disposition carries what it needs — a
// Truncated/Dropped record must actually report a drop, a Complete record must report none. It keeps the
// count arithmetic in one place so the ports/store records and any future producer agree.
func ValidateLossCounts(d LossDisposition, observed, kept, dropped int) error {
	if !d.Valid() {
		return fmt.Errorf("%w: unknown loss disposition %q", shared.ErrValidation, d)
	}
	if observed < 0 || kept < 0 || dropped < 0 {
		return fmt.Errorf("%w: loss counts cannot be negative (observed=%d kept=%d dropped=%d)", shared.ErrValidation, observed, kept, dropped)
	}
	if kept+dropped != observed {
		return fmt.Errorf("%w: loss counts must add up: kept(%d)+dropped(%d) != observed(%d)", shared.ErrValidation, kept, dropped, observed)
	}
	switch d {
	case Complete:
		if dropped != 0 {
			return fmt.Errorf("%w: a Complete window cannot report a drop (dropped=%d)", shared.ErrValidation, dropped)
		}
	case Truncated, Dropped:
		if dropped == 0 {
			return fmt.Errorf("%w: a %s loss must report at least one dropped event", shared.ErrValidation, d)
		}
	}
	return nil
}

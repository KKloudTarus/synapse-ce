package baseline

import "github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"

// LearnWindow describes the conditions under which an observation window was captured, so the baseline can
// refuse to learn from data that would poison it or that was not honestly observed. It is the
// anti-poisoning + coverage-honesty gate: a baseline must NEVER train on an incident-active,
// adversary-emulation, active-response, sensor-degraded, or low-coverage window.
type LearnWindow struct {
	// IncidentActive: an incident was open for this entity/group during the window — abnormal by definition.
	IncidentActive bool
	// Emulation: an adversary-emulation / purple-team exercise was running — synthetic malice.
	Emulation bool
	// ActiveResponse: a response action (kill/quarantine/isolate) was in flight — perturbed behavior.
	ActiveResponse bool
	// SensorDegraded: the sensor was degraded/unhealthy — the window is not a faithful sample.
	SensorDegraded bool
	// Coverage is the honest observed coverage floor for the window (0..100).
	Coverage riskassessment.Score
	// MinCoverage is the floor the window must meet to be trusted for learning (0..100).
	MinCoverage riskassessment.Score
}

// Eligible reports whether the window may be learned from, and if not, a human reason. It is FAIL-CLOSED:
// any disqualifying flag, or coverage below the required floor, excludes the window. Because a zero-value
// LearnWindow has Coverage 0, an unspecified/ambiguous window is ineligible by default — you must
// affirmatively establish clean, sufficiently-covered conditions to learn.
func (w LearnWindow) Eligible() (bool, string) {
	switch {
	case w.IncidentActive:
		return false, "incident active during window"
	case w.Emulation:
		return false, "adversary-emulation window"
	case w.ActiveResponse:
		return false, "active-response window"
	case w.SensorDegraded:
		return false, "sensor degraded during window"
	case !w.Coverage.Valid() || !w.MinCoverage.Valid():
		return false, "coverage out of range"
	case w.MinCoverage <= 0:
		// A zeroed/absent floor must NOT read as "trusted" — the zero value is ineligible, so a caller
		// that forgets to establish a floor cannot silently learn (fail-closed, golden rule 2).
		return false, "no coverage floor established"
	case w.Coverage <= 0:
		return false, "no observed coverage"
	case w.Coverage < w.MinCoverage:
		return false, "coverage below learning floor"
	default:
		return true, ""
	}
}

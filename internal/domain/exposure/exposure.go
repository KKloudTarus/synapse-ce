// Package exposure is the pure-domain continuous-exposure fusion for cross-cutting workstream X5 (#634):
// it fuses per-component vulnerability exposures for one asset into a single riskassessment.RiskContext
// Exposure factor (0..100). Its defining precision is RUNNING-vs-INSTALLED — the same CVE carried by a
// process actually observed running ranks strictly above one merely present in inventory. It REUSES the
// already-evaluated deterministic risk output (vulnerabilityrisk: KEV-then-EPSS×CVSS Priority); it never
// recomputes KEV/EPSS/CVSS. Like Phase D's Behavior factor, exposure is a FACTOR, never a verdict, and the
// producing usecase abstains (lowers Coverage, not Risk) when inventory/runtime data is incomplete.
package exposure

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Presence is whether a vulnerable component was merely INSTALLED (present in inventory/SBOM) or observed
// RUNNING (a process/container carrying it was seen executing) — the running-vs-installed distinction X5
// adds. A running vulnerable component is a materially higher exposure than an installed-only one.
type Presence string

const (
	// PresenceInstalled: present in inventory/SBOM, not observed running.
	PresenceInstalled Presence = "installed"
	// PresenceRunning: a running process/container carrying the component was observed via telemetry.
	PresenceRunning Presence = "running"
)

// Valid reports whether p is a known presence.
func (p Presence) Valid() bool { return p == PresenceInstalled || p == PresenceRunning }

// ComponentExposure is one vulnerable (component × advisory) occurrence's contribution to an asset's
// exposure, expressed with the ALREADY-evaluated risk Priority (1 highest .. 5 background, from
// vulnerabilityrisk) plus KEV and its running/installed presence. X5 reuses this evaluation, never redoing
// the KEV/EPSS/CVSS math.
type ComponentExposure struct {
	ComponentID shared.ID
	AdvisoryID  shared.ID
	// Severity is carried as EVIDENCE (for the producing usecase's reasons/display) and validated, but it
	// is NOT a fusion input — Priority already encodes the KEV-then-EPSS×CVSS ordering that drives scoring.
	Severity shared.Severity
	Priority int
	KEV      bool
	Presence Presence
}

// Validate enforces a well-formed exposure element.
func (c ComponentExposure) Validate() error {
	if c.ComponentID.IsZero() {
		return fmt.Errorf("%w: component exposure requires a component id", shared.ErrValidation)
	}
	if c.AdvisoryID.IsZero() {
		return fmt.Errorf("%w: component exposure requires an advisory id", shared.ErrValidation)
	}
	if c.Priority < 1 || c.Priority > 5 {
		return fmt.Errorf("%w: component exposure priority %d out of range [1,5]", shared.ErrValidation, c.Priority)
	}
	if !c.Severity.Valid() {
		return fmt.Errorf("%w: component exposure has unknown severity %q", shared.ErrValidation, c.Severity)
	}
	if !c.Presence.Valid() {
		return fmt.Errorf("%w: component exposure has unknown presence %q", shared.ErrValidation, c.Presence)
	}
	return nil
}

const (
	// kevFloor: a Known-Exploited vulnerability is at least this exposed regardless of its numeric priority
	// (CISA KEV ranks above all non-KEV — the "KEV, then EPSS×CVSS" ordering).
	kevFloor riskassessment.Score = 90
	// installedNumer/installedDenom damp an installed-but-not-observed-running exposure to half its running
	// weight, so the SAME CVE ranks strictly below its running counterpart (the running-vs-installed win).
	installedNumer riskassessment.Score = 1
	installedDenom riskassessment.Score = 2
)

// priorityBase maps a vulnerabilityrisk Priority (1 highest .. 5 background) to a 0..100 base exposure.
func priorityBase(priority int) riskassessment.Score {
	switch priority {
	case 1:
		return 100
	case 2:
		return 80
	case 3:
		return 55
	case 4:
		return 30
	case 5:
		return 10
	default:
		return 0
	}
}

// componentScore is the weighted 0..100 exposure of one vulnerable component: its priority base, floored
// up for KEV, then halved when only installed (not observed running).
func componentScore(c ComponentExposure) riskassessment.Score {
	base := priorityBase(c.Priority)
	if c.KEV && base < kevFloor {
		base = kevFloor
	}
	if c.Presence == PresenceInstalled {
		base = base * installedNumer / installedDenom
	}
	return base
}

// Fuse aggregates one asset's per-component exposures into a single RiskContext.Exposure Score. It is the
// WORST component's weighted exposure (a max): many low exposures never eclipse one severe one, and a
// running vulnerable component always outranks the same CVE merely installed. It is deterministic and
// ORDER-INDEPENDENT (max), integer-only, and reproducible. An empty set fuses to 0 (no known exposure —
// the producing usecase distinguishes "scanned clean" from "no data" via its abstain/Scoreable signal,
// mirroring the Behavior factor). Every element is validated; an invalid one fails closed.
func Fuse(exposures []ComponentExposure) (riskassessment.Score, error) {
	var worst riskassessment.Score
	for _, c := range exposures {
		if err := c.Validate(); err != nil {
			return 0, err
		}
		if s := componentScore(c); s > worst {
			worst = s
		}
	}
	return worst, nil
}

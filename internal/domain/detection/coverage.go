package detection

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ClassState is whether a host is actually observing a given event class right now.
//
// The whole point of this type is honesty about the negative case. A host that reports NO detections for
// a class is ambiguous: either nothing happened, or the sensor was not watching. StateActive is the only
// state under which "no detections" means "nothing detected". Every other state is an OBSERVATION GAP —
// the host is not clean for that class, it is unobserved, and a coverage number must say so (#422
// requirements 4, 5 and 6).
type ClassState string

const (
	StateActive   ClassState = "active"   // program loaded, map bound, events flowing
	StateDegraded ClassState = "degraded" // a required kernel feature is missing; this class is disabled
	StateFailed   ClassState = "failed"   // the program failed to load or attach on a supported kernel
	StateDisabled ClassState = "disabled" // switched off by configuration (SYNAPSE_DETECT_CLASSES)
)

func (s ClassState) valid() bool {
	switch s {
	case StateActive, StateDegraded, StateFailed, StateDisabled:
		return true
	default:
		return false
	}
}

// ClassCoverage is the observation status of one event class on one host, over a window. It is the input
// to the coverage report the purple ledger (#426) and the detections-as-evidence issue (#423) consume.
type ClassCoverage struct {
	Class   Class
	HostID  shared.ID
	AgentID shared.ID
	State   ClassState
	Reason  string // required when the state is not active/disabled: WHY the class is not observing
	Since   time.Time
}

// Observing reports whether this class is actually watching. Only StateActive observes; a caller must
// never treat any other state as "no activity".
func (c ClassCoverage) Observing() bool { return c.State == StateActive }

// IsObservationGap reports whether this class is an observation gap — a window during which the host was
// NOT observing this class. StateDisabled is a gap too: a class switched off by config still means the
// host is not covered for it, and hiding that would let a config change quietly erase coverage.
func (c ClassCoverage) IsObservationGap() bool { return c.State != StateActive }

// Validate ensures a coverage record is meaningful. A non-active, non-disabled state MUST carry a reason,
// so a gap can always be explained to an operator rather than appearing as an unexplained hole.
func (c ClassCoverage) Validate() error {
	if !c.Class.Valid() {
		return fmt.Errorf("%w: coverage has an unknown class %q", shared.ErrValidation, c.Class)
	}
	if c.HostID == "" {
		return fmt.Errorf("%w: coverage must name a host", shared.ErrValidation)
	}
	if !c.State.valid() {
		return fmt.Errorf("%w: coverage has an unknown state %q", shared.ErrValidation, c.State)
	}
	if (c.State == StateDegraded || c.State == StateFailed) && c.Reason == "" {
		return fmt.Errorf("%w: coverage class %s is %s but gives no reason", shared.ErrValidation, c.Class, c.State)
	}
	return nil
}

// HostCoverage is the per-host roll-up across every event class. Building it from ClassCoverage records
// makes the honest default structural: a class with no record at all is reported as an unknown gap, not
// silently omitted — you cannot accidentally drop a class and make a host look more covered than it is.
type HostCoverage struct {
	HostID  shared.ID
	Classes []ClassCoverage // exactly one per Class(), in Classes() order
}

// NewHostCoverage assembles a host roll-up from whatever class records were reported. Any class in
// Classes() with no reported record is filled in as StateFailed with an explicit "no report" reason —
// the absence of a report is itself an observation gap, never treated as clean.
func NewHostCoverage(host shared.ID, reported []ClassCoverage) (HostCoverage, error) {
	if host == "" {
		return HostCoverage{}, fmt.Errorf("%w: host coverage must name a host", shared.ErrValidation)
	}
	byClass := make(map[Class]ClassCoverage, len(reported))
	for _, c := range reported {
		if err := c.Validate(); err != nil {
			return HostCoverage{}, err
		}
		if c.HostID != host {
			return HostCoverage{}, fmt.Errorf("%w: coverage for host %q supplied to roll-up for host %q",
				shared.ErrValidation, c.HostID, host)
		}
		if _, dup := byClass[c.Class]; dup {
			// Two conflicting records for one class would let the last one silently win and could erase a
			// gap (e.g. failed then active). Refuse it — a coverage roll-up must be order-independent.
			return HostCoverage{}, fmt.Errorf("%w: duplicate coverage record for class %s", shared.ErrValidation, c.Class)
		}
		byClass[c.Class] = c
	}
	out := HostCoverage{HostID: host}
	for _, cls := range Classes() {
		if c, ok := byClass[cls]; ok {
			out.Classes = append(out.Classes, c)
			continue
		}
		out.Classes = append(out.Classes, ClassCoverage{
			Class: cls, HostID: host, State: StateFailed,
			Reason: "no coverage reported for this class; treated as an observation gap, not as clean",
		})
	}
	sort.Slice(out.Classes, func(i, j int) bool { return out.Classes[i].Class < out.Classes[j].Class })
	return out, nil
}

// Gaps returns the classes this host is NOT observing. An empty result means every class is actively
// observed; anything else is the honest list of where "no detections" cannot be trusted.
func (h HostCoverage) Gaps() []ClassCoverage {
	var gaps []ClassCoverage
	for _, c := range h.Classes {
		if c.IsObservationGap() {
			gaps = append(gaps, c)
		}
	}
	return gaps
}

// FullyObserved reports whether every event class is actively observed on this host.
func (h HostCoverage) FullyObserved() bool { return len(h.Gaps()) == 0 }

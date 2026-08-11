package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestOnlyActiveClassIsObserving is the core honesty property: no state other than active counts as
// observing, so "no detections" only means "nothing detected" under StateActive.
func TestOnlyActiveClassIsObserving(t *testing.T) {
	for _, st := range []ClassState{StateDegraded, StateFailed, StateDisabled} {
		c := ClassCoverage{Class: ClassProcess, HostID: "h", State: st, Reason: "x"}
		if c.Observing() {
			t.Errorf("state %s must not report as observing", st)
		}
		if !c.IsObservationGap() {
			t.Errorf("state %s must report as an observation gap", st)
		}
	}
	active := ClassCoverage{Class: ClassProcess, HostID: "h", State: StateActive}
	if !active.Observing() || active.IsObservationGap() {
		t.Error("an active class must observe and not be a gap")
	}
}

func TestClassCoverageRequiresReasonForFailure(t *testing.T) {
	for _, st := range []ClassState{StateDegraded, StateFailed} {
		c := ClassCoverage{Class: ClassProcess, HostID: "h", State: st}
		if err := c.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("state %s with no reason must fail validation, got %v", st, err)
		}
	}
}

// TestNewHostCoverageFillsMissingClassesAsGaps is the "unknown is never clean" invariant made
// structural: a class with no reported record becomes a failed gap, never silently omitted, so a host
// can never look more covered than its reports justify.
func TestNewHostCoverageFillsMissingClassesAsGaps(t *testing.T) {
	// Report only the process class as active; the other three are unreported.
	reported := []ClassCoverage{{Class: ClassProcess, HostID: "h", State: StateActive, Since: time.Unix(1, 0)}}
	hc, err := NewHostCoverage("h", reported)
	if err != nil {
		t.Fatalf("host coverage: %v", err)
	}
	if len(hc.Classes) != len(Classes()) {
		t.Fatalf("roll-up must contain every class, got %d", len(hc.Classes))
	}
	if hc.FullyObserved() {
		t.Fatal("a host with three unreported classes must not read as fully observed")
	}
	gaps := hc.Gaps()
	if len(gaps) != len(Classes())-1 {
		t.Fatalf("want %d gaps for the unreported classes, got %d", len(Classes())-1, len(gaps))
	}
	for _, g := range gaps {
		if g.State != StateFailed || g.Reason == "" {
			t.Errorf("an unreported class must be a failed gap with a reason: %+v", g)
		}
	}
}

func TestHostCoverageFullyObserved(t *testing.T) {
	var reported []ClassCoverage
	for _, cls := range Classes() {
		reported = append(reported, ClassCoverage{Class: cls, HostID: "h", State: StateActive})
	}
	hc, err := NewHostCoverage("h", reported)
	if err != nil {
		t.Fatal(err)
	}
	if !hc.FullyObserved() || len(hc.Gaps()) != 0 {
		t.Fatalf("every class active should be fully observed: %+v", hc.Gaps())
	}
}

func TestNewHostCoverageRejectsForeignHost(t *testing.T) {
	reported := []ClassCoverage{{Class: ClassProcess, HostID: "other", State: StateActive}}
	if _, err := NewHostCoverage("h", reported); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("coverage for a different host must be rejected, got %v", err)
	}
}

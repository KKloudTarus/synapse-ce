package exposure

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func ce(id string, priority int, kev bool, presence Presence) ComponentExposure {
	return ComponentExposure{
		ComponentID: shared.ID("comp-" + id),
		AdvisoryID:  shared.ID("adv-" + id),
		Severity:    shared.SeverityHigh,
		Priority:    priority,
		KEV:         kev,
		Presence:    presence,
	}
}

func TestFuseEmptyIsZero(t *testing.T) {
	s, err := Fuse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if s != 0 {
		t.Fatalf("empty exposure must fuse to 0, got %d", s)
	}
}

// TestRunningOutranksInstalled is the running-vs-installed precision: the SAME CVE ranks strictly higher
// when observed running than when merely installed.
func TestRunningOutranksInstalled(t *testing.T) {
	running, err := Fuse([]ComponentExposure{ce("a", 1, false, PresenceRunning)})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := Fuse([]ComponentExposure{ce("a", 1, false, PresenceInstalled)})
	if err != nil {
		t.Fatal(err)
	}
	if !(running > installed) {
		t.Fatalf("a running vuln (%d) must outrank the same installed vuln (%d)", running, installed)
	}
	if running != 100 || installed != 50 {
		t.Fatalf("priority-1 running=100 installed=50 expected, got running=%d installed=%d", running, installed)
	}
}

func TestFuseIsMaxAndOrderIndependent(t *testing.T) {
	set := []ComponentExposure{
		ce("low", 5, false, PresenceRunning),     // 10
		ce("mid", 3, false, PresenceInstalled),   // 55/2 = 27
		ce("crit", 1, false, PresenceInstalled),  // 100/2 = 50
		ce("running", 2, false, PresenceRunning), // 80
	}
	fwd, err := Fuse(set)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse order -> identical (max is order-independent).
	rev := make([]ComponentExposure, len(set))
	for i := range set {
		rev[len(set)-1-i] = set[i]
	}
	rev2, err := Fuse(rev)
	if err != nil {
		t.Fatal(err)
	}
	if fwd != rev2 {
		t.Fatalf("Fuse must be order-independent: %d vs %d", fwd, rev2)
	}
	// Worst is the running priority-2 (80), not the installed priority-1 (50): running-vs-installed matters.
	if fwd != 80 {
		t.Fatalf("expected worst=80 (running P2 beats installed P1), got %d", fwd)
	}
	// Many lows never eclipse one severe one.
	manyLows := []ComponentExposure{ce("l1", 5, false, PresenceRunning), ce("l2", 5, false, PresenceRunning), ce("l3", 4, false, PresenceRunning)}
	low, _ := Fuse(manyLows)
	if low >= fwd {
		t.Fatalf("many low exposures (%d) must not eclipse a severe one (%d)", low, fwd)
	}
}

func TestKEVFloor(t *testing.T) {
	// A KEV vuln with a mediocre numeric priority is still floored to a high exposure when running.
	s, err := Fuse([]ComponentExposure{ce("kev", 4, true, PresenceRunning)}) // base 30 -> KEV floor 90
	if err != nil {
		t.Fatal(err)
	}
	if s != 90 {
		t.Fatalf("KEV running must floor to 90, got %d", s)
	}
	// KEV but only installed: floored to 90 then halved to 45 (still ranks below a running KEV).
	inst, _ := Fuse([]ComponentExposure{ce("kev", 4, true, PresenceInstalled)})
	if inst != 45 {
		t.Fatalf("KEV installed = 45 expected, got %d", inst)
	}
	if !(s > inst) {
		t.Fatalf("running KEV (%d) must outrank installed KEV (%d)", s, inst)
	}
}

// TestRunningStrictlyOutranksInstalledAtEveryPriority locks the running-vs-installed invariant across the
// whole priority range (not just P1), for both KEV and non-KEV.
func TestRunningStrictlyOutranksInstalledAtEveryPriority(t *testing.T) {
	for p := 1; p <= 5; p++ {
		for _, kev := range []bool{false, true} {
			run, err := Fuse([]ComponentExposure{ce("x", p, kev, PresenceRunning)})
			if err != nil {
				t.Fatal(err)
			}
			inst, err := Fuse([]ComponentExposure{ce("x", p, kev, PresenceInstalled)})
			if err != nil {
				t.Fatal(err)
			}
			if !(run > inst) {
				t.Fatalf("running must strictly outrank installed at priority %d kev=%v: run=%d inst=%d", p, kev, run, inst)
			}
		}
	}
}

func TestFuseResultInRange(t *testing.T) {
	for p := 1; p <= 5; p++ {
		for _, kev := range []bool{false, true} {
			for _, pr := range []Presence{PresenceRunning, PresenceInstalled} {
				s, err := Fuse([]ComponentExposure{ce("x", p, kev, pr)})
				if err != nil {
					t.Fatal(err)
				}
				if !s.Valid() {
					t.Fatalf("score %d out of range for p=%d kev=%v presence=%s", s, p, kev, pr)
				}
			}
		}
	}
}

func TestFuseValidation(t *testing.T) {
	bad := []struct {
		name string
		c    ComponentExposure
	}{
		{"no component", ComponentExposure{AdvisoryID: "a", Priority: 1, Severity: shared.SeverityHigh, Presence: PresenceRunning}},
		{"no advisory", ComponentExposure{ComponentID: "c", Priority: 1, Severity: shared.SeverityHigh, Presence: PresenceRunning}},
		{"priority 0", ComponentExposure{ComponentID: "c", AdvisoryID: "a", Priority: 0, Severity: shared.SeverityHigh, Presence: PresenceRunning}},
		{"priority 6", ComponentExposure{ComponentID: "c", AdvisoryID: "a", Priority: 6, Severity: shared.SeverityHigh, Presence: PresenceRunning}},
		{"bad presence", ComponentExposure{ComponentID: "c", AdvisoryID: "a", Priority: 1, Severity: shared.SeverityHigh, Presence: "bogus"}},
	}
	for _, tc := range bad {
		if _, err := Fuse([]ComponentExposure{tc.c}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s must be rejected", tc.name)
		}
	}
}

// TestFactorFeedsRiskContext confirms a fused score is a legal RiskContext.Exposure value.
func TestFactorFeedsRiskContext(t *testing.T) {
	s, _ := Fuse([]ComponentExposure{ce("a", 1, true, PresenceRunning)})
	rc := riskassessment.RiskContext{Exposure: s}
	if err := rc.Validate(); err != nil {
		t.Fatalf("fused exposure must be a valid RiskContext factor: %v", err)
	}
}

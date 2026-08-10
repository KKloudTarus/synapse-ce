// Package emulation is the pure domain for adversary emulation (issue #421): techniques mapped to a
// public taxonomy, each declaring the detection it should produce, and the coverage record that pairs
// what executed with what was detected.
//
// It closes the purple-team loop honestly. Blue-team coverage is a measured number only if offensive
// and defensive share one ledger: of the techniques we can execute, how many did we detect. A technique
// that states no expected detection cannot contribute to that number, so the catalogue refuses one.
//
// No I/O, no clock. Emulation execution and its governance live in internal/usecase/emulation, which
// reuses the exploitation admission and sandbox path so emulation is a SUBSET of that machine's
// guarantees, never a looser path.
package emulation

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryClass is a category of signal an executed technique should generate. Coverage is expressed
// in terms of what telemetry a technique touches so a defender can see which sensors a gap implicates.
type TelemetryClass string

const (
	TelemetryProcess TelemetryClass = "process"
	TelemetryNetwork TelemetryClass = "network"
	TelemetryFile    TelemetryClass = "file"
	TelemetryAuth    TelemetryClass = "auth"
	TelemetryDNS     TelemetryClass = "dns"
)

func (c TelemetryClass) valid() bool {
	switch c {
	case TelemetryProcess, TelemetryNetwork, TelemetryFile, TelemetryAuth, TelemetryDNS:
		return true
	default:
		return false
	}
}

// ExpectedObservable is what a technique SHOULD produce: the telemetry classes it touches and the id of
// the detection that should fire. It is versioned with the technique so a coverage trend compares like
// with like — a detection expectation that changed silently would make the trend meaningless.
type ExpectedObservable struct {
	Telemetry   []TelemetryClass
	DetectionID string
	Version     string
}

func (o ExpectedObservable) validate() error {
	if strings.TrimSpace(o.DetectionID) == "" {
		return fmt.Errorf("%w: expected observable needs a detection id", shared.ErrValidation)
	}
	if strings.TrimSpace(o.Version) == "" {
		return fmt.Errorf("%w: expected observable must be versioned", shared.ErrValidation)
	}
	if len(o.Telemetry) == 0 {
		return fmt.Errorf("%w: expected observable names no telemetry class", shared.ErrValidation)
	}
	for _, c := range o.Telemetry {
		if !c.valid() {
			return fmt.Errorf("%w: unknown telemetry class %q", shared.ErrValidation, c)
		}
	}
	return nil
}

// Technique is one catalogued emulation technique.
//
// BenignVariant records that a benign proof of the observable exists — a way to generate the telemetry
// without the real effect, so coverage can be measured on production-adjacent systems. ProductionSafe
// cannot be true without it: a technique with no benign variant has no safe way to run against a
// customer estate, so it is lab-only and gated behind an explicit opt-in.
type Technique struct {
	ID             string
	TaxonomyRef    string
	BenignVariant  bool
	ProductionSafe bool
	Expected       ExpectedObservable
}

// Validate enforces the catalogue invariants. A technique that fails these cannot contribute a
// meaningful coverage number and must not be catalogued.
func (t Technique) Validate() error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("%w: technique has no id", shared.ErrValidation)
	}
	if strings.TrimSpace(t.TaxonomyRef) == "" {
		return fmt.Errorf("%w: technique %s has no taxonomy reference", shared.ErrValidation, t.ID)
	}
	if err := t.Expected.validate(); err != nil {
		return fmt.Errorf("technique %s: %w", t.ID, err)
	}
	if t.ProductionSafe && !t.BenignVariant {
		return fmt.Errorf("%w: technique %s is production-safe but has no benign variant", shared.ErrValidation, t.ID)
	}
	return nil
}

// CoverageRecord pairs what executed with what was detected, per technique. It is the offensive half of
// the purple ledger #426 consumes.
type CoverageRecord struct {
	TechniqueID string
	TaxonomyRef string
	Executed    bool
	Expected    string // detection id that should have fired
	Actual      string // detection id observed; empty until the #422 detection engine exists
	Gap         bool
}

// NewCoverageRecord builds a record and computes the gap. A gap is an EXECUTED technique whose expected
// detection did not fire — that is the honest definition of a coverage hole. A technique that did not
// execute is recorded (never omitted) but is not itself a gap: you cannot measure detection of
// something that did not run.
//
// Until the detection engine (#422) exists, actual is always empty, so every executed technique with an
// expected detection is a gap. That is the correct, honest state: coverage is unproven, not assumed.
func NewCoverageRecord(t Technique, executed bool, actualDetection string) CoverageRecord {
	actual := strings.TrimSpace(actualDetection)
	gap := executed && actual != t.Expected.DetectionID
	return CoverageRecord{
		TechniqueID: t.ID,
		TaxonomyRef: t.TaxonomyRef,
		Executed:    executed,
		Expected:    t.Expected.DetectionID,
		Actual:      actual,
		Gap:         gap,
	}
}

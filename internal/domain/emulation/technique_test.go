package emulation

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestCatalogueEveryTechniqueHasTaxonomyAndExpectedObservable is the catalogue drift test required by
// #421: every emulated technique carries a taxonomy reference and an expected observable. A technique
// missing either cannot contribute to a coverage number, so the catalogue must refuse it.
func TestCatalogueEveryTechniqueHasTaxonomyAndExpectedObservable(t *testing.T) {
	techniques, err := Catalogue()
	if err != nil {
		t.Fatalf("the shipped catalogue does not validate: %v", err)
	}
	if len(techniques) == 0 {
		t.Fatal("empty catalogue; the drift test would pass vacuously")
	}
	for _, tech := range techniques {
		if strings.TrimSpace(tech.TaxonomyRef) == "" {
			t.Errorf("%s has no taxonomy reference", tech.ID)
		}
		if tech.Expected.DetectionID == "" || tech.Expected.Version == "" || len(tech.Expected.Telemetry) == 0 {
			t.Errorf("%s has an incomplete expected observable: %+v", tech.ID, tech.Expected)
		}
		if tech.ProductionSafe && !tech.BenignVariant {
			t.Errorf("%s is production-safe with no benign variant", tech.ID)
		}
	}
}

// TestCatalogueDeterministicOrder pins the stable identity + ordering that makes a coverage trend
// comparable across runs.
func TestCatalogueDeterministicOrder(t *testing.T) {
	a, _ := Catalogue()
	b, _ := Catalogue()
	if len(a) != len(b) {
		t.Fatal("catalogue length is not stable")
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("catalogue order is not stable at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
		if i > 0 && a[i-1].ID > a[i].ID {
			t.Fatalf("catalogue is not sorted by id: %s before %s", a[i-1].ID, a[i].ID)
		}
	}
}

// TestEveryEmulationTechniqueIsInTheOffensiveRegister is the cross-check that makes "emulation goes
// through the same governance" real: every catalogued technique must have an offensive-policy register
// entry, or it would be refused at admission and could never run. This ties #421 to #418's allowlist.
func TestEveryEmulationTechniqueIsInTheOffensiveRegister(t *testing.T) {
	reg, err := offensivepolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	techniques, _ := Catalogue()
	for _, tech := range techniques {
		entry, ok := reg.Lookup(tech.ID)
		if !ok {
			t.Errorf("emulation technique %s has no offensive-policy register entry; it would be refused at admission", tech.ID)
			continue
		}
		if entry.TaxonomyRef != tech.TaxonomyRef {
			t.Errorf("%s taxonomy differs: catalogue %q, register %q", tech.ID, tech.TaxonomyRef, entry.TaxonomyRef)
		}
		// A production-safe emulation technique must be read-only in the register: a benign proof does
		// not change state. Conversely the lab-only one is state-changing and not production-safe.
		if tech.ProductionSafe && entry.BlastRadius != offensivepolicy.RadiusReadOnly {
			t.Errorf("%s is production-safe but its register entry is %s, not read_only", tech.ID, entry.BlastRadius)
		}
	}
}

func TestNewCoverageRecordGapDefinition(t *testing.T) {
	tech := Technique{ID: "emu.x", TaxonomyRef: "T0000",
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess}, DetectionID: "det.x", Version: "v1"}}

	// Executed with no matching detection → a gap. This is the honest state until the #422 detection
	// engine exists: coverage is unproven, not assumed clean.
	if r := NewCoverageRecord(tech, true, ""); !r.Gap || !r.Executed || r.Expected != "det.x" {
		t.Fatalf("an executed technique with no detection must be a gap with the expected id populated: %+v", r)
	}
	// Executed and the expected detection fired → not a gap.
	if r := NewCoverageRecord(tech, true, "det.x"); r.Gap {
		t.Fatalf("a matched detection must not be a gap: %+v", r)
	}
	// Executed and a DIFFERENT detection fired → still a gap (the expected one did not).
	if r := NewCoverageRecord(tech, true, "det.other"); !r.Gap {
		t.Fatalf("a mismatched detection must be a gap: %+v", r)
	}
	// Not executed → recorded, but not itself a gap: you cannot measure detection of what did not run.
	if r := NewCoverageRecord(tech, false, ""); r.Gap {
		t.Fatalf("a non-executed technique must not be a gap: %+v", r)
	}
}

func TestTechniqueValidateRefusesIncomplete(t *testing.T) {
	good := ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess}, DetectionID: "det.x", Version: "v1"}
	cases := map[string]Technique{
		"no id":               {TaxonomyRef: "T1", Expected: good},
		"no taxonomy":         {ID: "emu.x", Expected: good},
		"no detection id":     {ID: "emu.x", TaxonomyRef: "T1", Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess}, Version: "v1"}},
		"no version":          {ID: "emu.x", TaxonomyRef: "T1", Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess}, DetectionID: "det.x"}},
		"no telemetry":        {ID: "emu.x", TaxonomyRef: "T1", Expected: ExpectedObservable{DetectionID: "det.x", Version: "v1"}},
		"unknown telemetry":   {ID: "emu.x", TaxonomyRef: "T1", Expected: ExpectedObservable{Telemetry: []TelemetryClass{"telepathy"}, DetectionID: "det.x", Version: "v1"}},
		"prod-safe no benign": {ID: "emu.x", TaxonomyRef: "T1", ProductionSafe: true, Expected: good},
	}
	for name, tech := range cases {
		t.Run(name, func(t *testing.T) {
			if err := tech.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

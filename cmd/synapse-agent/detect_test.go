package main

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func TestParseDetectClasses(t *testing.T) {
	got, err := parseDetectClasses(" process , file ,network")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != detection.ClassProcess || got[1] != detection.ClassFile || got[2] != detection.ClassNetwork {
		t.Fatalf("wrong parse: %v", got)
	}
	// Empty → off, no error.
	if g, err := parseDetectClasses("  "); err != nil || len(g) != 0 {
		t.Fatalf("empty must be off with no error, got %v %v", g, err)
	}
	// Unknown class → error (the engine stays off rather than silently ignore a typo).
	if _, err := parseDetectClasses("process,telepathy"); err == nil {
		t.Fatal("an unknown class must be a configuration error")
	}
}

func TestParseCeiling(t *testing.T) {
	cases := map[string]float64{"": 0, "3": 3, "12.5": 12.5, "-1": 0, "abc": 0}
	for in, want := range cases {
		if got := parseCeiling(in); got != want {
			t.Errorf("parseCeiling(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFormatCoverageShowsGapsWithReason(t *testing.T) {
	cov := []detection.ClassCoverage{
		{Class: detection.ClassProcess, State: detection.StateActive},
		{Class: detection.ClassFile, State: detection.StateFailed, Reason: "load failed"},
	}
	s := formatCoverage(cov)
	if !strings.Contains(s, "process=active") {
		t.Errorf("active class missing: %q", s)
	}
	if !strings.Contains(s, "file=failed(load failed)") {
		t.Errorf("gap must show its reason: %q", s)
	}
}

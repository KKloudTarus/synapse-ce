package telemetry

import (
	"strings"
	"testing"
)

func TestDataQualityFlags(t *testing.T) {
	var q DataQuality
	if !q.IsClean() {
		t.Fatalf("zero value must be clean")
	}
	if q.String() != "clean" {
		t.Fatalf("clean String() = %q", q.String())
	}
	q = q.With(QualityTruncatedArgv).With(QualityMissingPPID)
	if !q.Has(QualityTruncatedArgv) || !q.Has(QualityMissingPPID) {
		t.Fatalf("With must set both flags")
	}
	if q.Has(QualityTruncatedPath) {
		t.Fatalf("must not report an unset flag")
	}
	if q.IsClean() {
		t.Fatalf("a set quality must not be clean")
	}
	s := q.String()
	if !strings.Contains(s, "truncated_argv") || !strings.Contains(s, "missing_ppid") {
		t.Fatalf("String() = %q, must name the set flags", s)
	}
	// Flags are independent bits.
	if QualityTruncatedArgv == QualityMissingPPID {
		t.Fatalf("flags must be distinct bits")
	}
}

func TestCoverageFlags(t *testing.T) {
	var c CoverageFlags
	if !c.IsComplete() {
		t.Fatalf("zero value must be complete")
	}
	c = c.With(CoverageSensorDegraded)
	if !c.Has(CoverageSensorDegraded) || c.IsComplete() {
		t.Fatalf("degraded coverage must not be complete")
	}
	if c.Has(CoverageBackfilled) {
		t.Fatalf("must not report an unset flag")
	}
}

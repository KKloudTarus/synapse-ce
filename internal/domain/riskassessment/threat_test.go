package riskassessment

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestThreatFromSeverity(t *testing.T) {
	cases := map[shared.Severity]Score{
		shared.SeverityCritical:  100,
		shared.SeverityHigh:      80,
		shared.SeverityMedium:    55,
		shared.SeverityLow:       30,
		shared.SeverityInfo:      10,
		shared.SeverityUnknown:   0,
		shared.Severity("bogus"): 0,
	}
	for sev, want := range cases {
		got := ThreatFromSeverity(sev)
		if got != want {
			t.Fatalf("ThreatFromSeverity(%q) = %d, want %d", sev, got, want)
		}
		if !got.Valid() {
			t.Fatalf("ThreatFromSeverity(%q) = %d out of range", sev, got)
		}
	}
	// Monotonic in rank: critical > high > medium > low > info > unknown.
	order := []shared.Severity{shared.SeverityUnknown, shared.SeverityInfo, shared.SeverityLow, shared.SeverityMedium, shared.SeverityHigh, shared.SeverityCritical}
	last := Score(-1)
	for _, sev := range order {
		s := ThreatFromSeverity(sev)
		if s < last {
			t.Fatalf("threat not monotonic in severity rank at %q: %d < %d", sev, s, last)
		}
		last = s
	}
}

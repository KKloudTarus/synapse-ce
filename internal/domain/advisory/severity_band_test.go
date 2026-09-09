package advisory

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMergePreservesMostSevereBand(t *testing.T) {
	c, err := Merge([]Observation{
		{Advisory: Advisory{ID: "CVE-2024-1", Severity: shared.SeverityMedium}},
		{Advisory: Advisory{ID: "CVE-2024-1", Severity: shared.SeverityHigh}},
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.Advisory.Severity != shared.SeverityHigh {
		t.Fatalf("canonical band = %q, want the most severe (high)", c.Advisory.Severity)
	}
}

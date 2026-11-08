package ports

import (
	"math"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDASTScanExecutionIDRoundTripAndBounds(t *testing.T) {
	e := DASTScanExecution{TenantID: shared.ID(strings.Repeat("t", 200)), RunID: shared.ID(strings.Repeat("r", 200)), JobID: strings.Repeat("j", 200), Fence: math.MaxInt64}
	id, err := e.ExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) > 1024 || !strings.HasPrefix(id, "v1.") {
		t.Fatalf("invalid execution ID length or version: %d", len(id))
	}
	got, err := ParseDASTScanExecutionID(id)
	if err != nil || got != e {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "v2." + id[3:], id + "=", strings.Repeat("x", 1025)} {
		if _, err := ParseDASTScanExecutionID(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	e.JobID += "x"
	if _, err := e.ExecutionID(); err == nil {
		t.Fatal("accepted overlong job id")
	}
}

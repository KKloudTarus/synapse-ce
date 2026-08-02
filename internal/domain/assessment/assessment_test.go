package assessment

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssessmentRequiresBusinessServiceAndBoundedPolicy(t *testing.T) {
	now := time.Now().UTC()
	a, err := New("assessment-1", "tenant-a", "service-1", "Payments release", "Validate the release", Policy{Cadence: "P30D", Release: "2026.08", Environment: "production"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusDraft {
		t.Fatalf("status=%s", a.Status)
	}
	_, err = New("assessment-2", "tenant-a", "", "missing parent", "", Policy{}, now)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing service error=%v", err)
	}
}

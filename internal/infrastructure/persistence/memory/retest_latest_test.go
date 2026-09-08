package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestLatestRetestsAreBoundedDeterministicAndTenantScoped(t *testing.T) {
	repo := NewRetestRepository()
	now := time.Now().UTC()
	ctx := shared.WithTenant(context.Background(), "tenant")
	for _, tenant := range []shared.ID{"tenant", "other"} {
		for _, id := range []shared.ID{"a", "z"} {
			if err := repo.Add(shared.WithTenant(ctx, tenant), finding.Retest{ID: tenant + id, EngagementID: "assessment", FindingID: "finding", Outcome: finding.RetestRemediated, At: now}); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := repo.LatestByEngagementFindings(ctx, "assessment", []shared.ID{"finding", "missing"})
	if err != nil || len(got) != 1 || got["finding"].ID != "tenantz" {
		t.Fatalf("latest=%+v err=%v", got, err)
	}
	if _, err := repo.LatestByEngagementFindings(context.Background(), "assessment", []shared.ID{"finding"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unscoped read accepted: %v", err)
	}
	if _, err := repo.LatestByEngagementFindings(ctx, "assessment", make([]shared.ID, 1001)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbounded read accepted: %v", err)
	}
	got, err = repo.LatestByEngagementFindings(ctx, "different", []shared.ID{"finding"})
	if err != nil || len(got) != 0 {
		t.Fatalf("cross assessment=%+v err=%v", got, err)
	}
	rows, err := repo.ListByEngagementFinding(ctx, "assessment", "finding")
	if err != nil || len(rows) != 2 {
		t.Fatalf("legacy list leaked tenant: %+v err=%v", rows, err)
	}
}

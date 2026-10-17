package memory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepositoryListFindingPageUsesIDKeyset(t *testing.T) {
	repository := NewFindingRepository()
	items := []finding.Finding{
		{ID: "finding-c", EngagementID: "engagement", DedupKey: "c", Status: finding.StatusOpen},
		{ID: "finding-a", EngagementID: "engagement", DedupKey: "a", Status: finding.StatusOpen},
		{ID: "finding-b", EngagementID: "engagement", DedupKey: "b", Status: finding.StatusOpen},
	}
	if err := repository.Upsert(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	first, err := repository.ListFindingPage(context.Background(), "engagement", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.Items[0].ID != "finding-a" || first.Items[1].ID != "finding-b" || first.NextAfter != "finding-b" {
		t.Fatalf("first page = %+v", first)
	}
	second, err := repository.ListFindingPage(context.Background(), "engagement", first.NextAfter, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].ID != "finding-c" || !second.NextAfter.IsZero() {
		t.Fatalf("second page = %+v", second)
	}
	if _, err := repository.ListFindingPage(context.Background(), shared.ID("engagement"), "", 0); err == nil {
		t.Fatal("zero page size succeeded")
	}
}

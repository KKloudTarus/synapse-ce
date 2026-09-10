package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFindingLineageBackfillSourcesUseChronologyThenID(t *testing.T) {
	repository := NewFindingLineageBackfillRepository()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	repository.SetSources("tenant", []ports.FindingLineageBackfillSourceRow{
		{TenantID: "tenant", FindingID: "a-newer", CreatedAt: now.Add(time.Minute), ObservedAt: now.Add(time.Minute)},
		{TenantID: "tenant", FindingID: "z-older", CreatedAt: now, ObservedAt: now},
		{TenantID: "tenant", FindingID: "a-oldest", CreatedAt: now, ObservedAt: now},
	})
	first, err := repository.ListFindingLineageBackfillSources(context.Background(), "tenant", "", now.Add(time.Hour), nil, 2)
	if err != nil || len(first) != 2 || first[0].FindingID != "a-oldest" || first[1].FindingID != "z-older" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := repository.ListFindingLineageBackfillSources(context.Background(), "tenant", "z-older", now.Add(time.Hour), nil, 2)
	if err != nil || len(second) != 1 || second[0].FindingID != "a-newer" {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
}

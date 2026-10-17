package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepositoryListFindingPageUsesIDKeyset(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := shared.WithTenant(context.Background(), "default")
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	engagementID := shared.ID("finding-page-" + randHex(t))
	item, err := engagement.New(engagementID, "", "finding page", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", engagementID.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", engagementID.String())
	})

	repository := NewFindingRepository(pool)
	seed := []finding.Finding{
		{ID: "finding-a-" + shared.ID(randHex(t)), EngagementID: engagementID, DedupKey: "page-a-" + randHex(t), Status: finding.StatusOpen},
		{ID: "finding-b-" + shared.ID(randHex(t)), EngagementID: engagementID, DedupKey: "page-b-" + randHex(t), Status: finding.StatusOpen},
		{ID: "finding-c-" + shared.ID(randHex(t)), EngagementID: engagementID, DedupKey: "page-c-" + randHex(t), Status: finding.StatusOpen},
	}
	if err := repository.Upsert(ctx, seed); err != nil {
		t.Fatal(err)
	}
	first, err := repository.ListFindingPage(ctx, engagementID, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextAfter != first.Items[1].ID || !(first.Items[0].ID < first.Items[1].ID) {
		t.Fatalf("first page = %+v", first)
	}
	second, err := repository.ListFindingPage(ctx, engagementID, first.NextAfter, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].ID <= first.NextAfter || !second.NextAfter.IsZero() {
		t.Fatalf("second page = %+v", second)
	}
}

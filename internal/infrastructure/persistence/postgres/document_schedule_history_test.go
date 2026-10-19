package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDocumentScheduleHistoryPostgresIsTenantScoped(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	schedule := docpublish.Schedule{
		ID:       shared.ID(fmt.Sprintf("history-pg-%d", time.Now().UnixNano())),
		TenantID: "doc-a",
		Source: docpublish.Source{
			SourceKind: docpublish.EngagementReport,
			SourceRef:  "engagement:doc-engagement-a",
			Scope:      docpublish.Engagement,
			ScopeID:    "doc-engagement-a",
		},
		Destination:   docpublish.ScheduleConfluence,
		IntegrationID: "doc-integration-a",
		OwnerUserID:   "admin",
		Timezone:      "UTC",
		Frequency:     docpublish.ScheduleWeekly,
		Weekday:       int(now.Weekday()),
		Hour:          11,
		Enabled:       true,
		Version:       1,
		NextDueAt:     now.Add(-time.Minute),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if _, err := store.SaveDocumentSchedule(ctx, "doc-a", schedule, 0); err != nil {
		t.Fatal(err)
	}
	if work, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 1, now); err != nil || len(work) != 1 {
		t.Fatalf("claim=%d err=%v", len(work), err)
	}
	runs, err := store.ListDocumentScheduleRuns(ctx, "doc-a", schedule.ID, 20)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	if got := runs[0]; got.State != docpublish.OccurrenceInFlight || got.DeliveredCount != 0 || got.UncertainCount != 0 || got.FailedCount != 0 {
		t.Fatalf("run=%+v", got)
	}
	other, err := store.ListDocumentScheduleRuns(ctx, "doc-b", schedule.ID, 20)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross tenant runs=%+v err=%v", other, err)
	}
}

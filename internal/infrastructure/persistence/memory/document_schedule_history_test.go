package memory

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDocumentScheduleHistoryAggregatesDeliveryStatesWithoutRecipients(t *testing.T) {
	engagements, projects := NewEngagementRepository(), NewProjectRepository()
	store, err := NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	fixture := docFixture()
	seedDocumentParents(t, engagements, projects, fixture)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	schedule := docpublish.Schedule{ID: "history-schedule", TenantID: fixture.Tenant, Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:eng", Scope: docpublish.Engagement, ScopeID: fixture.Engagement}, Destination: docpublish.ScheduleConfluence, IntegrationID: "integration", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	if _, err := store.SaveDocumentSchedule(context.Background(), fixture.Tenant, schedule, 0); err != nil {
		t.Fatal(err)
	}
	work, err := store.ClaimDueDocumentScheduleOccurrences(context.Background(), fixture.Tenant, 1, now)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim=%d err=%v", len(work), err)
	}
	occurrence := work[0].Occurrence
	occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = docpublish.OccurrenceDone, nil
	occurrence.Occurrence.ArtifactDigest = strings.Repeat("a", 64)
	occurrence.Occurrence.RemotePageID, occurrence.Occurrence.RemoteVersion = "page-1", 3
	if _, err := store.SaveDocumentScheduleOccurrence(context.Background(), fixture.Tenant, occurrence, occurrence.Occurrence.Version, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for index, state := range []ports.DocumentScheduleDeliveryState{ports.DocumentScheduleDeliveryDone, ports.DocumentScheduleDeliveryUncertain, ports.DocumentScheduleDeliveryFailed, ports.DocumentScheduleDeliveryRejected} {
		delivery := ports.DocumentScheduleDelivery{ID: portsID(index), TenantID: fixture.Tenant, OccurrenceID: occurrence.Occurrence.ID, Recipient: "hidden@example.test", RecipientHash: strings.Repeat(string(rune('b'+index)), 64), MessageID: portsID(index + 10), State: state, Version: 1, CreatedAt: now, UpdatedAt: now}
		if _, err := store.SaveDocumentScheduleDelivery(context.Background(), fixture.Tenant, delivery, 0, now); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := store.ListDocumentScheduleRuns(context.Background(), fixture.Tenant, schedule.ID, 20)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	got := runs[0]
	if got.State != docpublish.OccurrenceDone || got.ContentHash != strings.Repeat("a", 64) || got.RemotePageID != "page-1" || got.RemoteVersion != 3 || got.DeliveredCount != 1 || got.UncertainCount != 1 || got.FailedCount != 2 {
		t.Fatalf("history=%+v", got)
	}
	other, err := store.ListDocumentScheduleRuns(context.Background(), "other", schedule.ID, 20)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant history=%+v err=%v", other, err)
	}
}

func portsID(value int) shared.ID { return shared.ID(fmt.Sprintf("delivery-%d", value)) }

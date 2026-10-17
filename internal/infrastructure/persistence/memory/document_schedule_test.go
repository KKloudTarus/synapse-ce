package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDocumentScheduleMemoryAdmissionFairnessAndCAS(t *testing.T) {
	engagements := NewEngagementRepository()
	projects := NewProjectRepository()
	store, err := NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fixture := docFixture()
	seedDocumentParents(t, engagements, projects, fixture)
	s := docpublish.Schedule{ID: "schedule", TenantID: fixture.Tenant, Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:eng", Scope: docpublish.Engagement, ScopeID: fixture.Engagement}, Destination: docpublish.ScheduleConfluence, IntegrationID: "integration", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	if _, err := store.SaveDocumentSchedule(ctx, fixture.Tenant, s, 0); err != nil {
		t.Fatal(err)
	}
	work, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 20, now)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim=%+v err=%v", work, err)
	}
	if work[0].Occurrence.Occurrence.DueAt != s.NextDueAt {
		t.Fatal("wrong occurrence due")
	}
	if again, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 20, now); err != nil || len(again) != 0 {
		t.Fatalf("repeat claim=%d err=%v", len(again), err)
	}
	if _, err := store.SaveDocumentScheduleOccurrence(ctx, fixture.Tenant, work[0].Occurrence, work[0].Occurrence.Occurrence.Version+1, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale occurrence err=%v", err)
	}
}

func TestDocumentScheduleMemoryClaimsFreshWorkAfterFailedRecoveryBacklog(t *testing.T) {
	engagements := NewEngagementRepository()
	projects := NewProjectRepository()
	store, err := NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fixture := docFixture()
	seedDocumentParents(t, engagements, projects, fixture)
	newSchedule := func(id shared.ID) docpublish.Schedule {
		return docpublish.Schedule{ID: id, TenantID: fixture.Tenant, Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:eng", Scope: docpublish.Engagement, ScopeID: fixture.Engagement}, Destination: docpublish.ScheduleConfluence, IntegrationID: "integration", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	}
	for i := range 20 {
		if _, err := store.SaveDocumentSchedule(ctx, fixture.Tenant, newSchedule(shared.ID("failed-"+string(rune('a'+i)))), 0); err != nil {
			t.Fatal(err)
		}
	}
	healthy := newSchedule("healthy")
	if _, err := store.SaveDocumentSchedule(ctx, fixture.Tenant, healthy, 0); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 20, now)
	if err != nil || len(first) != 20 {
		t.Fatalf("initial claim=%d err=%v", len(first), err)
	}
	for _, work := range first {
		work.Occurrence.Occurrence.State = docpublish.OccurrenceFailed
		work.Occurrence.Occurrence.LeaseUntil = nil
		if _, err := store.SaveDocumentScheduleOccurrence(ctx, fixture.Tenant, work.Occurrence, work.Occurrence.Occurrence.Version, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 1, now.Add(2*time.Second))
	if err != nil || len(second) != 1 || second[0].Schedule.ID != healthy.ID {
		t.Fatalf("fresh work starved by failed backlog: work=%+v err=%v", second, err)
	}
	third, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 1, now.Add(3*time.Second))
	if err != nil || len(third) != 1 || third[0].Schedule.ID == healthy.ID {
		t.Fatalf("recovery did not resume after fresh work: work=%+v err=%v", third, err)
	}
}

func TestDocumentScheduleMemoryConcurrentClaimsDoNotDuplicate(t *testing.T) {
	engagements := NewEngagementRepository()
	projects := NewProjectRepository()
	store, err := NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fixture := docFixture()
	seedDocumentParents(t, engagements, projects, fixture)
	schedule := docpublish.Schedule{ID: "concurrent", TenantID: fixture.Tenant, Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:eng", Scope: docpublish.Engagement, ScopeID: fixture.Engagement}, Destination: docpublish.ScheduleConfluence, IntegrationID: "integration", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	if _, err := store.SaveDocumentSchedule(ctx, fixture.Tenant, schedule, 0); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	claimed := make(chan int, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			work, err := store.ClaimDueDocumentScheduleOccurrences(ctx, fixture.Tenant, 1, now)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			claimed <- len(work)
		}()
	}
	close(start)
	wait.Wait()
	close(claimed)
	total := 0
	for count := range claimed {
		total += count
	}
	if total != 1 {
		t.Fatalf("concurrent claims=%d", total)
	}
}

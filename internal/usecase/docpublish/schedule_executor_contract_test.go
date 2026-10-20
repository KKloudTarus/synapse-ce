package docpublish

import (
	"context"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scheduleExecutorArtifacts struct {
	artifact ports.DocumentArtifact
	calls    int
}

func (a *scheduleExecutorArtifacts) BuildSourceArtifact(ctx context.Context, tenant shared.ID, _ domain.Source) (ports.DocumentArtifact, error) {
	if got, ok := shared.TenantFrom(ctx); !ok || got != tenant {
		return ports.DocumentArtifact{}, shared.ErrForbidden
	}
	a.calls++
	return a.artifact, nil
}

func TestScheduleDocumentOccurrenceConvergesAfterYieldingExecutor(t *testing.T) {
	ctx := context.Background()
	f := newReleaseFixture(t)
	artifacts := &scheduleExecutorArtifacts{artifact: f.source.artifact}
	executor, err := NewExecutor(f.store, f.integration, releaseProviders{f.provider}, f.authority, f.policy, f.audit, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	schedules, err := NewScheduleService(ScheduleDependencies{
		Store:        f.store,
		Authority:    f.authority,
		ReportPolicy: scheduleReportPolicy{},
		Artifacts:    artifacts,
		Channels:     scheduleChannels{},
		Integrations: f.integration,
		EmailConfig:  scheduleEmailConfig{},
		EmailSender:  scheduleSender{},
		Publisher:    f.service,
		Executor:     executor,
		Audit:        f.audit,
		IDs:          &releaseIDs{},
		Clock:        f.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := f.actor
	schedule, err := schedules.SaveSchedule(ctx, "tenant", actor, ScheduleInput{
		ID:            "yielding-schedule",
		Source:        domain.Source{SourceKind: domain.EngagementReport, SourceRef: EngagementSourceRef("assessment"), Scope: domain.Engagement, ScopeID: "assessment"},
		Destination:   domain.ScheduleConfluence,
		IntegrationID: "connection",
		Timezone:      "UTC",
		Frequency:     domain.ScheduleWeekly,
		Weekday:       int(f.clock.Now().Weekday()),
		Hour:          f.clock.Now().Hour(),
		Minute:        f.clock.Now().Minute(),
		Enabled:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A real schedule is normally admitted for its next future wall time; make
	// this stored occurrence due without bypassing SaveSchedule admission.
	schedule.NextDueAt = f.clock.Now().Add(-time.Minute)
	schedule.UpdatedAt = f.clock.Now()
	schedule, err = f.store.SaveDocumentSchedule(ctx, "tenant", schedule, schedule.Version)
	if err != nil {
		t.Fatal(err)
	}
	if err = schedules.Tick(ctx, "tenant", 1); err != nil {
		t.Fatal(err)
	}
	runs, err := f.store.ListDocumentScheduleRuns(ctx, "tenant", schedule.ID, 20)
	if err != nil || len(runs) != 1 || runs[0].State != domain.OccurrenceInFlight || artifacts.calls != 1 {
		t.Fatalf("first scheduled slice runs=%+v artifacts=%d err=%v", runs, artifacts.calls, err)
	}
	occurrence, err := f.store.GetDocumentScheduleOccurrence(ctx, "tenant", runs[0].ID)
	if err != nil || occurrence.Occurrence.DocumentIntentID.IsZero() || occurrence.Occurrence.LeaseUntil == nil || f.provider.shells != 1 || f.provider.uploads != 0 || f.provider.writes != 0 {
		t.Fatalf("first occurrence=%+v provider=%+v err=%v", occurrence, f.provider, err)
	}
	intentID := occurrence.Occurrence.DocumentIntentID

	for tick := 0; tick < 16; tick++ {
		if err = executor.Tick(ctx, "tenant", 20); err != nil {
			t.Fatalf("executor tick %d: %v", tick, err)
		}
		intent, getErr := f.service.Intent(ctx, "tenant", intentID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if intent.State == writeintent.Done {
			break
		}
		if tick == 15 {
			t.Fatalf("yielding executor did not complete: %+v", intent)
		}
	}
	intent, err := f.service.Intent(ctx, "tenant", intentID)
	if err != nil || intent.State != writeintent.Done || f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
		t.Fatalf("executor result=%+v provider=%+v err=%v", intent, f.provider, err)
	}

	// The occurrence lease expires independently of the document command. The
	// next schedule pass must replay the frozen occurrence key, observe the
	// already-completed intent, and record the same occurrence as done.
	f.clock.at = f.clock.at.Add(6 * time.Minute)
	if err = schedules.Tick(ctx, "tenant", 1); err != nil {
		t.Fatal(err)
	}
	runs, err = f.store.ListDocumentScheduleRuns(ctx, "tenant", schedule.ID, 20)
	if err != nil || len(runs) != 1 || runs[0].ID != occurrence.Occurrence.ID || runs[0].State != domain.OccurrenceDone || runs[0].RemotePageID != intent.RemoteID {
		t.Fatalf("converged runs=%+v err=%v", runs, err)
	}
	converged, err := f.store.GetDocumentScheduleOccurrence(ctx, "tenant", occurrence.Occurrence.ID)
	if err != nil || converged.Occurrence.DocumentIntentID != intentID || artifacts.calls != 1 || f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
		t.Fatalf("converged occurrence=%+v artifacts=%d provider=%+v err=%v", converged, artifacts.calls, f.provider, err)
	}
	if err = schedules.Tick(ctx, "tenant", 1); err != nil {
		t.Fatal(err)
	}
	if err = executor.Tick(ctx, "tenant", 20); err != nil {
		t.Fatal(err)
	}
	if artifacts.calls != 1 || f.provider.shells != 1 || f.provider.uploads != 1 || f.provider.writes != 1 {
		t.Fatalf("later ticks repeated frozen occurrence artifacts=%d provider=%+v", artifacts.calls, f.provider)
	}
}

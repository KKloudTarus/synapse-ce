package docpublish

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scheduleHistoryScheduleFake struct {
	tenant shared.ID
	id     shared.ID
	err    error
}

func (f *scheduleHistoryScheduleFake) GetDocumentSchedule(_ context.Context, tenant, id shared.ID) (docpublish.Schedule, error) {
	f.tenant, f.id = tenant, id
	if f.err != nil {
		return docpublish.Schedule{}, f.err
	}
	return docpublish.Schedule{ID: id, TenantID: tenant}, nil
}

type scheduleHistoryReaderFake struct {
	tenant shared.ID
	id     shared.ID
	limit  int
	err    error
}

func (f *scheduleHistoryReaderFake) ListDocumentScheduleRuns(_ context.Context, tenant, id shared.ID, limit int) ([]ports.DocumentScheduleRunView, error) {
	f.tenant, f.id, f.limit = tenant, id, limit
	if f.err != nil {
		return nil, f.err
	}
	return []ports.DocumentScheduleRunView{{ID: "run-1", DueAt: time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC), State: docpublish.OccurrenceUncertain, UncertainCount: 1}}, nil
}

func TestScheduleHistoryServiceChecksScheduleTenantBeforeBoundedHistory(t *testing.T) {
	schedules := &scheduleHistoryScheduleFake{}
	history := &scheduleHistoryReaderFake{}
	service, err := NewScheduleHistoryService(schedules, history)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := service.RunHistory(context.Background(), "tenant-a", "schedule-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || schedules.tenant != "tenant-a" || schedules.id != "schedule-1" || history.tenant != "tenant-a" || history.id != "schedule-1" || history.limit != scheduleHistoryLimit {
		t.Fatalf("runs=%+v schedule=%+v history=%+v", runs, schedules, history)
	}
}

func TestScheduleHistoryServiceDoesNotReadHistoryWhenScheduleIsNotInTenant(t *testing.T) {
	schedules := &scheduleHistoryScheduleFake{err: shared.ErrNotFound}
	history := &scheduleHistoryReaderFake{}
	service, err := NewScheduleHistoryService(schedules, history)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RunHistory(context.Background(), "tenant-b", "schedule-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("error=%v", err)
	}
	if history.limit != 0 {
		t.Fatalf("history was queried after owner check: %+v", history)
	}
}

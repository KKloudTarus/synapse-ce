package ticketing

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type statusProgressClock struct{ now time.Time }

func (c statusProgressClock) Now() time.Time { return c.now }

type statusProgressMemory struct{ item ports.TicketStatusProgress }

func (s *statusProgressMemory) GetTicketStatusProgress(context.Context, shared.ID, shared.ID, shared.ID, shared.ID) (ports.TicketStatusProgress, error) {
	return s.item, nil
}
func (s *statusProgressMemory) CreateTicketStatusProgress(_ context.Context, _ shared.ID, item ports.TicketStatusProgress) (ports.TicketStatusProgress, bool, error) {
	item.Version = 1
	item.Episode = 1
	s.item = item
	return item, true, nil
}
func (s *statusProgressMemory) UpdateTicketStatusProgress(_ context.Context, _ shared.ID, item ports.TicketStatusProgress, expected int) (ports.TicketStatusProgress, error) {
	if expected != s.item.Version {
		return ports.TicketStatusProgress{}, shared.ErrConflict
	}
	item.Version++
	s.item = item
	return item, nil
}

func TestTicketStatusProgressMembershipSourceChangeDoesNotReopenAppliedState(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := &statusProgressMemory{item: ports.TicketStatusProgress{TenantID: "tenant", MappingID: "mapping", EngagementID: "engagement", FindingID: "finding", DesiredState: domain.SyncReopen, AppliedState: domain.SyncReopen, SourceRevision: "group:before", TransitionIntentID: "transition", UpdateIntentID: "update", Episode: 3, Version: 7, CheckedAt: now}}
	workflow := &Workflow{Service: &Service{clock: statusProgressClock{now: now.Add(time.Minute)}}}
	target := ports.TicketStatusTarget{Mapping: domain.Mapping{ID: "mapping"}, Intent: domain.Intent{EngagementID: "engagement", FindingID: "finding"}}
	got, err := workflow.ticketStatusProgress(context.Background(), "tenant", store, target, domain.SyncReopen, "group:member-added")
	if err != nil {
		t.Fatal(err)
	}
	if got.Episode != 3 || got.TransitionIntentID != "transition" || got.UpdateIntentID != "update" || got.AppliedState != domain.SyncReopen || got.SourceRevision != "group:member-added" {
		t.Fatalf("membership source started a duplicate transition: %+v", got)
	}
}

package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTicketPolicyReaderAllowsOnlyOwnedEngagements(t *testing.T) {
	ctx := context.Background()
	engagements := NewEngagementRepository()
	owned, err := engagement.New("owned", "tenant-a", "Owned", "", time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := engagement.New("foreign", "tenant-b", "Foreign", "", time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []*engagement.Engagement{owned, foreign} {
		if err := engagements.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := NewTicketPolicyReader(engagements)
	if err != nil {
		t.Fatal(err)
	}

	got, err := reader.GetEngagementNotificationSetting(ctx, "tenant-a", owned.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "tenant-a" || got.EngagementID != owned.ID || got.ExternalNotifications != notification.EngagementNotificationsInherit || got.Revision != 0 {
		t.Fatalf("owned setting = %+v, want inherit default for owned engagement", got)
	}

	for _, id := range []shared.ID{"missing", foreign.ID} {
		if _, err := reader.GetEngagementNotificationSetting(ctx, "tenant-a", id); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("GetEngagementNotificationSetting(tenant-a, %q) error = %v, want not found", id, err)
		}
	}
}

func TestTicketPolicyReaderHonorsCancellation(t *testing.T) {
	reader, err := NewTicketPolicyReader(NewEngagementRepository())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.GetEngagementNotificationSetting(ctx, "tenant", "engagement"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetEngagementNotificationSetting() error = %v, want context canceled", err)
	}
}

func TestNewTicketPolicyReaderRequiresEngagementOwnershipReader(t *testing.T) {
	if _, err := NewTicketPolicyReader(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("NewTicketPolicyReader(nil) error = %v, want validation", err)
	}
}

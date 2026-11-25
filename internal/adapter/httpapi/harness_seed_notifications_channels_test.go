package httpapi

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// notificationChannelMarker appears in the body of a notification channel route only when tenantA's
// own channel was served: it names the channel, and the delivery and attempt its pause records. It
// is distinct from every identifier the other seeds plant, and a tenantB response must never
// contain it.
const notificationChannelMarker = "tenantA-notification-channel-marker"

// notificationChannelID is the id the notification service hands the channel. Its generator is
// sequential and the engagement setting takes no id from it, so the channel gets the first one;
// seedNotificationChannel fails if it does not, rather than leaving the routes addressed at nothing.
const notificationChannelID = shared.ID("notifications-id-1")

// notificationChannelRoutes are the channel routes the notifications seed makes serve tenantA's
// channel. The template-resolution route under the same path needs the template store, which this
// fixture does not wire, so it stays with the other template routes in harnessKnownUnaddressable.
var notificationChannelRoutes = []string{
	"GET /api/v1/notifications/channels/{nid}",
	"GET /api/v1/notifications/channels/{nid}/health-events",
}

// seedNotificationChannel creates one tenantA webhook channel through the notification service the
// notifications seed wires, then records one permanent delivery failure against it at a threshold
// of one, which pauses the channel and writes the health event its history route serves. The
// delivery worker records every attempt's outcome through this same repository call.
//
// No channel route has a guard of its own: the service reads the tenant from the request context,
// and the repository keys every channel and health event by it. That key is what stands between
// tenantB and this channel.
func seedNotificationChannel(w *harnessWorld, service *notificationuc.Service, repo *memory.NotificationRepository) {
	t := w.t
	t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenantA")
	channel, err := service.CreateChannel(ctx, notificationChannelMarker, notificationuc.ChannelInput{
		Name: "channel " + notificationChannelMarker, Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://hooks-a.example/notify", Secret: "harness-webhook-signing-secret",
	})
	if err != nil {
		t.Fatalf("seed notification channel: %v", err)
	}
	if channel.ID != notificationChannelID {
		t.Fatalf("planted notification channel %s, but the routes are addressed with %s", channel.ID, notificationChannelID)
	}
	transition, err := repo.RecordChannelOutcome(ctx, "tenantA", ports.NotificationChannelOutcome{
		ChannelID: channel.ID, DeliveryID: shared.ID("delivery-" + notificationChannelMarker), AttemptID: shared.ID("attempt-" + notificationChannelMarker),
		Class: notification.AttemptPermanent, Code: "http_410", At: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC), Threshold: 1,
	})
	if err != nil {
		t.Fatalf("seed notification channel pause: %v", err)
	}
	if !transition.Paused {
		t.Fatal("one permanent failure at a threshold of one did not pause the channel; its health history stays empty")
	}
}

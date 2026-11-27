package httpapi

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// notificationRecordsMarker appears in the body of a notification rule, delivery or template route
// only when tenantA's own record was served: it names the rule and the template, it is in the id of
// the event a delivery carries and of the delivery's attempt, and it is in every template version. A
// tenantB response must never contain it.
const notificationRecordsMarker = "tenantA-notification-records-marker"

// harnessNotificationsKey is where the notifications seed leaves its service, repository and job
// queue for this seed (harnessWorld.state).
const harnessNotificationsKey = "notifications"

// harnessNotifications is what the notifications seed wired: the service the router serves, the
// repository behind it and the job queue the repository enqueues delivery work on.
type harnessNotifications struct {
	service *notificationuc.Service
	repo    *memory.NotificationRepository
	jobs    *memory.JobQueue
}

// The ids the records are addressed with. The service's generator is sequential and the
// notifications seed's channel took notifications-id-1, so the delivery channel, the rule and the
// template follow in the order this seed creates them. A delivery's id is derived from its tenant,
// event, channel and recipient. The seed fails when a record gets another id, rather than leaving the
// routes addressed at nothing.
const (
	notificationDeliveryChannelID = shared.ID("notifications-id-2")
	notificationRuleID            = shared.ID("notifications-id-3")
	notificationTemplateID        = shared.ID("notifications-id-4")
	notificationDeliveryID        = shared.ID("aa1f5b7f01d204d6c05444f72fd7f87d")
)

// notificationTemplateRevision is the template's revision when the seed is done: created, version 1
// activated, version 2 added. The write sweep names it, and the revisions after it, in its requests.
const notificationTemplateRevision = 3

// notificationRecordsEvent is the event type of the rule, the delivery and the template, so that the
// template resolution for the delivery channel finds the seed's template.
const notificationRecordsEvent = notification.EventScanCompleted

// notificationRecordRoutes maps each route this seed makes serve tenantA's data to the id of the
// record it is addressed with.
var notificationRecordRoutes = map[string]shared.ID{
	"GET /api/v1/notifications/rules/{nid}":                        notificationRuleID,
	"GET /api/v1/notifications/deliveries/{nid}":                   notificationDeliveryID,
	"GET /api/v1/notifications/deliveries/{nid}/attempts":          notificationDeliveryID,
	"GET /api/v1/notifications/templates/{nid}":                    notificationTemplateID,
	"GET /api/v1/notifications/templates/{nid}/versions":           notificationTemplateID,
	"GET /api/v1/notifications/channels/{nid}/template-resolution": notificationDeliveryChannelID,
}

func init() {
	routes := make([]string, 0, len(notificationRecordRoutes))
	values := map[string]map[string]string{}
	for route, id := range notificationRecordRoutes {
		routes = append(routes, route)
		values[route] = map[string]string{"{nid}": id.String()}
	}
	sort.Strings(routes)
	registerHarnessSeed(harnessSeed{
		Name:   "notifications-records",
		Routes: routes,
		// The notification service reads the tenant from the request context, and its repository
		// and template store key every row by it.
		TenantBound: routes,
		Queries: map[string]string{
			"GET /api/v1/notifications/channels/{nid}/template-resolution": "?event_type=" + string(notificationRecordsEvent),
		},
		RoutePathValues: values,
		Run:             seedNotificationRecords,
	})
}

// seedNotificationRecords plants, for tenantA and through the service the notifications seed wired:
//   - a webhook channel that is not paused, because a paused channel takes no new delivery;
//   - a rule that sends the seed's event type to that channel;
//   - a template for that event type and the webhook family, with version 1 active and version 2
//     added, so that an update, an activation, a rollback and an archive each have something to do;
//   - one delivery on that channel, whose single attempt failed permanently and whose worker job was
//     dead-lettered, which is the state a redrive starts from.
//
// None of these routes has a guard of its own: the service reads the tenant from the request
// context, and the repository and the template store key every record by it.
func seedNotificationRecords(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	n, ok := w.state[harnessNotificationsKey].(harnessNotifications)
	if !ok {
		t.Fatal("the notification records seed needs the service the notifications seed wires")
	}
	// The template routes are registered only for a service with a template store, and the route
	// table is built after every seed has run.
	n.service.SetTemplateStore(memory.NewNotificationTemplateStore())
	ctx := shared.WithTenant(context.Background(), "tenantA")
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

	channel, err := n.service.CreateChannel(ctx, notificationRecordsMarker, notificationuc.ChannelInput{
		Name: "deliveries " + notificationRecordsMarker, Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://hooks-a.example/deliveries", Secret: "harness-webhook-signing-secret",
	})
	if err != nil {
		t.Fatalf("seed notification delivery channel: %v", err)
	}
	if channel.ID != notificationDeliveryChannelID {
		t.Fatalf("planted the delivery channel as %s, but the routes are addressed with %s", channel.ID, notificationDeliveryChannelID)
	}

	rule, err := n.service.CreateRule(ctx, notificationRecordsMarker, notificationuc.RuleInput{
		Name: "rule " + notificationRecordsMarker, Enabled: true, EventType: notificationRecordsEvent,
		Cadence: notification.CadenceImmediate, ChannelIDs: []shared.ID{channel.ID},
	})
	if err != nil {
		t.Fatalf("seed notification rule: %v", err)
	}
	if rule.ID != notificationRuleID {
		t.Fatalf("planted the rule as %s, but the routes are addressed with %s", rule.ID, notificationRuleID)
	}

	seedNotificationTemplate(w, n.service, ctx)

	delivery, err := n.repo.PublishToChannel(ctx, notification.Event{
		TenantID: "tenantA", ID: shared.ID("event-" + notificationRecordsMarker), Type: notificationRecordsEvent,
		SourceKind: "harness", SourceID: notificationRecordsMarker, SchemaVersion: 1, OccurredAt: at,
		Data: json.RawMessage(`{"seed":"` + notificationRecordsMarker + `"}`),
	}, channel.ID)
	if err != nil {
		t.Fatalf("seed notification delivery: %v", err)
	}
	if delivery != notificationDeliveryID {
		t.Fatalf("planted the delivery as %s, but the routes are addressed with %s", delivery, notificationDeliveryID)
	}
	// The delivery worker's path: claim the job, start an attempt, record its permanent failure and
	// dead-letter the job.
	job, err := n.jobs.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || job == nil {
		t.Fatalf("claim the delivery job: %v, job %v", err, job)
	}
	attempt, err := n.repo.BeginAttempt(ctx, "tenantA", delivery, job.ID, job.Fence, shared.ID("attempt-"+notificationRecordsMarker), at, ports.AttemptAdmission{DataClass: notification.DataClassSignal})
	if err != nil {
		t.Fatalf("seed notification attempt: %v", err)
	}
	if err := n.repo.FinishAttempt(ctx, "tenantA", delivery, job.ID, job.Fence, attempt.ID, at, "failed", 410, "http_410", nil); err != nil {
		t.Fatalf("finish notification attempt: %v", err)
	}
	if err := n.jobs.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatalf("dead-letter the delivery job: %v", err)
	}
	return []string{notificationRecordsMarker}
}

// seedNotificationTemplate creates the seed's template, activates its first version and adds a second.
func seedNotificationTemplate(w *harnessWorld, service *notificationuc.Service, ctx context.Context) {
	t := w.t
	t.Helper()
	created, err := service.CreateTemplate(ctx, notificationRecordsMarker, notificationuc.TemplateInput{
		Name: "template " + notificationRecordsMarker, EventType: notificationRecordsEvent,
		Family: notification.FamilyWebhook, Locale: "en",
		Fields: map[string]string{"body": `{"seed":"` + notificationRecordsMarker + `","version":1}`},
	})
	if err != nil {
		t.Fatalf("seed notification template: %v", err)
	}
	if created.ID != notificationTemplateID {
		t.Fatalf("planted the template as %s, but the routes are addressed with %s", created.ID, notificationTemplateID)
	}
	activated, err := service.ActivateTemplate(ctx, notificationRecordsMarker, created.ID, notificationuc.TemplateChangeInput{Revision: created.Revision})
	if err != nil {
		t.Fatalf("activate notification template: %v", err)
	}
	updated, err := service.UpdateTemplate(ctx, notificationRecordsMarker, created.ID, notificationuc.TemplateUpdateInput{
		Fields:   map[string]string{"body": `{"seed":"` + notificationRecordsMarker + `","version":2}`},
		Revision: activated.Revision,
	})
	if err != nil {
		t.Fatalf("add notification template version: %v", err)
	}
	if updated.Revision != notificationTemplateRevision {
		t.Fatalf("the template is at revision %d, but the write sweep starts from %d", updated.Revision, notificationTemplateRevision)
	}
}

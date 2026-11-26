package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// notificationsMarker appears in the body of an engagement notification setting only when tenantA's own row was
// served. The setting names the engagement it belongs to ("engA" is not a marker) and a revision, so
// the row is planted with an actor and a lead that carry this string.
const notificationsMarker = "tenantA-notifications-marker"

// lifecycleCycleMarker is the name of the assessment cycle the harness fixture plants for tenantA
// (harness_test.go, "cycle-A", whose only member is the engagement engA). The fixture wires the
// lifecycle API and plants the cycle itself, so this seed plants nothing for that route: it only
// names the marker, so the sweep can tell tenantA's lifecycle from an empty or foreign one.
const lifecycleCycleMarker = "tenant-A-cycle-marker"

// notificationsEngagement is the engagement both routes of this seed are addressed with: the fixture's tenantA
// engagement, which is also the one assessment id the lifecycle route is asked about.
const notificationsEngagement = shared.ID("engA")

func init() {
	notificationSetting := "GET /api/v1/notifications/engagements/{nid}/settings"
	// "{nid}" names an engagement on the settings route and a channel on the channel routes, so
	// each route carries its own value.
	values := map[string]map[string]string{notificationSetting: {"{nid}": notificationsEngagement.String()}}
	for _, route := range notificationChannelRoutes {
		values[route] = map[string]string{"{nid}": notificationChannelID.String()}
	}
	registerHarnessSeed(harnessSeed{
		Name: "notifications",
		Routes: append([]string{
			"GET /api/v1/engagements/{assessmentId}/lifecycle",
			notificationSetting,
		}, notificationChannelRoutes...),
		// The notification service reads the tenant from the request context, as the production auth
		// middleware sets it, and its repository partitions every row by it. The assessment lifecycle
		// reads the tenant from the principal and needs nothing bound.
		TenantBound: append([]string{notificationSetting}, notificationChannelRoutes...),
		PathValues: map[string]string{
			"{assessmentId}": notificationsEngagement.String(),
		},
		RoutePathValues: values,
		Run:             seedFB,
	})
}

// seedFB wires the notification service over the real in-memory repository and plants one engagement
// setting and one channel for tenantA. The assessment lifecycle needs no wiring here (see
// lifecycleCycleMarker).
func seedFB(w *harnessWorld) []string {
	w.t.Helper()
	service, repo, jobs := seedNotificationSettings(w)
	seedNotificationChannel(w, service, repo)
	// The notification records seed plants a rule, a delivery and a template over this same service.
	w.state[harnessNotificationsKey] = harnessNotifications{service: service, repo: repo, jobs: jobs}
	return []string{notificationsMarker, lifecycleCycleMarker, notificationChannelMarker}
}

// notificationsProtector keeps a secret as it is. The seed's one channel is sealed through it, and
// nothing in the harness opens that secret again, but the service refuses to be built without one.
type notificationsProtector struct{}

func (notificationsProtector) Seal(plaintext, _ []byte) (string, error) {
	return string(plaintext), nil
}

func (notificationsProtector) Open(ciphertext string, _ []byte) ([]byte, error) {
	return []byte(ciphertext), nil
}

// seedNotificationSettings stores tenantA's override for the engagement engA through the real
// service, so the row takes the path a request takes, and wires that service into the router. Wiring
// it also registers the other notification routes; the channel routes are planted by
// seedNotificationChannel over the same service, and the rule, delivery and template routes by the
// notification records seed.
//
// The repository keeps one registry of engagements per tenant, and a setting can only be read or
// written for an engagement registered under the caller's tenant. That registry is the only thing
// standing between tenantB and the row, because the route has no engagement guard of its own.
//
// The repository runs over a real job queue, as in production, because a delivery can only be
// redriven once its worker job has failed: without a queue the redrive route refuses every caller.
func seedNotificationSettings(w *harnessWorld) (*notificationuc.Service, *memory.NotificationRepository, *memory.JobQueue) {
	t := w.t
	t.Helper()
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	jobs := memory.NewJobQueue(&notificationsIDs{prefix: "notification-job"}, func() time.Time { return at })
	repo := memory.NewNotificationRepository(jobs, func() time.Time { return at })
	repo.AddEngagement("tenantA", notificationsEngagement)
	service, err := notificationuc.NewService(repo, notificationsProtector{}, nil, &fakeAudit{}, fixedClock{t: at}, &notificationsIDs{})
	if err != nil {
		t.Fatalf("notification service: %v", err)
	}
	lead := shared.ID(notificationsMarker + "-lead")
	ctx := shared.WithTenant(context.Background(), "tenantA")
	if _, err := service.SetEngagementNotificationSetting(ctx, notificationsMarker, notificationsEngagement, notificationuc.EngagementSettingInput{
		ExternalNotifications: notification.EngagementNotificationsSignal, LeadUserID: &lead,
	}); err != nil {
		t.Fatalf("seed engagement notification setting: %v", err)
	}
	w.rt.SetNotifications(service)
	return service, repo, jobs
}

// notificationsIDs hands out distinct ids, so two rows planted through one use case never collide.
// The service's generator has no prefix and names its rows notifications-id-1, -2 and so on; the
// job queue's has its own prefix, so a queued job never takes an id a route is addressed with.
type notificationsIDs struct {
	prefix string
	n      int
}

func (g *notificationsIDs) NewID() shared.ID {
	g.n++
	prefix := g.prefix
	if prefix == "" {
		prefix = "notifications-id"
	}
	return shared.ID(fmt.Sprintf("%s-%d", prefix, g.n))
}

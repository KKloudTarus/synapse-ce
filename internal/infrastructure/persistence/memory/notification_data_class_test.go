package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordingAudit struct{ entries []ports.AuditEntry }

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type dataClassHarness struct {
	ctx     context.Context
	repo    *NotificationRepository
	jobs    *JobQueue
	outbox  *NotificationOutbox
	source  *NotificationSource
	sender  *recordingSender
	audit   *recordingAudit
	service *notificationuc.Service
	tx      *TenantTransactionRunner
}

func newDataClassHarness(t *testing.T) *dataClassHarness {
	t.Helper()
	clock := fixedClock{notificationTestNow}
	h := &dataClassHarness{ctx: shared.WithTenant(context.Background(), notificationTestTenant), sender: &recordingSender{}, audit: &recordingAudit{}, tx: NewTenantTransactionRunner()}
	h.jobs = NewJobQueue(idgen.RandomID{}, clock.Now)
	h.repo = NewNotificationRepository(h.jobs, clock.Now)
	h.outbox = NewNotificationOutbox()
	h.source = NewNotificationSource(h.repo, h.outbox)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if h.service, err = notificationuc.NewService(h.repo, cipher, h.sender, h.audit, clock, idgen.RandomID{}); err != nil {
		t.Fatal(err)
	}
	h.service.SetTransactionRunner(h.tx)
	return h
}

func (h *dataClassHarness) webhook(t *testing.T) notification.Channel {
	t.Helper()
	c, err := h.service.CreateChannel(h.ctx, "admin", notificationuc.ChannelInput{Name: "Ops", Type: notification.ChannelWebhook, Enabled: true, URL: "https://hooks.example/in", Secret: "0123456789abcdef"})
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	return c
}

func classPtr(c notification.DataClass) *notification.DataClass { return &c }

// TestChannelDataClassDefaultsAndRaises checks the type defaults, that a raise needs the
// administer capability while a lowering does not, and that a change is audited.
func TestChannelDataClassDefaultsAndRaises(t *testing.T) {
	h := newDataClassHarness(t)
	slack, err := h.service.CreateChannel(h.ctx, "admin", notificationuc.ChannelInput{Name: "Room", Type: notification.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/x"})
	if err != nil {
		t.Fatal(err)
	}
	hook := h.webhook(t)
	if slack.DataClass != notification.DataClassSignal || hook.DataClass != notification.DataClassSummary {
		t.Fatalf("defaults = %s/%s, want signal for chat and summary for a webhook", slack.DataClass, hook.DataClass)
	}

	raise := notificationuc.ChannelInput{Name: hook.Name, Enabled: true, Revision: hook.Revision, DataClass: classPtr(notification.DataClassDetail)}
	if _, err := h.service.UpdateChannel(h.ctx, "integrator", hook.ID, raise); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("raise without administer = %v, want ErrForbidden", err)
	}
	raise.AllowClassRaise = true
	raised, err := h.service.UpdateChannel(h.ctx, "admin", hook.ID, raise)
	if err != nil || raised.DataClass != notification.DataClassDetail {
		t.Fatalf("raise with administer = %+v, %v", raised, err)
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if last.Action != "notification.channel.updated" || last.Metadata["data_class"] != "detail" || last.Metadata["previous_data_class"] != "summary" {
		t.Fatalf("audit = %+v", last)
	}

	lower := notificationuc.ChannelInput{Name: hook.Name, Enabled: true, Revision: raised.Revision, DataClass: classPtr(notification.DataClassSignal)}
	if lowered, err := h.service.UpdateChannel(h.ctx, "integrator", hook.ID, lower); err != nil || lowered.DataClass != notification.DataClassSignal {
		t.Fatalf("lowering without administer = %+v, %v", lowered, err)
	}
	invalid := notificationuc.ChannelInput{Name: hook.Name, Enabled: true, Revision: raised.Revision + 1, DataClass: classPtr("secret")}
	if _, err := h.service.UpdateChannel(h.ctx, "admin", hook.ID, invalid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown class = %v, want ErrValidation", err)
	}
}

func TestEngagementSettingRaiseNeedsAdminister(t *testing.T) {
	h := newDataClassHarness(t)
	h.repo.AddEngagement(notificationTestTenant, "eng-1")
	if _, err := h.service.EngagementNotificationSetting(h.ctx, "eng-unknown"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown engagement = %v, want ErrNotFound", err)
	}
	current, err := h.service.EngagementNotificationSetting(h.ctx, "eng-1")
	if err != nil || current.ExternalNotifications != notification.EngagementNotificationsInherit || current.Revision != 0 {
		t.Fatalf("default = %+v, %v, want inherit at revision 0", current, err)
	}
	none, err := h.service.SetEngagementNotificationSetting(h.ctx, "integrator", "eng-1", notificationuc.EngagementSettingInput{ExternalNotifications: notification.EngagementNotificationsNone})
	if err != nil || none.Revision != 1 || none.UpdatedBy != "integrator" {
		t.Fatalf("lowering to none = %+v, %v", none, err)
	}
	reopen := notificationuc.EngagementSettingInput{ExternalNotifications: notification.EngagementNotificationsInherit, Revision: 1}
	if _, err := h.service.SetEngagementNotificationSetting(h.ctx, "integrator", "eng-1", reopen); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("raise without administer = %v, want ErrForbidden", err)
	}
	reopen.AllowRaise = true
	if _, err := h.service.SetEngagementNotificationSetting(h.ctx, "admin", "eng-1", reopen); err != nil {
		t.Fatalf("raise with administer: %v", err)
	}
	if _, err := h.service.SetEngagementNotificationSetting(h.ctx, "admin", "eng-1", reopen); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision = %v, want ErrConflict", err)
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if last.Action != "notification.engagement_setting.updated" || last.Metadata["external_notifications"] != "inherit" || last.Metadata["previous_external_notifications"] != "none" {
		t.Fatalf("audit = %+v", last)
	}
}

// TestEngagementNoneSuppressesDelivery is the #1360 acceptance test: a delivery about an engagement
// set to none is cancelled instead of sent.
func TestEngagementNoneSuppressesDelivery(t *testing.T) {
	h := newDataClassHarness(t)
	h.repo.AddEngagement(notificationTestTenant, "eng-1")
	channel := h.webhook(t)
	if _, err := h.service.CreateRule(h.ctx, "admin", notificationuc.RuleInput{Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.source.Poll(h.ctx, notificationTestNow, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.tx.Run(context.Background(), notificationTestTenant, func(ctx context.Context) error {
		return h.outbox.Append(ctx, notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: "scan-1",
			EventType: notification.EventScanCompleted, EngagementID: "eng-1", OccurredAt: notificationTestNow.Add(time.Minute),
			Data: json.RawMessage(`{"title":"Scan completed"}`)})
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.source.Poll(h.ctx, notificationTestNow.Add(2*time.Minute), 0); err != nil || n != 1 {
		t.Fatalf("poll = %d, %v", n, err)
	}
	if _, err := h.service.SetEngagementNotificationSetting(h.ctx, "admin", "eng-1", notificationuc.EngagementSettingInput{ExternalNotifications: notification.EngagementNotificationsNone}); err != nil {
		t.Fatal(err)
	}
	job, err := h.jobs.Claim(h.ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim = %v, %v", job, err)
	}
	if err := h.service.HandleJob(h.ctx, *job); err != nil {
		t.Fatalf("handle job: %v", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatalf("sent %d messages about a suppressed engagement", len(h.sender.sent))
	}
	page, err := h.service.ListDeliveries(h.ctx, ports.NotificationDeliveryFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].State != notification.DeliveryCancelled || page.Items[0].LastError != "engagement_suppressed" {
		t.Fatalf("deliveries = %+v, %v", page.Items, err)
	}
}

// changeAfterLoad runs change right after the worker loads its work, the interleaving of the #1360
// and #1566 reviews: the load and the render still see the old policy, and the attempt is admitted
// after the change commits.
type changeAfterLoad struct {
	*NotificationRepository
	change func(ctx context.Context) error
}

func (r changeAfterLoad) LoadWork(ctx context.Context, tenant, delivery shared.ID) (ports.NotificationWork, error) {
	work, err := r.NotificationRepository.LoadWork(ctx, tenant, delivery)
	if err != nil {
		return work, err
	}
	return work, r.change(ctx)
}

// setOverride commits the engagement override at revision 1.
func (h *dataClassHarness) setOverride(value notification.EngagementNotifications) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		at := notificationTestNow.Add(3 * time.Minute)
		_, err := h.repo.PutEngagementNotificationSetting(ctx, notification.EngagementNotificationSetting{TenantID: notificationTestTenant, EngagementID: "eng-1",
			ExternalNotifications: value, Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"})
		return err
	}
}

// queuedScan routes a scan.completed event about eng-1 to channel and projects it into one
// delivery, then returns the claimed delivery job.
func (h *dataClassHarness) queuedScan(t *testing.T, channel notification.Channel) ports.QueuedJob {
	t.Helper()
	if _, err := h.service.CreateRule(h.ctx, "admin", notificationuc.RuleInput{Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.source.Poll(h.ctx, notificationTestNow, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.tx.Run(context.Background(), notificationTestTenant, func(ctx context.Context) error {
		return h.outbox.Append(ctx, notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: "scan-1",
			EventType: notification.EventScanCompleted, EngagementID: "eng-1", OccurredAt: notificationTestNow.Add(time.Minute),
			Data: json.RawMessage(`{"title":"Scan completed"}`)})
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.source.Poll(h.ctx, notificationTestNow.Add(2*time.Minute), 0); err != nil || n != 1 {
		t.Fatalf("poll = %d, %v", n, err)
	}
	job, err := h.jobs.Claim(h.ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim = %v, %v", job, err)
	}
	return *job
}

// worker is a notification service over repo, as the worker process builds one.
func (h *dataClassHarness) worker(t *testing.T, repo ports.NotificationRepository) *notificationuc.Service {
	t.Helper()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := notificationuc.NewService(repo, cipher, h.sender, h.audit, fixedClock{notificationTestNow.Add(3 * time.Minute)}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

// TestEngagementNoneAfterLoadIsNotSent drives the worker through that interleaving: nothing is
// sent, no attempt is recorded, and the delivery ends cancelled with engagement_suppressed.
func TestEngagementNoneAfterLoadIsNotSent(t *testing.T) {
	h := newDataClassHarness(t)
	h.repo.AddEngagement(notificationTestTenant, "eng-1")
	job := h.queuedScan(t, h.webhook(t))
	worker := h.worker(t, changeAfterLoad{NotificationRepository: h.repo, change: h.setOverride(notification.EngagementNotificationsNone)})
	if err := worker.HandleJob(h.ctx, job); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("handle job = %v, want the retryable admission refusal", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatalf("sent %d messages after the engagement was set to none", len(h.sender.sent))
	}
	page, err := h.service.ListDeliveries(h.ctx, ports.NotificationDeliveryFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].State != notification.DeliveryCancelled || page.Items[0].LastError != notification.CodeEngagementSuppressed || page.Items[0].Attempts != 0 {
		t.Fatalf("deliveries = %+v, %v", page.Items, err)
	}
}

// TestLoweringAfterRenderIsNotSentAtTheOldClass is the #1566 review case: the worker renders at the
// channel's summary class, then the engagement is capped at signal, or the channel itself lowered,
// before the attempt starts. The summary-class message must not go out; the attempt is refused
// retryably and the delivery stays open, so the retry renders at signal.
func TestLoweringAfterRenderIsNotSentAtTheOldClass(t *testing.T) {
	for name, lower := range map[string]func(h *dataClassHarness, channel notification.Channel) func(ctx context.Context) error{
		"engagement capped at signal": func(h *dataClassHarness, _ notification.Channel) func(ctx context.Context) error {
			return h.setOverride(notification.EngagementNotificationsSignal)
		},
		"channel lowered to signal": func(h *dataClassHarness, channel notification.Channel) func(ctx context.Context) error {
			return func(ctx context.Context) error {
				_, err := h.service.UpdateChannel(ctx, "admin", channel.ID, notificationuc.ChannelInput{Name: channel.Name, Type: channel.Type, Enabled: true,
					Revision: channel.Revision, DataClass: classPtr(notification.DataClassSignal)})
				return err
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newDataClassHarness(t)
			h.repo.AddEngagement(notificationTestTenant, "eng-1")
			channel := h.webhook(t)
			job := h.queuedScan(t, channel)
			worker := h.worker(t, changeAfterLoad{NotificationRepository: h.repo, change: lower(h, channel)})
			if err := worker.HandleJob(h.ctx, job); !errors.Is(err, ports.ErrRetryable) {
				t.Fatalf("handle job = %v, want the retryable admission refusal", err)
			}
			if len(h.sender.sent) != 0 {
				t.Fatalf("sent %d messages rendered at the old class", len(h.sender.sent))
			}
			page, err := h.service.ListDeliveries(h.ctx, ports.NotificationDeliveryFilter{})
			if err != nil || len(page.Items) != 1 || page.Items[0].State != notification.DeliveryPending || page.Items[0].Attempts != 0 {
				t.Fatalf("deliveries = %+v, %v, want the delivery left open for a render at signal", page.Items, err)
			}
		})
	}
}

// TestAdmissionComparesTheRenderedClass checks BeginAttempt directly: a message rendered at the
// class the policy allows now starts, one rendered above it is refused retryably.
func TestAdmissionComparesTheRenderedClass(t *testing.T) {
	h := newDataClassHarness(t)
	h.repo.AddEngagement(notificationTestTenant, "eng-1")
	job := h.queuedScan(t, h.webhook(t))
	if err := h.setOverride(notification.EngagementNotificationsSignal)(h.ctx); err != nil {
		t.Fatal(err)
	}
	var delivery shared.ID
	if page, err := h.service.ListDeliveries(h.ctx, ports.NotificationDeliveryFilter{}); err != nil || len(page.Items) != 1 {
		t.Fatalf("deliveries = %+v, %v", page.Items, err)
	} else {
		delivery = page.Items[0].ID
	}
	if _, err := h.repo.BeginAttempt(h.ctx, notificationTestTenant, delivery, job.ID, job.Fence, "above", notificationTestNow.Add(3*time.Minute),
		ports.AttemptAdmission{DataClass: notification.DataClassSummary}); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("summary under a signal cap = %v, want ErrRetryable", err)
	}
	if _, err := h.repo.BeginAttempt(h.ctx, notificationTestTenant, delivery, job.ID, job.Fence, "at", notificationTestNow.Add(3*time.Minute),
		ports.AttemptAdmission{DataClass: notification.DataClassSignal}); err != nil {
		t.Fatalf("signal under a signal cap = %v, want admitted", err)
	}
}

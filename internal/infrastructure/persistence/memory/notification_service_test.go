package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type discardAudit struct{}

func (discardAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type recordingSender struct{ sent []ports.NotificationWork }

func (s *recordingSender) Send(_ context.Context, work ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.sent = append(s.sent, work)
	return ports.NotificationSendResult{StatusCode: 204}
}

// TestNotificationServiceRunsOnMemoryAdapters drives the real use case over the memory adapters:
// an administrator configures a channel and a rule, a producer appends in its transaction, the
// source projects it and the worker delivers it. It is the path WS1 emitter tests rely on.
func TestNotificationServiceRunsOnMemoryAdapters(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	clock := fixedClock{notificationTestNow}
	jobs := NewJobQueue(idgen.RandomID{}, clock.Now)
	repo := NewNotificationRepository(jobs, clock.Now)
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	transactions := NewTenantTransactionRunner()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	service, err := notificationuc.NewService(repo, cipher, sender, discardAudit{}, clock, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(transactions)

	channel, err := service.CreateChannel(ctx, "admin", notificationuc.ChannelInput{Name: "Ops", Type: notification.ChannelWebhook, Enabled: true, URL: "https://hooks.example/in", Secret: "0123456789abcdef"})
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := service.CreateRule(ctx, "admin", notificationuc.RuleInput{Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}}); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := source.Poll(ctx, notificationTestNow, 0); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if err := appendScanRecord(t, transactions, outbox, "scan-1", notificationTestNow.Add(time.Minute), nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if n, err := source.Poll(ctx, notificationTestNow.Add(2*time.Minute), 0); err != nil || n != 1 {
		t.Fatalf("drain poll = %d err=%v", n, err)
	}

	job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim delivery job = %v err=%v", job, err)
	}
	if err := service.HandleJob(ctx, *job); err != nil {
		t.Fatalf("handle job: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0].Event.SourceID != "scan-1" || sender.sent[0].Channel.ID != channel.ID {
		t.Fatalf("sent = %+v", sender.sent)
	}
	page, err := service.ListDeliveries(ctx, ports.NotificationDeliveryFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].State != notification.DeliverySucceeded {
		t.Fatalf("deliveries = %+v err=%v", page, err)
	}
}

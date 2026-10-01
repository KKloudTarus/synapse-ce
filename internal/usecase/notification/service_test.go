package notification

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRepo struct {
	ports.NotificationRepository
	work             ports.NotificationWork
	relevant         bool
	cancelled        bool
	finished         string
	next             *time.Time
	publishedEvent   domain.Event
	publishedChannel shared.ID
	cancelReason     string
	outcomes         []ports.NotificationChannelOutcome
	delivery         domain.Delivery
	redriveChannel   domain.Channel
	redriveErr       error
	redriveFence     int64
	redriveCalls     int
}

func (f *fakeRepo) LoadWork(context.Context, shared.ID, shared.ID) (ports.NotificationWork, error) {
	return f.work, nil
}
func (f *fakeRepo) ScanJobSucceeded(context.Context, shared.ID, string) (bool, error) {
	return f.relevant, nil
}
func (f *fakeRepo) BeginAttempt(_ context.Context, _, _ shared.ID, _ string, _ int64, id shared.ID, at time.Time, _ string) (domain.Attempt, error) {
	return domain.Attempt{ID: id, Number: 1, StartedAt: at}, nil
}
func (f *fakeRepo) FinishAttempt(_ context.Context, _, _ shared.ID, _ string, _ int64, _ shared.ID, _ time.Time, outcome string, _ int, _ string, next *time.Time) error {
	f.finished = outcome
	f.next = next
	return nil
}
func (f *fakeRepo) CancelDelivery(_ context.Context, _, _ shared.ID, _ string, _ int64, reason string) error {
	f.cancelled = true
	f.cancelReason = reason
	return nil
}
func (f *fakeRepo) GetDelivery(context.Context, shared.ID, shared.ID) (domain.Delivery, error) {
	return f.delivery, nil
}
func (f *fakeRepo) RedriveDelivery(_ context.Context, _, _ shared.ID, fence int64) (domain.Delivery, domain.Channel, error) {
	f.redriveFence = fence
	f.redriveCalls++
	if f.redriveErr != nil {
		return domain.Delivery{}, domain.Channel{}, f.redriveErr
	}
	return f.delivery, f.redriveChannel, nil
}
func (f *fakeRepo) DeadLetterDelivery(context.Context, shared.ID, shared.ID, int64, string) (bool, error) {
	return false, nil
}

// RecordChannelOutcome applies the domain rules to the loaded channel, like the Postgres
// repository does under its row lock.
func (f *fakeRepo) RecordChannelOutcome(_ context.Context, _ shared.ID, o ports.NotificationChannelOutcome) (ports.NotificationChannelTransition, error) {
	f.outcomes = append(f.outcomes, o)
	next, effect := f.work.Channel.Health.Observe(o.Class, o.Code, o.At, o.Threshold)
	f.work.Channel.Health = next
	return ports.NotificationChannelTransition{Paused: effect == domain.HealthPausedNow, PauseID: "pause", Health: next}, nil
}

type fakeProtector struct {
	raw []byte
	err error
}

func (f fakeProtector) Seal(v, _ []byte) (string, error)        { return string(v), nil }
func (f fakeProtector) Open(_ string, _ []byte) ([]byte, error) { return f.raw, f.err }

type fakeSender struct{ result ports.NotificationSendResult }

func (f fakeSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	return f.result
}

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

type fakeIDs struct{ n int }

func (f *fakeIDs) NewID() shared.ID { f.n++; return shared.ID("id" + string(rune('0'+f.n))) }

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type capturingAudit struct{ entries []ports.AuditEntry }

func (a *capturingAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

func TestRedriveDeliveryAuditsSafeReasonAndDestination(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &fakeRepo{
		delivery:       domain.Delivery{ID: "delivery", ChannelType: domain.ChannelWebhook, State: domain.DeliveryDead, LastError: "http_503"},
		redriveChannel: domain.Channel{ID: "channel", Type: domain.ChannelWebhook, Destination: "https://hooks.example.test/services/T1/B2/secret?token=private"},
	}
	repo.delivery.RedriveFence = 7
	audit := &capturingAudit{}
	svc, err := NewService(repo, fakeProtector{raw: []byte(`{}`)}, nil, audit, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.RedriveDelivery(ctx, " administrator ", "delivery", RedriveInput{Reason: "Fixed password=hunter2; retry", ExpectedFence: 7})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "delivery" || repo.redriveCalls != 1 || repo.redriveFence != 7 {
		t.Fatalf("result=%+v calls=%d fence=%d", got, repo.redriveCalls, repo.redriveFence)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries=%d", len(audit.entries))
	}
	entry := audit.entries[0]
	if entry.Action != "notification.delivery_redriven" || entry.Actor != "administrator" || entry.Target != "delivery" {
		t.Fatalf("audit identity=%+v", entry)
	}
	if entry.Metadata["destination_scheme"] != "https" || entry.Metadata["destination_host"] != "hooks.example.test" {
		t.Fatalf("unsafe destination metadata: %+v", entry.Metadata)
	}
	if entry.Metadata["previous_error_code"] != "http_503" {
		t.Fatalf("previous error code missing from audit metadata: %+v", entry.Metadata)
	}
	if strings.Contains(entry.Metadata["reason"], "hunter2") || strings.Contains(entry.Metadata["destination_host"], "secret") {
		t.Fatalf("audit metadata retained sensitive text: %+v", entry.Metadata)
	}
}

func TestRedriveEmailAuditKeepsOnlyRecipientDomains(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &fakeRepo{
		delivery: domain.Delivery{ID: "delivery", Recipient: "alice@example.test", ChannelType: domain.ChannelEmail, State: domain.DeliveryDead, RedriveFence: 2},
		redriveChannel: domain.Channel{
			ID: "channel", Type: domain.ChannelEmail, Destination: "alice@example.test",
			Recipients: []string{"alice@example.test", "bob@corp.test"},
		},
	}
	audit := &capturingAudit{}
	svc, err := NewService(repo, fakeProtector{raw: []byte(`{}`)}, nil, audit, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RedriveDelivery(ctx, "admin", "delivery", RedriveInput{Reason: "retry", ExpectedFence: 2}); err != nil {
		t.Fatal(err)
	}
	host := audit.entries[0].Metadata["destination_host"]
	if host != "example.test" || strings.Contains(host, "alice") || strings.Contains(host, "bob") {
		t.Fatalf("email audit destination=%q", host)
	}
}

func TestRedriveDeliveryRejectsInvalidAndDisabledRequestsBeforeRepository(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &fakeRepo{delivery: domain.Delivery{ID: "delivery", ChannelType: domain.ChannelWebhook, State: domain.DeliveryDead}}
	svc, err := NewService(repo, fakeProtector{}, nil, fakeAudit{}, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		actor string
		input RedriveInput
	}{
		{name: "blank actor", actor: " ", input: RedriveInput{Reason: "retry", ExpectedFence: 1}},
		{name: "blank reason", actor: "admin", input: RedriveInput{Reason: "  ", ExpectedFence: 1}},
		{name: "missing fence", actor: "admin", input: RedriveInput{Reason: "retry"}},
		{name: "long reason", actor: "admin", input: RedriveInput{Reason: strings.Repeat("x", 501), ExpectedFence: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.RedriveDelivery(ctx, tc.actor, "delivery", tc.input); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error=%v, want validation", err)
			}
		})
	}
	svc.SetDisabledChannelTypes([]domain.ChannelType{domain.ChannelWebhook})
	if _, err := svc.RedriveDelivery(ctx, "admin", "delivery", RedriveInput{Reason: "retry", ExpectedFence: 1}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled provider error=%v", err)
	}
	if repo.redriveCalls != 0 {
		t.Fatalf("invalid request reached repository %d times", repo.redriveCalls)
	}
}

func TestRedriveReasonRemovesURLsAndKnownChannelSecrets(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &fakeRepo{delivery: domain.Delivery{ID: "delivery", ChannelType: domain.ChannelWebhook, State: domain.DeliveryDead, RedriveFence: 1}}
	audit := &capturingAudit{}
	protector := fakeProtector{raw: []byte(`{"secret":"test-signing-value","url":"https://hooks.example.test/private-path"}`)}
	svc, err := NewService(repo, protector, nil, audit, fakeClock{}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RedriveDelivery(ctx, "admin", "delivery", RedriveInput{
		Reason: "Fixed https://hooks.example.test/private-path and https://other.example.test/opaque-credential; test-signing-value", ExpectedFence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	reason := audit.entries[0].Metadata["reason"]
	for _, secret := range []string{"private-path", "opaque-credential", "test-signing-value"} {
		if strings.Contains(reason, secret) {
			t.Fatal("audit reason leaked credential material")
		}
	}
	if !strings.Contains(reason, "Fixed") {
		t.Fatal("audit reason lost non-sensitive context")
	}
}

func TestRedriveRefusesUnredactableReasonBeforeMutation(t *testing.T) {
	for _, protector := range []fakeProtector{
		{err: errors.New("protector failed with sensitive details")},
		{raw: []byte("invalid sealed config")},
	} {
		repo := &fakeRepo{delivery: domain.Delivery{ID: "delivery", ChannelType: domain.ChannelWebhook, State: domain.DeliveryDead, RedriveFence: 1}}
		audit := &capturingAudit{}
		svc, err := NewService(repo, protector, nil, audit, fakeClock{}, &fakeIDs{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.RedriveDelivery(shared.WithTenant(context.Background(), "tenant"), "admin", "delivery", RedriveInput{Reason: "retry", ExpectedFence: 1})
		if !errors.Is(err, shared.ErrConflict) || strings.Contains(err.Error(), "sensitive") || repo.redriveCalls != 0 || len(audit.entries) != 0 {
			t.Fatalf("unredactable request mutated state or exposed error: %v", err)
		}
	}
}

func (f *fakeRepo) ListChannels(_ context.Context, tenant shared.ID) ([]domain.Channel, error) {
	return []domain.Channel{{TenantID: tenant, ID: "channel", Name: "Channel"}}, nil
}

func (f *fakeRepo) GetChannel(_ context.Context, tenant, id shared.ID) (domain.Channel, error) {
	return domain.Channel{TenantID: tenant, ID: id, Name: "Channel", Type: domain.ChannelWebhook, Destination: "https://hooks.example.com/…"}, nil
}

func (f *fakeRepo) PublishToChannel(_ context.Context, event domain.Event, channel shared.ID) (shared.ID, error) {
	f.publishedEvent = event
	f.publishedChannel = channel
	return "delivery", nil
}

// The API serves notification administration without the worker's delivery sender.
func TestAdministrationWithoutDeliverySender(t *testing.T) {
	repo := &fakeRepo{}
	svc, err := NewService(repo, fakeProtector{}, nil, fakeAudit{}, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant")
	channels, err := svc.ListChannels(ctx)
	if err != nil || len(channels) != 1 || channels[0].ID != "channel" {
		t.Fatalf("channels=%v, err=%v", channels, err)
	}
	id, err := svc.TestChannel(ctx, "admin", "channel")
	if err != nil || id != "delivery" || repo.publishedChannel != "channel" {
		t.Fatalf("test channel: id=%q, target=%q, err=%v", id, repo.publishedChannel, err)
	}
	if repo.publishedEvent.TenantID != "tenant" || repo.publishedEvent.Type != domain.EventTest {
		t.Fatalf("wrong tenant or event type: %+v", repo.publishedEvent)
	}
	if err := repo.publishedEvent.Validate(); err != nil {
		t.Fatalf("invalid test event: %v", err)
	}
	if _, err := svc.TestChannel(context.Background(), "admin", "channel"); err == nil {
		t.Fatal("test channel accepted a missing tenant context")
	}
	err = svc.HandleJob(context.Background(), ports.QueuedJob{})
	var deliveryErr *DeliveryError
	if !errors.As(err, &deliveryErr) || !deliveryErr.Terminal() {
		t.Fatalf("API must not handle delivery jobs without a sender: %v", err)
	}
}

func TestHandleJobPersistsRetryWithoutSleeping(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cfg, _ := json.Marshal(ports.WebhookChannelConfig{URL: "https://example.com", Secret: "0123456789abcdef"})
	repo := &fakeRepo{relevant: true, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending}, Event: domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)}, Channel: domain.Channel{ID: "channel", Type: domain.ChannelWebhook, Enabled: true, SecretVersion: 1}}}
	svc, err := NewService(repo, fakeProtector{raw: cfg}, fakeSender{result: ports.NotificationSendResult{StatusCode: 503, ErrorCode: "http_503", Retryable: true}}, fakeAudit{}, fakeClock{now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"delivery_id": "delivery"})
	err = svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{ID: "notification-delivery", TenantID: "tenant", Kind: JobKind, Payload: payload, Attempts: 1, Fence: 2})
	var directive *DeliveryError
	if !errors.As(err, &directive) || directive.Terminal() || directive.RetryAfter() <= 0 {
		t.Fatalf("err=%v", err)
	}
	if repo.finished != "retrying" || repo.next == nil {
		t.Fatalf("finish=%q next=%v", repo.finished, repo.next)
	}
}

func TestHandleJobCancelsRecoveredSource(t *testing.T) {
	// A scan.completed delivery whose job no longer reads as succeeded, for example a rejected CI import.
	scan := domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-1", Data: json.RawMessage(`{}`)}
	repo := &fakeRepo{relevant: false, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending}, Event: scan, Channel: domain.Channel{ID: "channel", Type: domain.ChannelEmail, Enabled: true}}}
	svc, _ := NewService(repo, fakeProtector{}, fakeSender{}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
	payload, _ := json.Marshal(map[string]string{"delivery_id": "delivery"})
	if err := svc.HandleJob(context.Background(), ports.QueuedJob{ID: "job", TenantID: "tenant", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if !repo.cancelled {
		t.Fatal("irrelevant source was not cancelled")
	}
}

func TestValidateChannelRejectsUnsafeEndpoints(t *testing.T) {
	for _, input := range []ChannelInput{{Name: "hook", Type: domain.ChannelWebhook, URL: "http://127.0.0.1/hook", Secret: "0123456789abcdef"}, {Name: "slack", Type: domain.ChannelSlack, URL: "https://example.com/services/x"}, {Name: "mail", Type: domain.ChannelEmail, Recipients: []string{"ok@example.com\r\nBcc:evil@example.com"}}} {
		if _, _, _, err := validateChannel(input, true); err == nil {
			t.Fatalf("accepted unsafe input: %+v", input)
		}
	}
}

func TestHandleJobRetryBudgetAndTerminalReplay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    domain.DeliveryState
		attempt  int
		terminal bool
	}{{"eighth failure", domain.DeliveryPending, 8, true}, {"ninth claim", domain.DeliveryPending, 9, true}, {"persisted dead", domain.DeliveryDead, 2, true}, {"persisted success", domain.DeliverySucceeded, 2, false}} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{relevant: true, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: tc.state}, Channel: domain.Channel{ID: "channel", Enabled: true}}}
			svc, _ := NewService(repo, fakeProtector{raw: []byte(`{}`)}, fakeSender{result: ports.NotificationSendResult{StatusCode: 500, Retryable: true, ErrorCode: "http_500"}}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
			err := svc.HandleJob(context.Background(), ports.QueuedJob{TenantID: "tenant", Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: tc.attempt})
			var directive *DeliveryError
			if tc.terminal {
				if !errors.As(err, &directive) || !directive.Terminal() {
					t.Fatalf("%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tc.attempt > 8 || tc.state != domain.DeliveryPending {
				if repo.finished != "" {
					t.Fatal("replay performed another attempt")
				}
			}
		})
	}
}

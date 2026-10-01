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

// killSwitchRepo records what the kill switch lets through to persistence.
type killSwitchRepo struct {
	fakeRepo
	current      domain.Channel
	created      bool
	updated      bool
	cancelReason string
	began        bool
}

func (r *killSwitchRepo) GetChannel(context.Context, shared.ID, shared.ID) (domain.Channel, error) {
	return r.current, nil
}
func (r *killSwitchRepo) CreateChannel(_ context.Context, c domain.Channel, _ string) (domain.Channel, error) {
	r.created = true
	return c, nil
}
func (r *killSwitchRepo) UpdateChannel(_ context.Context, c domain.Channel, _ string, _ bool) (domain.Channel, error) {
	r.updated = true
	return c, nil
}
func (r *killSwitchRepo) CancelDelivery(_ context.Context, _, _ shared.ID, _ string, _ int64, reason string) error {
	r.cancelReason = reason
	return nil
}
func (r *killSwitchRepo) BeginAttempt(ctx context.Context, tenant, delivery shared.ID, job string, fence int64, id shared.ID, at time.Time, ref string) (domain.Attempt, error) {
	r.began = true
	return r.fakeRepo.BeginAttempt(ctx, tenant, delivery, job, fence, id, at, ref)
}

func killSwitchService(t *testing.T, repo *killSwitchRepo, sender ports.NotificationSender, disabled ...domain.ChannelType) *Service {
	t.Helper()
	svc, err := NewService(repo, fakeProtector{raw: []byte(`{"url":"https://hooks.slack.com/services/x"}`)}, sender, fakeAudit{}, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetDisabledChannelTypes(disabled)
	return svc
}

func assertDisabledError(t *testing.T, err error, channelType domain.ChannelType) {
	t.Helper()
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if !strings.Contains(err.Error(), `"`+string(channelType)+`"`) || !strings.Contains(err.Error(), "SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED") {
		t.Fatalf("error %q does not name the type and the switch", err)
	}
}

func TestCreateChannelRefusesADisabledType(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &killSwitchRepo{}
	svc := killSwitchService(t, repo, nil, domain.ChannelSlack)
	_, err := svc.CreateChannel(ctx, "admin", ChannelInput{Name: "ops", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/x"})
	assertDisabledError(t, err, domain.ChannelSlack)
	if repo.created {
		t.Fatal("a channel of a disabled type was stored")
	}
	// Other types are unaffected.
	if _, err = svc.CreateChannel(ctx, "admin", ChannelInput{Name: "mail", Type: domain.ChannelEmail, Enabled: true, Recipients: []string{"ops@example.com"}}); err != nil || !repo.created {
		t.Fatalf("an enabled type was refused: %v", err)
	}
}

func TestUpdateChannelOfADisabledType(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	for _, tc := range []struct {
		name    string
		current bool
		in      ChannelInput
		refused bool
	}{
		{"switch on", false, ChannelInput{Name: "ops", Enabled: true, Revision: 1}, true},
		{"new destination", false, ChannelInput{Name: "ops", URL: "https://hooks.slack.com/services/y", Revision: 1, AllowDestinationChange: true}, true},
		{"rename while on", true, ChannelInput{Name: "renamed", Enabled: true, Revision: 1}, false},
		{"switch off", true, ChannelInput{Name: "ops", Enabled: false, Revision: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &killSwitchRepo{current: domain.Channel{ID: "channel", Name: "ops", Type: domain.ChannelSlack, Enabled: tc.current, Revision: 1, SecretVersion: 1}}
			svc := killSwitchService(t, repo, nil, domain.ChannelSlack)
			_, err := svc.UpdateChannel(ctx, "admin", "channel", tc.in)
			if tc.refused {
				assertDisabledError(t, err, domain.ChannelSlack)
				if repo.updated {
					t.Fatal("a refused update was stored")
				}
				return
			}
			if err != nil || !repo.updated {
				t.Fatalf("update refused: %v", err)
			}
		})
	}
}

func TestTestChannelRefusesADisabledType(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	repo := &killSwitchRepo{current: domain.Channel{ID: "channel", Type: domain.ChannelSlack, Enabled: true}}
	svc := killSwitchService(t, repo, nil, domain.ChannelSlack)
	_, err := svc.TestChannel(ctx, "admin", "channel")
	assertDisabledError(t, err, domain.ChannelSlack)
	if repo.publishedChannel != "" {
		t.Fatal("a test delivery was queued for a disabled type")
	}
}

type countingSender struct{ calls int }

func (s *countingSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.calls++
	return ports.NotificationSendResult{StatusCode: 200}
}

func TestHandleJobCancelsADisabledTypeWithProviderDisabled(t *testing.T) {
	sender := &countingSender{}
	repo := &killSwitchRepo{fakeRepo: fakeRepo{relevant: true, work: ports.NotificationWork{
		Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending, ChannelType: domain.ChannelSlack},
		Channel:  domain.Channel{ID: "channel", Type: domain.ChannelSlack, Enabled: true, SecretVersion: 1},
		Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
	}}}
	svc := killSwitchService(t, repo, sender, domain.ChannelSlack)
	job := ports.QueuedJob{ID: "job", TenantID: "tenant", Kind: JobKind, Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: 1, Fence: 1}
	// A cancelled delivery is a clean outcome, not a failure the queue retries or dead-letters.
	if err := svc.HandleJob(context.Background(), job); err != nil {
		t.Fatalf("HandleJob = %v, want nil", err)
	}
	if repo.cancelReason != "provider_disabled" {
		t.Fatalf("cancel reason = %q, want provider_disabled", repo.cancelReason)
	}
	if repo.began || sender.calls != 0 || repo.finished != "" {
		t.Fatalf("a disabled type was attempted: began=%v sends=%d finished=%q", repo.began, sender.calls, repo.finished)
	}

	// With the switch cleared the same work is delivered.
	svc.SetDisabledChannelTypes(nil)
	repo.cancelReason = ""
	if err := svc.HandleJob(context.Background(), job); err != nil || sender.calls != 1 || repo.cancelReason != "" {
		t.Fatalf("enabled type: err=%v sends=%d cancel=%q", err, sender.calls, repo.cancelReason)
	}
}

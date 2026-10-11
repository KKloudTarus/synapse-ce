package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type channelHealthRepo struct {
	ports.NotificationRepository
	channel domain.Channel
	actor   string
}

func (r *channelHealthRepo) GetChannel(context.Context, shared.ID, shared.ID) (domain.Channel, error) {
	return r.channel, nil
}
func (r *channelHealthRepo) ResumeChannel(_ context.Context, _, _ shared.ID, revision int, actor string, _ time.Time) (domain.Channel, error) {
	if revision != r.channel.Revision {
		return domain.Channel{}, fmt.Errorf("stale: %w", shared.ErrConflict)
	}
	next, err := r.channel.Health.Resume()
	if err != nil {
		return domain.Channel{}, err
	}
	r.actor = actor
	r.channel.Health, r.channel.Revision = next, revision+1
	return r.channel, nil
}
func (r *channelHealthRepo) ListChannelHealthEvents(context.Context, shared.ID, shared.ID, int) ([]domain.ChannelHealthEvent, error) {
	return []domain.ChannelHealthEvent{{ID: "h1", ChannelID: "c1", Action: domain.HealthActionPaused, Reason: domain.PauseReasonPermanentFailures, FailureCode: "destination_blocked", Failures: 5, DeliveryID: "d1", AttemptID: "a1", Actor: "system"}}, nil
}

type handlerAudit struct{}

func (handlerAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type handlerClock struct{}

func (handlerClock) Now() time.Time { return time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC) }

type handlerIDs struct{}

func (handlerIDs) NewID() shared.ID { return "id" }

type handlerProtector struct{}

func (handlerProtector) Seal(v, _ []byte) (string, error)        { return string(v), nil }
func (handlerProtector) Open(v string, _ []byte) ([]byte, error) { return []byte(v), nil }

func TestResumeNotificationChannelForAdministrator(t *testing.T) {
	pausedAt := time.Date(2026, 9, 29, 7, 0, 0, 0, time.UTC)
	repo := &channelHealthRepo{channel: domain.Channel{ID: "c1", Name: "Ops", Type: domain.ChannelWebhook, Destination: "https://hooks.example.com/…", Revision: 3,
		Health: domain.ChannelHealth{State: domain.ChannelPaused, PausedAt: &pausedAt, PausedReason: domain.PauseReasonPermanentFailures, ConsecutiveFailures: 5, LastFailureCode: "destination_blocked"}}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, handlerAudit{}, handlerClock{}, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		// The authentication middleware binds the tenant before authz in production.
		ctx := shared.WithTenant(req.Context(), "tenant")
		req = req.WithContext(context.WithValue(ctx, principalKey, Principal{ID: "admin-1", Role: "admin", TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		return response
	}
	if got := call("POST", "/api/v1/notifications/channels/c1/resume", `{"revision":3,"force":true}`); got.Code != 400 {
		t.Fatalf("unknown field: %d %s", got.Code, got.Body)
	}
	if got := call("POST", "/api/v1/notifications/channels/c1/resume", `{"revision":2}`); got.Code != 409 {
		t.Fatalf("stale revision: %d %s", got.Code, got.Body)
	}
	got := call("POST", "/api/v1/notifications/channels/c1/resume", `{"revision":3}`)
	if got.Code != 200 {
		t.Fatalf("resume: %d %s", got.Code, got.Body)
	}
	var body struct {
		Revision int `json:"revision"`
		Health   struct {
			State               string  `json:"state"`
			PausedAt            *string `json:"paused_at"`
			ConsecutiveFailures int     `json:"consecutive_failures"`
			LastFailureCode     string  `json:"last_failure_code"`
		} `json:"health"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Revision != 4 || body.Health.State != "active" || body.Health.PausedAt != nil || body.Health.ConsecutiveFailures != 0 || body.Health.LastFailureCode != "destination_blocked" || repo.actor != "admin-1" {
		t.Fatalf("resume body = %+v actor=%q", body, repo.actor)
	}
	if got := call("POST", "/api/v1/notifications/channels/c1/resume", `{"revision":4}`); got.Code != 409 {
		t.Fatalf("resume of an active channel: %d %s", got.Code, got.Body)
	}
	history := call("GET", "/api/v1/notifications/channels/c1/health-events", "")
	if history.Code != 200 || !strings.Contains(history.Body.String(), `"action":"paused"`) || !strings.Contains(history.Body.String(), `"attempt_id":"a1"`) {
		t.Fatalf("history: %d %s", history.Code, history.Body)
	}
}

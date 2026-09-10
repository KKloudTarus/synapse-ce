package notificationsender

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func testWork(kind notification.ChannelType) ports.NotificationWork {
	at := time.Unix(1700000000, 0).UTC()
	data, _ := json.Marshal(map[string]string{"title": "Critical <event>", "summary": "needs & review"})
	return ports.NotificationWork{Delivery: notification.Delivery{TenantID: "tenant", ID: "delivery", EventID: "event", ChannelID: "channel", ChannelType: kind, State: notification.DeliveryPending}, Event: notification.Event{TenantID: "tenant", ID: "event", Type: notification.EventVulnerabilityAction, SourceKind: "test", SourceID: "source", SchemaVersion: 1, OccurredAt: at, Data: data}, Channel: notification.Channel{TenantID: "tenant", ID: "channel", Type: kind, Enabled: true, Name: "test", Revision: 1, SecretVersion: 1, CreatedAt: at, UpdatedAt: at}}
}

func TestWebhookSignsExactBody(t *testing.T) {
	var body []byte
	var timestamp, signature, eventID, deliveryID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		timestamp = r.Header.Get("X-Synapse-Timestamp")
		signature = r.Header.Get("X-Synapse-Signature")
		eventID = r.Header.Get("X-Synapse-Event-ID")
		deliveryID = r.Header.Get("X-Synapse-Delivery-ID")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	s.now = func() time.Time { return time.Unix(1700000100, 0) }
	result := s.Send(context.Background(), testWork(notification.ChannelWebhook), ports.NotificationChannelConfig{URL: server.URL, Secret: "0123456789abcdef"})
	if result.StatusCode != 204 || result.ErrorCode != "" {
		t.Fatalf("result=%+v", result)
	}
	mac := hmac.New(sha256.New, []byte("0123456789abcdef"))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if signature != want || eventID != "event" || deliveryID != "delivery" {
		t.Fatalf("signature/identity headers incorrect")
	}
}

func TestSlack429IsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	result := s.Send(context.Background(), testWork(notification.ChannelSlack), ports.NotificationChannelConfig{URL: server.URL})
	if !result.Retryable || result.RetryAfter != 17*time.Second || result.ErrorCode != "http_429" {
		t.Fatalf("result=%+v", result)
	}
}

func TestEmailFailsClosedWithoutOperatorRelay(t *testing.T) {
	work := testWork(notification.ChannelEmail)
	work.Delivery.Recipient = "security@example.com"
	result := New(SMTPConfig{}, time.Second).Send(context.Background(), work, ports.NotificationChannelConfig{})
	if result.Retryable || result.ErrorCode != "smtp_not_configured" {
		t.Fatalf("result=%+v", result)
	}
}

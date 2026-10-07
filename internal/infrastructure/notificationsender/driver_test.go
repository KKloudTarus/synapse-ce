package notificationsender

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// goldenWork is the event the golden files were captured with. The files were produced by the
// sender before the driver registry existed, so these tests prove the wire output is unchanged.
func goldenWork(kind notification.ChannelType) ports.NotificationWork {
	return ports.NotificationWork{
		Delivery: notification.Delivery{ID: "delivery-1"},
		Channel:  notification.Channel{Type: kind},
		Event: notification.Event{
			ID: "event-1", Type: notification.EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-1", SchemaVersion: 1,
			OccurredAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
			Data:       json.RawMessage(`{"title":"Scan <done> & ok","summary":"All *good* <@U1>"}`),
		},
	}
}

type capturedRequest struct {
	body   []byte
	header http.Header
}

func captureSend(t *testing.T, kind notification.ChannelType, config func(url string) ports.NotificationChannelConfig) capturedRequest {
	t.Helper()
	var captured capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.body, _ = io.ReadAll(r.Body)
		captured.header = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	s.now = func() time.Time { return time.Unix(1700000100, 0) }
	if result := s.Send(context.Background(), goldenWork(kind), config(server.URL)); result.ErrorCode != "" {
		t.Fatalf("%s send: %+v", kind, result)
	}
	return captured
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWebhookWireOutputIsUnchanged(t *testing.T) {
	got := captureSend(t, notification.ChannelWebhook, func(url string) ports.NotificationChannelConfig {
		return ports.WebhookChannelConfig{URL: url, Secret: "0123456789abcdef"}
	})
	if want := readGolden(t, "webhook_body.golden"); !bytes.Equal(got.body, want) {
		t.Errorf("webhook body changed:\n got %s\nwant %s", got.body, want)
	}
	if want := string(readGolden(t, "webhook_signature.golden")); got.header.Get("X-Synapse-Signature") != want {
		t.Errorf("webhook signature = %q, want %q", got.header.Get("X-Synapse-Signature"), want)
	}
}

func TestSlackWireOutputIsUnchanged(t *testing.T) {
	got := captureSend(t, notification.ChannelSlack, func(url string) ports.NotificationChannelConfig {
		return ports.SlackChannelConfig{URL: url}
	})
	if want := readGolden(t, "slack_body.golden"); !bytes.Equal(got.body, want) {
		t.Errorf("slack body changed:\n got %s\nwant %s", got.body, want)
	}
}

func TestSendRefusesUnknownChannelTypes(t *testing.T) {
	result := New(SMTPConfig{}, time.Second).Send(context.Background(), testWork("carrier_pigeon"), ports.WebhookChannelConfig{URL: "https://example.com"})
	if result.ErrorCode != "unsupported_channel" || result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

// A configuration of another type must never reach a driver: a Slack URL used as a signed
// webhook, or the reverse, would send to the wrong receiver or without a signature.
func TestSendRefusesAConfigurationOfAnotherType(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests++; w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	for _, tc := range []struct {
		kind   notification.ChannelType
		config ports.NotificationChannelConfig
	}{
		{notification.ChannelWebhook, ports.SlackChannelConfig{URL: server.URL}},
		{notification.ChannelSlack, ports.WebhookChannelConfig{URL: server.URL}},
		{notification.ChannelEmail, ports.WebhookChannelConfig{URL: server.URL}},
		{notification.ChannelWebhook, nil},
	} {
		if result := s.Send(context.Background(), testWork(tc.kind), tc.config); result.ErrorCode != "channel_config_invalid" || result.Retryable {
			t.Errorf("%s with %T: result = %+v", tc.kind, tc.config, result)
		}
	}
	if requests != 0 {
		t.Fatalf("%d requests reached the receiver", requests)
	}
}

type recordingDriver struct {
	kind  notification.ChannelType
	calls int
}

func (d *recordingDriver) ChannelType() notification.ChannelType { return d.kind }

func (d *recordingDriver) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	d.calls++
	return ports.NotificationSendResult{StatusCode: http.StatusOK, RemoteRef: "1700000000.000100"}
}

type recordingConfig struct{}

func (recordingConfig) NotificationChannelType() notification.ChannelType { return "recording" }

func TestRegisterAddsAChannelWithoutTouchingSend(t *testing.T) {
	s := New(SMTPConfig{}, time.Second)
	driver := &recordingDriver{kind: "recording"}
	if err := s.Register(driver); err != nil {
		t.Fatal(err)
	}
	result := s.Send(context.Background(), testWork("recording"), recordingConfig{})
	if driver.calls != 1 || result.RemoteRef != "1700000000.000100" {
		t.Fatalf("calls=%d result=%+v", driver.calls, result)
	}
	if err := s.Register(&recordingDriver{kind: notification.ChannelSlack}); err == nil {
		t.Fatal("a second Slack driver replaced the built-in one")
	}
}

func TestBuiltinDriversCoverEveryChannelType(t *testing.T) {
	seen := map[notification.ChannelType]bool{}
	for _, driver := range builtinDrivers(nil) {
		if seen[driver.ChannelType()] {
			t.Errorf("two built-in drivers for %s", driver.ChannelType())
		}
		seen[driver.ChannelType()] = true
	}
	for _, kind := range []notification.ChannelType{notification.ChannelWebhook, notification.ChannelSlack, notification.ChannelEmail} {
		if !seen[kind] || !kind.Valid() {
			t.Errorf("no built-in driver for %s", kind)
		}
	}
}

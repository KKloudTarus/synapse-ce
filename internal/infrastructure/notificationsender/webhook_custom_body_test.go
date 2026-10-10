package notificationsender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const customBodySecret = "0123456789abcdef"

// verifySignature is what a receiver does: HMAC-SHA256 over "<timestamp>.<raw body>".
func verifySignature(t *testing.T, header http.Header, body []byte) {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(customBodySecret))
	mac.Write([]byte(header.Get("X-Synapse-Timestamp") + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := header.Get("X-Synapse-Signature"); !hmac.Equal([]byte(got), []byte(want)) {
		t.Fatalf("signature %s does not cover the body as sent (want %s)", got, want)
	}
}

func sendCustom(t *testing.T, body []byte) (capturedRequest, ports.NotificationSendResult, int) {
	t.Helper()
	var captured capturedRequest
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		captured.body = readAll(t, r)
		captured.header = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	s.now = func() time.Time { return time.Unix(1700000100, 0) }
	work := goldenWork(notification.ChannelWebhook)
	work.CustomWebhookBody = body
	result := s.Send(context.Background(), work, ports.WebhookChannelConfig{URL: server.URL, Secret: customBodySecret})
	return captured, result, requests
}

func readAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := b.ReadFrom(r.Body); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The driver sends the rendered custom body byte for byte, marks it, and signs exactly those bytes.
// The body is rendered from values trying to inject keys, and the receiver still sees the
// template's structure.
func TestWebhookSendsAndSignsTheCustomBody(t *testing.T) {
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: []string{"title"}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := notification.RenderCustomWebhookBody(`{"text":"{{.title}}","admin":false,"n":7}`, schema,
		msgtemplate.Data{Vars: map[string]string{"title": `x","admin":true,"y":"`}})
	if err != nil {
		t.Fatal(err)
	}
	got, result, _ := sendCustom(t, body)
	if result.ErrorCode != "" {
		t.Fatalf("send = %+v", result)
	}
	if !bytes.Equal(got.body, body) {
		t.Fatalf("sent %s, rendered %s", got.body, body)
	}
	if got.header.Get("X-Synapse-Body") != "custom" || got.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", got.header)
	}
	verifySignature(t, got.header, got.body)
	var decoded map[string]any
	if err := json.Unmarshal(got.body, &decoded); err != nil || decoded["admin"] != false || decoded["n"] != float64(7) || decoded["text"] != `x","admin":true,"y":"` || len(decoded) != 3 {
		t.Fatalf("receiver sees %v err=%v", decoded, err)
	}
}

// Without a custom body the envelope is sent unmarked, and its signature covers it.
func TestWebhookEnvelopeIsNotMarkedCustom(t *testing.T) {
	got := captureSend(t, notification.ChannelWebhook, func(url string) ports.NotificationChannelConfig {
		return ports.WebhookChannelConfig{URL: url, Secret: customBodySecret}
	})
	if got.header.Get("X-Synapse-Body") != "" {
		t.Fatalf("envelope marked as %q", got.header.Get("X-Synapse-Body"))
	}
	verifySignature(t, got.header, got.body)
}

// Bytes that are not one JSON value, or exceed the cap, are never sent.
func TestWebhookRefusesAnInvalidCustomBody(t *testing.T) {
	for name, body := range map[string][]byte{
		"not json":  []byte(`{"a":`),
		"two":       []byte(`{"a":1}{"b":2}`),
		"oversized": []byte(`{"a":"` + strings.Repeat("x", notification.MaxRenderedWebhookBodyBytes) + `"}`),
	} {
		_, result, requests := sendCustom(t, body)
		if result.ErrorCode != "custom_body_invalid" || result.Retryable || requests != 0 {
			t.Errorf("%s: result=%+v requests=%d", name, result, requests)
		}
	}
}

func TestWebhookRawModeUsesFilteredEnvelopeWhenEngagementLowersClass(t *testing.T) {
	var captured capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.body = readAll(t, r)
		captured.header = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender := New(SMTPConfig{}, time.Second)
	sender.http = server.Client()
	work := goldenWork(notification.ChannelWebhook)
	work.Channel.DataClass = notification.DataClassDetail
	work.Channel.RawEvent = true
	work.Engagement = notification.EngagementNotificationsSignal
	work.Event.Data = json.RawMessage(`{"title":"RAW-SECRET"}`)
	work.Event.Context = json.RawMessage(`{"vars":{"scan_kind":"sast","title":"RAW-SECRET"}}`)
	result := sender.Send(context.Background(), work, ports.WebhookChannelConfig{URL: server.URL, Secret: customBodySecret})
	if result.ErrorCode != "" {
		t.Fatalf("send = %+v", result)
	}
	if strings.Contains(string(captured.body), "RAW-SECRET") || !strings.Contains(string(captured.body), `"version":"synapse.notification.v1"`) {
		t.Fatalf("engagement-lowered raw event body = %s", captured.body)
	}
	verifySignature(t, captured.header, captured.body)
}

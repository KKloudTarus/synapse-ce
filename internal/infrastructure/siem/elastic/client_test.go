package elastic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

func TestBulkPartialDoesNotTreatConflictAsSuccess(t *testing.T) {
	var body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("content type %s", r.Header.Get("Content-Type"))
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errors":true,"items":[{"index":{"_id":"rec-1","status":201}},{"index":{"_id":"rec-2","status":409,"error":{"type":"conflict"}}},{"index":{"_id":"rec-3","status":201}}]}`)
	}))
	defer server.Close()
	result, err := testClient(server).Deliver(context.Background(), sample(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if result.Items[0].Disposition != siem.ItemAcked || result.Items[1].Disposition == siem.ItemAcked || !result.Items[1].Blocked || result.Items[2].Disposition != siem.ItemAcked {
		t.Fatalf("items %+v", result.Items)
	}
	if strings.Count(body, "\n") != 6 && strings.Count(body, "\n") != 4 {
		t.Fatalf("unexpected bulk framing: %q", body)
	}
	if !strings.Contains(body, `"_id":"rec-2"`) || strings.Contains(body, "api-key-secret") {
		t.Fatalf("body leaked or lost an id: %s", body)
	}
}

func TestMalformedAndThrottleDoNotAck(t *testing.T) {
	short := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer short.Close()
	if _, err := testClient(short).Deliver(context.Background(), sample(short.URL)); err == nil {
		t.Fatal("short response was accepted")
	}
	throttled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer throttled.Close()
	result, err := testClient(throttled).Deliver(context.Background(), sample(throttled.URL))
	if err != nil || !result.Items[0].Retryable || result.Items[0].RetryAfter != 2*time.Second {
		t.Fatalf("throttle %+v %v", result, err)
	}
}

func testClient(server *httptest.Server) *Client {
	httpClient := server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	return &Client{HTTP: httpClient, Guard: func(string) error { return nil }}
}

func sample(origin string) siem.Delivery {
	return siem.Delivery{
		Origin: origin, Secret: "api-key-secret", Target: "synapse-siem", AckMode: siem.AckBulkItem,
		Records: []siem.DeliveryRecord{
			{ID: "rec-1", Body: []byte(`{"action":"user.login"}`)},
			{ID: "rec-2", Body: []byte(`{"action":"user.login"}`)},
			{ID: "rec-3", Body: []byte(`{"action":"user.login"}`)},
		},
	}
}

package splunk

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

func TestHECCodeZeroIsRequired(t *testing.T) {
	var auth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "\n{") && !strings.Contains(string(body), `"event"`) {
			t.Errorf("body = %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()
	client := testClient(server)
	result, err := client.Deliver(context.Background(), sample(server.URL, siem.AckHECAcceptance))
	if err != nil || result.Items[0].Disposition != siem.ItemAcked {
		t.Fatalf("result %+v err %v", result, err)
	}
	if !strings.HasPrefix(auth, "Splunk ") {
		t.Fatalf("auth = %s", auth)
	}

	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"text":"Invalid data format","code":5}`))
	}))
	defer server2.Close()
	result, err = testClient(server2).Deliver(context.Background(), sample(server2.URL, siem.AckHECAcceptance))
	if err != nil || !result.Items[0].Blocked || strings.Contains(result.Items[0].Diagnostic, "splunk-secret") {
		t.Fatalf("nonzero code %+v %v", result, err)
	}
}

func TestIndexerAckIsExplicitAndPolled(t *testing.T) {
	client := &Client{HTTP: &http.Client{}, IndexerAck: false}
	result, err := client.Deliver(context.Background(), sample("https://splunk.example", siem.AckIndexer))
	if err != nil || !result.Items[0].Blocked {
		t.Fatalf("downgraded indexer ack: %+v %v", result, err)
	}
	var polls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ack") {
			polls++
			_, _ = w.Write([]byte(`{"acks":{"7":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":7}`))
	}))
	defer server.Close()
	ackClient := testClient(server).withAck()
	result, err = ackClient.Deliver(context.Background(), sample(server.URL, siem.AckIndexer))
	if err != nil || result.IndexerAckID == nil || *result.IndexerAckID != 7 || polls != 0 {
		t.Fatalf("receipt %+v polls %d err %v", result, polls, err)
	}
	confirmed, _, err := ackClient.PollAck(context.Background(), sample(server.URL, siem.AckIndexer), *result.IndexerAckID)
	if err != nil || !confirmed || polls != 1 {
		t.Fatalf("ack result %+v polls %d err %v", result, polls, err)
	}
}

func TestRedirectAndThrottle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
	}))
	defer server.Close()
	result, err := testClient(server).Deliver(context.Background(), sample(server.URL, siem.AckHECAcceptance))
	if err != nil || !result.Items[0].Blocked {
		t.Fatalf("redirect %+v %v", result, err)
	}
	throttled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer throttled.Close()
	result, err = testClient(throttled).Deliver(context.Background(), sample(throttled.URL, siem.AckHECAcceptance))
	if err != nil || !result.Items[0].Retryable || result.Items[0].RetryAfter != 3*time.Second {
		t.Fatalf("throttle %+v %v", result, err)
	}
}

func testClient(server *httptest.Server) *Client {
	httpClient := server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	return &Client{HTTP: httpClient, Guard: func(string) error { return nil }}
}

func (c *Client) withAck() *Client {
	c.IndexerAck = true
	return c
}

func sample(origin string, mode siem.AckMode) siem.Delivery {
	return siem.Delivery{
		Origin: origin, Secret: "splunk-secret", Target: "/services/collector/event", Channel: "channel-1",
		AckMode: mode, Records: []siem.DeliveryRecord{{ID: "rec-1", Body: []byte(`{"action":"user.login"}`)}},
	}
}

func TestHECResponseRequiresExplicitCodeAndAcceptsZeroAckID(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"code":null}`, `{"code":"0"}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		result, err := testClient(server).Deliver(context.Background(), sample(server.URL, siem.AckHECAcceptance))
		server.Close()
		if err == nil && len(result.Items) > 0 && result.Items[0].Disposition == siem.ItemAcked {
			t.Fatalf("malformed HEC response %s was acknowledged", body)
		}
	}
	polls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ack") {
			polls++
			_, _ = w.Write([]byte(`{"acks":{"0":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"ackId":0}`))
	}))
	defer server.Close()
	ackClient := testClient(server).withAck()
	result, err := ackClient.Deliver(context.Background(), sample(server.URL, siem.AckIndexer))
	if err != nil || result.IndexerAckID == nil || *result.IndexerAckID != 0 || polls != 0 {
		t.Fatalf("valid ack ID zero receipt: polls=%d result=%+v err=%v", polls, result, err)
	}
	confirmed, _, err := ackClient.PollAck(context.Background(), sample(server.URL, siem.AckIndexer), *result.IndexerAckID)
	if err != nil || !confirmed || polls != 1 {
		t.Fatalf("valid ack ID zero: polls=%d result=%+v err=%v", polls, result, err)
	}
}

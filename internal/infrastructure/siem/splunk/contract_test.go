package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// batch is a three-record delivery, so an assertion can tell a per-record result from a
// batch-level one.
func batch(origin string, mode siem.AckMode) siem.Delivery {
	delivery := sample(origin, mode)
	delivery.Records = []siem.DeliveryRecord{
		{ID: "rec-1", Body: []byte(`{"action":"user.login"}`)},
		{ID: "rec-2", Body: []byte(`{"action":"finding.created"}`)},
		{ID: "rec-3", Body: []byte(`{"action":"user.logout"}`)},
	}
	return delivery
}

// The event collector takes one JSON object per event, newline separated, with the event under
// "event". The token goes in `Authorization: Splunk <token>`, and a request that uses indexer
// acknowledgement carries the channel both as a header and as a query parameter.
// https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/get-data-with-http-event-collector/format-events-for-http-event-collector
func TestCollectorRequestMatchesTheDocumentedWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      siem.AckMode
		indexer   bool
		wantQuery string
	}{
		{name: "acceptance mode sends no channel query", mode: siem.AckHECAcceptance, wantQuery: ""},
		{name: "indexer mode sends the channel query", mode: siem.AckIndexer, indexer: true, wantQuery: "channel=channel-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got struct {
				method, path, query, contentType, auth, channel, body string
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.method, got.path, got.query = r.Method, r.URL.Path, r.URL.RawQuery
				got.contentType, got.auth = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
				got.channel = r.Header.Get("X-Splunk-Request-Channel")
				raw, _ := io.ReadAll(r.Body)
				got.body = string(raw)
				_, _ = io.WriteString(w, `{"text":"Success","code":0,"ackId":12}`)
			}))
			defer server.Close()

			client := testClient(server)
			client.IndexerAck = tc.indexer
			if _, err := client.Deliver(context.Background(), batch(server.URL, tc.mode)); err != nil {
				t.Fatal(err)
			}

			if got.method != http.MethodPost || got.path != "/services/collector/event" {
				t.Errorf("request line = %s %s, want POST /services/collector/event", got.method, got.path)
			}
			if got.query != tc.wantQuery {
				t.Errorf("query = %q, want %q", got.query, tc.wantQuery)
			}
			if got.contentType != "application/json" {
				t.Errorf("content type = %q, want application/json", got.contentType)
			}
			if got.auth != "Splunk splunk-secret" {
				t.Errorf("authorization = %q, want the Splunk scheme with the stored token", got.auth)
			}
			if got.channel != "channel-1" {
				t.Errorf("request channel = %q, want the sink channel on every request", got.channel)
			}
			if !strings.HasSuffix(got.body, "\n") {
				t.Errorf("the last event is not newline terminated: %q", got.body)
			}
			lines := strings.Split(strings.TrimSuffix(got.body, "\n"), "\n")
			if len(lines) != 3 {
				t.Fatalf("body has %d lines, want one per record: %q", len(lines), got.body)
			}
			for i, want := range []struct{ id, action string }{
				{"rec-1", "user.login"}, {"rec-2", "finding.created"}, {"rec-3", "user.logout"},
			} {
				var event struct {
					Event      map[string]any `json:"event"`
					Sourcetype string         `json:"sourcetype"`
					Fields     struct {
						RecordID string `json:"record_id"`
					} `json:"fields"`
				}
				if err := json.Unmarshal([]byte(lines[i]), &event); err != nil {
					t.Fatalf("event line %d is not json: %q", i, lines[i])
				}
				if event.Sourcetype != "synapse:siem" {
					t.Errorf("event line %d sourcetype = %q, want synapse:siem", i, event.Sourcetype)
				}
				if event.Fields.RecordID != want.id {
					t.Errorf("event line %d record_id = %q, want %s", i, event.Fields.RecordID, want.id)
				}
				if event.Event["action"] != want.action {
					t.Errorf("event line %d event = %v, want the record body unchanged", i, event.Event)
				}
			}
		})
	}
}

// A token belongs in the Authorization header and nowhere else.
func TestTheTokenNeverLeavesTheAuthorizationHeader(t *testing.T) {
	var gotURL, gotBody string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusUnauthorized)
		// A real collector names the token in its error. The client must not pass that on.
		_, _ = io.WriteString(w, `{"text":"Invalid token splunk-secret","code":4}`)
	}))
	defer server.Close()

	result, err := testClient(server).Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotURL, "splunk-secret") || strings.Contains(gotBody, "splunk-secret") {
		t.Errorf("the token reached the url (%s) or the body (%s)", gotURL, gotBody)
	}
	for i, item := range result.Items {
		if item.Disposition == siem.ItemAcked || !item.Blocked || item.Retryable {
			t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
		}
		if strings.Contains(item.Diagnostic, "splunk-secret") {
			t.Errorf("item %d diagnostic carried the token: %s", i, item.Diagnostic)
		}
	}
}

// TestOperatorDiagnosticsSurviveTheScrubber pins what the operator reads on a blocked sink.
// siem.SafeDiagnostic redacts everything after a credential marker, and `splunk ` is one of those
// markers, so a diagnostic that began with it lost its next word: "splunk rejected the credential"
// reached the operator as "[secret] the credential". The driver's own wording avoids the markers,
// and a credential the destination echoes is still redacted.
func TestOperatorDiagnosticsSurviveTheScrubber(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "a rejected credential", status: http.StatusUnauthorized, want: "the event collector rejected the credential"},
		{name: "a rejected batch", status: http.StatusBadRequest, want: "the event collector rejected the batch"},
		{name: "a throttled collector", status: http.StatusTooManyRequests, want: "the event collector returned 429"},
		{name: "a failing collector", status: http.StatusInternalServerError, want: "the event collector returned 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			result, err := testClient(server).Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance))
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Items[0].Diagnostic; got != tc.want {
				t.Errorf("diagnostic = %q, want %q", got, tc.want)
			}
			if strings.Contains(result.Items[0].Diagnostic, "[secret]") {
				t.Errorf("the scrubber ate part of an operator diagnostic: %q", result.Items[0].Diagnostic)
			}
		})
	}

	t.Run("an unsupported mode reads plainly", func(t *testing.T) {
		result, err := (&Client{HTTP: &http.Client{}}).Deliver(context.Background(), batch("https://splunk.example", siem.AckBulkItem))
		if err != nil {
			t.Fatal(err)
		}
		if got := result.Items[0].Diagnostic; got != "the event collector acknowledgement mode is not supported" {
			t.Errorf("diagnostic = %q", got)
		}
	})

	t.Run("a credential the destination echoes is still redacted", func(t *testing.T) {
		if got := siem.SafeDiagnostic("Authorization: Splunk 11111111-dead-beef-dead-111111111111 was rejected"); strings.Contains(got, "dead-beef") {
			t.Errorf("a token survived the scrubber: %q", got)
		}
	})
}

// TestTransportStatusClassification pins how each HTTP answer maps onto the batch. The difference
// between retryable and blocked decides whether the cursor can ever move past this batch.
func TestTransportStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		retryAfter    string
		wantBlocked   bool
		wantRetryable bool
		wantAfter     time.Duration
	}{
		{name: "unauthorized is blocked", status: http.StatusUnauthorized, wantBlocked: true},
		{name: "forbidden is blocked", status: http.StatusForbidden, wantBlocked: true},
		{name: "a bad request is blocked", status: http.StatusBadRequest, wantBlocked: true},
		{name: "a missing endpoint is blocked", status: http.StatusNotFound, wantBlocked: true},
		{name: "an oversized request is blocked", status: http.StatusRequestEntityTooLarge, wantBlocked: true},
		{name: "throttling is retryable with its delay", status: http.StatusTooManyRequests, retryAfter: "9", wantRetryable: true, wantAfter: 9 * time.Second},
		{name: "throttling without a delay is still retryable", status: http.StatusTooManyRequests, wantRetryable: true},
		{name: "a server error is retryable", status: http.StatusInternalServerError, wantRetryable: true},
		{name: "an unavailable collector is retryable", status: http.StatusServiceUnavailable, retryAfter: "4", wantRetryable: true, wantAfter: 4 * time.Second},
		{name: "a nonsense retry-after is ignored", status: http.StatusTooManyRequests, retryAfter: "later", wantRetryable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			result, err := testClient(server).Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance))
			if err != nil {
				t.Fatalf("status %d returned an error instead of a classified batch: %v", tc.status, err)
			}
			if len(result.Items) != 3 {
				t.Fatalf("items = %d, want one per record", len(result.Items))
			}
			for i, item := range result.Items {
				if item.Disposition != siem.ItemFailed {
					t.Errorf("item %d: %+v, want failed", i, item)
				}
				if item.Blocked != tc.wantBlocked || item.Retryable != tc.wantRetryable {
					t.Errorf("item %d: blocked=%v retryable=%v, want %v and %v", i, item.Blocked, item.Retryable, tc.wantBlocked, tc.wantRetryable)
				}
				if item.RetryAfter != tc.wantAfter {
					t.Errorf("item %d: retry after %v, want %v", i, item.RetryAfter, tc.wantAfter)
				}
			}
		})
	}
}

// TestHECCodeDecidesSuccess covers the collector's own verdict inside a 200. Only code zero is
// success, and a non-zero code blocks rather than retrying, because resending the same batch to
// the same misconfigured token would fail the same way.
func TestHECCodeDecidesSuccess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantAcked bool
		wantErr   bool
	}{
		{name: "code zero is success", body: `{"text":"Success","code":0}`, wantAcked: true},
		{name: "a token is disabled", body: `{"text":"Token disabled","code":1}`},
		{name: "no data", body: `{"text":"No data","code":5}`},
		{name: "an incorrect index", body: `{"text":"Incorrect index","code":7}`},
		{name: "a missing code is an error", body: `{"text":"Success"}`, wantErr: true},
		{name: "a null code is an error", body: `{"code":null}`, wantErr: true},
		{name: "a string code is an error", body: `{"code":"0"}`, wantErr: true},
		{name: "a body that is not json is an error", body: `Success`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			result, err := testClient(server).Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s was accepted", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s returned an error instead of a classified batch: %v", tc.name, err)
			}
			for i, item := range result.Items {
				if (item.Disposition == siem.ItemAcked) != tc.wantAcked {
					t.Errorf("item %d: %+v, want acked=%v", i, item, tc.wantAcked)
				}
				if !tc.wantAcked && (!item.Blocked || item.Retryable) {
					t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
				}
			}
		})
	}
}

// TestIndexerReceiptIsRequiredWhenRequested pins the receipt contract. A delivery in indexer mode
// acknowledges nothing by itself: it returns the receipt, and a response without a usable one is
// an error rather than a silent success.
func TestIndexerReceiptIsRequiredWhenRequested(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantID  int64
		wantErr bool
	}{
		{name: "a numeric receipt is kept", body: `{"text":"Success","code":0,"ackId":42}`, wantID: 42},
		{name: "receipt zero is valid", body: `{"text":"Success","code":0,"ackId":0}`, wantID: 0},
		{name: "a missing receipt is an error", body: `{"text":"Success","code":0}`, wantErr: true},
		{name: "a negative receipt is an error", body: `{"text":"Success","code":0,"ackId":-1}`, wantErr: true},
		{name: "a string receipt is an error", body: `{"text":"Success","code":0,"ackId":"42"}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			result, err := testClient(server).withAck().Deliver(context.Background(), batch(server.URL, siem.AckIndexer))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s was accepted: %+v", tc.name, result)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.IndexerAckID == nil || *result.IndexerAckID != tc.wantID {
				t.Fatalf("receipt = %v, want %d", result.IndexerAckID, tc.wantID)
			}
			if len(result.Items) != 0 {
				t.Errorf("an indexer-mode delivery acknowledged records before polling: %+v", result.Items)
			}
		})
	}
}

// TestPollAckClassification pins the poll endpoint: an unconfirmed receipt is not a failure, a
// throttled poll reports its delay, and a rejected or unreadable poll is an error. Treating any
// of those as confirmed would move a cursor past data the indexer never stored.
func TestPollAckClassification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		retryAfter    string
		body          string
		wantConfirmed bool
		wantWait      time.Duration
		wantErr       bool
	}{
		{name: "a confirmed receipt", status: http.StatusOK, body: `{"acks":{"7":true}}`, wantConfirmed: true},
		{name: "an unconfirmed receipt", status: http.StatusOK, body: `{"acks":{"7":false}}`},
		{name: "a receipt the collector does not know", status: http.StatusOK, body: `{"acks":{"9":true}}`},
		{name: "an empty ack map", status: http.StatusOK, body: `{"acks":{}}`},
		{name: "throttling reports its delay", status: http.StatusTooManyRequests, retryAfter: "6", wantWait: 6 * time.Second},
		{name: "a server error is not confirmation", status: http.StatusInternalServerError},
		{name: "a rejected poll is an error", status: http.StatusUnauthorized, wantErr: true},
		{name: "a malformed poll answer is an error", status: http.StatusOK, body: `not json`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotQuery, gotChannel, gotAuth, gotBody string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
				gotChannel, gotAuth = r.Header.Get("X-Splunk-Request-Channel"), r.Header.Get("Authorization")
				raw, _ := io.ReadAll(r.Body)
				gotBody = string(raw)
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			confirmed, wait, err := testClient(server).withAck().PollAck(context.Background(), sample(server.URL, siem.AckIndexer), 7)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s was accepted", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if confirmed != tc.wantConfirmed {
				t.Errorf("confirmed = %v, want %v", confirmed, tc.wantConfirmed)
			}
			if wait != tc.wantWait {
				t.Errorf("wait = %v, want %v", wait, tc.wantWait)
			}
			if gotPath != "/services/collector/ack" || gotQuery != "channel=channel-1" {
				t.Errorf("poll addressed %s?%s, want /services/collector/ack with the channel", gotPath, gotQuery)
			}
			if gotChannel != "channel-1" || gotAuth != "Splunk splunk-secret" {
				t.Errorf("poll sent channel %q and authorization %q", gotChannel, gotAuth)
			}
			if gotBody != `{"acks":[7]}` {
				t.Errorf("poll body = %q, want the receipt in an acks array", gotBody)
			}
		})
	}
}

// TestOversizedResponseIsRefused stops a destination from making the client hold an unbounded
// body in memory.
func TestOversizedResponseIsRefused(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"code":0,"text":"`)
		filler := strings.Repeat("x", 64<<10)
		for written := 0; written <= siem.MaxResponseBytes; written += len(filler) {
			_, _ = io.WriteString(w, filler)
		}
		_, _ = io.WriteString(w, `"}`)
	}))
	defer server.Close()
	if _, err := testClient(server).Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance)); err == nil {
		t.Fatal("an oversized response was accepted")
	}
}

// TestRequestsRefusedBeforeDialing covers every input the client rejects without opening a
// connection, so a malformed sink cannot reach a destination at all.
func TestRequestsRefusedBeforeDialing(t *testing.T) {
	var reached bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = io.WriteString(w, `{"code":0}`)
	}))
	defer server.Close()

	for _, tc := range []struct {
		name    string
		mutate  func(*siem.Delivery)
		wantErr bool
	}{
		{name: "an unsupported acknowledgement mode", mutate: func(d *siem.Delivery) { d.AckMode = siem.AckBulkItem }},
		{name: "an empty acknowledgement mode", mutate: func(d *siem.Delivery) { d.AckMode = "" }},
		{name: "a record body with a newline", mutate: func(d *siem.Delivery) {
			d.Records[0].Body = []byte("{\"action\":\"user.login\"}\n{\"action\":\"injected\"}")
		}},
		{name: "a record body that is not json", mutate: func(d *siem.Delivery) { d.Records[0].Body = []byte(`not json`) }},
		{name: "a batch over the byte cap", mutate: func(d *siem.Delivery) {
			d.Records[0].Body = []byte(`{"action":"` + strings.Repeat("x", siem.MaxBatchBytes) + `"}`)
		}},
		{name: "an http origin", mutate: func(d *siem.Delivery) { d.Origin = "http://splunk.example:8088" }, wantErr: true},
		{name: "an origin with userinfo", mutate: func(d *siem.Delivery) { d.Origin = "https://user:pass@splunk.example:8088" }, wantErr: true},
		{name: "an origin that is not a url", mutate: func(d *siem.Delivery) { d.Origin = "://" }, wantErr: true},
		{name: "a relative path", mutate: func(d *siem.Delivery) { d.Target = "services/collector/event" }, wantErr: true},
		{name: "a path that walks up", mutate: func(d *siem.Delivery) { d.Target = "/services/../../etc/passwd" }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			delivery := batch(server.URL, siem.AckHECAcceptance)
			tc.mutate(&delivery)
			result, err := testClient(server).Deliver(context.Background(), delivery)
			if reached {
				t.Errorf("%s still reached the destination", tc.name)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s was accepted", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s returned an error instead of a classified batch: %v", tc.name, err)
			}
			if len(result.Items) != 3 {
				t.Fatalf("items = %d, want one per record", len(result.Items))
			}
			for i, item := range result.Items {
				if item.Disposition != siem.ItemFailed || !item.Blocked || item.Retryable {
					t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
				}
			}
		})
	}
}

// TestBlockedHostIsNotDialed pins the destination guard.
func TestBlockedHostIsNotDialed(t *testing.T) {
	var reached bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer server.Close()
	client := testClient(server)
	client.Guard = func(string) error { return fmt.Errorf("blocked") }
	result, err := client.Deliver(context.Background(), batch(server.URL, siem.AckHECAcceptance))
	if err != nil {
		t.Fatal(err)
	}
	if reached {
		t.Error("a blocked host was still dialed")
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemFailed || !item.Blocked {
			t.Errorf("item %d: %+v, want blocked", i, item)
		}
	}
	if _, _, err := client.PollAck(context.Background(), sample(server.URL, siem.AckIndexer), 1); err == nil {
		t.Error("a blocked host was polled")
	}
}

// TestUnconfiguredClientIsAnError keeps a half-wired composition root from looking like a
// destination failure.
func TestUnconfiguredClientIsAnError(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Deliver(context.Background(), sample("https://splunk.example", siem.AckHECAcceptance)); err == nil {
		t.Error("a nil client delivered")
	}
	if _, err := (&Client{}).Deliver(context.Background(), sample("https://splunk.example", siem.AckHECAcceptance)); err == nil {
		t.Error("a client without an http client delivered")
	}
}

// TestNewClampsTheTimeoutAndDoesNotInferIndexerAck keeps a sink from holding a worker slot for an
// arbitrary time, and keeps the receipt capability explicit.
func TestNewClampsTheTimeoutAndDoesNotInferIndexerAck(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back", 0, 5 * time.Second},
		{"negative falls back", -time.Second, 5 * time.Second},
		{"too long falls back", time.Minute, 5 * time.Second},
		{"a sane value is kept", 3 * time.Second, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New(tc.in, false)
			if client.HTTP.Timeout != tc.want {
				t.Errorf("New(%v) timeout = %v, want %v", tc.in, client.HTTP.Timeout, tc.want)
			}
			if client.IndexerAck {
				t.Error("indexer acknowledgement was inferred")
			}
		})
	}
}

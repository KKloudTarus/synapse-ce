package elastic

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

// The wire format is fixed by the Elasticsearch bulk API: one action line and one source line per
// record, newline separated, with the final line also ending in a newline, and a Content-Type of
// application/x-ndjson. An API key authenticates as `ApiKey <base64(id:api_key)>`.
// https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
func TestBulkRequestMatchesTheDocumentedWireFormat(t *testing.T) {
	var (
		gotPath        string
		gotMethod      string
		gotContentType string
		gotAuth        string
		gotBody        string
		gotQuery       string
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotQuery = r.URL.Path, r.Method, r.URL.RawQuery
		gotContentType, gotAuth = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		_, _ = io.WriteString(w, `{"errors":false,"items":[{"index":{"_id":"rec-1","status":201}},{"index":{"_id":"rec-2","status":200}},{"index":{"_id":"rec-3","status":201}}]}`)
	}))
	defer server.Close()

	result, err := testClient(server).Deliver(context.Background(), sample(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemAcked {
			t.Fatalf("item %d: %+v, want acked", i, item)
		}
	}

	if gotMethod != http.MethodPost || gotPath != "/synapse-siem/_bulk" || gotQuery != "" {
		t.Errorf("request line = %s %s?%s, want POST /synapse-siem/_bulk with no query", gotMethod, gotPath, gotQuery)
	}
	if gotContentType != "application/x-ndjson" {
		t.Errorf("content type = %q, want application/x-ndjson", gotContentType)
	}
	if gotAuth != "ApiKey api-key-secret" {
		t.Errorf("authorization = %q, want the ApiKey scheme with the stored credential", gotAuth)
	}
	if !strings.HasSuffix(gotBody, "\n") {
		t.Errorf("the final line does not end with a newline: %q", gotBody)
	}
	lines := strings.Split(strings.TrimSuffix(gotBody, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("body has %d lines, want two per record: %q", len(lines), gotBody)
	}
	for i, id := range []string{"rec-1", "rec-2", "rec-3"} {
		var action struct {
			Index struct {
				Index string `json:"_index"`
				ID    string `json:"_id"`
			} `json:"index"`
		}
		if err := json.Unmarshal([]byte(lines[i*2]), &action); err != nil {
			t.Fatalf("action line %d is not json: %q", i, lines[i*2])
		}
		if action.Index.Index != "synapse-siem" || action.Index.ID != id {
			t.Errorf("action line %d = %q, want index synapse-siem and id %s", i, lines[i*2], id)
		}
		if lines[i*2+1] != `{"action":"user.login"}` {
			t.Errorf("source line %d = %q, want the record body unchanged", i, lines[i*2+1])
		}
	}
	// A pretty-printed line would break the framing the API requires.
	if strings.Contains(gotBody, "\n  ") || strings.Contains(gotBody, "\r") {
		t.Errorf("body is not compact ndjson: %q", gotBody)
	}
}

// A credential belongs in the Authorization header and nowhere else. The URL, the body and every
// diagnostic are places a credential could leak into a log, so each is checked.
func TestTheCredentialNeverLeavesTheAuthorizationHeader(t *testing.T) {
	var gotURL, gotBody string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusUnauthorized)
		// A real cluster echoes the key id in its error. The client must not pass that on.
		_, _ = io.WriteString(w, `{"error":{"reason":"unable to authenticate with provided credentials api-key-secret"}}`)
	}))
	defer server.Close()

	result, err := testClient(server).Deliver(context.Background(), sample(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotURL, "api-key-secret") || strings.Contains(gotBody, "api-key-secret") {
		t.Errorf("the credential reached the url (%s) or the body (%s)", gotURL, gotBody)
	}
	for i, item := range result.Items {
		if item.Disposition == siem.ItemAcked || !item.Blocked || item.Retryable {
			t.Errorf("item %d: %+v, want blocked and not retryable", i, item)
		}
		if strings.Contains(item.Diagnostic, "api-key-secret") {
			t.Errorf("item %d diagnostic carried the credential: %s", i, item.Diagnostic)
		}
	}
}

// TestTransportStatusClassification pins how each HTTP answer maps onto the batch, because the
// difference between retryable and blocked decides whether a cursor can ever move past the batch.
func TestTransportStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		retryAfter    string
		location      string
		wantBlocked   bool
		wantRetryable bool
		wantAfter     time.Duration
	}{
		{name: "a redirect is not followed", status: http.StatusFound, location: "https://elsewhere.example/_bulk", wantBlocked: true},
		{name: "unauthorized is blocked", status: http.StatusUnauthorized, wantBlocked: true},
		{name: "forbidden is blocked", status: http.StatusForbidden, wantBlocked: true},
		{name: "a bad request is blocked", status: http.StatusBadRequest, wantBlocked: true},
		{name: "throttling is retryable with its delay", status: http.StatusTooManyRequests, retryAfter: "7", wantRetryable: true, wantAfter: 7 * time.Second},
		{name: "throttling without a delay is still retryable", status: http.StatusTooManyRequests, wantRetryable: true},
		{name: "a server error is retryable", status: http.StatusInternalServerError, wantRetryable: true},
		{name: "an unavailable cluster is retryable", status: http.StatusServiceUnavailable, retryAfter: "3", wantRetryable: true, wantAfter: 3 * time.Second},
		{name: "a nonsense retry-after is ignored", status: http.StatusTooManyRequests, retryAfter: "soon", wantRetryable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			result, err := testClient(server).Deliver(context.Background(), sample(server.URL))
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

// TestPerItemStatusClassification covers the answer the API actually gives on a partial failure: a
// 200 whose items disagree. A conflict is not evidence this generation was stored.
func TestPerItemStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		wantAcked     bool
		wantBlocked   bool
		wantRetryable bool
	}{
		{name: "200 is stored", status: http.StatusOK, wantAcked: true},
		{name: "201 is stored", status: http.StatusCreated, wantAcked: true},
		{name: "409 is not a duplicate success", status: http.StatusConflict, wantBlocked: true},
		{name: "400 is blocked", status: http.StatusBadRequest, wantBlocked: true},
		{name: "403 is blocked", status: http.StatusForbidden, wantBlocked: true},
		{name: "429 is retryable", status: http.StatusTooManyRequests, wantRetryable: true},
		{name: "503 is retryable", status: http.StatusServiceUnavailable, wantRetryable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, fmt.Sprintf(
					`{"errors":true,"items":[{"index":{"_id":"rec-1","status":%d}},{"index":{"_id":"rec-2","status":201}},{"index":{"_id":"rec-3","status":201}}]}`, tc.status))
			}))
			defer server.Close()

			result, err := testClient(server).Deliver(context.Background(), sample(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			first := result.Items[0]
			if (first.Disposition == siem.ItemAcked) != tc.wantAcked {
				t.Errorf("item status %d: %+v, want acked=%v", tc.status, first, tc.wantAcked)
			}
			if first.Blocked != tc.wantBlocked || first.Retryable != tc.wantRetryable {
				t.Errorf("item status %d: blocked=%v retryable=%v, want %v and %v", tc.status, first.Blocked, first.Retryable, tc.wantBlocked, tc.wantRetryable)
			}
			// The records after a failed one are judged on their own answer, so a cursor can
			// still cross the acknowledged prefix.
			if result.Items[1].Disposition != siem.ItemAcked || result.Items[2].Disposition != siem.ItemAcked {
				t.Errorf("a failure changed its neighbours: %+v", result.Items)
			}
		})
	}
}

// TestMisalignedResponseIsAnError pins the responses the client refuses to interpret. Guessing
// which record an item belongs to would move a cursor past a record nobody stored.
func TestMisalignedResponseIsAnError(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"fewer items than records", `{"items":[{"index":{"_id":"rec-1","status":201}}]}`},
		{"more items than records", `{"items":[{"index":{"_id":"rec-1","status":201}},{"index":{"_id":"rec-2","status":201}},{"index":{"_id":"rec-3","status":201}},{"index":{"_id":"rec-4","status":201}}]}`},
		{"another action key", `{"items":[{"create":{"_id":"rec-1","status":201}},{"index":{"_id":"rec-2","status":201}},{"index":{"_id":"rec-3","status":201}}]}`},
		{"a reordered id", `{"items":[{"index":{"_id":"rec-3","status":201}},{"index":{"_id":"rec-2","status":201}},{"index":{"_id":"rec-1","status":201}}]}`},
		{"not json at all", `<html>502 Bad Gateway</html>`},
		{"no items member", `{"took":3,"errors":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			if _, err := testClient(server).Deliver(context.Background(), sample(server.URL)); err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
		})
	}
}

// TestOversizedResponseIsRefused stops a destination from making the client hold an unbounded
// body in memory. The body is otherwise valid and carries exactly the three expected items, so
// the only reason to refuse it is the byte cap: with the cap removed this response parses and
// the delivery succeeds, which is what makes the assertion specific.
func TestOversizedResponseIsRefused(t *testing.T) {
	var sent int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One ignored field carries the weight. Elasticsearch itself returns unknown fields
		// the client skips, so an oversized answer is a real shape rather than a malformed one.
		filler := strings.Repeat("x", siem.MaxResponseBytes+1024)
		body := `{"took":3,"errors":false,"note":"` + filler + `","items":[` +
			`{"index":{"_id":"rec-1","status":201}},` +
			`{"index":{"_id":"rec-2","status":201}},` +
			`{"index":{"_id":"rec-3","status":201}}]}`
		sent = len(body)
		if !json.Valid([]byte(body)) {
			t.Errorf("the oversized fixture is not valid json")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	_, err := testClient(server).Deliver(context.Background(), sample(server.URL))
	if err == nil {
		t.Fatal("an oversized response was accepted")
	}
	if !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("error = %v, want the response byte cap", err)
	}
	if sent <= siem.MaxResponseBytes {
		t.Fatalf("the fixture was %d bytes, which does not exceed the %d byte cap", sent, siem.MaxResponseBytes)
	}
}

// TestRequestsRefusedBeforeDialing covers every input the client rejects without opening a
// connection, so a malformed sink cannot reach a destination at all.
func TestRequestsRefusedBeforeDialing(t *testing.T) {
	var reached bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer server.Close()

	for _, tc := range []struct {
		name     string
		mutate   func(*siem.Delivery)
		wantErr  bool
		wantLoud string
	}{
		{name: "another acknowledgement mode", mutate: func(d *siem.Delivery) { d.AckMode = siem.AckIndexer }},
		{name: "an index with a path separator", mutate: func(d *siem.Delivery) { d.Target = "synapse/siem" }},
		{name: "a hidden index", mutate: func(d *siem.Delivery) { d.Target = "_internal" }},
		{name: "an index with a newline", mutate: func(d *siem.Delivery) { d.Target = "synapse\nsiem" }},
		{name: "a record body with a newline", mutate: func(d *siem.Delivery) {
			d.Records[0].Body = []byte("{\"action\":\"user.login\"}\n{\"action\":\"injected\"}")
		}},
		{name: "a record body that is not json", mutate: func(d *siem.Delivery) { d.Records[0].Body = []byte(`not json`) }},
		{name: "a batch over the byte cap", mutate: func(d *siem.Delivery) {
			d.Records[0].Body = []byte(`{"action":"` + strings.Repeat("x", siem.MaxBatchBytes) + `"}`)
		}},
		{name: "an http origin", mutate: func(d *siem.Delivery) { d.Origin = "http://cluster.example:9200" }, wantErr: true},
		{name: "an origin with userinfo", mutate: func(d *siem.Delivery) { d.Origin = "https://user:pass@cluster.example:9200" }, wantErr: true},
		{name: "an origin that is not a url", mutate: func(d *siem.Delivery) { d.Origin = "://" }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			delivery := sample(server.URL)
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

// TestBlockedHostIsNotDialed pins the destination guard: a host the policy refuses fails the batch
// without a request, and the diagnostic names no address.
func TestBlockedHostIsNotDialed(t *testing.T) {
	var reached bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer server.Close()
	client := testClient(server)
	client.Guard = func(string) error { return fmt.Errorf("blocked") }
	result, err := client.Deliver(context.Background(), sample(server.URL))
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
}

// TestUnconfiguredClientIsAnError keeps a half-wired composition root from looking like a
// destination failure.
func TestUnconfiguredClientIsAnError(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Deliver(context.Background(), sample("https://cluster.example:9200")); err == nil {
		t.Error("a nil client delivered")
	}
	if _, err := (&Client{}).Deliver(context.Background(), sample("https://cluster.example:9200")); err == nil {
		t.Error("a client without an http client delivered")
	}
}

// TestNewClampsTheTimeout keeps a sink from holding a worker slot for an arbitrary time.
func TestNewClampsTheTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back", 0, 5 * time.Second},
		{"negative falls back", -time.Second, 5 * time.Second},
		{"too long falls back", time.Minute, 5 * time.Second},
		{"a sane value is kept", 2 * time.Second, 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.in).HTTP.Timeout; got != tc.want {
				t.Errorf("New(%v) timeout = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestLiveOriginRefusesAnythingButHTTPS guards the live suite's own credential handling: the API
// key is attached to every administrative call it makes, so an origin that is not plain https
// has to be refused before the first request rather than by the driver afterwards.
func TestLiveOriginRefusesAnythingButHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		valid        bool
	}{
		{name: "https host and port", origin: "https://127.0.0.1:19243", valid: true},
		{name: "https with a trailing slash", origin: "https://cluster.example/", valid: true},
		{name: "plain http", origin: "http://127.0.0.1:19243"},
		{name: "no scheme", origin: "127.0.0.1:19243"},
		{name: "userinfo", origin: "https://elastic:secret@cluster.example"},
		{name: "a path", origin: "https://cluster.example/es"},
		{name: "a query", origin: "https://cluster.example?pretty=true"},
		{name: "a fragment", origin: "https://cluster.example#frag"},
		{name: "empty", origin: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := liveOrigin(tc.origin); (err == nil) != tc.valid {
				t.Fatalf("liveOrigin(%q) = %v, want valid=%v", tc.origin, err, tc.valid)
			}
		})
	}
}

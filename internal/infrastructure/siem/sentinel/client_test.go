package sentinel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

const (
	testTenant = "11111111-1111-4111-8111-111111111111"
	testClient = "22222222-2222-4222-8222-222222222222"
	testSecret = "sentinel-client-secret"
	testDCR    = "dcr-0123456789abcdef0123456789abcdef"
	testStream = "Custom-SynapseSIEM"
)

func TestLogsIngestionContract(t *testing.T) {
	var sawToken, sawIngest bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			sawToken = true
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Fatalf("token request = %s %s", r.Method, r.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(r.Body)
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatal(err)
			}
			if form.Get("client_id") != testClient || form.Get("client_secret") != testSecret || form.Get("grant_type") != "client_credentials" || form.Get("scope") != monitorScope {
				t.Fatalf("unexpected token form: %#v", form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token_type":"Bearer","access_token":"access-token"}`)
		case strings.Contains(r.URL.Path, "/dataCollectionRules/"):
			sawIngest = true
			if r.Method != http.MethodPost || r.URL.Path != "/dataCollectionRules/"+testDCR+"/streams/"+testStream || r.URL.Query().Get("api-version") != apiVersion {
				t.Fatalf("ingestion request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected ingestion headers")
			}
			if r.Header.Get("X-MS-Client-Request-Id") != "" {
				t.Fatal("sentinel must not reuse the stable sink channel as a per-request client id")
			}
			var records []struct {
				TimeGenerated  string         `json:"TimeGenerated"`
				RecordID       string         `json:"SynapseRecordId"`
				SourcePosition map[string]any `json:"SynapseSourcePosition"`
				SourceHash     string         `json:"SynapseSourceHash"`
				Payload        map[string]any `json:"SynapsePayload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].RecordID != "record-1" || records[0].SourceHash != "hash-1" || records[0].SourcePosition["source"] != "audit" || records[0].Payload["action"] != "finding.created" {
				t.Fatalf("unexpected records: %#v", records)
			}
			if records[0].TimeGenerated != "2026-09-21T14:13:20.000000Z" {
				t.Fatalf("TimeGenerated = %s", records[0].TimeGenerated)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testSentinelClient(server)
	result, err := client.Deliver(context.Background(), sample(server.URL))
	if err != nil || len(result.Items) != 1 || result.Items[0].Disposition != siem.ItemAcked || !sawToken || !sawIngest {
		t.Fatalf("result=%+v token=%t ingest=%t err=%v", result, sawToken, sawIngest, err)
	}
}

func TestOnlyNoContentAcknowledgesIngestion(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = io.WriteString(w, `{"access_token":"access-token"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := testSentinelClient(server).Deliver(context.Background(), sample(server.URL))
	if err != nil || len(result.Items) != 1 || !result.Items[0].Blocked || result.Items[0].Disposition == siem.ItemAcked {
		t.Fatalf("HTTP 200 result=%+v err=%v", result, err)
	}
}

func TestThrottleAndCredentialFailuresAreSafe(t *testing.T) {
	t.Run("ingestion throttle", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
				_, _ = io.WriteString(w, `{"access_token":"access-token"}`)
				return
			}
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		result, err := testSentinelClient(server).Deliver(context.Background(), sample(server.URL))
		if err != nil || !result.Items[0].Retryable || result.Items[0].Blocked || result.Items[0].RetryAfter != 3*time.Second {
			t.Fatalf("throttle result=%+v err=%v", result, err)
		}
	})

	t.Run("identity rejection", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error_description":"`+testSecret+`"}`)
		}))
		defer server.Close()
		result, err := testSentinelClient(server).Deliver(context.Background(), sample(server.URL))
		if err != nil || !result.Items[0].Blocked || result.Items[0].Retryable || strings.Contains(result.Items[0].Diagnostic, testSecret) {
			t.Fatalf("identity result=%+v err=%v", result, err)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
				_, _ = io.WriteString(w, `{"access_token":"access-token"}`)
				return
			}
			http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
		}))
		defer server.Close()
		result, err := testSentinelClient(server).Deliver(context.Background(), sample(server.URL))
		if err != nil || !result.Items[0].Blocked || result.Items[0].Disposition == siem.ItemAcked {
			t.Fatalf("redirect result=%+v err=%v", result, err)
		}
	})
}

func TestRejectsNonAzureIngestionHostBeforeTokenAcquisition(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer server.Close()
	client := &Client{http: server.Client(), guard: func(string) error { return nil }, authority: server.URL}
	result, err := client.Deliver(context.Background(), sample("https://collector.example"))
	if err != nil || len(result.Items) != 1 || !result.Items[0].Blocked || result.Items[0].Retryable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if calls != 0 {
		t.Fatalf("made %d network calls before rejecting non-Azure ingestion host", calls)
	}
}

func TestRejectsCustomIngestionPortBeforeTokenAcquisition(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer server.Close()
	client := &Client{http: server.Client(), guard: func(string) error { return nil }, authority: server.URL}
	result, err := client.Deliver(context.Background(), sample("https://example.eastus-1.ingest.monitor.azure.com:8443"))
	if err != nil || len(result.Items) != 1 || !result.Items[0].Blocked || result.Items[0].Retryable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if calls != 0 {
		t.Fatalf("made %d network calls before rejecting custom ingestion port", calls)
	}
}

func TestEncodeAllowsWrapperOverheadAboveRawBatchCap(t *testing.T) {
	records := make([]siem.DeliveryRecord, 0, siem.MaxBatchRecords)
	rawBytes := 0
	for i := 0; i < siem.MaxBatchRecords; i++ {
		body := []byte(`{"time":1790000000000,"message":"` + strings.Repeat("x", 2400) + `","source":{"kind":"audit","id":1,"hash_version":2,"source_hash":"hash"}}`)
		rawBytes += len(body)
		records = append(records, siem.DeliveryRecord{ID: "record-" + strconv.Itoa(i), Body: body})
	}
	if rawBytes >= siem.MaxBatchBytes {
		t.Fatalf("test raw batch = %d, want below %d", rawBytes, siem.MaxBatchBytes)
	}
	body, err := encode(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= siem.MaxBatchBytes {
		t.Fatalf("wire body = %d, expected wrapper overhead above raw cap %d", len(body), siem.MaxBatchBytes)
	}
	if len(body) > maxRequestBytes {
		t.Fatalf("wire body = %d, exceeds Sentinel request cap %d", len(body), maxRequestBytes)
	}
}

func TestDialTimePolicyRefusalBlocksWithoutRetry(t *testing.T) {
	client := &Client{
		http: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"access-token"}`)),
					Request:    r,
				}, nil
			}
			return nil, fmt.Errorf("dial refused: %w", safehttp.ErrBlockedDestination)
		})},
		authority:          defaultAuthority,
		allowIngestionHost: func(string) bool { return true },
	}
	result, err := client.Deliver(context.Background(), sample("https://example.eastus-1.ingest.monitor.azure.com"))
	if err != nil || len(result.Items) != 1 || !result.Items[0].Blocked || result.Items[0].Retryable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCredentialValidationIsStrict(t *testing.T) {
	valid := `{"tenant_id":"` + testTenant + `","client_id":"` + testClient + `","client_secret":"` + testSecret + `"}`
	parsed, err := parseCredential(valid)
	if err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	if parsed.TenantID != testTenant || parsed.ClientID != testClient {
		t.Fatalf("credential ids were not canonical: %+v", parsed)
	}
	canonicalizable := `{"tenant_id":"ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF","client_id":"ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDE0","client_secret":"` + testSecret + `"}`
	normalized, err := parseCredential(canonicalizable)
	if err != nil {
		t.Fatalf("canonicalizable credential rejected: %v", err)
	}
	if normalized.TenantID != "abcdefab-cdef-4abc-8def-abcdefabcdef" || normalized.ClientID != "abcdefab-cdef-4abc-8def-abcdefabcde0" {
		t.Fatalf("canonicalized ids = %s %s", normalized.TenantID, normalized.ClientID)
	}
	invalid := []string{
		`{"tenant_id":"00000000-0000-0000-0000-000000000000","client_id":"` + testClient + `","client_secret":"` + testSecret + `"}`,
		`{"tenant_id":"` + testTenant + `","client_id":"00000000-0000-0000-0000-000000000000","client_secret":"` + testSecret + `"}`,
		`{"tenant_id":"not-a-uuid","client_id":"` + testClient + `","client_secret":"` + testSecret + `"}`,
		`{"tenant_id":"` + testTenant + `","client_id":"not-a-uuid","client_secret":"` + testSecret + `"}`,
		`{"tenant_id":"` + testTenant + `","client_id":"` + testClient + `","client_secret":"abc"}`,
		`{"tenant_id":"` + testTenant + `","client_id":"` + testClient + `","client_secret":"secret\nvalue"}`,
		`{"tenant_id":"` + testTenant + `","client_id":"` + testClient + `","client_secret":"` + testSecret + `","unexpected":true}`,
		valid + ` {}`,
	}
	for _, raw := range invalid {
		if _, err := parseCredential(raw); err == nil {
			t.Fatalf("invalid credential accepted: %q", raw)
		}
	}
}

func TestSourceEvidenceFromIncidentEnvelope(t *testing.T) {
	position, hash := sourceEvidence([]byte(`{"incident_id":"inc-1","event_seq":3,"source":{"kind":"live","stream_seq":9}}`))
	var decoded map[string]any
	if err := json.Unmarshal(position, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["source"] != "live" || decoded["stream_seq"] != float64(9) || decoded["incident_id"] != "inc-1" || decoded["event_seq"] != float64(3) || hash != "" {
		t.Fatalf("position=%s hash=%q", position, hash)
	}
}

func TestSourceEvidenceFromOCSFUnmapped(t *testing.T) {
	position, hash := sourceEvidence([]byte(`{"unmapped":{"synapse_source_position":{"source":"audit","id":9,"hash_version":2},"synapse_source_hash":"hash-9"}}`))
	var decoded map[string]any
	if err := json.Unmarshal(position, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["source"] != "audit" || decoded["id"] != float64(9) || hash != "hash-9" {
		t.Fatalf("position=%s hash=%q", position, hash)
	}
}

func TestIngestionURLRejectsMalformedOrigin(t *testing.T) {
	if _, _, err := ingestionURL("https://%gh", testDCR+"/"+testStream); err == nil {
		t.Fatal("malformed origin was accepted")
	}
	if _, _, err := ingestionURL("https://example.eastus-1.ingest.monitor.azure.com", testDCR+"/SynapseSIEM"); err == nil {
		t.Fatal("sentinel stream without Custom- prefix was accepted")
	}
	if _, _, err := ingestionURL("https://example.eastus-1.ingest.monitor.azure.com", testDCR+"/Custom-"); err == nil {
		t.Fatal("sentinel stream with an empty name was accepted")
	}
}

func TestRetryAfterIsBounded(t *testing.T) {
	header := make(http.Header)
	header.Set("Retry-After", "999999999999")
	if got := retryAfter(header); got != siem.MaxRetry {
		t.Fatalf("Retry-After = %s, want %s", got, siem.MaxRetry)
	}
	header.Set("Retry-After", "not-a-number")
	if got := retryAfter(header); got != 0 {
		t.Fatalf("invalid Retry-After = %s, want 0", got)
	}
}

func TestNewRequiresVerifiedTLS12OrHigher(t *testing.T) {
	client := New(time.Second)
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("sentinel client does not expose a TLS policy")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("sentinel client disables certificate verification")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x", transport.TLSClientConfig.MinVersion)
	}
	if transport.Proxy != nil || transport.DialContext == nil {
		t.Fatal("sentinel client bypassed the safehttp transport policy")
	}
	if client.http.CheckRedirect == nil {
		t.Fatal("sentinel client has no redirect policy")
	}
	request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.http.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy returned %v", err)
	}
	if client.authority != defaultAuthority {
		t.Fatalf("authority = %s", client.authority)
	}
}

func testSentinelClient(server *httptest.Server) *Client {
	httpClient := server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		http: httpClient, guard: func(string) error { return nil }, authority: server.URL,
		allowIngestionHost: func(string) bool { return true },
	}
}

func sample(origin string) siem.Delivery {
	credential := `{"tenant_id":"` + testTenant + `","client_id":"` + testClient + `","client_secret":"` + testSecret + `"}`
	return siem.Delivery{
		Origin: origin, Secret: credential, Target: testDCR + "/" + testStream, Channel: "channel-1",
		AckMode: siem.AckIngestionAcceptance,
		Records: []siem.DeliveryRecord{{
			ID:   "record-1",
			Body: []byte(`{"action":"finding.created","time":1790000000000,"source":{"kind":"audit","id":7,"hash_version":2,"source_hash":"hash-1"}}`),
		}},
	}
}

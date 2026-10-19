package splunk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// The live suite runs against a real Splunk and is opt-in, like the Postgres suite. Set:
//
//	SYNAPSE_TEST_SPLUNK_URL        https origin of the event collector, for example https://127.0.0.1:18088
//	SYNAPSE_TEST_SPLUNK_TOKEN      HEC token with indexer acknowledgement off
//	SYNAPSE_TEST_SPLUNK_ACK_TOKEN  optional HEC token with indexer acknowledgement on
//	SYNAPSE_TEST_SPLUNK_CA         optional PEM bundle that signs the collector certificate
//	SYNAPSE_TEST_SPLUNK_MGMT_URL   optional management origin, for example https://127.0.0.1:18089
//	SYNAPSE_TEST_SPLUNK_MGMT_AUTH  optional user:password for the management API, used to search
//	SYNAPSE_TEST_SPLUNK_INDEX      optional index to search, default main
//
// Splunk authenticates a collector token as `Authorization: Splunk <token>`, and HTTP 200 is not
// success on its own: the HEC code in the body must be zero.
const (
	envSplunkURL      = "SYNAPSE_TEST_SPLUNK_URL"
	envSplunkToken    = "SYNAPSE_TEST_SPLUNK_TOKEN"
	envSplunkAckToken = "SYNAPSE_TEST_SPLUNK_ACK_TOKEN"
	envSplunkCA       = "SYNAPSE_TEST_SPLUNK_CA"
	envSplunkMgmtURL  = "SYNAPSE_TEST_SPLUNK_MGMT_URL"
	envSplunkMgmtAuth = "SYNAPSE_TEST_SPLUNK_MGMT_AUTH"
	envSplunkIndex    = "SYNAPSE_TEST_SPLUNK_INDEX"
)

type liveSplunk struct {
	origin   string
	token    string
	ackToken string
	mgmt     string
	mgmtAuth string
	index    string
	http     *http.Client
}

func liveSetup(t *testing.T) liveSplunk {
	t.Helper()
	origin, token := os.Getenv(envSplunkURL), os.Getenv(envSplunkToken)
	if origin == "" || token == "" {
		t.Skipf("set %s and %s to run the live Splunk contract", envSplunkURL, envSplunkToken)
	}
	// Both origins carry a credential on every request: the collector token on the delivery
	// path and the management user and password on the search path. safehttp constrains the
	// address and refuses redirects; it does not require TLS, so the scheme is checked here
	// before anything is sent.
	if err := liveOrigin(origin); err != nil {
		t.Fatalf("%s: %v", envSplunkURL, err)
	}
	if mgmt := os.Getenv(envSplunkMgmtURL); mgmt != "" {
		if err := liveOrigin(mgmt); err != nil {
			t.Fatalf("%s: %v", envSplunkMgmtURL, err)
		}
	}
	index := os.Getenv(envSplunkIndex)
	if index == "" {
		index = "main"
	}
	return liveSplunk{
		origin: origin, token: token, ackToken: os.Getenv(envSplunkAckToken),
		mgmt: os.Getenv(envSplunkMgmtURL), mgmtAuth: os.Getenv(envSplunkMgmtAuth),
		index: index, http: liveHTTP(t),
	}
}

// liveOrigin accepts only an https origin with nothing else in it.
func liveOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("origin is not a URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("origin must be https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("origin must be https://host[:port] with no userinfo, path, query or fragment")
	}
	return nil
}

// liveHTTP keeps the production safe dialer and the production TLS verification, and differs from
// the shipped client in one way: it dials under safehttp.OperatorPolicy, which admits a loopback
// address because a collector under test runs on the loopback interface. A tenant-configured
// destination never gets that policy (see docs/guide/siem-stream.md).
func liveHTTP(t *testing.T) *http.Client {
	t.Helper()
	client := safehttp.NewClient(20*time.Second, safehttp.OperatorPolicy())
	path := os.Getenv(envSplunkCA)
	if path == "" {
		return client
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", envSplunkCA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no certificate", envSplunkCA)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("safehttp transport changed shape: %T", client.Transport)
	}
	// Verification stays on. Only the trust anchor changes.
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return client
}

func (l liveSplunk) client(t *testing.T, indexerAck bool) *Client {
	t.Helper()
	return &Client{HTTP: liveHTTP(t), Guard: func(string) error { return nil }, IndexerAck: indexerAck}
}

func (l liveSplunk) delivery(token string, mode siem.AckMode, records []siem.DeliveryRecord) siem.Delivery {
	return siem.Delivery{
		Origin: l.origin, Secret: token, Target: "/services/collector/event",
		Channel: "11111111-2222-4333-8444-555555555555", AckMode: mode, Records: records,
	}
}

// search runs one oneshot search through the management API and returns its rows. The collector
// token cannot search, which is why the management credential is separate.
func (l liveSplunk) search(t *testing.T, query string) []map[string]any {
	t.Helper()
	if l.mgmt == "" || l.mgmtAuth == "" {
		t.Skipf("set %s and %s to read events back", envSplunkMgmtURL, envSplunkMgmtAuth)
	}
	user, password, found := strings.Cut(l.mgmtAuth, ":")
	if !found {
		t.Fatalf("%s must be user:password", envSplunkMgmtAuth)
	}
	form := url.Values{
		"search":      {query},
		"exec_mode":   {"oneshot"},
		"output_mode": {"json"},
		"earliest":    {"-1h"},
		"latest":      {"now"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, l.mgmt+"/services/search/jobs", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build search: %v", err)
	}
	req.SetBasicAuth(user, password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := l.http.Do(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatalf("read search: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("search returned %d: %s", response.StatusCode, payload)
	}
	var parsed struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("decode search: %v (%s)", err, payload)
	}
	return parsed.Results
}

// post sends one raw collector request with the token, for assertions about the collector's own
// answer rather than the driver's interpretation of it.
func (l liveSplunk) post(t *testing.T, path, token, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, l.origin+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := l.http.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return response.StatusCode, payload
}

// liveRecords builds what a real export produces, one record per stored shape, each carrying the
// cursor a consumer reads to place the event in the stream and notice a hole.
func liveRecords(tenant, marker string) []siem.DeliveryRecord {
	envelope := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 8101, Actor: "ada@example.test", Action: "user.login", Target: marker,
		AtUnixMicro: time.Now().UnixMicro(), Hash: strings.Repeat("a", 64), PreviousHash: strings.Repeat("b", 64),
		HashVersion: 2, Severity: "info", Host: marker + ".example.test",
	}, siem.ClassSummary, nil, "")
	detection := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 8102, Actor: "ada@example.test", Action: "finding.created", Target: marker,
		AtUnixMicro: time.Now().UnixMicro(), Hash: strings.Repeat("c", 64), PreviousHash: strings.Repeat("a", 64),
		HashVersion: 2, Severity: "high", FindingID: marker + "-finding", Title: "Live stream probe finding",
		FindingStatus: "open", Host: marker + ".example.test",
	}, siem.ClassSummary, nil, "")
	incident := siem.ExportIncident(tenant, siem.IncidentFact{
		StreamSeq: 8103, Phase: siem.PhaseLive, IncidentID: marker + "-incident", EventSeq: 1,
		Kind: "created", AtUnixMicro: time.Now().UnixMicro(), Actor: "ada@example.test",
		Owner: "ada@example.test", Title: "Live stream probe incident", Severity: "medium",
	}, siem.ClassSummary, nil, "")
	return []siem.DeliveryRecord{
		{ID: envelope.RecordID, Body: envelope.Body},
		{ID: detection.RecordID, Body: detection.Body},
		{ID: incident.RecordID, Body: incident.Body},
	}
}

// TestLiveHECAcceptsTheBatchAndSearchFindsIt is the live half of the collector contract: a real
// Splunk accepts the records a real export produces, answers with HEC code zero, and a search finds
// each record by the indexed record_id with its cursor fields intact.
func TestLiveHECAcceptsTheBatchAndSearchFindsIt(t *testing.T) {
	live := liveSetup(t)
	marker := fmt.Sprintf("synapse-live-%d", time.Now().UnixNano())
	records := liveRecords("tenant-live", marker)

	result, err := live.client(t, false).Deliver(context.Background(), live.delivery(live.token, siem.AckHECAcceptance, records))
	if err != nil {
		t.Fatalf("live hec delivery: %v", err)
	}
	if len(result.Items) != len(records) {
		t.Fatalf("items = %d, want %d", len(result.Items), len(records))
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemAcked {
			t.Fatalf("record %d: %+v, want acked", i, item)
		}
	}
	if result.IndexerAckID != nil {
		t.Errorf("acceptance mode returned an indexer receipt: %d", *result.IndexerAckID)
	}

	// Indexing is asynchronous, so the search is retried until the batch appears or the budget
	// runs out. A flaky wait here would be worse than a slow one.
	// record_id is an indexed field from the event's "fields" key, so it has to be selected
	// explicitly: a bare search returns the default columns only.
	var rows []map[string]any
	query := fmt.Sprintf(`search index=%s sourcetype="synapse:siem" %s | head 10 | table record_id, sourcetype, _raw`, live.index, marker)
	for attempt := 0; attempt < 20; attempt++ {
		rows = live.search(t, query)
		if len(rows) >= len(records) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(rows) < len(records) {
		t.Fatalf("the search found %d of %d records after the wait: %v", len(rows), len(records), rows)
	}

	byRecordID := map[string]map[string]any{}
	for _, row := range rows {
		id, _ := row["record_id"].(string)
		if id == "" {
			t.Errorf("a row carries no indexed record_id: %v", row)
			continue
		}
		byRecordID[id] = row
		raw, _ := row["_raw"].(string)
		t.Logf("searched record_id=%s\n%s", id, indent(raw))
	}
	for _, record := range records {
		row, ok := byRecordID[record.ID]
		if !ok {
			t.Fatalf("record %s is not in the search results: %v", record.ID, byRecordID)
		}
		raw, _ := row["_raw"].(string)
		var stored map[string]any
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			t.Fatalf("record %s stored a _raw that is not the record: %v (%s)", record.ID, err, raw)
		}
		if !sameJSON(t, record.Body, []byte(raw)) {
			t.Errorf("record %s was stored with a different body:\nsent  %s\nstored %s", record.ID, record.Body, raw)
		}
		cursor := cursorOf(stored)
		if cursor == nil {
			t.Fatalf("record %s stored no cursor: %s", record.ID, raw)
		}
		if cursor["id"] == nil && cursor["stream_seq"] == nil {
			t.Errorf("record %s cursor has neither an audit id nor a stream sequence: %v", record.ID, cursor)
		}
		if sourcetype, _ := row["sourcetype"].(string); sourcetype != "synapse:siem" {
			t.Errorf("record %s was indexed as sourcetype %q", record.ID, sourcetype)
		}
	}
}

// TestLiveIndexerAcknowledgementIsPolledUntilConfirmed proves the receipt path against a real
// collector: the delivery returns an ack id rather than an acknowledgement, and the poll endpoint
// confirms it once the indexer has the data. The field name and value type of the receipt are
// exactly what this asserts, because a client that misreads them never advances a cursor.
func TestLiveIndexerAcknowledgementIsPolledUntilConfirmed(t *testing.T) {
	live := liveSetup(t)
	if live.ackToken == "" {
		t.Skipf("set %s to a token with indexer acknowledgement enabled", envSplunkAckToken)
	}
	marker := fmt.Sprintf("synapse-live-ack-%d", time.Now().UnixNano())
	records := liveRecords("tenant-live-ack", marker)
	client := live.client(t, true)
	delivery := live.delivery(live.ackToken, siem.AckIndexer, records)

	result, err := client.Deliver(context.Background(), delivery)
	if err != nil {
		t.Fatalf("live indexer-ack delivery: %v", err)
	}
	if result.IndexerAckID == nil {
		t.Fatalf("the collector returned no ack id: %+v", result)
	}
	if len(result.Items) != 0 {
		t.Errorf("an indexer-ack delivery acknowledged records before polling: %+v", result.Items)
	}
	t.Logf("indexer receipt ackId=%d", *result.IndexerAckID)

	var confirmed bool
	for attempt := 0; attempt < 20 && !confirmed; attempt++ {
		var wait time.Duration
		confirmed, wait, err = client.PollAck(context.Background(), delivery, *result.IndexerAckID)
		if err != nil {
			t.Fatalf("poll ack: %v", err)
		}
		if confirmed {
			break
		}
		if wait == 0 {
			wait = 2 * time.Second
		}
		time.Sleep(wait)
	}
	if !confirmed {
		t.Fatalf("the collector never confirmed ack id %d", *result.IndexerAckID)
	}

	// An unknown receipt is reported as unconfirmed rather than confirmed, so a lost ack id can
	// never be mistaken for a stored batch.
	unknown, _, err := client.PollAck(context.Background(), delivery, *result.IndexerAckID+100_000)
	if err != nil {
		t.Fatalf("poll an unknown ack: %v", err)
	}
	if unknown {
		t.Error("the collector confirmed an ack id it never issued")
	}
}

// TestLiveHECRejectionsAreClassified drives the failure paths against the real collector, because
// the classification only matters if the real server answers the way the stub servers do.
func TestLiveHECRejectionsAreClassified(t *testing.T) {
	live := liveSetup(t)
	records := liveRecords("tenant-live-reject", "synapse-live-reject")

	t.Run("a wrong token is blocked and never echoed", func(t *testing.T) {
		const wrong = "11111111-dead-beef-dead-111111111111"
		result, err := live.client(t, false).Deliver(context.Background(), live.delivery(wrong, siem.AckHECAcceptance, records))
		if err != nil {
			t.Fatalf("deliver with a wrong token: %v", err)
		}
		for i, item := range result.Items {
			if item.Disposition == siem.ItemAcked || !item.Blocked || item.Retryable {
				t.Errorf("record %d: %+v, want blocked and not retryable", i, item)
			}
			if strings.Contains(item.Diagnostic, wrong) {
				t.Errorf("record %d diagnostic carried the token: %s", i, item.Diagnostic)
			}
		}
	})

	t.Run("an empty batch is refused with a non-zero hec code", func(t *testing.T) {
		// The driver returns no items for an empty batch whatever the collector says, so the
		// collector's own answer is read directly: a zero code here would mean Splunk accepted
		// an empty request and this assertion would be vacuous.
		status, body := live.post(t, "/services/collector/event", live.token, "")
		var hec struct {
			Code *int   `json:"code"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(body, &hec); err != nil {
			t.Fatalf("collector answer is not json: %v (%s)", err, body)
		}
		if hec.Code == nil || *hec.Code == 0 {
			t.Fatalf("the collector accepted an empty request: status=%d body=%s", status, body)
		}
		t.Logf("empty request rejected: status=%d code=%d text=%q", status, *hec.Code, hec.Text)

		result, err := live.client(t, false).Deliver(context.Background(), live.delivery(live.token, siem.AckHECAcceptance, nil))
		if err != nil {
			t.Fatalf("deliver an empty batch: %v", err)
		}
		if len(result.Items) != 0 {
			t.Errorf("an empty batch produced %d items", len(result.Items))
		}
	})

	t.Run("indexer acknowledgement on a token without it is not acknowledged", func(t *testing.T) {
		result, err := live.client(t, true).Deliver(context.Background(), live.delivery(live.token, siem.AckIndexer, records))
		if err != nil {
			// A collector that answers without a usable receipt is an error rather than a
			// silent acknowledgement, which is the behaviour that matters here.
			return
		}
		if result.IndexerAckID != nil {
			t.Errorf("a token without indexer acknowledgement returned a receipt: %d", *result.IndexerAckID)
		}
		for i, item := range result.Items {
			if item.Disposition == siem.ItemAcked {
				t.Errorf("record %d was acknowledged without a receipt: %+v", i, item)
			}
		}
	})
}

// cursorOf returns the stored cursor of one record. The audit envelope carries it under "source";
// an OCSF finding carries it under "unmapped.synapse_source_position".
func cursorOf(doc map[string]any) map[string]any {
	if source, ok := doc["source"].(map[string]any); ok {
		return source
	}
	if unmapped, ok := doc["unmapped"].(map[string]any); ok {
		if position, ok := unmapped["synapse_source_position"].(map[string]any); ok {
			return position
		}
	}
	return nil
}

// sameJSON compares two documents by content, with numbers kept as literals so a microsecond
// timestamp is not rounded by a float round trip.
func sameJSON(t *testing.T, left, right []byte) bool {
	t.Helper()
	return string(canonical(t, left)) == string(canonical(t, right))
}

func canonical(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var doc any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode %s: %v", raw, err)
	}
	return out
}

func indent(raw string) string {
	var buf strings.Builder
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return raw
	}
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return raw
	}
	return strings.TrimRight(buf.String(), "\n")
}

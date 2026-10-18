package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// The live suite runs against a real Elasticsearch and is opt-in, like the Postgres suite. Set:
//
//	SYNAPSE_TEST_ELASTIC_URL      https origin of the cluster, for example https://127.0.0.1:19243
//	SYNAPSE_TEST_ELASTIC_API_KEY  the base64 "encoded" credential from POST /_security/api_key
//	SYNAPSE_TEST_ELASTIC_CA       optional PEM bundle that signs the cluster certificate
//	SYNAPSE_TEST_ELASTIC_INDEX    optional index name, default synapse-siem-live
//
// Elasticsearch authenticates an API key as `Authorization: ApiKey <base64(id:api_key)>`, which is
// the `encoded` field of the create response, so that is the value a sink stores as its secret.
const (
	envLiveURL    = "SYNAPSE_TEST_ELASTIC_URL"
	envLiveAPIKey = "SYNAPSE_TEST_ELASTIC_API_KEY"
	envLiveCA     = "SYNAPSE_TEST_ELASTIC_CA"
	envLiveIndex  = "SYNAPSE_TEST_ELASTIC_INDEX"
)

type liveTarget struct {
	origin string
	apiKey string
	index  string
	admin  *http.Client
}

// liveSetup skips unless the cluster is configured, and returns a client for the test's own
// verification calls (refresh, search, delete) alongside the sink's connection details.
func liveSetup(t *testing.T) liveTarget {
	t.Helper()
	origin, apiKey := os.Getenv(envLiveURL), os.Getenv(envLiveAPIKey)
	if origin == "" || apiKey == "" {
		t.Skipf("set %s and %s to run the live Elasticsearch contract", envLiveURL, envLiveAPIKey)
	}
	index := os.Getenv(envLiveIndex)
	if index == "" {
		index = "synapse-siem-live"
	}
	return liveTarget{origin: origin, apiKey: apiKey, index: index, admin: liveHTTP(t)}
}

// liveHTTP keeps the production safe dialer and the production TLS verification, and differs from
// the shipped client in exactly one way: it dials under safehttp.OperatorPolicy, which admits a
// loopback address because a cluster under test sits on the loopback interface. A tenant-configured
// destination never gets that policy (see docs/guide/siem-stream.md), so the widening lives in the
// test rather than in the client. Cloud metadata stays refused either way.
func liveHTTP(t *testing.T) *http.Client {
	t.Helper()
	client := safehttp.NewClient(10*time.Second, safehttp.OperatorPolicy())
	path := os.Getenv(envLiveCA)
	if path == "" {
		return client
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", envLiveCA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no certificate", envLiveCA)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("safehttp transport changed shape: %T", client.Transport)
	}
	// Verification stays on. Only the trust anchor changes, so a wrong-host or expired
	// certificate still fails the test.
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return client
}

func (l liveTarget) client(t *testing.T) *Client {
	t.Helper()
	return &Client{HTTP: liveHTTP(t), Guard: func(string) error { return nil }}
}

// call runs one request against the cluster with the API key, for the test's own assertions.
func (l liveTarget) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, l.origin+path, reader)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "ApiKey "+l.apiKey)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := l.admin.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}
	return response.StatusCode, payload
}

func (l liveTarget) drop(t *testing.T, index string) {
	t.Helper()
	if code, body := l.call(t, http.MethodDelete, "/"+index, ""); code != http.StatusOK && code != http.StatusNotFound {
		t.Errorf("drop index %s: code=%d body=%s", index, code, body)
	}
}

func (l liveTarget) refresh(t *testing.T, index string) {
	t.Helper()
	if code, body := l.call(t, http.MethodPost, "/"+index+"/_refresh", ""); code != http.StatusOK {
		t.Fatalf("refresh %s: code=%d body=%s", index, code, body)
	}
}

// liveRecord is one record plus where its cursor must be found in the stored document. The paths
// are the contract a SIEM consumer depends on: without them an event cannot be placed in the
// stream, so a missing one is a gap nobody can detect.
type liveRecord struct {
	record     siem.DeliveryRecord
	shape      string
	cursorPath []string
	cursorKeys []string
	hashPath   []string
}

// liveShapes pairs each exported record with its stored cursor contract.
func liveShapes(tenant string) []liveRecord {
	records := liveRecords(tenant)
	return []liveRecord{
		{
			record: records[0], shape: "audit envelope",
			cursorPath: []string{"source"}, cursorKeys: []string{"kind", "id", "hash_version"},
			hashPath: []string{"source", "source_hash"},
		},
		{
			record: records[1], shape: "ocsf detection finding",
			cursorPath: []string{"unmapped", "synapse_source_position"}, cursorKeys: []string{"source", "id", "hash_version"},
			hashPath: []string{"unmapped", "synapse_source_hash"},
		},
		{
			// An incident event has no audit chain hash. Its stream sequence is the gap
			// detector, so the sequence and the event identity are what must survive.
			record: records[2], shape: "ocsf incident finding",
			cursorPath: []string{"unmapped", "synapse_source_position"}, cursorKeys: []string{"source", "stream_seq", "incident_id", "event_seq"},
		},
	}
}

// liveRecords builds what a real export produces, one record per stored shape: the audit envelope,
// an OCSF detection finding, and an OCSF incident finding.
func liveRecords(tenant string) []siem.DeliveryRecord {
	envelope := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 4711, Actor: "ada@example.test", Action: "user.login", Target: "console",
		AtUnixMicro: 1_700_000_000_000_000, Hash: strings.Repeat("a", 64), PreviousHash: strings.Repeat("b", 64),
		HashVersion: 2, Severity: "info", Host: "console.example.test",
	}, siem.ClassSummary, nil, "")
	detection := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 4712, Actor: "ada@example.test", Action: "finding.created", Target: "finding",
		AtUnixMicro: 1_700_000_001_000_000, Hash: strings.Repeat("c", 64), PreviousHash: strings.Repeat("a", 64),
		HashVersion: 2, Severity: "high", FindingID: "fnd-live-1", Title: "Live stream probe finding",
		FindingStatus: "open", Host: "target.example.test",
	}, siem.ClassSummary, nil, "")
	incident := siem.ExportIncident(tenant, siem.IncidentFact{
		StreamSeq: 97, Phase: siem.PhaseLive, IncidentID: "inc-live-1", EventSeq: 1,
		Kind: "created", AtUnixMicro: 1_700_000_002_000_000, Actor: "ada@example.test",
		Owner: "ada@example.test", Title: "Live stream probe incident", Severity: "medium",
	}, siem.ClassSummary, nil, "")
	return []siem.DeliveryRecord{
		{ID: envelope.RecordID, Body: envelope.Body},
		{ID: detection.RecordID, Body: detection.Body},
		{ID: incident.RecordID, Body: incident.Body},
	}
}

// at walks a stored document by path and returns the value, or nil when any step is missing.
func at(doc map[string]any, path []string) any {
	var current any = doc
	for _, step := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[step]
		if !ok {
			return nil
		}
	}
	return current
}

// TestLiveBulkStoresTheRecordAndItsCursorFields is the live half of the bulk contract: a real
// cluster accepts the records a real export produces, acknowledges each item, stores the body
// unchanged, and keeps the cursor fields searchable so a consumer can place each event in the
// stream and notice a hole.
func TestLiveBulkStoresTheRecordAndItsCursorFields(t *testing.T) {
	live := liveSetup(t)
	t.Cleanup(func() { live.drop(t, live.index) })
	live.drop(t, live.index)

	shapes := liveShapes("tenant-live")
	records := make([]siem.DeliveryRecord, len(shapes))
	for i, shape := range shapes {
		records[i] = shape.record
	}
	delivery := siem.Delivery{Origin: live.origin, Secret: live.apiKey, Target: live.index, AckMode: siem.AckBulkItem, Records: records}
	result, err := live.client(t).Deliver(context.Background(), delivery)
	if err != nil {
		t.Fatalf("live bulk: %v", err)
	}
	if len(result.Items) != len(records) {
		t.Fatalf("items = %d, want %d", len(result.Items), len(records))
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemAcked {
			t.Fatalf("record %d: %+v, want acked", i, item)
		}
	}

	live.refresh(t, live.index)
	code, payload := live.call(t, http.MethodPost, "/"+live.index+"/_search?size=10", `{"query":{"match_all":{}}}`)
	if code != http.StatusOK {
		t.Fatalf("search: code=%d body=%s", code, payload)
	}
	var search struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				ID     string          `json:"_id"`
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(payload, &search); err != nil {
		t.Fatalf("decode search: %v (%s)", err, payload)
	}
	if search.Hits.Total.Value != len(records) {
		t.Fatalf("the cluster stored %d documents, want %d: %s", search.Hits.Total.Value, len(records), payload)
	}

	stored := map[string]json.RawMessage{}
	for _, hit := range search.Hits.Hits {
		stored[hit.ID] = hit.Source
		t.Logf("stored _id=%s\n%s", hit.ID, indent(t, hit.Source))
	}
	for _, shape := range shapes {
		raw, ok := stored[shape.record.ID]
		if !ok {
			t.Fatalf("%s record %s is not in the index: %s", shape.shape, shape.record.ID, payload)
		}
		// The action line addresses the document by the record id, so the stored _source must
		// be the record the export produced, byte for byte once key order is normalized.
		if !bytes.Equal(canonical(t, shape.record.Body), canonical(t, raw)) {
			t.Errorf("%s record %s was stored with a different body:\nsent  %s\nstored %s", shape.shape, shape.record.ID, shape.record.Body, raw)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decode stored %s: %v", shape.record.ID, err)
		}
		cursor, ok := at(doc, shape.cursorPath).(map[string]any)
		if !ok {
			t.Errorf("%s record %s stored no cursor at %s: %s", shape.shape, shape.record.ID, strings.Join(shape.cursorPath, "."), raw)
			continue
		}
		for _, key := range shape.cursorKeys {
			if cursor[key] == nil {
				t.Errorf("%s record %s lost %s.%s: %v", shape.shape, shape.record.ID, strings.Join(shape.cursorPath, "."), key, cursor)
			}
		}
		if len(shape.hashPath) > 0 {
			hash, _ := at(doc, shape.hashPath).(string)
			if len(hash) != 64 {
				t.Errorf("%s record %s stored no chain hash at %s: %q", shape.shape, shape.record.ID, strings.Join(shape.hashPath, "."), hash)
			}
		}
	}

	// A replay of the same batch is the at-least-once case. It must acknowledge again and leave
	// the document count where it was, because the record id is the document id.
	replay, err := live.client(t).Deliver(context.Background(), delivery)
	if err != nil {
		t.Fatalf("live replay: %v", err)
	}
	for i, item := range replay.Items {
		if item.Disposition != siem.ItemAcked {
			t.Errorf("replayed record %d: %+v, want acked", i, item)
		}
	}
	live.refresh(t, live.index)
	code, payload = live.call(t, http.MethodGet, "/"+live.index+"/_count", "")
	if code != http.StatusOK {
		t.Fatalf("count: code=%d body=%s", code, payload)
	}
	var counted struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(payload, &counted); err != nil {
		t.Fatalf("decode count: %v (%s)", err, payload)
	}
	if counted.Count != len(records) {
		t.Errorf("a replay changed the document count to %d, want %d", counted.Count, len(records))
	}
}

// TestLiveBulkRejectionsAreClassified drives the failure paths against the real cluster, because
// the classification only matters if the real server answers the way the stub servers do.
func TestLiveBulkRejectionsAreClassified(t *testing.T) {
	live := liveSetup(t)
	records := liveRecords("tenant-live-reject")

	t.Run("a wrong credential is blocked and never echoed", func(t *testing.T) {
		const wrong = "bm90LWEtcmVhbC1rZXk6bm90LWEtcmVhbC1zZWNyZXQ="
		delivery := siem.Delivery{Origin: live.origin, Secret: wrong, Target: live.index, AckMode: siem.AckBulkItem, Records: records}
		result, err := live.client(t).Deliver(context.Background(), delivery)
		if err != nil {
			t.Fatalf("deliver with a wrong credential: %v", err)
		}
		for i, item := range result.Items {
			if item.Disposition == siem.ItemAcked || !item.Blocked || item.Retryable {
				t.Errorf("record %d: %+v, want blocked and not retryable", i, item)
			}
			if strings.Contains(item.Diagnostic, wrong) || strings.Contains(item.Diagnostic, "bm90LWEt") {
				t.Errorf("record %d diagnostic carried the credential: %s", i, item.Diagnostic)
			}
		}
	})

	t.Run("an index the cluster refuses fails the whole batch", func(t *testing.T) {
		// Uppercase passes the client's own name check and Elasticsearch rejects it, so this
		// exercises the server's refusal rather than the local guard.
		delivery := siem.Delivery{Origin: live.origin, Secret: live.apiKey, Target: "Synapse-SIEM-Live", AckMode: siem.AckBulkItem, Records: records}
		result, err := live.client(t).Deliver(context.Background(), delivery)
		if err != nil {
			t.Fatalf("deliver to a refused index: %v", err)
		}
		for i, item := range result.Items {
			if item.Disposition == siem.ItemAcked || !item.Blocked {
				t.Errorf("record %d: %+v, want blocked", i, item)
			}
		}
	})

	t.Run("a record the cluster cannot map is not acknowledged", func(t *testing.T) {
		index := live.index + "-mapping"
		t.Cleanup(func() { live.drop(t, index) })
		live.drop(t, index)
		if code, body := live.call(t, http.MethodPut, "/"+index, `{"mappings":{"properties":{"time":{"type":"date"}}}}`); code != http.StatusOK {
			t.Fatalf("create the mapped index: code=%d body=%s", code, body)
		}
		broken := []siem.DeliveryRecord{
			records[0],
			{ID: "live-unmappable", Body: []byte(`{"schema":"synapse.siem.audit.v1","time":"not-a-date","source":{"kind":"audit","id":1}}`)},
		}
		delivery := siem.Delivery{Origin: live.origin, Secret: live.apiKey, Target: index, AckMode: siem.AckBulkItem, Records: broken}
		result, err := live.client(t).Deliver(context.Background(), delivery)
		if err != nil {
			t.Fatalf("deliver a partially mappable batch: %v", err)
		}
		if len(result.Items) != 2 {
			t.Fatalf("items = %d, want 2", len(result.Items))
		}
		if result.Items[0].Disposition != siem.ItemAcked {
			t.Errorf("the mappable record was not acknowledged: %+v", result.Items[0])
		}
		if result.Items[1].Disposition == siem.ItemAcked || !result.Items[1].Blocked {
			t.Errorf("the unmappable record was acknowledged: %+v", result.Items[1])
		}
	})
}

// canonical re-encodes JSON with numbers kept as literals, so two documents compare by content
// without float rounding turning a microsecond timestamp into something else.
func canonical(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
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

func indent(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

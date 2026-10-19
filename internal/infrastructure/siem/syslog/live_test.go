package syslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// The live suite runs against a real syslog receiver and is opt-in, like the Postgres suite. Set:
//
//	SYNAPSE_TEST_SYSLOG_ORIGIN   tls://host:port as a tenant would configure it, for example
//	                             tls://syslog.synapse.test:6514. The host must match the receiver
//	                             certificate, because hostname verification is part of what this
//	                             suite proves.
//	SYNAPSE_TEST_SYSLOG_ADDR     host:port to dial, for example 127.0.0.1:16514. A sink origin can
//	                             never be a loopback address: siem.ForbiddenHost refuses it in the
//	                             domain layer, before any policy runs. So the suite resolves the
//	                             origin itself and leaves address policy to safehttp's own tests.
//	SYNAPSE_TEST_SYSLOG_CA       optional PEM bundle that signs the receiver certificate
//	SYNAPSE_TEST_SYSLOG_LOG_URL  optional URL that returns what the receiver parsed, for the read-back
//	SYNAPSE_TEST_SYSLOG_APP      optional APP-NAME, default synapse-live
//
// The read-back is what proves the receiver's own RFC 5424 parser accepted the frame, which is the
// only acknowledgement syslog cannot give the sender: a completed TLS write says nothing about the
// parse. Any receiver works as long as the URL returns its parsed output as text.
const (
	envSyslogOrigin = "SYNAPSE_TEST_SYSLOG_ORIGIN"
	envSyslogAddr   = "SYNAPSE_TEST_SYSLOG_ADDR"
	envSyslogCA     = "SYNAPSE_TEST_SYSLOG_CA"
	envSyslogLogURL = "SYNAPSE_TEST_SYSLOG_LOG_URL"
	envSyslogApp    = "SYNAPSE_TEST_SYSLOG_APP"
)

type liveSyslog struct {
	origin string
	addr   string
	caPEM  string
	logURL string
	app    string
}

func liveSetup(t *testing.T) liveSyslog {
	t.Helper()
	origin, addr := os.Getenv(envSyslogOrigin), os.Getenv(envSyslogAddr)
	if origin == "" || addr == "" {
		t.Skipf("set %s and %s to run the live syslog contract", envSyslogOrigin, envSyslogAddr)
	}
	live := liveSyslog{origin: origin, addr: addr, logURL: os.Getenv(envSyslogLogURL), app: os.Getenv(envSyslogApp)}
	if live.app == "" {
		live.app = "synapse-live"
	}
	if path := os.Getenv(envSyslogCA); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", envSyslogCA, err)
		}
		live.caPEM = string(pem)
	}
	return live
}

// client keeps the production framing, the production credential handling, the production TLS
// configuration (hostname verification against the origin host, TLS 1.2 floor) and the real clock.
// One thing is the test's: the dial goes to the configured address instead of resolving the origin,
// because a receiver under test listens on loopback and a sink origin can never name one. The
// address policy itself is covered by safehttp's own tests.
func (l liveSyslog) client() *Client {
	return &Client{
		timeout: 10 * time.Second, now: time.Now,
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", l.addr)
		},
		wrapTLS: func(conn net.Conn, config *tls.Config) connection { return tls.Client(conn, config) },
	}
}

func (l liveSyslog) secret(t *testing.T) string {
	t.Helper()
	if l.caPEM == "" {
		return `{}`
	}
	raw, err := json.Marshal(credential{CAPEM: l.caPEM})
	if err != nil {
		t.Fatalf("encode credential: %v", err)
	}
	return string(raw)
}

// received fetches what the receiver parsed. The fetch is the test's own instrument, so it uses a
// plain client rather than the driver's guarded one.
func (l liveSyslog) received(t *testing.T) string {
	t.Helper()
	if l.logURL == "" {
		t.Skipf("set %s to read the receiver's parsed output back", envSyslogLogURL)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, l.logURL, nil)
	if err != nil {
		t.Fatalf("build read-back: %v", err)
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("read back from %s: %v", l.logURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		t.Fatalf("read back body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read-back returned %d: %s", response.StatusCode, payload)
	}
	return string(payload)
}

// liveRecords builds what a real export produces, one record per stored shape.
func liveRecords(tenant, marker string) []siem.DeliveryRecord {
	envelope := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 9101, Actor: "ada@example.test", Action: "user.login", Target: marker,
		AtUnixMicro: time.Now().UnixMicro(), Hash: strings.Repeat("a", 64), PreviousHash: strings.Repeat("b", 64),
		HashVersion: 2, Severity: "info", Host: marker + ".example.test",
	}, siem.ClassSummary, nil, "")
	detection := siem.ExportAudit(tenant, siem.AuditFact{
		ID: 9102, Actor: "ada@example.test", Action: "finding.created", Target: marker,
		AtUnixMicro: time.Now().UnixMicro(), Hash: strings.Repeat("c", 64), PreviousHash: strings.Repeat("a", 64),
		HashVersion: 2, Severity: "high", FindingID: marker + "-finding", Title: "Live stream probe finding",
		FindingStatus: "open", Host: marker + ".example.test",
	}, siem.ClassSummary, nil, "")
	incident := siem.ExportIncident(tenant, siem.IncidentFact{
		StreamSeq: 9103, Phase: siem.PhaseLive, IncidentID: marker + "-incident", EventSeq: 1,
		Kind: "created", AtUnixMicro: time.Now().UnixMicro(), Actor: "ada@example.test",
		Owner: "ada@example.test", Title: "Live stream probe incident", Severity: "medium",
	}, siem.ClassSummary, nil, "")
	return []siem.DeliveryRecord{
		{ID: envelope.RecordID, Body: envelope.Body},
		{ID: detection.RecordID, Body: detection.Body},
		{ID: incident.RecordID, Body: incident.Body},
	}
}

// TestLiveReceiverParsesTheFrame is the live half of the RFC 5424 contract: a real receiver accepts
// the frames a real export produces, and its own parser reports the app name, the message id, the
// priority and the JSON message. A completed TLS write is the only acknowledgement the transport
// offers, so the read-back is what turns that write into evidence.
func TestLiveReceiverParsesTheFrame(t *testing.T) {
	live := liveSetup(t)
	// Both the tenant and the marker carry the run, so the record ids, and with them the
	// message ids the receiver reports, never repeat across runs. A receiver log is
	// append-only: a fixed identity would let a previous run's line answer this one.
	run := time.Now().UnixNano()
	marker := fmt.Sprintf("synapse-live-%d", run)
	records := liveRecords(fmt.Sprintf("tenant-live-%d", run), marker)

	result, err := live.client().Deliver(context.Background(), siem.Delivery{
		Origin: live.origin, Secret: live.secret(t), Target: live.app,
		AckMode: siem.AckTransportWrite, Records: records,
	})
	if err != nil {
		t.Fatalf("live syslog delivery: %v", err)
	}
	if len(result.Items) != len(records) {
		t.Fatalf("items = %d, want %d", len(result.Items), len(records))
	}
	for i, item := range result.Items {
		if item.Disposition != siem.ItemAcked {
			t.Fatalf("record %d: %+v, want acked", i, item)
		}
	}

	// The receiver writes asynchronously, so the read-back is retried until every message id is
	// present or the budget runs out.
	var parsed string
	for attempt := 0; attempt < 10; attempt++ {
		parsed = live.received(t)
		if allPresent(parsed, records, marker) {
			break
		}
		time.Sleep(time.Second)
	}
	for _, record := range records {
		line := lineFor(parsed, messageID(record.ID), marker)
		if line == "" {
			t.Fatalf("the receiver has no line for %s (msgid %s)", record.ID, messageID(record.ID))
		}
		t.Logf("receiver parsed %s\n%s", record.ID, line)
		if !strings.Contains(line, "app="+live.app) {
			t.Errorf("record %s was parsed with another app name: %s", record.ID, line)
		}
		// Facility 16 (local0) and severity 6 (informational) are what PRI 134 means, so a
		// receiver that reports them has parsed the priority rather than guessed it.
		if !strings.Contains(line, "pri=134") || !strings.Contains(line, "facility=local0") || !strings.Contains(line, "severity=info") {
			t.Errorf("record %s lost its priority in the parse: %s", record.ID, line)
		}
		message := messageOf(line)
		if message == "" {
			t.Fatalf("record %s was parsed without a message: %s", record.ID, line)
		}
		if !sameJSON(t, record.Body, []byte(message)) {
			t.Errorf("record %s reached the receiver with a different body:\nsent     %s\nreceived %s", record.ID, record.Body, message)
		}
	}
}

// TestLiveVerificationIsMandatory is the other half of the issue's requirement: the sink refuses a
// receiver it cannot verify. The receiver here is signed by a private CA, so the system trust store
// cannot vouch for it, and the batch has to be blocked rather than delivered or retried.
func TestLiveVerificationIsMandatory(t *testing.T) {
	live := liveSetup(t)
	if live.caPEM == "" {
		t.Skipf("set %s to a private CA so the system trust store cannot verify the receiver", envSyslogCA)
	}
	run := time.Now().UnixNano()
	records := liveRecords(fmt.Sprintf("tenant-live-verify-%d", run), fmt.Sprintf("synapse-live-verify-%d", run))

	result, err := live.client().Deliver(context.Background(), siem.Delivery{
		Origin: live.origin, Secret: `{}`, Target: live.app,
		AckMode: siem.AckTransportWrite, Records: records,
	})
	if err != nil {
		t.Fatalf("deliver without the CA: %v", err)
	}
	for i, item := range result.Items {
		if item.Disposition == siem.ItemAcked {
			t.Errorf("record %d was delivered to an unverified receiver: %+v", i, item)
		}
		if !item.Blocked || item.Retryable {
			t.Errorf("record %d: %+v, want blocked and not retryable", i, item)
		}
		if item.Diagnostic != "syslog TLS certificate verification failed" {
			t.Errorf("record %d diagnostic = %q", i, item.Diagnostic)
		}
	}
}

func allPresent(parsed string, records []siem.DeliveryRecord, marker string) bool {
	for _, record := range records {
		if lineFor(parsed, messageID(record.ID), marker) == "" {
			return false
		}
	}
	return true
}

// lineFor selects the receiver line for one record of the current run. The receiver log is
// append-only, so a line has to carry the run marker as well as the message id to answer.
func lineFor(parsed, msgID, marker string) string {
	for _, line := range strings.Split(parsed, "\n") {
		if strings.Contains(line, msgID) && strings.Contains(line, marker) {
			return line
		}
	}
	return ""
}

// messageOf returns the receiver's parsed message. The read-back format is the receiver's own, so
// the message is taken as everything after the last "msg=" marker.
func messageOf(line string) string {
	index := strings.LastIndex(line, "msg=")
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(line[index+len("msg="):])
}

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

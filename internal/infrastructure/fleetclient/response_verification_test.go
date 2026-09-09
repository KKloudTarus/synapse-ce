package fleetclient

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
)

func testResponseVerificationReport(t *testing.T) fleetagent.ResponseVerificationReport {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	key, err := BuildResponseResultSigningKey("agent-response-test", private, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "response-report-test", AgentID: "agent-response-test", HostID: "agent-response-test",
		AgentSessionID: fleetagent.CanonicalSessionID("agent-response-test"), AssetID: "asset-response-test", EngagementID: "eng-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-response-test", ProcessEntityID: "process-1"},
		ObservedAt: at, KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignResponseVerification(private, report)
	return report
}

func TestShipResponseVerificationUsesDedicatedMediaTypeAndMatchingACK(t *testing.T) {
	report := testResponseVerificationReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/response-verifications" || r.Header.Get("Content-Type") != responseVerificationMediaType ||
			r.Header.Get(protoHeader) != protoVersion || r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("request path=%q headers=%v", r.URL.Path, r.Header)
		}
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip request: %v", err)
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer reader.Close()
		var got fleetagent.ResponseVerificationReport
		if err := json.NewDecoder(reader).Decode(&got); err != nil || got.ReportID != report.ReportID || got.Signature != report.Signature {
			t.Errorf("response verification mismatch: report=%+v err=%v", got, err)
		}
		_ = json.NewEncoder(w).Encode(ResponseVerificationShipResponse{Acknowledged: true, ReportID: report.ReportID})
	}))
	defer server.Close()

	response, err := New(server.URL, time.Second).ShipResponseVerification(context.Background(), "token", report)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Acknowledged || response.ReportID != report.ReportID {
		t.Fatalf("ack=%+v", response)
	}
}

func TestShipResponseVerificationRejectsMismatchingACK(t *testing.T) {
	report := testResponseVerificationReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ResponseVerificationShipResponse{Acknowledged: true, ReportID: "other-report"})
	}))
	defer server.Close()
	if _, err := New(server.URL, time.Second).ShipResponseVerification(context.Background(), "token", report); err == nil {
		t.Fatal("mismatching acknowledgement must fail")
	}
}

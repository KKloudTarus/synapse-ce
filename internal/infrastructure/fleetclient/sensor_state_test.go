package fleetclient

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestShipSensorStateUsesDedicatedMediaTypeAndMatchingACK(t *testing.T) {
	report := testSensorStateReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/sensor-states" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != sensorStateMediaType {
			t.Errorf("content type = %q", got)
		}
		if got := r.Header.Get(protoHeader); got != protoVersion {
			t.Errorf("protocol header = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("authorization = %q", got)
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip request: %v", err)
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer zr.Close()
		var got fleetagent.SensorStateReport
		if err := json.NewDecoder(zr).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if got.ReportID != report.ReportID || got.Signature != report.Signature {
			t.Errorf("sensor-state report mismatch: %+v", got)
		}
		_ = json.NewEncoder(w).Encode(SensorStateShipResponse{Acknowledged: true, ReportID: report.ReportID})
	}))
	defer server.Close()

	resp, err := New(server.URL, time.Second).ShipSensorState(context.Background(), "token", report)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Acknowledged || resp.ReportID != report.ReportID {
		t.Fatalf("ACK = %+v", resp)
	}
}

func TestShipSensorStateRejectsMismatchingACK(t *testing.T) {
	report := testSensorStateReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SensorStateShipResponse{Acknowledged: true, ReportID: "other-report"})
	}))
	defer server.Close()

	_, err := New(server.URL, time.Second).ShipSensorState(context.Background(), "token", report)
	if err == nil {
		t.Fatal("ShipSensorState error = nil, want matching acknowledgement failure")
	}
}

func testSensorStateReport(t *testing.T) fleetagent.SensorStateReport {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentID := shared.ID("agent-state-test")
	at := time.Unix(1_700_000_000, 0).UTC()
	key, err := BuildTelemetrySigningKey(agentID.String(), private, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	report := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		ReportID:        "state-test",
		AgentID:         agentID,
		HostID:          agentID,
		AgentSessionID:  fleetagent.CanonicalSessionID(agentID),
		AssetID:         "asset-state-test",
		Kind:            "sensor_state",
		ObservedAt:      at,
		SchemaVersion:   1,
		PayloadDigest:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		States: []detection.ClassCoverage{{
			Class: detection.ClassProcess, HostID: agentID, AgentID: agentID,
			State: detection.StateActive, Since: at,
		}},
		KeyID: key.KeyID,
	}
	report.Signature = fleetagent.SignSensorState(private, report)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestShipSensorStatePreservesRetryAfter(t *testing.T) {
	report := testSensorStateReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "busy", http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := New(server.URL, time.Second).ShipSensorState(context.Background(), "token", report)
	var status *HTTPStatusError
	if !errors.As(err, &status) {
		t.Fatalf("error = %T %v, want HTTPStatusError", err, err)
	}
	if status.StatusCode != http.StatusTooManyRequests || status.RetryAfter != 7*time.Second || !status.Retryable() {
		t.Fatalf("status = %+v", status)
	}
}

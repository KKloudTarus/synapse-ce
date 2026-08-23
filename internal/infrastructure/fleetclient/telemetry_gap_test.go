package fleetclient

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestShipTelemetryGapUsesDedicatedMediaTypeAndParsesACK(t *testing.T) {
	report := testTelemetryGapReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/telemetry" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != telemetryGapMediaType {
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
		var got fleetagent.TelemetryGapReport
		if err := json.NewDecoder(zr).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if got.GapID != report.GapID || got.Signature != report.Signature {
			t.Errorf("gap report mismatch: %+v", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true, "gap_id": report.GapID})
	}))
	defer server.Close()

	client := New(server.URL, time.Second)
	resp, err := client.ShipTelemetryGap(context.Background(), "token", report)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Acknowledged || resp.GapID != report.GapID {
		t.Fatalf("ACK = %+v", resp)
	}
}

func TestShipTelemetryGapPreservesRetryAfter(t *testing.T) {
	report := testTelemetryGapReport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "busy", http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := New(server.URL, time.Second).ShipTelemetryGap(context.Background(), "token", report)
	var status *HTTPStatusError
	if !errors.As(err, &status) {
		t.Fatalf("error = %T %v, want HTTPStatusError", err, err)
	}
	if status.StatusCode != http.StatusTooManyRequests || status.RetryAfter != 7*time.Second || !status.Retryable() {
		t.Fatalf("status = %+v", status)
	}
}

func testTelemetryGapReport(t *testing.T) fleetagent.TelemetryGapReport {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentID := shared.ID("agent-gap-test")
	session := fleetagent.CanonicalSessionID(agentID)
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	report := fleetagent.TelemetryGapReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		GapID:           shared.ID("gap-test"),
		AgentID:         agentID,
		HostID:          agentID,
		AgentSessionID:  session,
		AssetID:         shared.ID("asset-gap-test"),
		StreamID:        streamID,
		Priority:        fleetagent.PriorityP3,
		Epoch:           1,
		Count:           2,
		Reason:          fleetagent.TelemetryGapQuotaEviction,
		FromAt:          now.Add(-time.Second),
		ToAt:            now,
		KeyID:           "key-gap-test",
	}
	report.Signature = fleetagent.SignTelemetryGap(priv, report)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	return report
}

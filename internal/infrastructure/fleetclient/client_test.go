package fleetclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestClientRoundTrips(t *testing.T) {
	var gotProto, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get(protoHeader)
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v1/fleet/enrol":
			var req EnrolRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Name == "" {
				t.Errorf("enrol should carry a name")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(EnrolResponse{AgentID: "a1", Token: "tok", CertificatePEM: "PEM"})
		case "/api/v1/fleet/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/fleet/work/claim":
			_ = json.NewEncoder(w).Encode([]Order{{ID: "o1", Capability: "scan.host"}})
		case "/api/v1/fleet/work/o1/progress":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/fleet/work/o1/result":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["status"] != "succeeded" {
				t.Errorf("result status = %q", body["status"])
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, 5*time.Second)
	ctx := context.Background()

	enr, err := c.Enrol(ctx, "enrol-token", EnrolRequest{Name: "host1", Platform: "linux"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if enr.Token != "tok" || enr.CertificatePEM != "PEM" {
		t.Fatalf("enrol response not decoded: %+v", enr)
	}
	if gotProto != protoVersion {
		t.Fatalf("proto header not set, got %q", gotProto)
	}
	if gotAuth != "Bearer enrol-token" {
		t.Fatalf("enrol should use the enrol token, got %q", gotAuth)
	}

	if _, err := c.Heartbeat(ctx, enr.Token, EnrolRequest{Name: "host1"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	orders, err := c.ClaimWork(ctx, enr.Token, 4)
	if err != nil || len(orders) != 1 || orders[0].ID != "o1" {
		t.Fatalf("claim: %v %v", orders, err)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("post-enrol calls must use the agent token, got %q", gotAuth)
	}
	if err := c.Progress(ctx, enr.Token, "o1"); err != nil {
		t.Fatalf("progress: %v", err)
	}
	if err := c.SubmitResult(ctx, enr.Token, "o1", "succeeded", "12 packages"); err != nil {
		t.Fatalf("result: %v", err)
	}
}

func TestClientNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, 5*time.Second)
	if _, err := c.Heartbeat(context.Background(), "t", EnrolRequest{}); err == nil {
		t.Fatalf("a 500 must surface as an error")
	} else if status, retryAfter, ok := HTTPStatus(err); !ok || status != 500 || retryAfter != "7" {
		t.Fatalf("HTTP metadata = status=%d retry-after=%q ok=%v err=%v", status, retryAfter, ok, err)
	}
}

func TestDetectionKeyAndBatchWireShape(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeDetectionBatch, pub, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proof := fleetagent.ProveKeyPossession(privateKey, key)
	event := detection.Event{Class: detection.ClassProcess, At: now, Host: "asset-1",
		Process: &detection.ProcessEvent{PID: 42, PPID: 1, Comm: "curl"}}
	value := detection.Detection{RuleID: "proc.curl", RuleVersion: 1, Class: detection.ClassProcess,
		Severity: shared.SeverityHigh, HostID: "asset-1", AgentID: "agent-1",
		Evidence: []detection.Event{event}, ObservedCount: 1, Observed: now}
	item := fleetagent.DetectionBatchItem{ID: "det-1", Detection: value, AssetID: "asset-1"}
	body, _ := json.Marshal(value)
	batch := fleetagent.AgentBatch{AgentID: "agent-1", EngagementID: "eng-1", Sequence: 1, KeyID: key.KeyID,
		Detections: []fleetagent.DetectionRef{{ID: item.ID, ContentSHA256: fleetagent.DetectionContentHash(body, item.AssetID)}}}
	batch.Signature = fleetagent.SignBatch(privateKey, batch)

	var keyCalls, batchCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/fleet/keys":
			keyCalls++
			var request struct {
				PublicKey string    `json:"public_key"`
				Purpose   string    `json:"purpose"`
				NotBefore time.Time `json:"not_before"`
				NotAfter  time.Time `json:"not_after"`
				Proof     string    `json:"proof"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.Purpose != string(fleetagent.PurposeDetectionBatch) || request.Proof != proof || request.PublicKey == "" || !request.NotAfter.Equal(key.NotAfter) {
				t.Errorf("key registration = %#v", request)
			}
			w.WriteHeader(http.StatusCreated)
		case "/api/v1/fleet/detections":
			batchCalls++
			var request struct {
				Batch fleetagent.AgentBatch           `json:"batch"`
				Items []fleetagent.DetectionBatchItem `json:"items"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if err := fleetagent.VerifyBatch(pub, request.Batch); err != nil || len(request.Items) != 1 || request.Items[0].ID != item.ID {
				t.Errorf("detection request batch=%#v items=%#v verify=%v", request.Batch, request.Items, err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := New(srv.URL, time.Second)
	if err := client.RegisterDetectionKey(context.Background(), "token", key, proof); err != nil {
		t.Fatal(err)
	}
	if err := client.SendDetectionBatch(context.Background(), "token", batch, []fleetagent.DetectionBatchItem{item}); err != nil {
		t.Fatal(err)
	}
	if keyCalls != 1 || batchCalls != 1 {
		t.Fatalf("key calls=%d batch calls=%d", keyCalls, batchCalls)
	}
}

func TestNetworkFailureRetainsTypedCause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	client := New(url, 100*time.Millisecond)
	_, err := client.Heartbeat(context.Background(), "token", EnrolRequest{})
	if err == nil || !IsNetworkError(err) {
		t.Fatalf("network error not classified: %v", err)
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) || netErr.Path != "/api/v1/fleet/heartbeat" {
		t.Fatalf("network error metadata = %#v", netErr)
	}
}

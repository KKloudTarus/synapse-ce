package fleetclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, 5*time.Second)
	if _, err := c.Heartbeat(context.Background(), "t", EnrolRequest{}); err == nil {
		t.Fatalf("a 500 must surface as an error")
	}
}

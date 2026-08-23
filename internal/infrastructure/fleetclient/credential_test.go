package fleetclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
)

type fakeEnroller struct {
	calls  int
	resp   EnrolResponse
	gotReq EnrolRequest
}

func (f *fakeEnroller) Enrol(_ context.Context, _ string, req EnrolRequest) (EnrolResponse, error) {
	f.calls++
	f.gotReq = req
	return f.resp, nil
}

func TestEnsureEnrolledFirstRunThenReuse(t *testing.T) {
	dir := t.TempDir()
	store := NewCredentialStore(dir)
	enr := &fakeEnroller{resp: EnrolResponse{AgentID: "a1", Token: "secret", CertificatePEM: "PEM"}}
	req := EnrolRequest{Name: "agent-1", Platform: "kubernetes", Capabilities: []string{"scan.cluster"}}

	cred, err := EnsureEnrolled(context.Background(), enr, store, "enrol-tok", req)
	if err != nil {
		t.Fatalf("first enrol: %v", err)
	}
	if cred.Token != "secret" || enr.calls != 1 {
		t.Fatalf("first run must enrol once, got cred=%+v calls=%d", cred, enr.calls)
	}
	// A CSR was generated and sent (private key stays local).
	if enr.gotReq.CSRPEM == "" {
		t.Fatalf("enrol must carry a generated CSR")
	}
	// credential + key persisted 0600.
	info, err := os.Stat(store.credentialPath())
	if err != nil {
		t.Fatalf("credential must be persisted: %v", err)
	}
	// The 0600 guarantee is a Unix one. On Windows os.Chmod only toggles the read-only attribute, so
	// asserting the bits there would assert something no platform enforces.
	if fssecurity.UnixModeEnforced() && info.Mode().Perm() != 0o600 {
		t.Fatalf("credential must be persisted 0600, got %v", info.Mode().Perm())
	}
	if _, err := os.Stat(store.keyPath()); err != nil {
		t.Fatalf("key must be persisted: %v", err)
	}

	// Second call loads the stored credential — no re-enrol.
	cred2, err := EnsureEnrolled(context.Background(), enr, store, "enrol-tok", req)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if enr.calls != 1 {
		t.Fatalf("a stored credential must not re-enrol, calls=%d", enr.calls)
	}
	if cred2.Token != "secret" {
		t.Fatalf("second call must return the stored credential")
	}
}

func TestValidateControlPlaneURL(t *testing.T) {
	ok := []string{"https://cp.example.com", "https://cp.example.com:8443/base", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"}
	for _, u := range ok {
		if err := ValidateControlPlaneURL(u); err != nil {
			t.Errorf("%q should be accepted: %v", u, err)
		}
	}
	bad := []string{"http://cp.example.com", "http://10.0.0.5:8080", "ftp://cp.example.com", "ws://localhost"}
	for _, u := range bad {
		if err := ValidateControlPlaneURL(u); err == nil {
			t.Errorf("%q should be rejected (cleartext/unsupported scheme)", u)
		}
	}
}

func TestEnsureEnrolledNoCredentialNoTokenErrors(t *testing.T) {
	store := NewCredentialStore(t.TempDir())
	if _, err := EnsureEnrolled(context.Background(), &fakeEnroller{}, store, "", EnrolRequest{Name: "a"}); err == nil {
		t.Fatal("neither stored credential nor enrol token must error")
	}
}

func TestSendClusterInventoryPostsSnapshot(t *testing.T) {
	var gotPath, gotAuth, gotProto string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotProto = r.Header.Get(protoHeader)
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, 5*time.Second)
	snap := map[string]any{"cluster": "prod-eu"}
	if err := c.SendClusterInventory(context.Background(), "tok", snap); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotPath != "/api/v1/fleet/inventory/cluster" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" || gotProto != protoVersion {
		t.Fatalf("auth/proto headers wrong: %q %q", gotAuth, gotProto)
	}
	if gotBody["cluster"] != "prod-eu" {
		t.Fatalf("snapshot body not sent: %v", gotBody)
	}
}

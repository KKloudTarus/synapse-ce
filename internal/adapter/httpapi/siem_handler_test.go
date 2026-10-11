package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/ocsf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

func TestSIEMPatchPresenceAndUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"name":"Renamed","version":2}`, true},
		{`{"allow_hosts":[],"indexer_ack_supported":false,"version":2}`, true},
		{`{"version":2,"typo":true}`, false},
	} {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/siem/sinks/id", bytes.NewBufferString(tc.body))
		var body siemSinkBody
		err := decodeSIEM(httptest.NewRecorder(), req, &body)
		if (err == nil) != tc.valid {
			t.Fatalf("body %s: err=%v", tc.body, err)
		}
		if tc.valid && body.IndexerAckPresent && !body.AllowHostsPresent {
			t.Fatalf("presence flags lost: %+v", body)
		}
	}
}

func TestSIEMRoutesAreAdminOnlyAndHideSecrets(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := siemuc.NewMemory()
	svc, err := siemuc.NewService(store, store, store, vaultSealer{cipher}, nil, nil, siemClock{now: time.Unix(1_700_000_000, 0).UTC()}, &siemIDs{}, testSIEMSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rt.SetSIEM(svc)
	mux := rt.routes()

	denied := httptest.NewRequest(http.MethodGet, "/api/v1/siem/sinks", nil)
	denied = denied.WithContext(context.WithValue(denied.Context(), principalKey, Principal{ID: "ada", Role: "readonly", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, denied)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly status %d", rec.Code)
	}

	body := []byte(`{"name":"Main","provider":"splunk_hec","origin":"https://splunk.example:8088","secret":"splunk-token-value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/siem/sinks", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ada", Role: "admin", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("splunk-token-value")) {
		t.Fatalf("response leaked the secret: %s", rec.Body.String())
	}
	var created struct {
		ID string `json:"ID"`
	}
	// Encoding uses the Go field name unless the domain struct has json tags.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	id, _ := raw["ID"].(string)
	if id == "" {
		id, _ = raw["id"].(string)
	}
	if id == "" {
		t.Fatalf("missing id in %s", rec.Body.String())
	}
	_ = created
	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/siem/sinks/"+id+"/status", nil)
	statusReq = statusReq.WithContext(context.WithValue(statusReq.Context(), principalKey, Principal{ID: "ada", Role: "admin", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, statusReq)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("legacy v1")) {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestSIEMSentinelCreateValidatesTargetAndHidesCredential(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := siemuc.NewMemory()
	svc, err := siemuc.NewService(store, store, store, vaultSealer{cipher}, nil, nil, siemClock{now: time.Unix(1_700_000_000, 0).UTC()}, &siemIDs{}, testSIEMSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rt.SetSIEM(svc)
	mux := rt.routes()

	const credential = `{"tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","client_secret":"sentinel-client-secret"}`
	validBody, err := json.Marshal(map[string]any{
		"name":     "Sentinel",
		"provider": "microsoft_sentinel",
		"origin":   "https://example.eastus-1.ingest.monitor.azure.com",
		"target":   "dcr-0123456789abcdef0123456789abcdef/Custom-SynapseSIEM",
		"secret":   credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	created := siemAs(mux, http.MethodPost, "/api/v1/siem/sinks", string(validBody), "tenant-a")
	if created.Code != http.StatusCreated {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if bytes.Contains(created.Body.Bytes(), []byte("sentinel-client-secret")) || bytes.Contains(created.Body.Bytes(), []byte("client_secret")) {
		t.Fatalf("response leaked Sentinel credential material: %s", created.Body.String())
	}

	invalidBody, err := json.Marshal(map[string]any{
		"name":     "Bad Sentinel",
		"provider": "microsoft_sentinel",
		"origin":   "https://example.eastus-1.ingest.monitor.azure.com",
		"target":   "dcr-0123456789abcdef0123456789abcdef/SynapseSIEM",
		"secret":   credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	rejected := siemAs(mux, http.MethodPost, "/api/v1/siem/sinks", string(invalidBody), "tenant-a")
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("non-Custom stream status %d %s", rejected.Code, rejected.Body.String())
	}
	if bytes.Contains(rejected.Body.Bytes(), []byte("sentinel-client-secret")) {
		t.Fatalf("validation response leaked Sentinel credential: %s", rejected.Body.String())
	}
}

func TestSIEMRoutesHideOtherTenants(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store := siemuc.NewMemory()
	svc, err := siemuc.NewService(store, store, store, vaultSealer{cipher}, nil, nil, siemClock{now: time.Unix(1_700_000_000, 0).UTC()}, &siemIDs{}, testSIEMSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rt.SetSIEM(svc)
	mux := rt.routes()

	created := siemAs(mux, http.MethodPost, "/api/v1/siem/sinks", `{"name":"Main","provider":"splunk_hec","origin":"https://splunk.example:8088","secret":"splunk-token-value"}`, "tenant-a")
	if created.Code != http.StatusCreated {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	id, _ := raw["id"].(string)
	if id == "" {
		id, _ = raw["ID"].(string)
	}
	if id == "" {
		t.Fatalf("missing id in %s", created.Body.String())
	}
	own := siemAs(mux, http.MethodGet, "/api/v1/siem/sinks/"+id, "", "tenant-a")
	if own.Code != http.StatusOK {
		t.Fatalf("owner get %d %s", own.Code, own.Body.String())
	}
	paths := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/siem/sinks/" + id, ""},
		{http.MethodPatch, "/api/v1/siem/sinks/" + id, `{"name":"Stolen","version":1}`},
		{http.MethodPost, "/api/v1/siem/sinks/" + id + "/secret", `{"secret":"replacement-token","version":1}`},
		{http.MethodPost, "/api/v1/siem/sinks/" + id + "/origin", `{"origin":"https://other.example","secret":"replacement-token","replay":"cursor","version":1}`},
		{http.MethodPost, "/api/v1/siem/sinks/" + id + "/pause", `{"version":1}`},
		{http.MethodPost, "/api/v1/siem/sinks/" + id + "/resume", `{"version":1}`},
		{http.MethodPost, "/api/v1/siem/sinks/" + id + "/test", ""},
		{http.MethodGet, "/api/v1/siem/sinks/" + id + "/status", ""},
	}
	for _, path := range paths {
		rec := siemAs(mux, path.method, path.path, path.body, "tenant-b")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s tenant-b status %d %s", path.method, path.path, rec.Code, rec.Body.String())
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("splunk-token-value")) || bytes.Contains(rec.Body.Bytes(), []byte("https://splunk.example:8088")) {
			t.Fatalf("%s %s leaked tenant-a sink: %s", path.method, path.path, rec.Body.String())
		}
	}
	listed := siemAs(mux, http.MethodGet, "/api/v1/siem/sinks", "", "tenant-b")
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(`"items":[]`)) {
		t.Fatalf("tenant-b list %d %s", listed.Code, listed.Body.String())
	}
	if bytes.Contains(listed.Body.Bytes(), []byte(id)) {
		t.Fatalf("tenant-b list contained tenant-a sink %s", listed.Body.String())
	}
}

func siemAs(mux http.Handler, method, path, body, tenant string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ada", Role: "admin", TenantID: tenant}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

type vaultSealer struct{ cipher *vault.Cipher }

func (v vaultSealer) Seal(context.Context, []byte, []byte) (string, error) { return "sealed", nil }
func (v vaultSealer) Open(context.Context, string, []byte) ([]byte, error) {
	return nil, shared.ErrValidation
}

type siemClock struct{ now time.Time }

func (c siemClock) Now() time.Time { return c.now }

type siemIDs struct{ n int }

func (s *siemIDs) NewID() shared.ID {
	s.n++
	return shared.ID("sink-1")
}

var _ ports.SIEMSealer = vaultSealer{}

func testSIEMSchema(t *testing.T) *ocsf.Validator {
	t.Helper()
	schema, err := ocsf.New()
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

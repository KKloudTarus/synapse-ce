package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
)

type scopeContactStore struct{ seenTenant, seenUser shared.ID }

func (s *scopeContactStore) List(_ context.Context, tenant, user shared.ID) ([]ports.UserContact, error) {
	s.seenTenant, s.seenUser = tenant, user
	return []ports.UserContact{}, nil
}
func (s *scopeContactStore) Create(_ context.Context, c ports.UserContact) (ports.UserContact, error) {
	s.seenTenant, s.seenUser = c.TenantID, c.UserID
	return c, nil
}
func (*scopeContactStore) Delete(context.Context, shared.ID, shared.ID, shared.ID) error { return nil }
func (*scopeContactStore) RequestVerification(context.Context, ports.UserContactChallenge, shared.ID) error {
	return nil
}
func (*scopeContactStore) Verify(context.Context, shared.ID, shared.ID, shared.ID, func(shared.ID) string, time.Time) (ports.UserContact, error) {
	return ports.UserContact{}, nil
}
func (*scopeContactStore) LoadDelivery(context.Context, shared.ID, shared.ID) (ports.UserContactDelivery, bool, error) {
	return ports.UserContactDelivery{}, false, nil
}
func (*scopeContactStore) MarkSent(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*scopeContactStore) MarkDeliveryFailed(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*scopeContactStore) ImportOIDCEmail(context.Context, shared.ID, shared.ID, shared.ID, string, string, time.Time) error {
	return nil
}
func (*scopeContactStore) RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string, time.Time) error {
	return nil
}

func TestContactRoutesDeriveUserAndTenantFromPrincipal(t *testing.T) {
	store := &scopeContactStore{}
	cipher, err := vault.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := usercontacts.NewService(store, memory.NewUserRepository(), cipher, nil, idgen.RandomID{}, idgen.SystemClock{}, usercontacts.DeriveVerifierKey("test-key"), false)
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		switch token {
		case "alice":
			return Principal{ID: "alice", Name: "Alice", Role: "readonly", TenantID: "tenant-a"}, true
		case "bob":
			return Principal{ID: "bob", Name: "Bob", Role: "consultant", TenantID: "tenant-b"}, true
		case "machine":
			return Principal{ID: "machine", Role: "agent", TenantID: "tenant-a"}, true
		default:
			return Principal{}, false
		}
	})
	accepted := newFakeAUPStore()
	accepted.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{log: discardLog(), auth: auth, aup: newTestAUP(accepted, &fakeAudit{})}
	rt.SetUserContacts(svc)
	h := rt.Handler()
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := request(http.MethodGet, "/api/v1/me/contacts?user_id=bob&tenant_id=tenant-b", "alice", ""); w.Code != 200 || store.seenTenant != "tenant-a" || store.seenUser != "alice" {
		t.Fatalf("Alice read scope: %d %s %s", w.Code, store.seenTenant, store.seenUser)
	}
	if w := request(http.MethodGet, "/api/v1/me/contacts?user_id=alice", "bob", ""); w.Code != 200 || store.seenTenant != "tenant-b" || store.seenUser != "bob" {
		t.Fatalf("Bob read scope: %d %s %s", w.Code, store.seenTenant, store.seenUser)
	}
	body, _ := json.Marshal(map[string]string{"kind": "email", "value": "alice@example.com", "user_id": "bob", "tenant_id": "tenant-b"})
	if w := request(http.MethodPost, "/api/v1/me/contacts", "alice", string(body)); w.Code != 201 || store.seenTenant != "tenant-a" || store.seenUser != "alice" {
		t.Fatalf("create scope: %d %s %s", w.Code, store.seenTenant, store.seenUser)
	}
	if w := request(http.MethodGet, "/api/v1/me/contacts", "machine", ""); w.Code != 403 {
		t.Fatalf("machine read: %d", w.Code)
	}
	if w := request(http.MethodGet, "/api/v1/me/contacts", "", ""); w.Code != 401 {
		t.Fatalf("anonymous read: %d", w.Code)
	}
}

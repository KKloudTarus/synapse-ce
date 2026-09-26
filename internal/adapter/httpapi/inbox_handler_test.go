package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	inboxuc "github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scopeInbox struct{ tenant, user shared.ID }

func (s *scopeInbox) ListInbox(_ context.Context, tenant, user shared.ID, _ time.Time, _ shared.ID, _ bool, _ int) ([]ports.InboxItem, error) {
	s.tenant, s.user = tenant, user
	return nil, nil
}
func (*scopeInbox) UnreadInbox(context.Context, shared.ID, shared.ID) (int, error) { return 0, nil }
func (*scopeInbox) MarkInboxRead(context.Context, shared.ID, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*scopeInbox) MarkInboxAllRead(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*scopeInbox) ListInboxPreferences(context.Context, shared.ID, shared.ID) ([]ports.InboxPreference, error) {
	return nil, nil
}
func (*scopeInbox) SaveInboxPreference(context.Context, shared.ID, shared.ID, notification.EventType, string, notification.Preference, int, time.Time) (ports.InboxPreference, error) {
	return ports.InboxPreference{}, nil
}
func (*scopeInbox) LoadPersonalMail(context.Context, shared.ID, shared.ID, shared.ID, shared.ID, int) (string, string, string, bool, error) {
	return "", "", "", false, nil
}

type inboxClock struct{}

func (inboxClock) Now() time.Time { return time.Unix(1, 0).UTC() }

func TestInboxRoutesRejectSpoofedIdentityAndMachineRoles(t *testing.T) {
	store := &scopeInbox{}
	svc, err := inboxuc.NewService(store, inboxClock{})
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
	rt.SetInbox(svc)
	h := rt.Handler()
	request := func(path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := request("/api/v1/me/inbox?user_id=bob&tenant_id=tenant-b", "alice"); w.Code != http.StatusBadRequest {
		t.Fatalf("spoofed query: %d", w.Code)
	}
	if w := request("/api/v1/me/inbox", "alice"); w.Code != http.StatusOK || store.tenant != "tenant-a" || store.user != "alice" {
		t.Fatalf("alice scope: %d %s %s", w.Code, store.tenant, store.user)
	}
	if w := request("/api/v1/me/inbox", "bob"); w.Code != http.StatusOK || store.tenant != "tenant-b" || store.user != "bob" {
		t.Fatalf("bob scope: %d %s %s", w.Code, store.tenant, store.user)
	}
	if w := request("/api/v1/me/inbox", "machine"); w.Code != http.StatusForbidden {
		t.Fatalf("machine inbox: %d", w.Code)
	}
	if w := request("/api/v1/me/inbox/unread", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous unread: %d", w.Code)
	}
}

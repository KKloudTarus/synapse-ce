package httpapi

import (
	"context"
	"fmt"
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

// #1412 asks for a cross-user harness. TestContactRoutesDeriveUserAndTenantFromPrincipal covers the
// read and the create; these cover the four routes that address a contact by an identifier in the
// path, which is where a caller can name somebody else's row. The store below holds contacts per
// (tenant, user) and refuses to answer outside that pair, so a handler that passed through a
// caller-supplied identity would show up as another person's contact being read, changed or
// deleted.

type ownedContact struct {
	tenant, user shared.ID
	contact      ports.UserContact
}

type crossUserContactStore struct {
	contacts []ownedContact
	calls    []string
}

func (s *crossUserContactStore) record(method string, tenant, user shared.ID) {
	s.calls = append(s.calls, fmt.Sprintf("%s(%s,%s)", method, tenant, user))
}

func (s *crossUserContactStore) own(tenant, user shared.ID) []ports.UserContact {
	var out []ports.UserContact
	for _, row := range s.contacts {
		if row.tenant == tenant && row.user == user {
			out = append(out, row.contact)
		}
	}
	return out
}

func (s *crossUserContactStore) List(_ context.Context, tenant, user shared.ID) ([]ports.UserContact, error) {
	s.record("List", tenant, user)
	return s.own(tenant, user), nil
}

func (s *crossUserContactStore) Create(_ context.Context, c ports.UserContact) (ports.UserContact, error) {
	s.record("Create", c.TenantID, c.UserID)
	s.contacts = append(s.contacts, ownedContact{tenant: c.TenantID, user: c.UserID, contact: c})
	return c, nil
}

func (s *crossUserContactStore) Delete(_ context.Context, tenant, user, id shared.ID) error {
	s.record("Delete", tenant, user)
	for i, row := range s.contacts {
		if row.tenant == tenant && row.user == user && row.contact.ID == id {
			s.contacts = append(s.contacts[:i], s.contacts[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("contact: %w", shared.ErrNotFound)
}

func (s *crossUserContactStore) RequestVerification(_ context.Context, challenge ports.UserContactChallenge, _ shared.ID) error {
	s.record("RequestVerification", challenge.TenantID, challenge.UserID)
	return nil
}

func (s *crossUserContactStore) Verify(_ context.Context, tenant, user, id shared.ID, _ func(shared.ID) string, _ time.Time) (ports.UserContact, error) {
	s.record("Verify", tenant, user)
	for _, row := range s.contacts {
		if row.tenant == tenant && row.user == user && row.contact.ID == id {
			return row.contact, nil
		}
	}
	return ports.UserContact{}, fmt.Errorf("contact: %w", shared.ErrNotFound)
}

func (*crossUserContactStore) LoadDelivery(context.Context, shared.ID, shared.ID) (ports.UserContactDelivery, bool, error) {
	return ports.UserContactDelivery{}, false, nil
}
func (*crossUserContactStore) MarkSent(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*crossUserContactStore) MarkDeliveryFailed(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (*crossUserContactStore) ImportOIDCEmail(context.Context, shared.ID, shared.ID, shared.ID, string, string, time.Time) error {
	return nil
}
func (*crossUserContactStore) RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string, time.Time) error {
	return nil
}

var _ ports.UserContactStore = (*crossUserContactStore)(nil)

// stubContactMailer accepts the verification mail so the allow case reaches 202. The code itself
// is never read here: this file is about which identity a route acts on.
type stubContactMailer struct{ sent []string }

func (m *stubContactMailer) SendContactVerification(_ context.Context, address, _ string, _ shared.ID) ports.NotificationSendResult {
	m.sent = append(m.sent, address)
	return ports.NotificationSendResult{StatusCode: http.StatusOK}
}

var _ ports.UserContactMailer = (*stubContactMailer)(nil)

// TestContactWriteRoutesStayOnTheCallersOwnIdentity drives every contact route that takes an
// identifier in the path, as a second person in the same tenant and as a person in another tenant.
func TestContactWriteRoutesStayOnTheCallersOwnIdentity(t *testing.T) {
	store := &crossUserContactStore{}
	bobsContact := ports.UserContact{ID: "contact-bob", TenantID: "tenant-a", UserID: "bob", Kind: "email", Value: "bob@example.test"}
	store.contacts = append(store.contacts, ownedContact{tenant: "tenant-a", user: "bob", contact: bobsContact})

	cipher, err := vault.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	mailer := &stubContactMailer{}
	svc, err := usercontacts.NewService(store, memory.NewUserRepository(), cipher, mailer, idgen.RandomID{}, idgen.SystemClock{}, usercontacts.DeriveVerifierKey("test-key"), true)
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, error) {
		switch token {
		case "alice":
			return Principal{ID: "alice", Name: "Alice", Role: "readonly", TenantID: "tenant-a"}, nil
		case "bob":
			return Principal{ID: "bob", Name: "Bob", Role: "readonly", TenantID: "tenant-a"}, nil
		case "carol":
			return Principal{ID: "carol", Name: "Carol", Role: "admin", TenantID: "tenant-b"}, nil
		case "machine":
			return Principal{ID: "machine", Role: "agent", TenantID: "tenant-a"}, nil
		default:
			return Principal{}, errTestCredentialInvalid
		}
	})
	accepted := newFakeAUPStore()
	accepted.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{log: discardLog(), auth: auth, aup: newTestAUP(accepted, &fakeAudit{})}
	rt.SetUserContacts(svc)
	handler := rt.Handler()

	send := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}
	bobStillHasHisContact := func(t *testing.T, when string) {
		t.Helper()
		if len(store.own("tenant-a", "bob")) != 1 {
			t.Fatalf("%s: bob's contact is gone: %+v", when, store.contacts)
		}
	}

	for _, probe := range []struct {
		name, method, path, body string
	}{
		{"delete", http.MethodDelete, "/api/v1/me/contacts/contact-bob", ""},
		{"request verification", http.MethodPost, "/api/v1/me/contacts/contact-bob/verification", ""},
		{"verify", http.MethodPost, "/api/v1/me/contacts/contact-bob/verify", `{"code":"12345678"}`},
		// The same three routes with an identity supplied by the caller, in the query and in the
		// body. A handler that reads either one would act as bob.
		{"delete with a user_id query", http.MethodDelete, "/api/v1/me/contacts/contact-bob?user_id=bob&tenant_id=tenant-a", ""},
		{"request verification with a user_id query", http.MethodPost, "/api/v1/me/contacts/contact-bob/verification?user_id=bob", ""},
		{"verify with an identity in the body", http.MethodPost, "/api/v1/me/contacts/contact-bob/verify?user_id=bob", `{"code":"12345678","user_id":"bob","tenant_id":"tenant-a"}`},
	} {
		t.Run("another person in the same tenant cannot "+probe.name, func(t *testing.T) {
			store.calls = nil
			response := send(probe.method, probe.path, "alice", probe.body)
			if response.Code == http.StatusOK || response.Code == http.StatusNoContent || response.Code == http.StatusAccepted {
				t.Errorf("alice %s bob's contact: %d %s", probe.name, response.Code, response.Body.String())
			}
			for _, call := range store.calls {
				if strings.Contains(call, "bob") {
					t.Errorf("alice's %s reached the store as bob: %v", probe.name, store.calls)
				}
				if !strings.Contains(call, "alice") {
					t.Errorf("alice's %s addressed %q rather than her own identity", probe.name, call)
				}
			}
			bobStillHasHisContact(t, "after alice's "+probe.name)
		})

		t.Run("another tenant cannot "+probe.name, func(t *testing.T) {
			store.calls = nil
			response := send(probe.method, probe.path, "carol", probe.body)
			if response.Code == http.StatusOK || response.Code == http.StatusNoContent || response.Code == http.StatusAccepted {
				t.Errorf("carol %s bob's contact: %d %s", probe.name, response.Code, response.Body.String())
			}
			for _, call := range store.calls {
				if strings.Contains(call, "tenant-a") {
					t.Errorf("carol's %s reached tenant-a: %v", probe.name, store.calls)
				}
			}
			bobStillHasHisContact(t, "after carol's "+probe.name)
		})

		t.Run("a machine role cannot "+probe.name, func(t *testing.T) {
			store.calls = nil
			if response := send(probe.method, probe.path, "machine", probe.body); response.Code != http.StatusForbidden {
				t.Errorf("machine %s = %d, want 403", probe.name, response.Code)
			}
			if len(store.calls) != 0 {
				t.Errorf("a machine role reached the store: %v", store.calls)
			}
			bobStillHasHisContact(t, "after the machine's "+probe.name)
		})

		t.Run("no principal cannot "+probe.name, func(t *testing.T) {
			store.calls = nil
			if response := send(probe.method, probe.path, "", probe.body); response.Code != http.StatusUnauthorized {
				t.Errorf("anonymous %s = %d, want 401", probe.name, response.Code)
			}
			if len(store.calls) != 0 {
				t.Errorf("an anonymous call reached the store: %v", store.calls)
			}
			bobStillHasHisContact(t, "after the anonymous "+probe.name)
		})
	}

	t.Run("bob can still act on his own contact", func(t *testing.T) {
		store.calls = nil
		if response := send(http.MethodPost, "/api/v1/me/contacts/contact-bob/verification", "bob", ""); response.Code != http.StatusAccepted {
			t.Fatalf("bob's own verification request = %d %s", response.Code, response.Body.String())
		}
		if len(store.calls) == 0 || !strings.Contains(store.calls[len(store.calls)-1], "bob") {
			t.Errorf("bob's request did not reach the store as bob: %v", store.calls)
		}
		if response := send(http.MethodDelete, "/api/v1/me/contacts/contact-bob", "bob", ""); response.Code != http.StatusNoContent {
			t.Fatalf("bob's own delete = %d %s", response.Code, response.Body.String())
		}
		if len(store.own("tenant-a", "bob")) != 0 {
			t.Errorf("bob's own delete left the contact: %+v", store.contacts)
		}
	})

	t.Run("the personal channel view is scoped and machine roles are refused", func(t *testing.T) {
		if response := send(http.MethodGet, "/api/v1/me/personal-channels", "alice", ""); response.Code != http.StatusOK {
			t.Errorf("alice personal channels = %d %s", response.Code, response.Body.String())
		}
		if response := send(http.MethodGet, "/api/v1/me/personal-channels", "machine", ""); response.Code != http.StatusForbidden {
			t.Errorf("machine personal channels = %d, want 403", response.Code)
		}
		if response := send(http.MethodGet, "/api/v1/me/personal-channels", "", ""); response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous personal channels = %d, want 401", response.Code)
		}
	})
}

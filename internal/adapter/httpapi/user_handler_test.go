package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

func newUsersRouter(t *testing.T) *Router {
	t.Helper()
	svc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("users svc: %v", err)
	}
	return &Router{log: discardLog(), users: svc}
}

func ctxAs(role string) context.Context {
	return context.WithValue(context.Background(), principalKey, Principal{ID: "p1", Name: "P", Role: role})
}

// ctxAsUser builds a principal with an explicit id and tenant, which is what user management is
// scoped by.
func ctxAsUser(id, role, tenant string) context.Context {
	return context.WithValue(context.Background(), principalKey, Principal{ID: id, Name: id, Role: role, TenantID: tenant})
}

func TestCreateUserAdminOnly(t *testing.T) {
	rt := newUsersRouter(t)

	// A member may not create users.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"name":"Bob","role":"member"}`)).WithContext(ctxAs("member"))
	rec := httptest.NewRecorder()
	rt.authz(userdom.PermAdminister, rt.createUser)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member create: want 403, got %d", rec.Code)
	}

	// An admin can, and gets the API key exactly once.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"name":"Bob","role":"member"}`)).WithContext(ctxAs("admin"))
	rec = httptest.NewRecorder()
	rt.authz(userdom.PermAdminister, rt.createUser)(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			ID, Name, Role string
		} `json:"user"`
		APIKey string `json:"apiKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.User.Name != "Bob" || !strings.HasPrefix(resp.APIKey, "syn_") {
		t.Errorf("unexpected create response: %+v", resp)
	}
	// The hash must never be serialized.
	if strings.Contains(rec.Body.String(), "api_key_hash") || strings.Contains(rec.Body.String(), "APIKeyHash") {
		t.Error("user response leaked the api-key hash")
	}
}

func TestListUsersAdminOnly(t *testing.T) {
	rt := newUsersRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil).WithContext(ctxAs("member"))
	rec := httptest.NewRecorder()
	rt.authz(userdom.PermAdminister, rt.listUsers)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member list: want 403, got %d", rec.Code)
	}
}

// seqIDs mints distinct ids so a test can provision more than one user (the shared engIDs helper
// returns a constant).
type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID("u-" + strconv.Itoa(g.n))
}

// usersRouterWithService returns a router over a real users service so the tests exercise the
// production route → authz → handler → use case chain.
func usersRouterWithService(t *testing.T) (*Router, *usersuc.Service) {
	t.Helper()
	svc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("users svc: %v", err)
	}
	return &Router{log: discardLog(), users: svc}, svc
}

func callUsers(t *testing.T, rt *Router, ctx context.Context, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

// seedTenantAdmin provisions an admin through the use case and returns its id and API key.
func seedTenantAdmin(t *testing.T, svc *usersuc.Service, tenant, name string) (string, string) {
	t.Helper()
	u, key, err := svc.CreateUser(context.Background(), usersuc.Actor{ID: usersuc.BootstrapID}, tenant, name, userdom.RoleAdmin)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return u.ID.String(), key
}

func decodeUserKey(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var resp struct {
		User   userView `json:"user"`
		APIKey string   `json:"apiKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return resp.User.ID, resp.APIKey
}

// TestRotateKeyInvalidatesTheOldKey drives the whole revocation path over HTTP: the rotated key
// authenticates, the previous one does not.
func TestRotateKeyInvalidatesTheOldKey(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	admin := ctxAsUser(adminID, "admin", "acme")

	created := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	targetID, oldKey := decodeUserKey(t, created)

	rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users/"+targetID+"/rotate-key", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	_, newKey := decodeUserKey(t, rec)
	if newKey == "" || newKey == oldKey {
		t.Fatalf("rotate must return a new key, got %q", newKey)
	}
	if strings.Contains(rec.Body.String(), "api_key_hash") || strings.Contains(rec.Body.String(), "APIKeyHash") {
		t.Error("rotate response leaked the api-key hash")
	}
	if _, err := svc.Authenticate(context.Background(), oldKey); err == nil {
		t.Error("the rotated-away key still authenticates")
	}
	if _, err := svc.Authenticate(context.Background(), newKey); err != nil {
		t.Errorf("the new key must authenticate: %v", err)
	}
}

// TestDisableRejectsTheKeyAndEnableRestoresIt proves the product can revoke access without deleting
// the identity, and put it back.
func TestDisableRejectsTheKeyAndEnableRestoresIt(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	admin := ctxAsUser(adminID, "admin", "acme")
	created := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`)
	targetID, key := decodeUserKey(t, created)

	if rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users/"+targetID+"/disable", ""); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Authenticate(context.Background(), key); err == nil {
		t.Error("a disabled user's key still authenticates")
	}
	if rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users/"+targetID+"/enable", ""); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Authenticate(context.Background(), key); err != nil {
		t.Errorf("a re-enabled user's key must authenticate: %v", err)
	}
}

func TestUpdateUserNameAndRole(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	admin := ctxAsUser(adminID, "admin", "acme")
	targetID, _ := decodeUserKey(t, callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`))

	rec := callUsers(t, rt, admin, http.MethodPatch, "/api/v1/users/"+targetID, `{"name":"Alice Smith","role":"reviewer"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	var got userView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "Alice Smith" || got.Role != string(userdom.RoleReviewer) {
		t.Fatalf("update = %+v", got)
	}
	if rec := callUsers(t, rt, admin, http.MethodPatch, "/api/v1/users/"+targetID, `{"role":"mcp"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("machine role = %d, want 400", rec.Code)
	}
	if rec := callUsers(t, rt, admin, http.MethodPatch, "/api/v1/users/nope", `{"name":"Ghost"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown user = %d, want 404", rec.Code)
	}
}

// TestUserManagementIsAdminOnly pins the authorization floor for every mutation added here.
func TestUserManagementIsAdminOnly(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Admin")
	admin := ctxAsUser(adminID, "admin", "acme")
	targetID, _ := decodeUserKey(t, callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","role":"member"}`))

	routes := []struct {
		method, path, body string
	}{
		{http.MethodPatch, "/api/v1/users/" + targetID, `{"name":"Mallory"}`},
		{http.MethodPost, "/api/v1/users/" + targetID + "/disable", ""},
		{http.MethodPost, "/api/v1/users/" + targetID + "/enable", ""},
		{http.MethodPost, "/api/v1/users/" + targetID + "/rotate-key", ""},
	}
	for _, role := range []string{"member", "consultant", "reviewer", "readonly", "agent", "mcp"} {
		for _, route := range routes {
			rec := callUsers(t, rt, ctxAsUser("intruder", role, "acme"), route.method, route.path, route.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %q = %d, want 403", route.method, route.path, role, rec.Code)
			}
		}
	}
}

// TestCannotDisableTheLastEnabledAdminOverHTTP keeps an admin from locking its tenant out.
func TestCannotDisableTheLastEnabledAdminOverHTTP(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "acme", "Only Admin")
	admin := ctxAsUser(adminID, "admin", "acme")

	rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users/"+adminID+"/disable", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("self-disable of the last admin = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if rec := callUsers(t, rt, admin, http.MethodPatch, "/api/v1/users/"+adminID, `{"role":"readonly"}`); rec.Code != http.StatusConflict {
		t.Fatalf("self-demote of the last admin = %d, want 409", rec.Code)
	}
	// A second admin lifts the guard.
	secondID, _ := decodeUserKey(t, callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Second","role":"admin"}`))
	if secondID == "" {
		t.Fatal("second admin was not created")
	}
	if rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users/"+adminID+"/disable", ""); rec.Code != http.StatusOK {
		t.Fatalf("disable with a second admin present = %d: %s", rec.Code, rec.Body.String())
	}
}

// TestCreateUserRejectsAnotherTenant is the cross-tenant defect: a tenant-A admin could provision an
// admin into tenant B and receive that admin's API key.
func TestCreateUserRejectsAnotherTenant(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminID, _ := seedTenantAdmin(t, svc, "tenant-a", "A Admin")
	admin := ctxAsUser(adminID, "admin", "tenant-a")

	rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Planted","role":"admin","tenant_id":"other-b"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "syn_") {
		t.Fatal("a refused cross-tenant create still returned an API key")
	}
	// The caller's own tenant, spelled explicitly, is still allowed.
	if rec := callUsers(t, rt, admin, http.MethodPost, "/api/v1/users", `{"name":"Alice","tenant_id":"tenant-a"}`); rec.Code != http.StatusCreated {
		t.Fatalf("same-tenant create = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestListUsersReturnsOnlyTheCallersTenant is the read half of the same defect.
func TestListUsersReturnsOnlyTheCallersTenant(t *testing.T) {
	rt, svc := usersRouterWithService(t)
	adminAID, _ := seedTenantAdmin(t, svc, "tenant-a", "A Admin")
	adminBID, _ := seedTenantAdmin(t, svc, "tenant-b", "B Admin")
	if _, _, err := svc.CreateUser(context.Background(), usersuc.Actor{ID: adminBID, TenantID: "tenant-b"}, "", "B Member", userdom.RoleMember); err != nil {
		t.Fatalf("seed tenant-b member: %v", err)
	}

	rec := callUsers(t, rt, ctxAsUser(adminBID, "admin", "tenant-b"), http.MethodGet, "/api/v1/users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var roster []userView
	if err := json.Unmarshal(rec.Body.Bytes(), &roster); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(roster) != 2 {
		t.Fatalf("tenant-b roster = %d users, want 2: %s", len(roster), rec.Body.String())
	}
	for _, u := range roster {
		if u.ID == adminAID {
			t.Errorf("tenant-b listed tenant-a's admin %s", u.ID)
		}
	}
}

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

func newUsersRouter(t *testing.T) *Router {
	t.Helper()
	svc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, engIDs{})
	if err != nil {
		t.Fatalf("users svc: %v", err)
	}
	return &Router{log: discardLog(), users: svc}
}

func ctxAs(role string) context.Context {
	return context.WithValue(context.Background(), principalKey, Principal{ID: "p1", Name: "P", Role: role})
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

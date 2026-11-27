package httpapi

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// The users seed plants one tenantA operator with one approved OIDC link, under fixed ids, so the user
// routes are addressed at a real tenantA record instead of at the engagement id "{id}" otherwise takes.
const (
	usersSeedUser   = shared.ID("harness-user-A")
	usersSeedLink   = shared.ID("harness-oidc-link-A")
	usersSeedIssuer = "https://idp.harness.example"
	usersSeedMarker = "tenant-A-oidc-subject-marker"
)

func init() {
	byUser := []string{
		"GET /api/v1/users/{id}/oidc-links",
		"PATCH /api/v1/users/{id}",
		"POST /api/v1/users/{id}/disable",
		"POST /api/v1/users/{id}/enable",
		"POST /api/v1/users/{id}/rotate-key",
		"POST /api/v1/users/{id}/oidc-links",
	}
	values := map[string]map[string]string{
		"DELETE /api/v1/users/{id}/oidc-links/{linkId}": {"{id}": usersSeedUser.String(), "{linkId}": usersSeedLink.String()},
	}
	for _, route := range byUser {
		values[route] = map[string]string{"{id}": usersSeedUser.String()}
	}
	registerHarnessSeed(harnessSeed{
		Name:            "users",
		Routes:          []string{"GET /api/v1/users/{id}/oidc-links"},
		RoutePathValues: values,
		Run:             seedUsers,
	})
}

// seedUsers plants the operator directly in the fixture's user repository, so its id is fixed, and
// enables OIDC linking for tenantA over an in-memory identity store holding the one link. The link's
// subject is the marker the read sweep looks for.
func seedUsers(w *harnessWorld) []string {
	w.t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenantA")
	now := time.Unix(1, 0).UTC()
	operator := &userdom.User{ID: usersSeedUser, Name: "A Operator", Role: userdom.RoleConsultant, TenantID: "tenantA", APIKeyHash: "harness-user-A-key", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := w.userRepo.Create(ctx, operator); err != nil {
		w.t.Fatalf("seed tenantA operator: %v", err)
	}
	identities, err := memory.NewIdentityStore(w.userRepo)
	if err != nil {
		w.t.Fatalf("identity store: %v", err)
	}
	link, err := identity.NewExternalIdentity(usersSeedLink, "tenantA", usersSeedUser, usersSeedIssuer, usersSeedMarker, now)
	if err != nil {
		w.t.Fatalf("build OIDC link: %v", err)
	}
	if err := identities.CreateExternalIdentity(ctx, link); err != nil {
		w.t.Fatalf("seed OIDC link: %v", err)
	}
	w.users.SetIdentityStore(identities)
	if err := w.users.SetOIDCLinking(usersSeedIssuer, "tenantA"); err != nil {
		w.t.Fatalf("enable OIDC linking: %v", err)
	}
	return []string{usersSeedMarker}
}

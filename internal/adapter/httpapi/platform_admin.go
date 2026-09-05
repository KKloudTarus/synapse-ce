package httpapi

import (
	"context"
	"net/http"
)

// Some resources are deliberately global rather than tenant-scoped: the vulnerability sources
// every tenant's detection reads from are one shared registry, with no tenant_id column. A
// tenant admin who could rewrite that registry would decide what advisories every other tenant
// sees, and could point the control plane's own HTTP client at a host of their choosing. The
// tenant-admin capability is therefore not sufficient for those routes.
//
// The platform identity is the bootstrap principal seeded from SYNAPSE_API_TOKEN (id
// PrincipalOperator). It is the operator of the deployment rather than a member of any tenant,
// which is exactly the authority a global registry needs.

// IsPlatformAdmin reports whether the request principal operates the deployment itself rather
// than a single tenant.
//
// It reads the authenticated principal directly instead of going through PrincipalFrom, which
// falls back to the operator id when no principal is bound. That fallback keeps historical
// attribution coherent, but as an authorization test it would fail open for any request that
// somehow reached a handler without passing the authenticator.
func IsPlatformAdmin(ctx context.Context) bool {
	p, ok := principalObj(ctx)
	return ok && p.ID == PrincipalOperator
}

// requirePlatformAdmin rejects a caller who holds only tenant-level authority. It is applied on
// top of the usual authz check, never instead of it, so the permission floor still applies.
func (rt *Router) requirePlatformAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsPlatformAdmin(r.Context()) {
			writeJSON(w, http.StatusForbidden, errorBody{Error: "this resource is global to the deployment and can only be changed by the platform operator"})
			return
		}
		next(w, r)
	}
}

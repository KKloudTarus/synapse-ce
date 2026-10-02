package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
)

// Some resources are deliberately global rather than tenant-scoped: the vulnerability sources
// every tenant's detection reads from are one shared registry, with no tenant_id column. A
// tenant admin who could rewrite that registry would decide what advisories every other tenant
// sees, and could point the control plane's own HTTP client at a host of their choosing. The
// tenant-admin capability is therefore not sufficient for those routes.
//
// The platform identity is the bootstrap principal seeded from SYNAPSE_API_TOKEN (id
// PrincipalOperator, credential kind bootstrap). It is the operator of the deployment rather than
// a member of any tenant, which is exactly the authority a global registry needs.

// IsPlatformAdmin reports whether the request principal operates the deployment itself rather
// than a single tenant. It asks the same authorization decision as every route guard, so the
// answer requires both the bootstrap actor id and the bootstrap credential: a per-user key or a
// browser session never carries platform authority, whatever its id.
func IsPlatformAdmin(ctx context.Context) bool {
	return decideContext(ctx, authz.Action{PlatformOnly: true}).Allowed
}

// requirePlatformAdmin rejects a caller who holds only tenant-level authority. It is applied on
// top of the usual authz check, never instead of it, so the permission floor still applies.
func (rt *Router) requirePlatformAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decision := decideRequest(r, authz.Action{PlatformOnly: true})
		if !decision.Allowed {
			if decision.Reason == authz.ReasonUnauthenticated {
				authenticationRequired(w)
				return
			}
			writeJSON(w, http.StatusForbidden, errorBody{Error: "this resource is global to the deployment and can only be changed by the platform operator", Code: CodePermissionDenied})
			return
		}
		next(w, r)
	}
}

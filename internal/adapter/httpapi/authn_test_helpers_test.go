package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
)

// errTestCredentialInvalid is what a test resolver returns for an unknown token.
var errTestCredentialInvalid = authz.ErrCredentialInvalid

// testCredentialErr maps a test resolver's match to the resolver error contract.
func testCredentialErr(ok bool) error {
	if ok {
		return nil
	}
	return errTestCredentialInvalid
}

// testPrincipal builds a request principal the way the authenticator does: the bootstrap actor id
// carries the bootstrap credential, every other id a per-user key.
func testPrincipal(id, role, tenant string) Principal {
	kind := authz.KindAPIKey
	if id == PrincipalOperator {
		kind = authz.KindBootstrap
	}
	return Principal{ID: id, Name: id, Role: role, TenantID: tenant, Credential: kind}
}

// wantDenied is the status a denied request gets: 401 without a principal, 403 with one.
func wantDenied(role string) int {
	if role == "" {
		return 401
	}
	return 403
}

// asOperator binds the bootstrap principal, which is what a direct handler call used to inherit
// from the removed operator fallback. Attribution to "operator" stays the bootstrap actor id.
func asOperator(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), principalKey, testPrincipal(PrincipalOperator, "admin", "")))
}

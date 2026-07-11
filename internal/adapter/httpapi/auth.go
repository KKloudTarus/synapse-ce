package httpapi

import (
	"context"
	"net/http"
	"strings"
)

// PrincipalOperator is the fallback principal id (the bootstrap admin also uses it,
// so historical "operator" attribution stays coherent). Once auth is wired, the real
// authenticated user is stamped into the context per request.
const PrincipalOperator = "operator"

// Principal is the authenticated subject for a request.
type Principal struct {
	ID   string
	Name string
	Role string
	// TenantID is the tenant the principal belongs to – it scopes the request's data and stamps
	// new records. Empty = the single default tenant (single-tenant mode).
	TenantID string
}

type ctxKey int

const principalKey ctxKey = iota

// PrincipalFrom returns the authenticated principal's id from ctx (the value used as
// the actor on every attributable action), defaulting to operator if unset.
func PrincipalFrom(ctx context.Context) string {
	if p, ok := ctx.Value(principalKey).(Principal); ok && p.ID != "" {
		return p.ID
	}
	return PrincipalOperator
}

// TenantFrom returns the authenticated principal's tenant from ctx – the tenant that scopes the
// request's data and stamps new records. Empty = the single default tenant (single-tenant mode).
func TenantFrom(ctx context.Context) string {
	if p, ok := ctx.Value(principalKey).(Principal); ok {
		return p.TenantID
	}
	return ""
}

// principalObj returns the full authenticated principal from ctx.
func principalObj(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok && p.ID != ""
}

// Resolver maps a presented bearer token to a Principal. ok=false means the token
// is unknown/disabled (→ 401). Implemented over the users service in the wiring.
type Resolver func(ctx context.Context, token string) (Principal, bool)

// Authenticator validates the bearer token on each request via the Resolver and
// stamps the resolved principal into the request context for attribution.
type Authenticator struct {
	resolve Resolver
}

// NewAuthenticator builds an authenticator from a token resolver.
func NewAuthenticator(resolve Resolver) *Authenticator {
	return &Authenticator{resolve: resolve}
}

// Middleware enforces a valid bearer token on every route except publicPaths (no
// anonymous access) and stamps the authenticated principal into the context.
func (a *Authenticator) Middleware(publicPaths map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		token, ok := bearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}
		principal, ok := a.resolve(r.Context(), token)
		if !ok {
			unauthorized(w)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, errorBody{Error: "missing or invalid API token"})
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		t := strings.TrimSpace(h[len(prefix):])
		return t, t != ""
	}
	return "", false
}

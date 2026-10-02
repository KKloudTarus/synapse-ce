package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// PrincipalOperator is the stable actor id of the bootstrap principal seeded from
// SYNAPSE_API_TOKEN. Historical records are attributed to it. It is never a fallback: a request
// without an authenticated principal is refused, not attributed to the operator.
const PrincipalOperator = authz.BootstrapActorID

// Principal is the authenticated subject for a request.
type Principal struct {
	ID   string
	Name string
	Role string
	// TenantID is the tenant the principal belongs to – it scopes the request's data and stamps
	// new records. Empty = the single default tenant (single-tenant mode).
	TenantID string
	// Credential is the kind of credential that authenticated the request. The authenticator
	// always sets it. An empty kind is read as an ordinary per-user credential: it can never be
	// the bootstrap credential, so it never carries platform authority.
	Credential authz.CredentialKind
	// CredentialID is the non-secret id of the credential (the session id for a browser session).
	CredentialID string
	// AuthenticatedAt is when the credential lineage was established, when known.
	AuthenticatedAt time.Time
	// Provenance names the authentication source, for example "bearer" or "oidc".
	Provenance string
}

// authz returns the typed domain principal the authorization decision reads.
func (p Principal) authz() authz.Principal {
	kind := p.Credential
	if kind == "" {
		kind = authz.KindAPIKey
	}
	return authz.Principal{
		ActorID:         p.ID,
		TenantID:        shared.TenantOrDefault(shared.ID(p.TenantID)).String(),
		Role:            userdom.Role(p.Role),
		Credential:      authz.Credential{Kind: kind, ID: p.CredentialID},
		AuthenticatedAt: p.AuthenticatedAt,
		Provenance:      p.Provenance,
	}
}

type ctxKey int

const principalKey ctxKey = iota

// PrincipalFrom returns the authenticated principal's id from ctx (the value used as the actor on
// every attributable action). It returns "" when no principal is bound: there is no operator
// fallback. Protected routes are refused by the authorization guard before a handler runs, so a
// handler only ever sees "" if it is reachable without authentication, and "" fails every actor
// validation rather than being recorded as the operator.
func PrincipalFrom(ctx context.Context) string {
	if p, ok := principalObj(ctx); ok {
		return p.ID
	}
	return ""
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

// decideRequest is the single human authorization decision for a request. Route guards and
// handler-level checks both call it.
func decideRequest(r *http.Request, action authz.Action) authz.Decision {
	return decideContext(r.Context(), action)
}

// decideContext evaluates action for the principal bound to ctx. A missing principal is denied.
func decideContext(ctx context.Context, action authz.Action) authz.Decision {
	p, ok := principalObj(ctx)
	if !ok {
		return authz.Decide(authz.Principal{}, action)
	}
	return authz.Decide(p.authz(), action)
}

// Resolver maps a presented bearer token to a Principal. The error wraps
// authz.ErrCredentialInvalid when the token is definitively bad and
// authz.ErrAuthenticationUnavailable when a dependency failed. Implemented over the users service
// in the wiring.
type Resolver func(ctx context.Context, token string) (Principal, error)

// SessionResolver validates an opaque browser session. CSRF is passed only for cookie
// authentication. Errors follow the Resolver contract, plus authz.ErrCSRFInvalid.
type SessionResolver interface {
	Authenticate(ctx context.Context, token, csrfToken string, unsafe bool) (Principal, error)
}

// Authenticator validates the bearer token or browser session on each request and stamps the
// resolved principal into the request context for attribution and authorization.
type Authenticator struct {
	resolve Resolver
	session SessionResolver
}

// SetSessionResolver enables the OIDC BFF cookie session fallback while retaining bearer authentication.
func (a *Authenticator) SetSessionResolver(resolve SessionResolver) { a.session = resolve }

// NewAuthenticator builds an authenticator from a token resolver.
func NewAuthenticator(resolve Resolver) *Authenticator {
	return &Authenticator{resolve: resolve}
}

// Middleware enforces a valid credential on every route except publicPaths (no anonymous access)
// and stamps the authenticated principal into the context.
func (a *Authenticator) Middleware(publicPaths map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		var principal Principal
		if token, ok := bearerToken(r); ok {
			// Bearer credentials retain their existing API semantics, including no CSRF requirement.
			var err error
			principal, err = a.resolve(r.Context(), token)
			if err == nil && principal.ID == "" {
				err = authz.ErrCredentialInvalid
			}
			if err != nil {
				writeAuthenticationError(w, err)
				return
			}
			if principal.Provenance == "" {
				principal.Provenance = "bearer"
			}
		} else {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || cookie.Value == "" || a.session == nil {
				authenticationRequired(w)
				return
			}
			unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			principal, err = a.session.Authenticate(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token"), unsafe)
			if err == nil && principal.ID == "" {
				err = authz.ErrCredentialInvalid
			}
			if err != nil {
				writeAuthenticationError(w, err)
				return
			}
			principal.Credential = authz.KindBrowserSession
		}
		principal.TenantID = shared.TenantOrDefault(shared.ID(principal.TenantID)).String()
		ctx := context.WithValue(r.Context(), principalKey, principal)
		ctx = shared.WithTenant(ctx, shared.ID(principal.TenantID))
		if observation := requestObservationFrom(ctx); observation != nil {
			observation.setPrincipal(principal.ID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const unauthorizedMessage = "missing or invalid API token"

// unauthorized is the machine-plane 401 (for example the internal egress-grant endpoint), which
// has its own static credential and no human credential semantics.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, errorBody{Error: unauthorizedMessage, Code: CodeAuthenticationRequired})
}

// authenticationRequired answers a request that presented no credential.
func authenticationRequired(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, errorBody{Error: unauthorizedMessage, Code: CodeAuthenticationRequired})
}

// writeAuthenticationError classifies a failed authentication. Only a definitively invalid
// credential is authentication_invalid; a CSRF failure keeps the session; any other failure,
// including an unclassified one, is a dependency outage that never tells the client to discard a
// credential that may still be valid.
func writeAuthenticationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authz.ErrCSRFInvalid):
		writeCodedError(w, CodeCSRFInvalid, "CSRF token is missing or invalid")
	case errors.Is(err, authz.ErrAuthenticationUnavailable):
		writeCodedError(w, CodeAuthenticationUnavailable, "authentication is temporarily unavailable; retry shortly")
	case errors.Is(err, authz.ErrCredentialInvalid):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: unauthorizedMessage, Code: CodeAuthenticationInvalid})
	default:
		writeCodedError(w, CodeAuthenticationUnavailable, "authentication is temporarily unavailable; retry shortly")
	}
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

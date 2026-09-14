package httpapi

import (
	"context"
	"net/http"
	"strings"

	identitydom "github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PrincipalOperator is the explicit bootstrap principal id. It is only present when
// authentication resolves the deployment operator; missing principal context never implies it.
const PrincipalOperator = "operator"

// HumanPrincipal is the protocol-neutral authenticated-human identity shared with the domain.
// Principal remains as a source-compatible alias while callers migrate to the explicit name.
type HumanPrincipal = identitydom.HumanPrincipal
type Principal = HumanPrincipal

type ctxKey int

const principalKey ctxKey = iota

// HumanPrincipalFrom returns the authenticated human principal from ctx. Missing or empty
// principal context is never interpreted as the deployment operator.
func HumanPrincipalFrom(ctx context.Context) (HumanPrincipal, bool) {
	p, ok := ctx.Value(principalKey).(HumanPrincipal)
	return p, ok && p.ID != ""
}

// PrincipalFrom returns the authenticated principal id used as the actor on attributable actions.
// It returns an empty string when no authenticated human principal is bound; callers must never
// infer bootstrap/operator authority from absence.
func PrincipalFrom(ctx context.Context) string {
	p, ok := HumanPrincipalFrom(ctx)
	if !ok {
		return ""
	}
	return p.ID
}

// TenantFrom returns the authenticated principal's tenant from ctx – the tenant that scopes the
// request's data and stamps new records. Missing principal context returns empty rather than
// fabricating a tenant or identity.
func TenantFrom(ctx context.Context) string {
	p, ok := HumanPrincipalFrom(ctx)
	if !ok {
		return ""
	}
	return p.TenantID
}

// principalObj is the package-local compatibility accessor for existing authorization and privacy
// guards. New code should use HumanPrincipalFrom so the human-plane requirement is explicit.
func principalObj(ctx context.Context) (HumanPrincipal, bool) {
	return HumanPrincipalFrom(ctx)
}

// Resolver maps a presented bearer token to a HumanPrincipal. ok=false means the token
// is unknown/disabled (→ 401). It is retained for test and adapter compatibility; production
// authentication must use ErrorResolver so dependency failures cannot be mistaken for a bad token.
type Resolver func(ctx context.Context, token string) (HumanPrincipal, bool)

// ErrorResolver maps a bearer token while retaining the failure distinction needed by the public
// identity error contract. A returned error is never interpreted as an invalid credential.
type ErrorResolver func(ctx context.Context, token string) (HumanPrincipal, error)

// SessionResolver validates an opaque browser session. CSRF is passed only for cookie authentication.
type SessionResolver interface {
	Authenticate(ctx context.Context, token, csrfToken string, unsafe bool) (HumanPrincipal, error)
}

type Authenticator struct {
	resolve      Resolver
	resolveError ErrorResolver
	session      SessionResolver
}

// SetSessionResolver enables the OIDC BFF cookie session fallback while retaining bearer authentication.
func (a *Authenticator) SetSessionResolver(resolve SessionResolver) { a.session = resolve }

// NewAuthenticator builds an authenticator from a token resolver.
func NewAuthenticator(resolve Resolver) *Authenticator {
	return &Authenticator{resolve: resolve}
}

// NewAuthenticatorWithErrorResolver builds the production bearer authenticator. It preserves
// dependency failures as retryable identity errors instead of collapsing them into a 401.
func NewAuthenticatorWithErrorResolver(resolve ErrorResolver) *Authenticator {
	return &Authenticator{resolveError: resolve}
}

// Middleware enforces a valid bearer token on every route except publicPaths (no
// anonymous access) and stamps the authenticated principal into the context.
func (a *Authenticator) Middleware(publicPaths map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		var principal HumanPrincipal
		if token, ok := bearerToken(r); ok {
			// Bearer credentials retain their existing API semantics, including no CSRF requirement.
			if a.resolveError != nil {
				var err error
				principal, err = a.resolveError(r.Context(), token)
				if err != nil {
					writeIdentityFailure(w, r.Context(), err)
					return
				}
			} else if a.resolve == nil {
				writeIdentityError(w, r.Context(), IdentityErrorDependencyUnavailable, nil)
				return
			} else {
				var authenticated bool
				principal, authenticated = a.resolve(r.Context(), token)
				if !authenticated {
					writeIdentityError(w, r.Context(), IdentityErrorAuthenticationInvalid, nil)
					return
				}
			}
			if principal.ID == "" {
				writeIdentityError(w, r.Context(), IdentityErrorAuthenticationInvalid, nil)
				return
			}
		} else {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || cookie.Value == "" || a.session == nil {
				writeIdentityError(w, r.Context(), IdentityErrorAuthenticationInvalid, nil)
				return
			}
			unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			principal, err = a.session.Authenticate(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token"), unsafe)
			if err != nil {
				code := identityCodeFor(err)
				if code == IdentityErrorAuthenticationInvalid {
					clearSessionCookie(w)
				}
				writeIdentityError(w, r.Context(), code, err)
				return
			}
			if principal.ID == "" {
				clearSessionCookie(w)
				writeIdentityError(w, r.Context(), IdentityErrorAuthenticationInvalid, nil)
				return
			}
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

// unauthorized is retained for non-human auxiliary endpoints (for example the isolated egress
// grant listener). Human-plane authentication uses the stable identity error contract above.
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

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identitybff"
)

const (
	sessionCookieName = "__Host-synapse_session"
	nonceCookieName   = "__Host-synapse_oidc_nonce"
)

// OIDCService is the narrow HTTP boundary for the OIDC BFF use-case.
type OIDCAuthorization struct{ URL, Nonce string }
type OIDCSession struct {
	Token, CSRFToken string
	Principal        OIDCPrincipal
}
type OIDCPrincipal struct {
	ID, Name, Role, TenantID string
	// SessionID is the non-secret id of the browser session row.
	SessionID string
	// AuthenticatedAt is the session lineage origin (the login time).
	AuthenticatedAt time.Time
}

type OIDCService interface {
	Begin(context.Context) (OIDCAuthorization, error)
	Complete(context.Context, string, string, string) (OIDCSession, error)
	Discover(context.Context, string) (OIDCSession, error)
	Authenticate(context.Context, string, string, bool) (OIDCPrincipal, error)
	Logout(context.Context, string) error
}

type oidcSessionResolver struct{ service OIDCService }

func (r oidcSessionResolver) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (Principal, error) {
	p, err := r.service.Authenticate(ctx, token, csrf, unsafe)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		ID: p.ID, Name: p.Name, Role: p.Role, TenantID: p.TenantID,
		Credential: authz.KindBrowserSession, CredentialID: p.SessionID,
		AuthenticatedAt: p.AuthenticatedAt, Provenance: "oidc",
	}, nil
}

// SetOIDC installs the browser OIDC BFF and its fixed, validated frontend destination.
func (rt *Router) SetOIDC(service OIDCService, frontendURL string) {
	rt.oidc = service
	rt.oidcFrontendURL = frontendURL
	if rt.auth != nil {
		rt.auth.SetSessionResolver(oidcSessionResolver{service: service})
	}
}

// SetLegacyOIDCFence checks durable authority before any public legacy session write.
func (rt *Router) SetLegacyOIDCFence(fence func(context.Context) error) { rt.legacyOIDCFence = fence }

func (rt *Router) checkLegacyOIDC(w http.ResponseWriter, r *http.Request) bool {
	if rt.legacyOIDCFence != nil {
		if err := rt.legacyOIDCFence(r.Context()); err != nil {
			writeAuthenticationError(w, err)
			return false
		}
	}
	return true
}

func (rt *Router) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if !rt.checkLegacyOIDC(w, r) {
		return
	}
	authorization, err := rt.oidc.Begin(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	setNonceCookie(w, authorization.Nonce)
	http.Redirect(w, r, authorization.URL, http.StatusFound)
}

func (rt *Router) oidcCallback(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	if !rt.checkLegacyOIDC(w, r) {
		clearNonceCookie(w)
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	nonce, err := r.Cookie(nonceCookieName)
	if state == "" || code == "" || err != nil || nonce.Value == "" {
		clearNonceCookie(w)
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "OIDC callback requires state, code, and nonce"})
		return
	}
	clearNonceCookie(w)
	session, err := rt.oidc.Complete(r.Context(), state, code, nonce.Value)
	if err != nil {
		// The callback is a top-level browser navigation. A refused subject returns the browser to
		// the dashboard with a fixed reason so it can render the access-denied state instead of a
		// raw error body. Every other failure keeps the coded JSON response.
		reason := ""
		switch {
		case errors.Is(err, identitybff.ErrAccessDenied):
			reason = "access_denied"
		case errors.Is(err, authz.ErrAuthenticationUnavailable):
			requestLogger(w, rt.log).Error("OIDC callback dependency failure", "err", err)
			reason = "unavailable"
		}
		if reason != "" {
			if destination, ok := frontendURLWithAuthError(rt.oidcFrontendURL, reason); ok {
				http.Redirect(w, r, destination, http.StatusFound)
				return
			}
		}
		writeError(w, rt.log, err)
		return
	}
	setSessionCookie(w, session.Token)
	// The configured destination, rather than a request parameter, prevents open redirects.
	http.Redirect(w, r, rt.oidcFrontendURL, http.StatusFound)
}

// frontendURLWithAuthError appends a fixed auth_error reason to the configured frontend URL. The
// destination is never taken from the request, so this cannot become an open redirect.
func frontendURLWithAuthError(frontendURL, reason string) (string, bool) {
	destination, err := url.Parse(frontendURL)
	if err != nil || frontendURL == "" {
		return "", false
	}
	query := destination.Query()
	query.Set("auth_error", reason)
	destination.RawQuery = query.Encode()
	return destination.String(), true
}

// oidcSession discovers a browser session without disclosing its opaque token, provider claims,
// or provider credentials. A successful discovery rotates the opaque cookie and CSRF token.
func (rt *Router) oidcSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	if rt.enterpriseDiscover(w, r, cookie.Value) {
		return
	}
	if rt.oidc == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	if !rt.checkLegacyOIDC(w, r) {
		return
	}
	session, err := rt.oidc.Discover(r.Context(), cookie.Value)
	if err != nil {
		// Only a definitively invalid session is cleared. A storage or provider failure keeps the
		// cookie and answers 503 so the browser retries instead of signing the user out.
		if errors.Is(err, authz.ErrCredentialInvalid) {
			clearSessionCookie(w)
			writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
			return
		}
		// A conflict means a concurrent discovery of the same session (another tab) rotated it
		// first. That tab's response may already have replaced the cookie, so it is not cleared
		// here; the browser retries once and resolves against whichever cookie it now holds.
		if errors.Is(err, shared.ErrConflict) {
			writeRetryableConflict(w, "the session was refreshed by a concurrent request; retry")
			return
		}
		requestLogger(w, rt.log).Warn("OIDC session discovery unavailable", "err", err)
		writeCodedError(w, CodeAuthenticationUnavailable, "authentication is temporarily unavailable; retry shortly")
		return
	}
	if rt.enterprise != nil {
		if err := rt.enterprise.browser.RefuseDeclaredLegacy(r.Context(), shared.ID(session.Principal.TenantID)); err != nil {
			writeAuthenticationError(w, err)
			return
		}
	}
	setSessionCookie(w, session.Token)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"principal": map[string]string{
			"id":        session.Principal.ID,
			"name":      session.Principal.Name,
			"role":      session.Principal.Role,
			"tenant_id": session.Principal.TenantID,
		},
		"csrf_token": session.CSRFToken,
	})
}

func (rt *Router) oidcLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		var logoutErr error
		if p, ok := principalObj(r.Context()); ok && p.Provenance == "enterprise_oidc" && rt.enterprise != nil {
			logoutErr = rt.enterprise.browser.Logout(r.Context(), cookie.Value)
		} else if rt.oidc != nil {
			logoutErr = rt.oidc.Logout(r.Context(), cookie.Value)
		}
		if err := logoutErr; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, authz.ErrCredentialInvalid) {
			writeError(w, rt.log, err)
			return
		}
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func setNonceCookie(w http.ResponseWriter, nonce string) {
	// The __Host- prefix forbids Domain and requires Path=/, preventing a sibling path or
	// subdomain from planting the nonce consumed by the callback.
	http.SetCookie(w, &http.Cookie{Name: nonceCookieName, Value: nonce, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int((10 * time.Minute).Seconds())})
}

func clearNonceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: nonceCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

type oidcServiceFuncs struct {
	begin        func(context.Context) (OIDCAuthorization, error)
	complete     func(context.Context, string, string, string) (OIDCSession, error)
	discover     func(context.Context, string) (OIDCSession, error)
	authenticate func(context.Context, string, string, bool) (OIDCPrincipal, error)
	logout       func(context.Context, string) error
}

func NewOIDCService(begin func(context.Context) (OIDCAuthorization, error), complete func(context.Context, string, string, string) (OIDCSession, error), discover func(context.Context, string) (OIDCSession, error), authenticate func(context.Context, string, string, bool) (OIDCPrincipal, error), logout func(context.Context, string) error) (OIDCService, error) {
	if begin == nil || complete == nil || discover == nil || authenticate == nil || logout == nil {
		return nil, errors.New("OIDC HTTP service requires all operations")
	}
	return oidcServiceFuncs{begin: begin, complete: complete, discover: discover, authenticate: authenticate, logout: logout}, nil
}
func (s oidcServiceFuncs) Begin(ctx context.Context) (OIDCAuthorization, error) { return s.begin(ctx) }
func (s oidcServiceFuncs) Complete(ctx context.Context, state, code, nonce string) (OIDCSession, error) {
	return s.complete(ctx, state, code, nonce)
}
func (s oidcServiceFuncs) Discover(ctx context.Context, token string) (OIDCSession, error) {
	return s.discover(ctx, token)
}
func (s oidcServiceFuncs) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (OIDCPrincipal, error) {
	return s.authenticate(ctx, token, csrf, unsafe)
}
func (s oidcServiceFuncs) Logout(ctx context.Context, token string) error {
	return s.logout(ctx, token)
}

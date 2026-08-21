package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"
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
type OIDCPrincipal struct{ ID, Name, Role, TenantID string }

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
	return Principal(p), nil
}

// SetOIDC installs the browser OIDC BFF and its fixed, validated frontend destination.
func (rt *Router) SetOIDC(service OIDCService, frontendURL string) {
	rt.oidc = service
	rt.oidcFrontendURL = frontendURL
	if rt.auth != nil {
		rt.auth.SetSessionResolver(oidcSessionResolver{service: service})
	}
}

func (rt *Router) oidcLogin(w http.ResponseWriter, r *http.Request) {
	authorization, err := rt.oidc.Begin(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	setNonceCookie(w, authorization.Nonce)
	http.Redirect(w, r, authorization.URL, http.StatusFound)
}

func (rt *Router) oidcCallback(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, rt.log, err)
		return
	}
	setSessionCookie(w, session.Token)
	// The configured destination, rather than a request parameter, prevents open redirects.
	http.Redirect(w, r, rt.oidcFrontendURL, http.StatusFound)
}

// oidcSession discovers a browser session without disclosing its opaque token, provider claims,
// or provider credentials. A successful discovery rotates the opaque cookie and CSRF token.
func (rt *Router) oidcSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" || rt.oidc == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	session, err := rt.oidc.Discover(r.Context(), cookie.Value)
	if err != nil {
		clearSessionCookie(w)
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
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
		if err := rt.oidc.Logout(r.Context(), cookie.Value); err != nil && !errors.Is(err, context.Canceled) {
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

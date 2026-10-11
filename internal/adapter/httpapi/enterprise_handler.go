package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrecovery"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const enterpriseNonceCookie = "__Host-synapse_enterprise_nonce"
const enterpriseInvitationCookie = "__Host-synapse_invitation"

func secureHTTPNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (rt *Router) enterpriseDiscover(w http.ResponseWriter, r *http.Request, token string) bool {
	if rt.enterprise == nil {
		return false
	}
	route, err := rt.enterprise.browser.Route(r.Context(), token)
	if identityenterprise.IsRouteMiss(err) {
		return false
	}
	if err != nil {
		writeAuthenticationError(w, authz.ErrAuthenticationUnavailable)
		return true
	}
	if route.Kind != ports.IdentityCredentialBrowserSession && route.Kind != ports.IdentityCredentialBreakGlass {
		writeAuthenticationError(w, authz.ErrCredentialInvalid)
		return true
	}
	result, p, err := rt.enterprise.browser.Discover(r.Context(), token)
	if err != nil {
		if errors.Is(err, authz.ErrCredentialInvalid) {
			clearSessionCookie(w)
			writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		} else if errors.Is(err, shared.ErrConflict) {
			writeRetryableConflict(w, "the session was refreshed by a concurrent request; retry")
		} else {
			writeAuthenticationError(w, authz.ErrAuthenticationUnavailable)
		}
		return true
	}
	enterprisePrivate(w)
	setSessionCookie(w, result.Token)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": result.CSRFToken, "principal": map[string]any{"id": p.ActorID, "role": p.Role, "tenant_id": p.TenantID, "person_id": p.PersonID, "membership_id": p.MembershipID, "credential_kind": p.Credential.Kind}})
	return true
}

type enterpriseDeps struct {
	browser     *identityenterprise.Browser
	connections *identityenterprise.Connections
	recovery    *identityrecovery.Service
	admission   *identityenterprise.AdmissionService
	store       identityenterprise.BrowserStore
	protector   ports.IdentitySecretProtector
	clock       ports.Clock
	tenant      shared.ID
	frontend    string
	limit       *enterpriseAdmissionLimit
}

func (rt *Router) SetEnterprise(browser *identityenterprise.Browser, connections *identityenterprise.Connections, recovery *identityrecovery.Service, admission *identityenterprise.AdmissionService, store identityenterprise.BrowserStore, protector ports.IdentitySecretProtector, clock ports.Clock, tenant shared.ID, frontend string) error {
	if browser == nil || connections == nil || recovery == nil || admission == nil || store == nil || protector == nil || clock == nil || tenant.IsZero() || frontend == "" || rt.auth == nil {
		return shared.ErrValidation
	}
	rt.enterprise = &enterpriseDeps{browser: browser, connections: connections, recovery: recovery, admission: admission, store: store, protector: protector, clock: clock, tenant: tenant, frontend: frontend, limit: newEnterpriseAdmissionLimit()}
	rt.auth.SetSessionResolver(enterpriseSessionResolver{enterprise: browser, legacy: rt.oidc})
	return nil
}

type enterpriseSessionResolver struct {
	enterprise *identityenterprise.Browser
	legacy     OIDCService
}

func (s enterpriseSessionResolver) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (Principal, error) {
	route, err := s.enterprise.Route(ctx, token)
	if err == nil {
		if route.Kind != ports.IdentityCredentialBrowserSession && route.Kind != ports.IdentityCredentialBreakGlass {
			return Principal{}, authz.ErrCredentialInvalid
		}
		p, err := s.enterprise.Authenticate(ctx, token, csrf, unsafe)
		return enterprisePrincipal(p), err
	}
	if !identityenterprise.IsRouteMiss(err) {
		return Principal{}, authz.ErrAuthenticationUnavailable
	}
	if s.legacy == nil {
		return Principal{}, authz.ErrCredentialInvalid
	}
	p, err := s.legacy.Authenticate(ctx, token, csrf, unsafe)
	if err != nil {
		return Principal{}, err
	}
	if err = s.enterprise.RefuseDeclaredLegacy(ctx, shared.ID(p.TenantID)); err != nil {
		return Principal{}, err
	}
	return Principal{ID: p.ID, Name: p.Name, Role: p.Role, TenantID: p.TenantID, Credential: authz.KindBrowserSession, CredentialID: p.SessionID, AuthenticatedAt: p.AuthenticatedAt, Provenance: "oidc"}, nil
}

func enterprisePrincipal(p authz.Principal) Principal {
	return Principal{ID: p.ActorID, Role: string(p.Role), TenantID: p.TenantID, PersonID: p.PersonID, MembershipID: p.MembershipID, Epochs: p.Epochs, Credential: p.Credential.Kind, CredentialID: p.Credential.ID, AuthenticatedAt: p.AuthenticatedAt, Provenance: p.Provenance}
}

func (rt *Router) registerEnterprise(mux *http.ServeMux) {
	if rt.enterprise == nil {
		return
	}
	mux.HandleFunc("GET /api/auth/enterprise/context", rt.enterpriseContext)
	mux.HandleFunc("POST /api/auth/enterprise/begin", rt.enterpriseBegin)
	mux.HandleFunc("GET /api/auth/enterprise/callback", rt.enterpriseCallback)
	mux.HandleFunc("POST /api/auth/enterprise/recovery", rt.enterpriseRecovery)
	mux.HandleFunc("POST /api/auth/enterprise/switch", rt.enterpriseSwitch)
	mux.HandleFunc("POST /api/auth/enterprise/invitation", rt.enterpriseInvitation)
	mux.HandleFunc("GET /api/auth/enterprise/invitation/pending", rt.enterpriseInvitationPending)
	mux.HandleFunc("POST /api/auth/enterprise/invitation/challenge", rt.enterpriseInvitationChallenge)
	mux.HandleFunc("GET /api/v1/identity/memberships", rt.authenticated(rt.enterpriseMemberships))
	rt.registerEnterpriseAdministration(mux)
}

func enterprisePrivate(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
func enterpriseDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	enterprisePrivate(w)
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid identity request"})
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid identity request"})
		return false
	}
	return true
}

func (rt *Router) enterpriseContext(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	e := rt.enterprise
	if err := e.browser.CheckAuthority(r.Context(), e.tenant, false); err != nil {
		state, stateErr := e.store.CutoverState(r.Context(), e.tenant)
		if stateErr != nil || state.Declared {
			writeAuthenticationError(w, authz.ErrAuthenticationUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	policy, err := e.store.GetIdentityRecoveryPolicy(r.Context(), e.tenant)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	connections, err := e.store.ListIdentityConnections(r.Context(), e.tenant, true)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	choices := make([]map[string]string, 0, len(connections))
	for _, c := range connections {
		choices = append(choices, map[string]string{"id": c.ID.String(), "name": c.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "tenant_id": e.tenant, "requirement": policy.Organization.Requirement, "connections": choices, "bootstrap_eligible": false})
}

type enterpriseNonce struct {
	Tenant      shared.ID
	CallerNonce string
	ExpiresAt   time.Time
}

func (rt *Router) enterpriseBegin(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	rt.enterpriseBeginAllowed(w, r)
}

func (rt *Router) enterpriseBeginAllowed(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ConnectionID         shared.ID                          `json:"connection_id"`
		Purpose              ports.IdentityAuthorizationPurpose `json:"purpose"`
		BootstrapEligibility string                             `json:"bootstrap_eligibility"`
		InvitationCode       string                             `json:"invitation_code"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	e := rt.enterprise
	nonce, err := secureHTTPNonce()
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	in := identityenterprise.BrowserAuthorization{TenantID: e.tenant, ConnectionID: body.ConnectionID, Purpose: body.Purpose, CallerNonce: nonce, CSRFToken: r.Header.Get("X-CSRF-Token"), InvitationCode: body.InvitationCode}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		in.SourceToken = cookie.Value
	}
	if body.Purpose == ports.IdentityAuthorizationTest {
		p, err := rt.enterpriseAuthenticated(r)
		if err != nil {
			writeAuthenticationError(w, err)
			return
		}
		proof, err := e.connections.RepairProof(r.Context(), p.authz(), body.BootstrapEligibility)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		in.TenantID = shared.ID(p.TenantID)
		in.AdminProof = &proof
	} else if body.Purpose == ports.IdentityAuthorizationInvitation {
		route, err := e.admission.ResolveInvitation(r.Context(), body.InvitationCode)
		if err != nil {
			writeError(w, rt.log, shared.ErrForbidden)
			return
		}
		in.TenantID = route.TenantID
	} else if body.Purpose != ports.IdentityAuthorizationLogin {
		p, err := e.browser.Authenticate(r.Context(), in.SourceToken, in.CSRFToken, true)
		if err != nil {
			writeAuthenticationError(w, err)
			return
		}
		in.TenantID = shared.ID(p.TenantID)
	}
	result, err := e.browser.Begin(r.Context(), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	plain, err := json.Marshal(enterpriseNonce{Tenant: in.TenantID, CallerNonce: nonce, ExpiresAt: result.ExpiresAt})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	sealed, err := e.protector.Seal(r.Context(), plain, []byte(enterpriseNonceCookie))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: enterpriseNonceCookie, Value: sealed, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	writeJSON(w, http.StatusOK, map[string]string{"authorization_url": result.AuthorizationURL})
}

func (rt *Router) enterpriseSwitch(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	accepted, err := rt.aup.IsAccepted(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if !accepted {
		writeJSON(w, http.StatusForbidden, errorBody{Code: CodeAUPRequired, Error: "acceptable-use policy not accepted; GET then POST /api/v1/aup/accept"})
		return
	}
	var body struct {
		TenantID     shared.ID `json:"tenant_id"`
		MembershipID shared.ID `json:"membership_id"`
		ConnectionID shared.ID `json:"connection_id"`
		RetryKey     string    `json:"retry_key"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		authenticationRequired(w)
		return
	}
	nonce, err := secureHTTPNonce()
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	result, err := rt.enterprise.browser.Switch(r.Context(), identityenterprise.BrowserSwitchInput{SourceToken: cookie.Value, CSRFToken: r.Header.Get("X-CSRF-Token"), TenantID: body.TenantID, MembershipID: body.MembershipID, ConnectionID: body.ConnectionID, RetryKey: body.RetryKey, CallerNonce: nonce})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if result.Session != nil {
		setSessionCookie(w, result.Session.Token)
		writeJSON(w, http.StatusOK, map[string]any{"csrf_token": result.Session.CSRFToken, "tenant_id": result.Session.Session.TenantID})
		return
	}
	if result.Authorization != nil {
		plain, err := json.Marshal(enterpriseNonce{Tenant: body.TenantID, CallerNonce: nonce, ExpiresAt: result.Authorization.ExpiresAt})
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		sealed, err := rt.enterprise.protector.Seal(r.Context(), plain, []byte(enterpriseNonceCookie))
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: enterpriseNonceCookie, Value: sealed, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		writeJSON(w, http.StatusOK, map[string]string{"authorization_url": result.Authorization.AuthorizationURL})
		return
	}
	choices := make([]map[string]string, 0, len(result.Connections))
	for _, c := range result.Connections {
		choices = append(choices, map[string]string{"id": c.ID.String(), "name": c.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"reauthentication_required": true, "connections": choices})
}

func (rt *Router) enterpriseAuthenticated(r *http.Request) (Principal, error) {
	if token, ok := bearerToken(r); ok {
		return rt.auth.resolve(r.Context(), token)
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Principal{}, authz.ErrCredentialInvalid
	}
	return rt.auth.session.Authenticate(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token"), true)
}

func (rt *Router) enterpriseCallback(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	e := rt.enterprise
	cookie, err := r.Cookie(enterpriseNonceCookie)
	http.SetCookie(w, &http.Cookie{Name: enterpriseNonceCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if err != nil {
		writeAuthenticationError(w, authz.ErrCredentialInvalid)
		return
	}
	plain, err := e.protector.Open(r.Context(), cookie.Value, []byte(enterpriseNonceCookie))
	if err != nil {
		writeAuthenticationError(w, authz.ErrCredentialInvalid)
		return
	}
	var nonce enterpriseNonce
	if json.Unmarshal(plain, &nonce) != nil || !e.clock.Now().Before(nonce.ExpiresAt) {
		writeAuthenticationError(w, authz.ErrCredentialInvalid)
		return
	}
	source := ""
	if session, err := r.Cookie(sessionCookieName); err == nil {
		source = session.Value
	}
	result, err := e.browser.Complete(r.Context(), identityenterprise.BrowserCallback{TenantID: nonce.Tenant, CallerNonce: nonce.CallerNonce, State: r.URL.Query().Get("state"), Code: r.URL.Query().Get("code"), SourceToken: source})
	if err != nil {
		reason := "access_denied"
		if errors.Is(err, authz.ErrAuthenticationUnavailable) {
			reason = "unavailable"
		}
		destination, ok := frontendURLWithAuthError(e.frontend, reason)
		if !ok {
			writeError(w, rt.log, err)
			return
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if result.Pending != nil {
		plain, err := json.Marshal(result.Pending)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		sealed, err := e.protector.Seal(r.Context(), plain, []byte(enterpriseInvitationCookie))
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: enterpriseInvitationCookie, Value: sealed, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		destination, _ := frontendURLWithAuthError(e.frontend, "mailbox_verification_required")
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if !result.TestOnly {
		setSessionCookie(w, result.Session.Token)
	}
	http.Redirect(w, r, e.frontend, http.StatusSeeOther)
}

func (rt *Router) enterpriseRecovery(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	tenant, err := rt.enterprise.recovery.ActivationTenant(r.Context(), body.Secret)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err = rt.enterprise.browser.CheckAuthority(r.Context(), tenant, true); err != nil {
		writeError(w, rt.log, err)
		return
	}
	result, err := rt.enterprise.recovery.Activate(r.Context(), identityrecovery.ActivateInput{Secret: body.Secret})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	setSessionCookie(w, result.Token)
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": result.CSRFToken, "recovery_only": true})
}

func (rt *Router) enterpriseMemberships(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		authenticationRequired(w)
		return
	}
	choices, err := rt.enterprise.browser.Picker(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]map[string]any, 0, len(choices))
	for _, c := range choices {
		out = append(out, map[string]any{"tenant_id": c.TenantID, "membership_id": c.MembershipID, "name": c.TenantLabel, "role": c.Role, "active": true})
	}
	writeJSON(w, http.StatusOK, map[string]any{"memberships": out})
}

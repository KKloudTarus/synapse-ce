package httpapi

import (
	"bytes"
	"encoding/json"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"io"
	"net/http"
)

func (rt *Router) enterpriseInvitation(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	var body struct {
		Code         string    `json:"code"`
		ConnectionID shared.ID `json:"connection_id"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	route, err := rt.enterprise.admission.ResolveInvitation(r.Context(), body.Code)
	if err != nil {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	if err = rt.enterprise.browser.CheckAuthority(r.Context(), route.TenantID, true); err != nil {
		writeError(w, rt.log, err)
		return
	}
	if body.ConnectionID.IsZero() {
		connections, err := rt.enterprise.store.ListIdentityConnections(r.Context(), route.TenantID, true)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		choices := make([]map[string]string, 0, len(connections))
		for _, c := range connections {
			choices = append(choices, map[string]string{"id": c.ID.String(), "name": c.DisplayName})
		}
		writeJSON(w, http.StatusOK, map[string]any{"connections": choices})
		return
	}
	raw, _ := json.Marshal(map[string]any{"purpose": ports.IdentityAuthorizationInvitation, "invitation_code": body.Code, "connection_id": body.ConnectionID})
	r.Body = io.NopCloser(bytes.NewReader(raw))
	rt.enterpriseBeginAllowed(w, r)
}

func (rt *Router) readPendingInvitation(r *http.Request) (identityenterprise.PendingInvitation, error) {
	var pending identityenterprise.PendingInvitation
	cookie, err := r.Cookie(enterpriseInvitationCookie)
	if err != nil {
		return pending, shared.ErrNotFound
	}
	plain, err := rt.enterprise.protector.Open(r.Context(), cookie.Value, []byte(enterpriseInvitationCookie))
	if err != nil {
		return pending, shared.ErrForbidden
	}
	if json.Unmarshal(plain, &pending) != nil || !rt.enterprise.clock.Now().Before(pending.ExpiresAt) {
		return pending, shared.ErrForbidden
	}
	return pending, nil
}
func (rt *Router) enterpriseInvitationPending(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	_, err := rt.readPendingInvitation(r)
	writeJSON(w, http.StatusOK, map[string]bool{"challenge_required": err == nil})
}
func (rt *Router) enterpriseInvitationChallenge(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	pending, err := rt.readPendingInvitation(r)
	if err != nil {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	source := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		source = c.Value
	}
	result, err := rt.enterprise.browser.CompleteInvitation(r.Context(), pending, body.Code, source)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	setSessionCookie(w, result.Session.Token)
	http.SetCookie(w, &http.Cookie{Name: enterpriseInvitationCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": result.Session.CSRFToken})
}

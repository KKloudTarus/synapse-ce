package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (rt *Router) registerEnterpriseAdministration(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/identity/connections", rt.recoverable(user.PermAdminister, authz.RecoveryReadIdentity, rt.enterpriseConnections))
	mux.HandleFunc("POST /api/v1/identity/connections/draft", rt.recoverable(user.PermAdminister, authz.RecoveryRepairConnection, rt.enterpriseDraft))
	mux.HandleFunc("POST /api/v1/identity/connections/activate", rt.recoverable(user.PermAdminister, authz.RecoveryRepairConnection, rt.enterpriseActivate))
	mux.HandleFunc("POST /api/v1/identity/connections/disable", rt.recoverable(user.PermAdminister, authz.RecoveryRepairConnection, rt.enterpriseDisable))
	mux.HandleFunc("POST /api/v1/identity/connections/test", rt.recoverable(user.PermAdminister, authz.RecoveryRepairConnection, rt.enterpriseConnectionTest))
	mux.HandleFunc("POST /api/v1/identity/bootstrap", rt.authz(user.PermAdminister, rt.enterpriseBootstrap))
	mux.HandleFunc("GET /api/v1/identity/policy", rt.recoverable(user.PermAdminister, authz.RecoveryReadIdentity, rt.enterprisePolicy))
	mux.HandleFunc("PUT /api/v1/identity/policy", rt.recoverable(user.PermAdminister, authz.RecoveryRelaxSSO, rt.enterprisePolicy))
	mux.HandleFunc("POST /api/v1/identity/policy/rehearse", rt.authz(user.PermAdminister, rt.enterpriseRehearse))
	mux.HandleFunc("POST /api/v1/identity/policy/recovery-code", rt.authz(user.PermAdminister, rt.enterpriseRecoveryCode))
	mux.HandleFunc("POST /api/v1/identity/policy/test-alert", rt.authz(user.PermAdminister, rt.enterpriseTestAlert))
	mux.HandleFunc("GET /api/v1/identity/recovery/alerts", rt.recoverable(user.PermAdminister, authz.RecoveryReadIdentity, rt.enterpriseAlerts))
	mux.HandleFunc("GET /api/v1/identity/invitations", rt.authz(user.PermAdminister, rt.enterpriseInvitations))
	mux.HandleFunc("POST /api/v1/identity/invitations", rt.authz(user.PermAdminister, rt.enterpriseCreateInvitation))
	mux.HandleFunc("POST /api/v1/identity/invitations/revoke", rt.authz(user.PermAdminister, rt.enterpriseRevokeInvitation))
	mux.HandleFunc("GET /api/v1/identity/roster", rt.recoverable(user.PermAdminister, authz.RecoveryListUsers, rt.enterpriseRoster))
	mux.HandleFunc("POST /api/v1/identity/memberships/change", rt.recoverable(user.PermAdminister, authz.RecoveryAssignRole, rt.enterpriseChangeMembership))
	mux.HandleFunc("GET /api/v1/identity/authenticators", rt.authenticated(rt.enterpriseAuthenticators))
	mux.HandleFunc("GET /api/v1/identity/link-connections", rt.authenticated(rt.enterpriseLinkConnections))
}

func invitationProjection(v ports.IdentityInvitation) map[string]any {
	return map[string]any{"id": v.ID, "recipient": v.Recipient, "role": v.Role, "state": v.State, "version": v.Version, "expires_at": v.ExpiresAt}
}
func (rt *Router) enterpriseInvitations(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	p, _ := principalObj(r.Context())
	items, err := rt.enterprise.store.ListIdentityInvitations(r.Context(), shared.ID(p.TenantID), 100)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	list := make([]map[string]any, 0, len(items))
	for _, v := range items {
		list = append(list, invitationProjection(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": list})
}
func (rt *Router) enterpriseCreateInvitation(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	var b struct {
		Recipient            string    `json:"recipient"`
		Role                 user.Role `json:"role"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	proof, err := rt.enterprise.connections.AdminProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	v, err := rt.enterprise.admission.CreateInvitation(r.Context(), shared.ID(p.TenantID), b.Recipient, b.Role, proof)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": invitationProjection(v.Invitation), "code": v.Code})
}
func (rt *Router) enterpriseRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	var b struct {
		ID                   shared.ID `json:"id"`
		Version              int       `json:"version"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	proof, err := rt.enterprise.connections.AdminProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err == nil {
		err = rt.enterprise.store.RevokeIdentityInvitation(r.Context(), shared.ID(p.TenantID), b.ID, b.Version, proof, rt.enterprise.clock.Now().UTC())
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) enterpriseAdminGuard(w http.ResponseWriter, r *http.Request, recovery authz.RecoveryAction) bool {
	enterprisePrivate(w)
	if !decideRequest(r, authz.Action{Permission: user.PermAdminister, Recovery: recovery}).Allowed {
		writeJSON(w, http.StatusForbidden, errorBody{Error: "identity administration is not authorized"})
		return false
	}
	if r.Method != http.MethodGet {
		p, _ := principalObj(r.Context())
		if err := rt.enterprise.browser.AdministrationEnabled(r.Context(), p.authz()); err != nil {
			writeError(w, rt.log, err)
			return false
		}
	}
	return true
}
func (rt *Router) enterpriseConnections(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryReadIdentity) {
		return
	}
	enterprisePrivate(w)
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.store.ListIdentityConnections(r.Context(), shared.ID(p.TenantID), false)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": v})
}
func (rt *Router) enterpriseDraft(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryRepairConnection) {
		return
	}
	var b struct {
		ID                   shared.ID `json:"id"`
		DisplayName          string    `json:"display_name"`
		Issuer               string    `json:"issuer"`
		ClientID             string    `json:"client_id"`
		ClientSecret         string    `json:"client_secret"`
		Version              int       `json:"version"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.connections.SaveDraft(r.Context(), p.authz(), b.BootstrapEligibility, identityenterprise.ConnectionDraftInput{ID: b.ID, DisplayName: b.DisplayName, Issuer: b.Issuer, ClientID: b.ClientID, ClientSecret: b.ClientSecret, ExpectedVersion: b.Version})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (rt *Router) enterpriseActivate(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryRepairConnection) {
		return
	}
	var b struct {
		ID                   shared.ID `json:"id"`
		Revision             int       `json:"revision"`
		Version              int       `json:"version"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.connections.Activate(r.Context(), p.authz(), b.BootstrapEligibility, b.ID, b.Revision, b.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (rt *Router) enterpriseDisable(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryRepairConnection) {
		return
	}
	var b struct {
		ID                   shared.ID `json:"id"`
		Version              int       `json:"version"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.connections.Disable(r.Context(), p.authz(), b.BootstrapEligibility, b.ID, b.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (rt *Router) enterpriseConnectionTest(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryRepairConnection) {
		return
	}
	var b struct {
		ID                   shared.ID `json:"id"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	raw, _ := json.Marshal(map[string]any{"connection_id": b.ID, "purpose": ports.IdentityAuthorizationTest, "bootstrap_eligibility": b.BootstrapEligibility})
	r.Body = io.NopCloser(bytes.NewReader(raw))
	rt.enterpriseBegin(w, r)
}
func (rt *Router) enterpriseBootstrap(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	enterprisePrivate(w)
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.connections.BeginBootstrap(r.Context(), p.authz())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"bootstrap_eligibility": v})
}
func (rt *Router) enterprisePolicy(w http.ResponseWriter, r *http.Request) {
	action := authz.RecoveryRelaxSSO
	if r.Method == http.MethodGet {
		action = authz.RecoveryReadIdentity
	}
	if !rt.enterpriseAdminGuard(w, r, action) {
		return
	}
	enterprisePrivate(w)
	p, _ := principalObj(r.Context())
	if r.Method == http.MethodGet {
		v, err := rt.enterprise.store.GetIdentityRecoveryPolicy(r.Context(), shared.ID(p.TenantID))
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		writeJSON(w, http.StatusOK, enterprisePolicyProjection(v))
		return
	}
	var b struct {
		Requirement          string `json:"requirement"`
		Version              int    `json:"version"`
		BootstrapEligibility string `json:"bootstrap_eligibility"`
		LegacyGraceEnabled   bool   `json:"legacy_grace_enabled"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	proof, err := rt.enterprise.connections.RepairProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	v, err := rt.enterprise.recovery.Configure(r.Context(), ports.IdentityRecoveryPolicy{TenantID: shared.ID(p.TenantID), Organization: authz.OrganizationPolicy{Requirement: authz.SSORequirement(b.Requirement), LegacyBearerGraceEnabled: b.LegacyGraceEnabled, DeploymentGraceDuration: rt.enterprise.browser.LegacyBearerGraceDuration()}, ExpectedVersion: b.Version}, proof)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, enterprisePolicyProjection(v))
}
func enterprisePolicyProjection(v ports.IdentityRecoveryPolicy) map[string]any {
	return map[string]any{"requirement": v.Organization.Requirement, "version": v.Version, "rehearsed_at": v.LastRehearsedAt, "alert_configured": v.AlertConfigured, "legacy_grace_enabled": v.Organization.LegacyBearerGraceEnabled, "grace_cutoff": v.Organization.ActivatedAt.Add(v.Organization.DeploymentGraceDuration)}
}
func (rt *Router) enterpriseRehearse(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	var b struct {
		BootstrapEligibility string `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	proof, err := rt.enterprise.connections.AdminProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err == nil {
		err = rt.enterprise.recovery.Rehearse(r.Context(), shared.ID(p.TenantID), proof)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rehearsed_at": rt.enterprise.clock.Now().UTC()})
}
func (rt *Router) enterpriseRecoveryCode(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	var b struct {
		MembershipID         shared.ID `json:"membership_id"`
		PersonID             shared.ID `json:"person_id"`
		BootstrapEligibility string    `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	if b.MembershipID.IsZero() {
		b.MembershipID = shared.ID(p.MembershipID)
		b.PersonID = shared.ID(p.PersonID)
	}
	proof, err := rt.enterprise.connections.AdminProof(r.Context(), p.authz(), b.BootstrapEligibility)
	var code string
	if err == nil {
		code, err = rt.enterprise.recovery.CreateActivation(r.Context(), shared.ID(p.TenantID), b.MembershipID, b.PersonID, proof)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"recovery_code": code})
}
func (rt *Router) enterpriseAlerts(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryReadIdentity) {
		return
	}
	enterprisePrivate(w)
	p, _ := principalObj(r.Context())
	v, err := rt.enterprise.store.ListIdentityRecoveryAlerts(r.Context(), shared.ID(p.TenantID), 100)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": v})
}

func (rt *Router) enterpriseTestAlert(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, "") {
		return
	}
	var b struct {
		BootstrapEligibility string `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	proof, err := rt.enterprise.connections.AdminProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	recipients, err := rt.enterprise.store.IdentityRecoveryAlertRecipients(r.Context(), shared.ID(p.TenantID), shared.ID(p.MembershipID))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if len(recipients) == 0 {
		writeError(w, rt.log, shared.ErrConflict)
		return
	}
	err = rt.enterprise.recovery.TestAlert(r.Context(), shared.ID(p.TenantID), recipients[0], proof)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"alert_configured": true})
}

package httpapi

import (
	"net/http"
	"net/url"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (rt *Router) SetEnterpriseProvisioning(provisioning *identityenterprise.Provisioning, protocol *identityenterprise.Service) error {
	if rt.enterprise == nil || provisioning == nil || protocol == nil {
		return shared.ErrValidation
	}
	rt.enterprise.provisioning = provisioning
	rt.enterprise.protocol = protocol
	return nil
}

func (rt *Router) registerEnterpriseProvisioning(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/identity/provisioning/begin", rt.enterpriseProvisioningRoute("begin"))
	mux.HandleFunc("POST /api/v1/identity/provisioning/status", rt.enterpriseProvisioningRoute("status"))
	mux.HandleFunc("POST /api/v1/identity/provisioning/draft", rt.enterpriseProvisioningRoute("draft"))
	mux.HandleFunc("POST /api/v1/identity/provisioning/test", rt.enterpriseProvisioningRoute("test"))
	mux.HandleFunc("POST /api/v1/identity/provisioning/activate", rt.enterpriseProvisioningRoute("activate"))
	mux.HandleFunc("POST /api/v1/identity/provisioning/invitation", rt.enterpriseProvisioningRoute("invitation"))
}

func (rt *Router) enterpriseProvisioningRoute(action string) http.HandlerFunc {
	return rt.authz(user.PermAdminister, func(w http.ResponseWriter, r *http.Request) {
		rt.enterpriseProvisioning(w, r, action)
	})
}

func initialProvisioningView(v ports.IdentityInitialProvisioning) map[string]any {
	result := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "recipient": v.Recipient, "state": v.State, "version": v.Version, "connection": nil, "invitation": nil}
	if v.Connection != nil {
		result["connection"] = struct {
			enterpriseConnectionProjection
			ClientID string `json:"client_id"`
		}{enterpriseConnectionView(*v.Connection), v.Connection.Settings.ClientID}
	}
	if v.Invitation != nil {
		result["invitation"] = invitationProjection(*v.Invitation)
	}
	return result
}

func (rt *Router) enterpriseProvisioning(w http.ResponseWriter, r *http.Request, action string) {
	enterprisePrivate(w)
	if !decideRequest(r, authz.Action{Permission: user.PermAdminister, PlatformOnly: true}).Allowed {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	if rt.enterprise.provisioning == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	if !rt.enterpriseAdmissionAllowed(w, r) {
		return
	}
	var body struct {
		TenantID            shared.ID `json:"tenant_id"`
		Recipient           string    `json:"recipient"`
		Capability          string    `json:"capability"`
		DisplayName         string    `json:"display_name"`
		Issuer              string    `json:"issuer"`
		ClientID            string    `json:"client_id"`
		ClientSecret        string    `json:"client_secret"`
		Auth0OrganizationID string    `json:"auth0_organization_id"`
		EntraDiscoveryMode  string    `json:"entra_discovery_mode"`
		Version             int       `json:"version"`
		Revision            int       `json:"revision"`
	}
	if !enterpriseDecode(w, r, &body) {
		return
	}
	p, _ := principalObj(r.Context())
	actor := p.authz()
	service := rt.enterprise.provisioning
	var state ports.IdentityInitialProvisioning
	var capability, code string
	var err error
	switch action {
	case "begin":
		state, capability, err = service.Begin(r.Context(), actor, body.TenantID, body.Recipient)
	case "status":
		state, err = service.Status(r.Context(), actor, body.Capability)
	case "draft":
		state, err = service.Draft(r.Context(), actor, body.Capability, identityenterprise.ConnectionDraftInput{DisplayName: body.DisplayName, Issuer: body.Issuer, ClientID: body.ClientID, ClientSecret: body.ClientSecret, Auth0OrganizationID: body.Auth0OrganizationID, EntraDiscoveryMode: body.EntraDiscoveryMode, ExpectedVersion: body.Version})
	case "activate":
		state, err = service.Activate(r.Context(), actor, body.Capability, body.Revision, body.Version)
	case "invitation":
		state, code, err = service.Invitation(r.Context(), actor, body.Capability)
	case "test":
		var proof ports.IdentityProvisioningProof
		proof, err = service.RequestProof(r.Context(), actor, body.Capability)
		if err == nil {
			err = rt.enterprise.browser.CheckAuthority(r.Context(), proof.TenantID, true)
		}
		var nonce string
		if err == nil {
			nonce, err = secureHTTPNonce()
		}
		var begin identityenterprise.BeginResult
		if err == nil {
			begin, err = rt.enterprise.protocol.Begin(r.Context(), identityenterprise.BeginInput{TenantID: proof.TenantID, ConnectionID: proof.ConnectionID, Purpose: ports.IdentityAuthorizationTest, CallerNonce: nonce, ProvisioningToken: body.Capability})
		}
		if err == nil {
			rt.enterpriseAuthorizationResponse(w, r, proof.TenantID, nonce, begin)
			return
		}
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	response := map[string]any{"provisioning": initialProvisioningView(state)}
	if capability != "" {
		response["capability"] = capability
	}
	if code != "" {
		response["code"] = code
	}
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) provisioningReturnURL(tenant shared.ID, reason string) string {
	u, err := url.Parse(rt.enterprise.frontend)
	if err != nil {
		return rt.enterprise.frontend
	}
	u.Path = "/settings/authentication"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	q := u.Query()
	q.Set("provisioning_tenant", tenant.String())
	if reason != "" {
		q.Set("auth_error", reason)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

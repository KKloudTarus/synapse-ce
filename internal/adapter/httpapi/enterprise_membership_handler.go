package httpapi

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"net/http"
)

func (rt *Router) enterpriseRoster(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryListUsers) {
		return
	}
	p, _ := principalObj(r.Context())
	members, err := rt.enterprise.store.ListIdentityRoster(r.Context(), shared.ID(p.TenantID), 100)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, map[string]any{"id": m.ID, "person_id": m.PersonID, "name": m.Name, "role": m.Role, "state": m.State, "version": m.Version})
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}
func (rt *Router) enterpriseChangeMembership(w http.ResponseWriter, r *http.Request) {
	if !rt.enterpriseAdminGuard(w, r, authz.RecoveryAssignRole) {
		return
	}
	var b struct {
		ID                   shared.ID                          `json:"id"`
		Kind                 ports.IdentityMembershipChangeKind `json:"kind"`
		Role                 user.Role                          `json:"role"`
		Version              int                                `json:"version"`
		BootstrapEligibility string                             `json:"bootstrap_eligibility"`
	}
	if !enterpriseDecode(w, r, &b) {
		return
	}
	p, _ := principalObj(r.Context())
	if b.Version < 1 {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	proof, err := rt.enterprise.connections.RepairProof(r.Context(), p.authz(), b.BootstrapEligibility)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	m, err := rt.enterprise.store.ChangeIdentityMembershipAdministration(r.Context(), ports.IdentityMembershipAdministration{TenantID: shared.ID(p.TenantID), MembershipID: b.ID, Kind: b.Kind, Role: b.Role, ExpectedVersion: b.Version, Proof: proof})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": m.ID, "person_id": m.PersonID, "role": m.Role, "state": m.State, "version": m.Version})
}
func (rt *Router) enterpriseAuthenticators(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	p, ok := principalObj(r.Context())
	if !ok || p.Credential != authz.KindBrowserSession || p.PersonID == "" {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	identities, err := rt.enterprise.store.ListOwnIdentityAuthenticators(r.Context(), ports.IdentityAdminProof{Principal: p.authz(), At: rt.enterprise.clock.Now()})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]map[string]string, 0, len(identities))
	for _, v := range identities {
		out = append(out, map[string]string{"connection_id": v.ConnectionID.String(), "name": v.Name, "state": v.State})
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out})
}
func (rt *Router) enterpriseLinkConnections(w http.ResponseWriter, r *http.Request) {
	enterprisePrivate(w)
	p, ok := principalObj(r.Context())
	if !ok || p.Credential != authz.KindBrowserSession || p.PersonID == "" {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	choices, err := rt.enterprise.store.ListIdentityConnections(r.Context(), shared.ID(p.TenantID), true)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]map[string]string, 0, len(choices))
	for _, c := range choices {
		out = append(out, map[string]string{"id": c.ID.String(), "name": c.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}

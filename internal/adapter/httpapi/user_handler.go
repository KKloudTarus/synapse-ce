package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// userBodyLimit bounds a user-management request body. These payloads carry a name, a role, and a
// tenant id; anything larger is a mistake or an attack.
const userBodyLimit = 8 << 10

// userView is the safe, serialized shape of a user – never the API-key hash.
type userView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"createdAt"`
}

func toUserView(u *userdom.User) userView {
	return userView{ID: u.ID.String(), Name: u.Name, Role: string(u.Role), Disabled: u.Disabled, CreatedAt: u.Audit.CreatedAt}
}

// actorFrom builds the user-management actor from the authenticated principal. The tenant comes
// from the token, never from the request body, so a caller cannot claim another tenant.
func actorFrom(r *http.Request) usersuc.Actor {
	return usersuc.Actor{ID: PrincipalFrom(r.Context()), TenantID: TenantFrom(r.Context())}
}

// currentUser returns the authenticated principal (who am I), so the UI can show
// the logged-in consultant and gate admin-only surfaces.
func (rt *Router) currentUser(w http.ResponseWriter, r *http.Request) {
	p, ok := principalObj(r.Context())
	if !ok {
		authenticationRequired(w)
		return
	}
	tenantID := TenantFrom(r.Context())
	readEnabled := rt.assessmentLifecycleRead != nil && rt.assessmentLifecycleRead(tenantID)
	uiEnabled := rt.assessmentLifecycleUI != nil && rt.assessmentLifecycleUI(tenantID)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": p.ID, "name": p.Name, "role": p.Role,
		"features": map[string]bool{"assessment_lifecycle_read": readEnabled, "assessment_lifecycle_ui_default": uiEnabled},
	})
}

// listUsers returns the team roster of the caller's own tenant (admin only).
func (rt *Router) listUsers(w http.ResponseWriter, r *http.Request) {
	// Authorization (admin only) is enforced at the route via authz(PermAdminister).
	us, err := rt.users.List(r.Context(), actorFrom(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, toUserView(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// createUser provisions a consultant and returns their API key ONCE (admin only).
func (rt *Router) createUser(w http.ResponseWriter, r *http.Request) {
	// Authorization (admin only) is enforced at the route via authz(PermAdminister).
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
		// TenantID assigns the new user's tenant. It is set by the provisioning admin, never by the
		// user's own token, and the use case refuses a tenant other than the caller's own unless the
		// caller is the platform admin. Empty defaults to the calling admin's tenant, so a
		// single-tenant admin keeps creating default-tenant users with no extra ceremony.
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, userBodyLimit)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	role := userdom.Role(body.Role)
	if role == "" {
		role = userdom.RoleMember
	}
	u, apiKey, err := rt.users.CreateUser(r.Context(), actorFrom(r), body.TenantID, body.Name, role)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	// apiKey is shown exactly once – it is not recoverable afterwards.
	writeJSON(w, http.StatusCreated, map[string]any{"user": toUserView(u), "apiKey": apiKey})
}

// updateUser changes a user's display name and role (admin only). An omitted field is left as it
// is. Demoting the tenant's last enabled admin is refused with 409.
func (rt *Router) updateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, userBodyLimit)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	u, err := rt.users.Update(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")), body.Name, userdom.Role(body.Role))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserView(u))
}

// disableUser revokes a user's access without deleting the identity, so past actions stay
// attributable (admin only). Disabling the tenant's last enabled admin is refused with 409.
func (rt *Router) disableUser(w http.ResponseWriter, r *http.Request) {
	rt.setUserDisabled(w, r, true)
}

// enableUser re-enables a disabled user (admin only). Disabling revoked the user's key and browser
// sessions permanently, so the administrator rotates the key to issue a new one.
func (rt *Router) enableUser(w http.ResponseWriter, r *http.Request) {
	rt.setUserDisabled(w, r, false)
}

func (rt *Router) setUserDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	u, err := rt.users.SetDisabled(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")), disabled)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserView(u))
}

// oidcLinkView is the non-secret shape of an approved OIDC subject link.
type oidcLinkView struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	CreatedAt time.Time `json:"createdAt"`
}

func toOIDCLinkView(link usersuc.OIDCLink) oidcLinkView {
	return oidcLinkView{ID: link.ID.String(), UserID: link.UserID.String(), Issuer: link.Issuer, Subject: link.Subject, CreatedAt: link.CreatedAt}
}

// linkUserOIDCIdentity approves one exact (issuer, subject) for an existing user of the fixed OIDC
// tenant (admin only). It never looks up email or groups; the subject's next successful callback
// signs in as this user. The link and its audit record commit together.
func (rt *Router) linkUserOIDCIdentity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, userBodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	link, err := rt.users.LinkOIDCIdentity(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")), body.Issuer, body.Subject)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOIDCLinkView(link))
}

// listUserOIDCLinks returns a user's approved OIDC subject links (admin only).
func (rt *Router) listUserOIDCLinks(w http.ResponseWriter, r *http.Request) {
	links, err := rt.users.ListOIDCLinks(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items := make([]oidcLinkView, 0, len(links))
	for _, link := range links {
		items = append(items, toOIDCLinkView(link))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// unlinkUserOIDCIdentity removes one approved OIDC subject link and revokes the user's browser
// sessions (admin only), returning the removed link.
func (rt *Router) unlinkUserOIDCIdentity(w http.ResponseWriter, r *http.Request) {
	link, err := rt.users.UnlinkOIDCIdentity(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("linkId")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toOIDCLinkView(link))
}

// rotateUserAPIKey issues a new API key and invalidates the previous one, returning the new key
// ONCE (admin only). This is how a leaked key is revoked from the product.
func (rt *Router) rotateUserAPIKey(w http.ResponseWriter, r *http.Request) {
	u, apiKey, err := rt.users.RotateAPIKey(r.Context(), actorFrom(r), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserView(u), "apiKey": apiKey})
}

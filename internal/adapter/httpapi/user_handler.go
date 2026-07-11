package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

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

// currentUser returns the authenticated principal (who am I), so the UI can show
// the logged-in consultant and gate admin-only surfaces.
func (rt *Router) currentUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalObj(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"id": p.ID, "name": p.Name, "role": p.Role})
}

// listUsers returns the team roster (admin only).
func (rt *Router) listUsers(w http.ResponseWriter, r *http.Request) {
	// Authorization (admin only) is enforced at the route via authz(PermAdminister).
	us, err := rt.users.List(r.Context())
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
		// TenantID assigns the new user's tenant. It is set by the provisioning admin,
		// never by the user's own token. Empty defaults to the creating admin's own tenant, so a
		// single-tenant ('') admin keeps creating default-tenant users with no extra ceremony.
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	role := userdom.Role(body.Role)
	if role == "" {
		role = userdom.RoleMember
	}
	tenant := body.TenantID
	if tenant == "" {
		tenant = TenantFrom(r.Context())
	}
	u, apiKey, err := rt.users.CreateUser(r.Context(), PrincipalFrom(r.Context()), tenant, body.Name, role)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	// apiKey is shown exactly once – it is not recoverable afterwards.
	writeJSON(w, http.StatusCreated, map[string]any{"user": toUserView(u), "apiKey": apiKey})
}

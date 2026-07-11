package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// listCredentials returns an engagement's credential NAMES + timestamps (never values).
func (rt *Router) listCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // engagement existence + tenant isolation enforced by withEngTenant
	metas, err := rt.credentials.List(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, metas)
}

type setCredentialRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// setCredential stores (write-only) a secret for an engagement. The value is never
// rendered back; the response carries only the name. Attributed + audited (sans value).
func (rt *Router) setCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // engagement existence + tenant isolation enforced by withEngTenant
	var req setCredentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	if err := rt.credentials.Set(r.Context(), PrincipalFrom(r.Context()), shared.ID(id), req.Name, []byte(req.Value)); err != nil {
		writeError(w, rt.log, err)
		return
	}
	// Echo the name only – never the value.
	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "status": "stored"})
}

// deleteCredential removes a credential by name. 404 if absent.
func (rt *Router) deleteCredential(w http.ResponseWriter, r *http.Request) {
	if err := rt.credentials.Delete(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), r.PathValue("name")); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

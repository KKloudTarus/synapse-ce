package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
)

func (rt *Router) SetUserContacts(s *usercontacts.Service) { rt.userContacts = s }

func myContactScope(r *http.Request) (shared.ID, shared.ID) {
	return shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(PrincipalFrom(r.Context()))
}

func (rt *Router) listMyContacts(w http.ResponseWriter, r *http.Request) {
	tenantID, userID := myContactScope(r)
	contacts, err := rt.userContacts.List(r.Context(), tenantID, userID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, contacts)
}

func (rt *Router) addMyContact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&body); err != nil || body.Kind != "email" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid email contact"})
		return
	}
	tenantID, userID := myContactScope(r)
	contact, err := rt.userContacts.AddEmail(r.Context(), tenantID, userID, body.Value)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, contact)
}

func (rt *Router) deleteMyContact(w http.ResponseWriter, r *http.Request) {
	tenantID, userID := myContactScope(r)
	if err := rt.userContacts.Delete(r.Context(), tenantID, userID, shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) requestMyContactVerification(w http.ResponseWriter, r *http.Request) {
	tenantID, userID := myContactScope(r)
	if err := rt.userContacts.RequestVerification(r.Context(), tenantID, userID, shared.ID(r.PathValue("id"))); err != nil {
		rt.writeContactError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (rt *Router) verifyMyContact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid verification request"})
		return
	}
	tenantID, userID := myContactScope(r)
	contact, err := rt.userContacts.Verify(r.Context(), tenantID, userID, shared.ID(r.PathValue("id")), body.Code)
	if err != nil {
		rt.writeContactError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, contact)
}

func (rt *Router) writeContactError(w http.ResponseWriter, err error) {
	if errors.Is(err, usercontacts.ErrMailUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "email verification is unavailable"})
		return
	}
	writeError(w, rt.log, err)
}

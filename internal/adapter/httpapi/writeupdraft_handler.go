package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// listWriteupDrafts returns the engagement's AI-proposed finding write-up drafts (read; PermView +
// tenant-gated via withEngTenant). Drafts are working data – a separate human sign-off applies one to a
// finding; nothing here renders into a report.
func (rt *Router) listWriteupDrafts(w http.ResponseWriter, r *http.Request) {
	ds, err := rt.drafts.ListByEngagement(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"writeup_drafts": ds})
}

// editWriteupDraft revises a still-proposed draft's prose (PermReview = sign-off authority; a human
// revising the AI draft before accepting it). The domain rejects an edit on a decided draft.
func (rt *Router) editWriteupDraft(w http.ResponseWriter, r *http.Request) {
	engID, did := r.PathValue("id"), r.PathValue("did")
	if engID == "" || did == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and draft id are required"})
		return
	}
	var body struct {
		Description string `json:"description"`
		Remediation string `json:"remediation"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.drafts.Edit(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(did), body.Description, body.Remediation)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// acceptWriteupDraft is the human sign-off on a proposed draft (PermReview, separation of duties: the
// acceptor must be a non-proposer – enforced in the domain). An accepted draft becomes eligible to be
// applied to its finding; acceptance itself renders nothing.
func (rt *Router) acceptWriteupDraft(w http.ResponseWriter, r *http.Request) {
	engID, did := r.PathValue("id"), r.PathValue("did")
	if engID == "" || did == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and draft id are required"})
		return
	}
	updated, err := rt.drafts.Accept(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(did))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// rejectWriteupDraft discards a proposed draft (PermReview).
func (rt *Router) rejectWriteupDraft(w http.ResponseWriter, r *http.Request) {
	engID, did := r.PathValue("id"), r.PathValue("did")
	if engID == "" || did == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and draft id are required"})
		return
	}
	updated, err := rt.drafts.Reject(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(did))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

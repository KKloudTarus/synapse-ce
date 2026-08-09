package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (rt *Router) listAITriageReviews(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := ports.AITriageReviewFilter{
		Severity:  shared.Severity(strings.TrimSpace(q.Get("severity"))),
		CWE:       strings.TrimSpace(q.Get("cwe")),
		ProjectID: shared.ID(strings.TrimSpace(q.Get("project"))),
		State:     aitriagereview.State(strings.TrimSpace(q.Get("state"))),
	}
	items, err := rt.aiTriageReviews.List(r.Context(), shared.ID(TenantFrom(r.Context())), filter)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": items})
}

func (rt *Router) decideAITriageReview(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(strings.TrimSpace(r.PathValue("rid")))
	if id.IsZero() {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "review id is required"})
		return
	}
	var body struct {
		Decision  aitriagereview.Decision `json:"decision"`
		Rationale string                  `json:"rationale"`
		Version   int                     `json:"version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.aiTriageReviews.Decide(r.Context(), shared.ID(TenantFrom(r.Context())), id,
		PrincipalFrom(r.Context()), body.Decision, body.Rationale, body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (rt *Router) claimAITriageReview(w http.ResponseWriter, r *http.Request) {
	id := shared.ID(strings.TrimSpace(r.PathValue("rid")))
	var body struct {
		Version int `json:"version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10))
	dec.DisallowUnknownFields()
	if id.IsZero() || dec.Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "review id and valid request body are required"})
		return
	}
	updated, err := rt.aiTriageReviews.Claim(r.Context(), shared.ID(TenantFrom(r.Context())), id, PrincipalFrom(r.Context()), body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

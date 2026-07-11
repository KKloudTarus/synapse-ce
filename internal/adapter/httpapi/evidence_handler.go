package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type captureEvidenceRequest struct {
	Kind     string `json:"kind"`           // screenshot|http|terminal_log|artifact|… (default: artifact)
	Filename string `json:"filename"`       // optional original name
	Note     string `json:"note"`           // optional operator note
	Content  string `json:"content_base64"` // base64 of the artifact bytes
}

// captureEvidence ingests a manual artifact into the engagement's tamper-evident
// vault: the bytes are stored content-addressed and a sealed, hash-chained
// link referencing them by sha256 is appended + audited. Not gated by scope/window
// – recording an observation is not running a tool.
func (rt *Router) captureEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // engagement existence + tenant isolation enforced by withEngTenant
	var req captureEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "content_base64 must be valid base64"})
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "artifact"
	}
	link, err := rt.evidence.CaptureArtifact(r.Context(), shared.ID(id), PrincipalFrom(r.Context()), kind, req.Filename, data, req.Note)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

// downloadArtifact streams a captured artifact's bytes by blob sha256, verifying
// the bytes against that hash on read (tamper check). A mismatch is a 409.
func (rt *Router) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	data, err := rt.evidence.ArtifactForEngagement(r.Context(), shared.ID(r.PathValue("id")), r.PathValue("sha"))
	if err != nil {
		if errors.Is(err, evdom.ErrChainBroken) {
			writeJSON(w, http.StatusConflict, errorBody{Error: "artifact failed integrity verification (tampered)"})
			return
		}
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

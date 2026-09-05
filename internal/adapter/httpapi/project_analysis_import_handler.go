package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// importProjectAnalysisRequest is the body synapse-cli sends from a pipeline: the scan result it
// produced, plus what it knows about the run that produced it.
type importProjectAnalysisRequest struct {
	CI     projectanalysis.CIContext `json:"ci"`
	Result *scauc.ScanResult         `json:"result"`
}

// importProjectAnalysis records a pipeline-produced scan result as the project's next analysis.
//
// The route carries importBodyLimit because a full scan result with its SBOM is a whole document
// produced elsewhere, in the same class as a SARIF or CycloneDX import. Unknown fields are refused
// so a client built against a newer server cannot have half its payload silently dropped.
func (rt *Router) importProjectAnalysis(w http.ResponseWriter, r *http.Request) {
	var req importProjectAnalysisRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "scan result exceeds the import size limit"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid analysis import body: expected {\"ci\": {...}, \"result\": {...}}"})
		return
	}
	if req.Result == nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "result is required"})
		return
	}
	analysis, err := rt.projects.ImportAnalysis(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), projectuc.ImportAnalysisInput{
		Actor: PrincipalFrom(r.Context()), CI: req.CI, Result: req.Result,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, projectAnalysisDTO(analysis))
}

package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (rt *Router) exportSARIF(w http.ResponseWriter, r *http.Request) { rt.writeExport(w, r, "sarif") }
func (rt *Router) exportOpenVEX(w http.ResponseWriter, r *http.Request) {
	rt.writeExport(w, r, "openvex")
}

// exportSPDX renders the engagement's latest scan SBOM as a downloadable SPDX
// document (deterministic, from stored data). Defaults to SPDX 3.0.1 (CRA-aligned);
// ?version=2.3 serves the legacy 2.3 projection. The SBOM lives with the scan, so
// it is served by the SCA service rather than the findings-based export service.
func (rt *Router) exportSPDX(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	var (
		body []byte
		err  error
	)
	if r.URL.Query().Get("version") == "2.3" {
		body, err = rt.sca.SPDX(r.Context(), shared.ID(id))
	} else {
		body, err = rt.sca.SPDX3(r.Context(), shared.ID(id))
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/spdx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="synapse-`+safeID(id)+`.spdx.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// exportCycloneDX renders the engagement's latest scan SBOM as a downloadable CycloneDX 1.6 document
// (deterministic, from stored data — no LLM in the report path). The SBOM lives with the scan, so it is
// served by the SCA service.
func (rt *Router) exportCycloneDX(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	body, err := rt.sca.CycloneDX(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="synapse-`+safeID(id)+`.cdx.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// applyVEX ingests a client OpenVEX document and applies each statement to the
// engagement's findings (e.g. not_affected → false positive). CRA-aligned.
func (rt *Router) applyVEX(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	body, err := readBounded(w, r, 8<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "request body too large or unreadable"})
		return
	}
	res, err := rt.vex.Apply(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(id), body)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// importSBOM ingests a client CycloneDX SBOM as the engagement's scan result
// . Components become visible + exportable + sealed into the evidence chain.
func (rt *Router) importSBOM(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	body, err := readBounded(w, r, 32<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "request body too large or unreadable"})
		return
	}
	res, err := rt.sca.ImportSBOMFile(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(id), "SBOM.json", body)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"target": res.Target, "components": len(res.SBOM.Components), "dependencies": len(res.SBOM.Dependencies)})
}

// importedSBOM returns safe metadata for the active imported SBOM. It never
// returns the raw client document.
func (rt *Router) importedSBOM(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	meta, err := rt.sca.ImportedSBOMMetadata(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

// readBounded reads the request body capped at maxBytes (defensive).
func readBounded(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
}

// writeExport renders an engagement's findings as a downloadable SARIF / OpenVEX
// document (templated from stored data — no LLM in the report path).
func (rt *Router) writeExport(w http.ResponseWriter, r *http.Request, format string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}

	var (
		doc      any
		err      error
		ctype    string
		filename string
	)
	switch format {
	case "sarif":
		doc, err = rt.export.SARIF(r.Context(), shared.ID(id))
		ctype, filename = "application/sarif+json", "synapse-"+safeID(id)+".sarif.json"
	default:
		doc, err = rt.export.OpenVEX(r.Context(), shared.ID(id))
		ctype, filename = "application/json", "synapse-"+safeID(id)+".openvex.json"
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// safeID keeps only filename-safe characters, so a crafted engagement id cannot
// inject into the Content-Disposition header.
func safeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "engagement"
	}
	return b.String()
}

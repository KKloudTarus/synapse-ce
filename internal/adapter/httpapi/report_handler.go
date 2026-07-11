package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
)

// exportReport streams the engagement's deterministic PDF report (templated from
// stored data, no LLM in the report path). The PDF bytes are sealed with a SHA-256
// returned in the X-Report-SHA256 header (chain-of-custody).
func (rt *Router) exportReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	pdf, sum, err := rt.report.Generate(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="synapse-`+safeID(id)+`-report.pdf"`)
	w.Header().Set("X-Report-SHA256", sum)
	w.Header().Set("Content-Length", strconv.Itoa(len(pdf)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
}

// exportReportHTML streams a builder-customized HTML report.
func (rt *Router) exportReportHTML(w http.ResponseWriter, r *http.Request) {
	rt.renderReportDoc(w, r, reportuc.FormatHTML)
}

// exportReportDOCX streams a builder-customized Word (.docx) report.
func (rt *Router) exportReportDOCX(w http.ResponseWriter, r *http.Request) {
	rt.renderReportDoc(w, r, reportuc.FormatDOCX)
}

// renderReportDoc renders a report in the given builder format. The "report
// builder" spec is carried in query params (repeatable or comma-separated):
//
//	?type=external – report variant (sca|external|internal|retest)
//	?status=confirmed&status=triage – include only these finding statuses
//	?section=summary,findings – include only these sections (overrides the type default)
//	?title=Q3 External Assessment – override the report title
//
// Like the PDF, the bytes are templated from stored data (no LLM) and SHA-256
// sealed (X-Report-SHA256).
func (rt *Router) renderReportDoc(w http.ResponseWriter, r *http.Request, format string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	q := r.URL.Query()
	opts := reportuc.Options{
		Format:   format,
		Type:     strings.TrimSpace(strings.ToLower(q.Get("type"))),
		Statuses: splitCSV(q["status"]),
		Sections: splitCSV(q["section"]),
		Title:    strings.TrimSpace(q.Get("title")),
	}
	data, contentType, sum, err := rt.report.Render(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id), opts)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// format is a fixed constant ("html"/"docx") and doubles as the extension; the
	// only user-controlled part of the filename is the id, sanitized via safeID.
	w.Header().Set("Content-Disposition", `attachment; filename="synapse-`+safeID(id)+`-report.`+format+`"`)
	w.Header().Set("X-Report-SHA256", sum)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// splitCSV flattens repeated and comma-separated query values into a trimmed,
// non-empty slice (e.g. ["a,b", "c"] -> ["a","b","c"]).
func splitCSV(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

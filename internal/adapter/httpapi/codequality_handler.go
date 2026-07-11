package httpapi

import (
	"context"
	"net/http"
	"os"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
)

// codeQualityService is the narrow slice of the code-quality use-case the HTTP layer needs: build the
// dashboard report (inventory + findings + duplication + ratings) for a local source tree.
// *codequality.Service satisfies it. Optional: nil => the code-quality route is not registered.
type codeQualityService interface {
	BuildReport(ctx context.Context, root string) (codequality.Report, error)
}

// SetCodeQuality wires the read-only code-quality dashboard endpoint.
func (rt *Router) SetCodeQuality(s codeQualityService) { rt.codeQuality = s }

// codeQualityReportView wraps the report with an availability flag: code quality is computed over a LOCAL
// source directory, so an engagement whose scope has no on-disk directory (e.g. an image-only or remote
// target) returns Available=false with a reason rather than an error.
type codeQualityReportView struct {
	Available bool                `json:"available"`
	Reason    string              `json:"reason,omitempty"`
	Report    *codequality.Report `json:"report,omitempty"`
}

// codeQualityReport returns the code-quality report for the engagement's in-scope local source directory.
// Auth (PermView) + tenant scoping are applied by the route wrapper. The analyzed path is taken ONLY from
// the engagement's authorized in-scope targets (never a client-supplied path), and must exist on disk.
func (rt *Router) codeQualityReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	e, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	root := localSourceDir(e.Scope)
	if root == "" {
		writeJSON(w, http.StatusOK, codeQualityReportView{
			Available: false,
			Reason:    "code quality requires an in-scope local source directory; this engagement has none",
		})
		return
	}
	rep, err := rt.codeQuality.BuildReport(r.Context(), root)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, codeQualityReportView{Available: true, Report: &rep})
}

// localSourceDir returns the first in-scope repo target whose value is an existing local directory and is
// not excluded by the engagement's out-of-scope rules, or "" when none is. Only authorized scope targets
// are considered, so a caller can never point the analyzer at an arbitrary server path; the AllowsTarget
// check honors the "out-of-scope always wins" invariant at the repo level. (Pruning out-of-scope SUBPATHS
// inside an allowed repo is a follow-up; the analyzer walk currently covers the whole allowed directory.)
func localSourceDir(scope engagement.Scope) string {
	for _, t := range scope.InScope {
		if t.Kind != engagement.TargetRepo || !scope.AllowsTarget(t) {
			continue
		}
		if fi, err := os.Stat(t.Value); err == nil && fi.IsDir() {
			return t.Value
		}
	}
	return ""
}

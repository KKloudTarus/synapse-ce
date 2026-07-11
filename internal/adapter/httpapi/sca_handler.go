package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type scaScanRequest struct {
	EngagementID string `json:"engagement_id"`
	Target       string `json:"target"`
	Kind         string `json:"kind"` // local (default) | git | archive | image
	Ref          string `json:"ref"`  // optional git branch/tag
	Mode         string `json:"mode"` // full (default) | vulnerabilities | licenses
}

// validateScanTarget rejects a malformed target synchronously. Returns
// "" when valid, else a client-facing reason. Scope + the authorization window are
// still enforced in the use case; this is a fast-fail UX guard at the edge.
func validateScanTarget(kind, target string) string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "-") {
		return "target must not start with '-'"
	}
	switch kind {
	case "git":
		u, err := url.Parse(target)
		if err != nil {
			return "git target must be a valid URL"
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "git target must be an http(s):// URL"
		}
		if u.Host == "" {
			return "git target URL must have a host"
		}
	case "archive", "image":
		return "archive/image targets are not supported yet"
	case "", "local":
		if !filepath.IsAbs(filepath.Clean(target)) {
			return "local target must be an absolute path"
		}
	default:
		return "unknown target kind: " + kind
	}
	return ""
}

func validateScanMode(mode string) string {
	_, err := scauc.NormalizeScanOptions(scauc.ScanOptions{Mode: mode})
	if err != nil {
		return "unknown scan mode: " + strings.TrimSpace(mode)
	}
	return ""
}

// runSCAScan enforces engagement scope/authorization (in the use case), then
// starts the SCA pipeline ASYNCHRONOUSLY and returns the scan job (202). The
// pipeline runs server-side; the UI polls GET.../scan-status for progress and
// can resume after a reload.
func (rt *Router) runSCAScan(w http.ResponseWriter, r *http.Request) {
	var req scaScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	if req.EngagementID == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement_id is required"})
		return
	}
	// Tenant isolation: the engagement id is in the BODY, not a path param, so the
	// withEngTenant route wrapper can't cover this route – verify the engagement belongs to the
	// caller's tenant here (404 cross-tenant, before any scope/window gate or scan starts).
	if _, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(req.EngagementID)); err != nil {
		writeError(w, rt.log, err)
		return
	}
	usingImportedSBOM := false
	if strings.TrimSpace(req.Target) == "" {
		if _, err := rt.sca.ImportedSBOMMetadata(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(req.EngagementID)); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "target is required unless an imported SBOM is active"})
			return
		}
		usingImportedSBOM = true
	}
	// Validate the target synchronously so a malformed target is rejected
	// at submit with a clear reason – not accepted (202) then failed asynchronously.
	if msg := validateScanTarget(req.Kind, req.Target); !usingImportedSBOM && msg != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: msg})
		return
	}
	if msg := validateScanMode(req.Mode); msg != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: msg})
		return
	}
	job, err := rt.sca.StartScanWithOptions(
		r.Context(),
		PrincipalFrom(r.Context()),
		shared.ID(req.EngagementID),
		ports.AcquireRequest{Kind: req.Kind, Value: req.Target, Ref: req.Ref},
		scauc.ScanOptions{Mode: req.Mode},
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// evidenceLedger returns the engagement's hash-chained evidence + verification.
func (rt *Router) evidenceLedger(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	rep, err := rt.sca.VerifyEvidence(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// scanRuns returns the engagement's scan-run history (manifests + repro scores).
func (rt *Router) scanRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	runs, err := rt.sca.ScanRuns(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// compareScanRuns returns the drift between two scan runs + the manifest deltas
// that explain it (reproducibility / chain-of-custody).
func (rt *Router) compareScanRuns(w http.ResponseWriter, r *http.Request) {
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if a == "" || b == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "both run ids (a, b) are required"})
		return
	}
	drift, err := rt.sca.CompareRuns(r.Context(), a, b)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, drift)
}

// scanStatus returns the engagement's most recent scan job (status + stage +
// progress) so the UI can show a progress bar and resume after a page reload.
func (rt *Router) scanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	job, err := rt.sca.LatestJob(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// latestScan returns the engagement's most recent full scan result (JSON) so the
// UI can rehydrate the SBOM / vulnerabilities / graph / languages / provenance on
// page load, not only in the session that ran the scan.
func (rt *Router) latestScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	data, err := rt.sca.LatestResult(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

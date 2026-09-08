package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// scanImageRefRE bounds a container image reference to safe characters at the HTTP edge, mirroring
// the acquirer's authoritative check (no shell metacharacters, no leading '-'). The acquirer still
// validates and pulls the reference daemonlessly (crane); this is a fast-fail 400 for garbage.
var scanImageRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)

type scaScanRequest struct {
	SourceVersionID string `json:"source_version_id,omitempty"`
	EngagementID    string `json:"engagement_id"`
	Target          string `json:"target"`
	Kind            string `json:"kind"`         // local (default) | git | archive | upload | image
	Ref             string `json:"ref"`          // optional git branch/tag
	Mode            string `json:"mode"`         // full (default) | vulnerabilities | licenses
	CodeQuality     bool   `json:"code_quality"` // include first-party code-quality findings
}

type uploadedSourceResponse struct {
	VersionID           shared.ID `json:"version_id,omitempty"`
	ReusedFromVersionID shared.ID `json:"reused_from_version_id,omitempty"`
	AssociatedBy        string    `json:"associated_by,omitempty"`
	AssociatedAt        time.Time `json:"associated_at,omitempty"`
	Filename            string    `json:"filename"`
	Size                int64     `json:"size"`
	SHA256              string    `json:"sha256"`
	Target              string    `json:"target"`
	UploadedBy          string    `json:"uploaded_by"`
	UploadedAt          time.Time `json:"uploaded_at"`
}

func uploadedSourceView(item sourcepackage.Package) uploadedSourceResponse {
	return uploadedSourceResponse{
		VersionID: item.VersionID, ReusedFromVersionID: item.ReusedFromVersionID,
		AssociatedBy: item.AssociatedBy, AssociatedAt: item.AssociatedAt,
		Filename: item.Filename, Size: item.Size, SHA256: item.SHA256, Target: item.Target(), UploadedBy: item.CreatedBy, UploadedAt: item.CreatedAt,
	}
}

// scanRunHistoryReader is the normalized, tenant-scoped provenance read side.
// It deliberately excludes mutation methods: this existing HTTP route is view-only.
type scanRunHistoryReader interface {
	ListScanRuns(ctx context.Context, tenantID, engagementID shared.ID) ([]scanrun.ScanRun, error)
}

// SetScanRunHistory wires normalized provenance into the existing scan-run history route.
func (rt *Router) SetScanRunHistory(history scanRunHistoryReader) { rt.scanRunHistory = history }

type scanRunHistoryResponse struct {
	SourcePackage    *uploadedSourceResponse `json:"source_package,omitempty"`
	TargetKind       string                  `json:"target_kind,omitempty"`
	Target           string                  `json:"target,omitempty"`
	ID               string                  `json:"id"`
	EngagementID     string                  `json:"engagement_id"`
	CreatedAt        time.Time               `json:"created_at"`
	Manifest         ports.ScanManifest      `json:"manifest"`
	FindingKeys      []string                `json:"finding_keys"`
	Provenance       string                  `json:"provenance"`
	TerminalStatus   string                  `json:"terminal_status"`
	SealedAt         *time.Time              `json:"sealed_at,omitempty"`
	ManifestHash     string                  `json:"manifest_hash,omitempty"`
	LaneCount        int                     `json:"lane_count"`
	CompleteCoverage bool                    `json:"complete_coverage"`
}

func legacyScanRunResponse(run ports.ScanRun) scanRunHistoryResponse {
	view := scanRunHistoryResponse{
		ID: run.ID, EngagementID: run.EngagementID, CreatedAt: run.CreatedAt,
		Manifest: run.Manifest, FindingKeys: run.FindingKeys,
		Provenance: "legacy", TerminalStatus: "unknown",
	}
	attachScanSource(&view, run.Manifest.SourcePackage)
	return view
}

func attachScanSource(view *scanRunHistoryResponse, item *sourcepackage.Package) {
	if item == nil {
		return
	}
	source := uploadedSourceView(*item)
	view.SourcePackage, view.TargetKind, view.Target = &source, ports.TargetUpload, item.Target()
}

func mergeScanRunHistory(legacy []ports.ScanRun, normalized []scanrun.ScanRun) []scanRunHistoryResponse {
	legacyByID := make(map[string]ports.ScanRun, len(legacy))
	for _, run := range legacy {
		legacyByID[run.ID] = run
	}
	out := make([]scanRunHistoryResponse, 0, len(legacy)+len(normalized))
	seen := make(map[string]struct{}, len(normalized))
	for _, run := range normalized {
		view := scanRunHistoryResponse{
			ID: run.ID, EngagementID: run.EngagementID.String(), CreatedAt: run.CreatedAt,
			Provenance: string(run.Provenance), TerminalStatus: string(run.TerminalStatus),
			SealedAt: run.SealedAt, ManifestHash: run.ManifestHash, LaneCount: len(run.Lanes),
			CompleteCoverage: run.IsCompleteCoverage(),
		}
		if legacyRun, ok := legacyByID[run.ID]; ok {
			view.Manifest, view.FindingKeys = legacyRun.Manifest, legacyRun.FindingKeys
		} else if len(run.LegacyManifest) > 0 {
			// The normalized read side also retains this run's immutable
			// manifest; never substitute engagement-level current metadata.
			var manifest ports.ScanManifest
			if json.Unmarshal(run.LegacyManifest, &manifest) == nil {
				view.Manifest = manifest
			}
		}
		attachScanSource(&view, view.Manifest.SourcePackage)
		out = append(out, view)
		seen[run.ID] = struct{}{}
	}
	for _, run := range legacy {
		if _, ok := seen[run.ID]; !ok {
			out = append(out, legacyScanRunResponse(run))
		}
	}
	return out
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
	case ports.TargetUpload:
		if target != "" {
			return "uploaded source target is managed by the server"
		}
	case ports.TargetImage:
		// Container-image scanning: the acquirer pulls the reference daemonlessly (crane) into an
		// OCI layout and catalogs its OS + language packages, so the server accepts an image ref here.
		if !scanImageRefRE.MatchString(target) {
			return "image target must be a valid container image reference"
		}
	case "archive":
		// A remote archive is not fetched by the server; upload it via the source-upload route instead.
		return "archive targets are uploaded via the source-upload route, not scanned by reference"
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
	tenantID := shared.TenantOrDefault(shared.ID(TenantFrom(r.Context())))
	engagementID := shared.ID(req.EngagementID)
	if _, err := rt.eng.Get(r.Context(), tenantID, engagementID); err != nil {
		writeError(w, rt.log, err)
		return
	}
	if req.Kind == ports.TargetUpload {
		if msg := validateScanTarget(req.Kind, req.Target); msg != "" {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: msg})
			return
		}
		if msg := validateScanMode(req.Mode); msg != "" {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: msg})
			return
		}
		job, err := rt.sca.StartUploadedSourceVersionScanWithOptions(r.Context(), PrincipalFrom(r.Context()), tenantID, engagementID, shared.ID(req.SourceVersionID), scauc.ScanOptions{Mode: req.Mode, CodeQuality: req.CodeQuality})
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		writeJSON(w, http.StatusAccepted, job)
		return
	}
	if req.SourceVersionID != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "source_version_id requires an upload target"})
		return
	}
	usingImportedSBOM := false
	if strings.TrimSpace(req.Target) == "" {
		if _, err := rt.sca.ImportedSBOMMetadata(r.Context(), tenantID, engagementID); err != nil {
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
		engagementID,
		ports.AcquireRequest{Kind: req.Kind, Value: req.Target, Ref: req.Ref},
		scauc.ScanOptions{Mode: req.Mode, CodeQuality: req.CodeQuality},
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (rt *Router) uploadedSource(w http.ResponseWriter, r *http.Request) {
	engagementID := shared.ID(r.PathValue("id"))
	if engagementID.IsZero() {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	item, err := rt.sca.UploadedSourceMetadata(r.Context(), shared.ID(TenantFrom(r.Context())), engagementID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, uploadedSourceView(item))
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
	legacy, err := rt.sca.ScanRuns(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if rt.scanRunHistory == nil {
		writeJSON(w, http.StatusOK, legacy)
		return
	}
	normalized, err := rt.scanRunHistory.ListScanRuns(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, mergeScanRunHistory(legacy, normalized))
}

// compareScanRuns returns the drift between two scan runs + the manifest deltas
// that explain it (reproducibility / chain-of-custody).
func (rt *Router) compareScanRuns(w http.ResponseWriter, r *http.Request) {
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if a == "" || b == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "both run ids (a, b) are required"})
		return
	}
	drift, err := rt.sca.CompareRuns(r.Context(), shared.ID(r.PathValue("id")), a, b)
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

// scanJob returns one asynchronous scan by job ID. The job is resolved first, then its
// engagement is checked against the authenticated tenant before any job data is returned.
func (rt *Router) scanJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "scan job id is required"})
		return
	}
	job, err := rt.sca.ScanJob(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if _, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(job.EngagementID)); err != nil {
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

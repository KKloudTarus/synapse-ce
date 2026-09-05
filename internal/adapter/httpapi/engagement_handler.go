package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

const createEngagementMetadataLimit = int64(1 << 20)

type scopeTargetDTO struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type createEngagementRequest struct {
	Name           string           `json:"name"`
	Client         string           `json:"client"`
	InScope        []scopeTargetDTO `json:"in_scope"`
	OutOfScope     []scopeTargetDTO `json:"out_of_scope"`
	AuthorizedFrom string           `json:"authorized_from"` // RFC3339, optional
	AuthorizedTo   string           `json:"authorized_to"`   // RFC3339, optional
	Timezone       string           `json:"timezone"`        // IANA, optional (display)
	AssetID        string           `json:"asset_id"`
}

// parseRFC3339Ptr parses an optional RFC3339 timestamp. Empty -> (nil, nil).
func parseRFC3339Ptr(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func toTargets(dtos []scopeTargetDTO) []engdom.Target {
	out := make([]engdom.Target, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, engdom.Target{Kind: engdom.TargetKind(d.Kind), Value: d.Value})
	}
	return out
}

func decodeCreateEngagementRequest(raw []byte) (createEngagementRequest, error) {
	var request createEngagementRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return createEngagementRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return createEngagementRequest{}, fmt.Errorf("unexpected trailing JSON")
	}
	return request, nil
}

func hashSourceUpload(file multipart.File) (int64, string, error) {
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, sourcepackage.MaxArchiveBytes+1))
	if err != nil {
		return 0, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	if written > sourcepackage.MaxArchiveBytes {
		return written, "", fmt.Errorf("%w: uploaded source exceeds %d bytes", shared.ErrValidation, sourcepackage.MaxArchiveBytes)
	}
	if written == 0 {
		return 0, "", fmt.Errorf("%w: uploaded source is empty", shared.ErrValidation)
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func (rt *Router) createEngagement(w http.ResponseWriter, r *http.Request) {
	var (
		req            createEngagementRequest
		sourceFile     multipart.File
		sourceFilename string
		sourceSize     int64
		sourceSHA256   string
		err            error
	)
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr == nil && mediaType == "multipart/form-data" {
		r.Body = http.MaxBytesReader(w, r.Body, sourcepackage.MaxArchiveBytes+createEngagementMetadataLimit)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			status := http.StatusBadRequest
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) || strings.Contains(strings.ToLower(err.Error()), "too large") {
				status = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, status, errorBody{Error: "invalid or oversized source upload"})
			return
		}
		if r.MultipartForm != nil {
			defer func() { _ = r.MultipartForm.RemoveAll() }()
		}
		raw := []byte(r.FormValue("metadata"))
		if len(raw) == 0 || int64(len(raw)) > createEngagementMetadataLimit {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "metadata is required and must be valid JSON"})
			return
		}
		req, err = decodeCreateEngagementRequest(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid metadata JSON"})
			return
		}
		var header *multipart.FileHeader
		sourceFile, header, err = r.FormFile("source")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "source package is required"})
			return
		}
		defer func() { _ = sourceFile.Close() }()
		sourceFilename = sourcepackage.BaseFilename(header.Filename)
		if !sourcepackage.ValidFilename(sourceFilename) {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "source package must be .zip, .tar, .tar.gz, or .tgz"})
			return
		}
		sourceSize, sourceSHA256, err = hashSourceUpload(sourceFile)
		if err != nil {
			switch {
			case sourceSize > sourcepackage.MaxArchiveBytes:
				writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: err.Error()})
			case errors.Is(err, shared.ErrValidation):
				writeJSON(w, http.StatusBadRequest, errorBody{Error: err.Error()})
			default:
				// A raw read/seek failure: don't leak the internal error text to the client.
				writeError(w, rt.log, fmt.Errorf("read source upload: %w", err))
			}
			return
		}
	} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, createEngagementMetadataLimit)).Decode(&req); err != nil {
		// The route carries the source-archive ceiling for the multipart branch, so the JSON
		// branch states its own bound rather than inheriting one sized for a 512 MiB upload.
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	from, err := parseRFC3339Ptr(req.AuthorizedFrom)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_from must be RFC3339"})
		return
	}
	to, err := parseRFC3339Ptr(req.AuthorizedTo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_to must be RFC3339"})
		return
	}
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "timezone must be a valid IANA name"})
			return
		}
	}
	tenantID := shared.TenantOrDefault(shared.ID(TenantFrom(r.Context())))
	if req.AssetID != "" && rt.businessAssets != nil {
		a, getErr := rt.businessAssets.Get(r.Context(), tenantID, shared.ID(req.AssetID))
		if getErr != nil {
			writeError(w, rt.log, getErr)
			return
		}
		if !a.AcceptsAssignments() {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "retired asset is read-only"})
			return
		}
	}
	input := enguc.CreateInput{
		TenantID:        tenantID,
		BusinessAssetID: shared.ID(req.AssetID),
		CreatedBy:       PrincipalFrom(r.Context()), // engagement owner (ownership)
		Name:            req.Name,
		Client:          req.Client,
		InScope:         toTargets(req.InScope),
		OutOfScope:      toTargets(req.OutOfScope),
		AuthorizedFrom:  from,
		AuthorizedTo:    to,
		Timezone:        req.Timezone,
	}
	var e *engdom.Engagement
	if sourceFile != nil {
		e, _, err = rt.eng.CreateFromSourcePackage(r.Context(), input, sourceFilename, sourceSize, sourceSHA256, sourceFile)
	} else {
		e, err = rt.eng.Create(r.Context(), input)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEngagementView(e))
}

func (rt *Router) listEngagements(w http.ResponseWriter, r *http.Request) {
	// Scope the listing to the principal's tenant; the repo treats '' (default tenant)
	// as unscoped, so single-tenant behavior is unchanged until users carry a real tenant.
	list, err := rt.eng.List(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementViews(list))
}

func (rt *Router) getEngagement(w http.ResponseWriter, r *http.Request) {
	e, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

type updateScopeRequest struct {
	InScope    []scopeTargetDTO `json:"in_scope"`
	OutOfScope []scopeTargetDTO `json:"out_of_scope"`
}

// updateScope replaces an engagement's scope. The execution gate reads scope
// live, so the change takes effect on the next tool run.
func (rt *Router) updateScope(w http.ResponseWriter, r *http.Request) {
	var req updateScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.UpdateScope(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), toTargets(req.InScope), toTargets(req.OutOfScope))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

type setWindowRequest struct {
	AuthorizedFrom string `json:"authorized_from"` // RFC3339, optional (empty clears)
	AuthorizedTo   string `json:"authorized_to"`   // RFC3339, optional (empty clears)
	Timezone       string `json:"timezone"`        // IANA, optional (display)
}

func (rt *Router) setAuthorizationWindow(w http.ResponseWriter, r *http.Request) {
	var req setWindowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	from, err := parseRFC3339Ptr(req.AuthorizedFrom)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_from must be RFC3339"})
		return
	}
	to, err := parseRFC3339Ptr(req.AuthorizedTo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_to must be RFC3339"})
		return
	}
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "timezone must be a valid IANA name"})
			return
		}
	}
	e, err := rt.eng.SetWindow(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), from, to, req.Timezone)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

type transitionRequest struct {
	Status string `json:"status"` // target lifecycle status: active|completed|archived
}

// transitionEngagement applies a lifecycle status change (activate/complete/archive).
func (rt *Router) transitionEngagement(w http.ResponseWriter, r *http.Request) {
	var req transitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.Transition(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), engdom.Status(req.Status))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

type blackoutDTO struct {
	From string `json:"from"` // RFC3339
	To   string `json:"to"`   // RFC3339
}

type roeRequest struct {
	AllowedToolClasses []string      `json:"allowed_tool_classes"` // empty = no restriction
	Blackouts          []blackoutDTO `json:"blackouts"`
}

// setLiveRecon toggles the engagement's lab-only live-recon enablement.
func (rt *Router) setLiveRecon(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		// Required when enabling: re-confirm the AUP version and
		// record a lab-authorization attestation. Ignored when disabling.
		AUPVersion  string `json:"aup_version"`
		Attestation string `json:"attestation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.SetLiveRecon(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), req.Enabled, req.AUPVersion, req.Attestation)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

// setRoE replaces the engagement's rules of engagement. The execution gate
// enforces tool-class + blackout rules on every tool run.
func (rt *Router) setRoE(w http.ResponseWriter, r *http.Request) {
	var req roeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	var roe engdom.RoE
	for _, c := range req.AllowedToolClasses {
		roe.AllowedToolClasses = append(roe.AllowedToolClasses, engdom.ToolClass(c))
	}
	for _, b := range req.Blackouts {
		from, err := time.Parse(time.RFC3339, b.From)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "blackout.from must be RFC3339"})
			return
		}
		to, err := time.Parse(time.RFC3339, b.To)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "blackout.to must be RFC3339"})
			return
		}
		roe.Blackouts = append(roe.Blackouts, engdom.Blackout{From: from, To: to})
	}
	e, err := rt.eng.SetRoE(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), roe)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementView(e))
}

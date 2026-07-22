package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

const codeRepresentationVersion = "code:v2"

type codeFilesResponse struct {
	AnalysisID   string                   `json:"analysis_id"`
	Base         *projectuc.CodeRevision  `json:"base,omitempty"`
	Head         projectuc.CodeRevision   `json:"head"`
	Capabilities codeCapabilitiesResponse `json:"capabilities"`
	Files        []projectuc.CodeFile     `json:"files"`
}

type codeCapabilitiesResponse struct {
	Source       bool `json:"source"`
	UnifiedDiff  bool `json:"unified_diff"`
	SplitDiff    bool `json:"split_diff"`
	LineCoverage bool `json:"line_coverage"`
}

type codeFileResponse struct {
	projectuc.CodeFileView
	Capabilities codeCapabilitiesResponse `json:"capabilities"`
}

func codeCapabilities(capabilities projectanalysis.SourceCapabilities, lineCoverage bool) codeCapabilitiesResponse {
	return codeCapabilitiesResponse{
		Source: capabilities.Source.Available, UnifiedDiff: capabilities.UnifiedDiff.Available,
		SplitDiff: capabilities.SplitDiff.Available, LineCoverage: lineCoverage,
	}
}

func codeHeadRevision(analysis projectanalysis.Analysis) projectuc.CodeRevision {
	return projectuc.CodeRevision{
		Ref:            analysis.SourceRef,
		Commit:         analysis.SourceRevision.Head,
		ArtifactDigest: analysis.SourceManifest.ArtifactDigest(),
	}
}

func codeBaseRevision(analysis projectanalysis.Analysis) *projectuc.CodeRevision {
	if !analysis.Comparison.Available {
		return nil
	}
	return &projectuc.CodeRevision{
		Ref:            analysis.Comparison.BaseRef,
		Commit:         analysis.Comparison.BaseCommit,
		ArtifactDigest: analysis.Comparison.BaseManifest.ArtifactDigest(),
	}
}

type codeDiffResponse struct {
	Capabilities projectanalysis.SourceCapabilities `json:"capabilities"`
	Diff         projectuc.CodeDiffView             `json:"diff"`
}

func (rt *Router) listProjectCodeFiles(w http.ResponseWriter, r *http.Request) {
	filter, err := codeFilesParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	files, capabilities, err := rt.projects.ListCodeFilesWithFilter(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("id"), filter)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	analysis, err := rt.projects.GetAnalysis(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("id"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	response := codeFilesResponse{
		AnalysisID: analysis.ID,
		Base:       codeBaseRevision(analysis),
		Head:       codeHeadRevision(analysis),
		Capabilities: codeCapabilities(
			capabilities,
			analysis.Coverage != nil,
		),
		Files: files,
	}
	writeCodeJSON(w, r, http.StatusOK, codeETag(TenantFrom(r.Context()), r.PathValue("key"), r.PathValue("id"), response), response)
}

func (rt *Router) getProjectCodeDiff(w http.ResponseWriter, r *http.Request) {
	path, view, contextLines, err := codeDiffParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	diff, capabilities, err := rt.projects.ReadCodeDiff(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("id"), path, view, contextLines)
	if err != nil {
		writeCodeError(w, rt, err)
		return
	}
	response := codeDiffResponse{Capabilities: capabilities, Diff: diff}
	writeCodeJSON(w, r, http.StatusOK, codeETag(TenantFrom(r.Context()), r.PathValue("key"), r.PathValue("id"), response), response)
}

func codeDiffParams(r *http.Request) (string, string, int, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "path" && key != "view" && key != "context" {
			return "", "", 0, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	path := strings.TrimSpace(query.Get("path"))
	if path == "" {
		return "", "", 0, fmt.Errorf("%w: path is required", shared.ErrValidation)
	}
	view := strings.TrimSpace(query.Get("view"))
	if view == "" {
		view = "unified"
	}
	if view != "unified" && view != "split" {
		return "", "", 0, fmt.Errorf("%w: view must be unified or split", shared.ErrValidation)
	}
	contextLines := 3
	if raw := strings.TrimSpace(query.Get("context")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 100 {
			return "", "", 0, fmt.Errorf("%w: context must be between 0 and 100", shared.ErrValidation)
		}
		contextLines = value
	}
	return path, view, contextLines, nil
}

func (rt *Router) getProjectCodeFile(w http.ResponseWriter, r *http.Request) {
	path, fromLine, toLine, err := codeFileParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	view, capabilities, err := rt.projects.ReadCodeFile(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("id"), path, fromLine, toLine)
	if err != nil {
		writeCodeError(w, rt, err)
		return
	}
	response := codeFileResponse{CodeFileView: view, Capabilities: codeCapabilities(capabilities, view.LineCoverageAvailable)}
	writeCodeJSON(w, r, http.StatusOK, codeETag(TenantFrom(r.Context()), r.PathValue("key"), r.PathValue("id"), response), response)
}

func codeFilesParams(r *http.Request) (projectuc.CodeFileFilter, error) {
	query := r.URL.Query()
	for key := range query {
		switch key {
		case "include_generated", "changed", "has_findings", "prefix", "status":
		default:
			return projectuc.CodeFileFilter{}, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	filter := projectuc.CodeFileFilter{}
	parseBool := func(key string) (*bool, error) {
		raw := strings.TrimSpace(query.Get(key))
		if raw == "" {
			return nil, nil
		}
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s must be true or false", shared.ErrValidation, key)
		}
		return &value, nil
	}
	var err error
	if include, err := parseBool("include_generated"); err != nil {
		return filter, err
	} else if include != nil {
		filter.IncludeGenerated = *include
	}
	if filter.Changed, err = parseBool("changed"); err != nil {
		return filter, err
	}
	if filter.HasFindings, err = parseBool("has_findings"); err != nil {
		return filter, err
	}
	filter.Prefix = strings.TrimSpace(query.Get("prefix"))
	if filter.Prefix != "" {
		if utf8.RuneCountInString(filter.Prefix) > 256 || strings.HasSuffix(filter.Prefix, "/") {
			return filter, fmt.Errorf("%w: prefix is invalid", shared.ErrValidation)
		}
		canonical, err := measure.CanonicalPath(filter.Prefix)
		if err != nil || canonical != filter.Prefix {
			return filter, fmt.Errorf("%w: prefix is invalid", shared.ErrValidation)
		}
	}
	if raw := strings.TrimSpace(query.Get("status")); raw != "" {
		if raw != "unchanged" && !projectanalysis.FileStatus(raw).Valid() {
			return filter, fmt.Errorf("%w: status is invalid", shared.ErrValidation)
		}
		filter.Status = raw
	}
	return filter, nil
}

func codeFileParams(r *http.Request) (string, int, int, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "path" && key != "from_line" && key != "to_line" {
			return "", 0, 0, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	path := strings.TrimSpace(query.Get("path"))
	if path == "" {
		return "", 0, 0, fmt.Errorf("%w: path is required", shared.ErrValidation)
	}
	parse := func(key string) (int, error) {
		raw := strings.TrimSpace(query.Get(key))
		if raw == "" {
			return 0, nil
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, fmt.Errorf("%w: %s must be a positive integer", shared.ErrValidation, key)
		}
		return value, nil
	}
	fromLine, err := parse("from_line")
	if err != nil {
		return "", 0, 0, err
	}
	toLine, err := parse("to_line")
	if err != nil {
		return "", 0, 0, err
	}
	return path, fromLine, toLine, nil
}

func writeCodeError(w http.ResponseWriter, rt *Router, err error) {
	switch {
	case errors.Is(err, projectanalysis.ErrSourceIntegrity):
		writeJSON(w, http.StatusConflict, errorBody{Error: err.Error()})
	case errors.Is(err, projectanalysis.ErrSourceLimit):
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: err.Error()})
	case errors.Is(err, projectanalysis.ErrSourceUnsupported):
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: err.Error()})
	case errors.Is(err, projectanalysis.ErrSourceTransient):
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "source artifact temporarily unavailable"})
	case errors.Is(err, projectanalysis.ErrSourceNotRetained):
		writeJSON(w, http.StatusGone, errorBody{Error: err.Error()})
	default:
		writeError(w, rt.log, err)
	}
}

func writeCodeJSON(w http.ResponseWriter, r *http.Request, status int, etag string, value any) {
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, status, value)
}

func codeETag(tenant, key, analysisID string, value any) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(codeRepresentationVersion+"\x00"+tenant+"\x00"+key+"\x00"+analysisID+"\x00"), body...))
	return strconv.Quote(hex.EncodeToString(sum[:]))
}

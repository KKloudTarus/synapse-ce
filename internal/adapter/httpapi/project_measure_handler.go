package httpapi

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (rt *Router) getProjectMeasures(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}

	q := r.URL.Query()

	// Strict parsing: reject any unknown parameters
	allowed := map[string]bool{"path": true, "limit": true, "cursor": true, "domain": true}
	for k := range q {
		if !allowed[k] {
			writeError(w, rt.log, fmt.Errorf("%w: unknown query parameter %q", shared.ErrValidation, k))
			return
		}
		// scalar parameters must not have duplicates
		if (k == "path" || k == "limit" || k == "cursor") && len(q[k]) > 1 {
			writeError(w, rt.log, fmt.Errorf("%w: duplicate query parameter %q", shared.ErrValidation, k))
			return
		}
	}

	pathParam := q.Get("path")
	if pathParam != "" {
		if _, err := measure.CanonicalPath(pathParam); err != nil {
			writeError(w, rt.log, fmt.Errorf("%w: invalid path parameter", shared.ErrValidation))
			return
		}
	}

	limit := 50
	if l := q.Get("limit"); l != "" {
		val, err := strconv.Atoi(l)
		if err != nil || val < 1 || val > 200 {
			writeError(w, rt.log, fmt.Errorf("%w: limit must be an integer between 1 and 200", shared.ErrValidation))
			return
		}
		limit = val
	}

	cursorStr := q.Get("cursor")
	domains := q["domain"] // Extract all `domain` values

	res, err := rt.projects.GetMeasures(r.Context(), TenantFrom(r.Context()), key, pathParam, domains, limit, cursorStr)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (rt *Router) getProjectBehavioralHotspots(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	analysisID := r.PathValue("analysisID")
	if key == "" || analysisID == "" {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}

	q := r.URL.Query()
	for k, values := range q {
		if k != "path" && k != "limit" {
			writeError(w, rt.log, fmt.Errorf("%w: unknown query parameter %q", shared.ErrValidation, k))
			return
		}
		if len(values) > 1 {
			writeError(w, rt.log, fmt.Errorf("%w: duplicate query parameter %q", shared.ErrValidation, k))
			return
		}
	}

	pathParam := q.Get("path")
	if canonical, err := measure.CanonicalPath(pathParam); err != nil || canonical != pathParam {
		writeError(w, rt.log, fmt.Errorf("%w: invalid path parameter", shared.ErrValidation))
		return
	}
	limit := 50
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, rt.log, fmt.Errorf("%w: limit must be an integer between 1 and 100", shared.ErrValidation))
			return
		}
		limit = parsed
	}

	res, err := rt.projects.GetBehavioralHotspots(r.Context(), shared.ID(TenantFrom(r.Context())), key, analysisID, pathParam, limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

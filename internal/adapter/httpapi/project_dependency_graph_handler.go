package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const maxDependencyRootBytes = 2_048

func (rt *Router) projectDependencyGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := rt.projects.ProjectDependencyGraph(
		r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"),
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "private, no-cache")
	writeJSON(w, http.StatusOK, graph)
}

func (rt *Router) exportProjectDependencySubtree(w http.ResponseWriter, r *http.Request) {
	root, err := dependencyRootParam(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	data, filename, err := rt.projects.ExportProjectDependencySubtree(
		r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), root,
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func dependencyRootParam(r *http.Request) (string, error) {
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	if len(root) > maxDependencyRootBytes {
		return "", fmt.Errorf("%w: dependency root exceeds %d bytes", shared.ErrValidation, maxDependencyRootBytes)
	}
	for _, char := range root {
		if unicode.IsControl(char) {
			return "", fmt.Errorf("%w: dependency root contains control characters", shared.ErrValidation)
		}
	}
	return root, nil
}

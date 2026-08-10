package httpapi

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

const (
	projectSourcePublishMediaType   = "application/x-tar"
	projectSourceToolVersionHeader = "X-Synapse-Tool-Version"
	// The retained source default is 500 MiB. Keep an independent transport ceiling above that
	// budget so tar headers/padding fit, while ignored-path streams still cannot be unbounded.
	projectSourcePublishMaxBody = int64(600 << 20)
)

type projectSourcePublisher interface {
	PublishSource(context.Context, projectuc.PublishSourceInput) (projectanalysis.SourceManifest, error)
}

func (rt *Router) publishProjectSource(w http.ResponseWriter, r *http.Request) {
	rt.publishProjectSourceWithLimit(w, r, projectSourcePublishMaxBody)
}

func (rt *Router) publishProjectSourceWithLimit(w http.ResponseWriter, r *http.Request, maxBody int64) {
	publisher, ok := rt.projects.(projectSourcePublisher)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, errorBody{Error: "source publication is not configured"})
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != projectSourcePublishMediaType {
		writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "Content-Type must be application/x-tar"})
		return
	}
	toolVersion := strings.TrimSpace(r.Header.Get(projectSourceToolVersionHeader))
	if toolVersion == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: projectSourceToolVersionHeader + " is required"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxBody)
	defer func() { _ = body.Close() }()
	manifest, err := publisher.PublishSource(r.Context(), projectuc.PublishSourceInput{
		TenantID:    shared.ID(TenantFrom(r.Context())),
		ProjectKey:  r.PathValue("key"),
		AnalysisID:  r.PathValue("id"),
		Actor:       PrincipalFrom(r.Context()),
		ToolVersion: toolVersion,
		Archive:     body,
	})
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "source archive exceeds upload limit"})
			return
		}
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, manifest)
}

package httpapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type sourcePublishHTTPStub struct {
	projectService
	input  projectuc.PublishSourceInput
	called int
	read   bool
}

func (s *sourcePublishHTTPStub) PublishSource(_ context.Context, in projectuc.PublishSourceInput) (projectanalysis.SourceManifest, error) {
	s.called++
	s.input = in
	if s.read {
		if _, err := io.Copy(io.Discard, in.Archive); err != nil {
			return projectanalysis.SourceManifest{}, fmt.Errorf("consume archive: %w", err)
		}
	}
	return projectanalysis.SourceManifest{Digest: "sha256:test"}, nil
}

func TestPublishProjectSourceDerivesTenantAndActorFromAuthenticatedContext(t *testing.T) {
	stub := &sourcePublishHTTPStub{}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil)), projects: stub}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project/analyses/analysis/source", strings.NewReader("tar-bytes"))
	req.Header.Set("Content-Type", "application/x-tar")
	req.Header.Set(projectSourceToolVersionHeader, "v1.2.3")
	req.SetPathValue("key", "project")
	req.SetPathValue("id", "analysis")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ci-user", TenantID: "tenant-auth", Role: "operator"}))
	res := httptest.NewRecorder()

	rt.publishProjectSource(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if stub.called != 1 {
		t.Fatalf("publish calls=%d, want 1", stub.called)
	}
	if stub.input.TenantID.String() != "tenant-auth" || stub.input.Actor != "ci-user" || stub.input.ProjectKey != "project" || stub.input.AnalysisID != "analysis" || stub.input.ToolVersion != "v1.2.3" {
		t.Fatalf("unexpected publish input: %+v", stub.input)
	}
}

func TestPublishProjectSourceFailsClosedOnTransportContract(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		toolVersion string
		wantStatus  int
	}{
		{name: "wrong media type", contentType: "application/json", toolVersion: "v1", wantStatus: http.StatusUnsupportedMediaType},
		{name: "missing tool version", contentType: "application/x-tar", wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &sourcePublishHTTPStub{}
			rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil)), projects: stub}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.toolVersion != "" {
				req.Header.Set(projectSourceToolVersionHeader, tc.toolVersion)
			}
			res := httptest.NewRecorder()
			rt.publishProjectSourceWithLimit(res, req, 16)
			if res.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
			}
			if stub.called != 0 {
				t.Fatalf("invalid request reached publisher %d time(s)", stub.called)
			}
		})
	}
}

func TestPublishProjectSourceRejectsOversizedArchiveBeforeSuccess(t *testing.T) {
	stub := &sourcePublishHTTPStub{read: true}
	rt := &Router{log: slog.New(slog.NewTextHandler(io.Discard, nil)), projects: stub}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("0123456789abcdef"))
	req.Header.Set("Content-Type", "application/x-tar")
	req.Header.Set(projectSourceToolVersionHeader, "v1")
	res := httptest.NewRecorder()

	rt.publishProjectSourceWithLimit(res, req, 8)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if stub.called != 1 {
		t.Fatalf("publisher calls=%d, want 1", stub.called)
	}
}

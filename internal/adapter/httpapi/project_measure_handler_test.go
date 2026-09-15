package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type mockMeasureService struct {
	projectService
	err       error
	res       projectuc.ProjectMeasureResponse
	cursorStr string
}

type mockBehavioralHotspotsService struct {
	projectService
	err error
	res projectuc.BehavioralHotspotsResponse
}

func (m mockBehavioralHotspotsService) GetBehavioralHotspots(context.Context, shared.ID, string, string, string, int) (projectuc.BehavioralHotspotsResponse, error) {
	return m.res, m.err
}

func (m mockMeasureService) GetMeasures(_ context.Context, _, _, _ string, _ []string, _ int, cursorStr string) (projectuc.ProjectMeasureResponse, error) {
	return m.res, m.err
}

func TestGetProjectBehavioralHotspots(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		serviceErr error
		want       int
	}{
		{name: "success", query: "path=src&limit=10", want: http.StatusOK},
		{name: "unknown query", query: "cursor=x", want: http.StatusBadRequest},
		{name: "duplicate path", query: "path=a&path=b", want: http.StatusBadRequest},
		{name: "invalid path", query: "path=src%2F..%2Fsrc", want: http.StatusBadRequest},
		{name: "invalid limit", query: "limit=101", want: http.StatusBadRequest},
		{name: "not found", serviceErr: shared.ErrNotFound, want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockBehavioralHotspotsService{err: tt.serviceErr}
			rt := &Router{log: discardLog(), projects: svc}
			url := "/api/v1/projects/demo/analyses/a1/behavioral-hotspots"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.SetPathValue("key", "demo")
			req.SetPathValue("analysisID", "a1")
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
			rr := httptest.NewRecorder()
			rt.getProjectBehavioralHotspots(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestGetProjectMeasures(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		pathParam  string
		extraQuery string
		svcErr     error
		wantStatus int
	}{
		{
			name:       "success root",
			key:        "demo",
			pathParam:  "",
			svcErr:     nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "success path",
			key:        "demo",
			pathParam:  "src",
			svcErr:     nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing key",
			key:        "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "not found",
			key:        "demo",
			pathParam:  "missing",
			svcErr:     shared.ErrNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "internal error",
			key:        "demo",
			svcErr:     errors.New("db error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unknown param",
			key:        "demo",
			extraQuery: "foo=bar",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "duplicate scalar param",
			key:        "demo",
			extraQuery: "limit=10&limit=20",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "repeatable domain param",
			key:        "demo",
			extraQuery: "domain=size&domain=coverage",
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid cursor",
			key:        "demo",
			extraQuery: "cursor=invalidbase64",
			svcErr:     shared.ErrValidation,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "cursor mismatch via service",
			key:        "demo",
			extraQuery: "cursor=eyJ2IjoxfQ", // "{"v":1}" encoded
			svcErr:     shared.ErrValidation,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := mockMeasureService{err: tt.svcErr, res: projectuc.ProjectMeasureResponse{
				Node: &projectuc.MeasureNode{Path: tt.pathParam},
			}}

			rt := &Router{log: discardLog(), projects: &svc}

			reqURL := "/api/v1/projects/" + tt.key + "/measures"
			query := ""
			if tt.pathParam != "" {
				query += "path=" + tt.pathParam
			}
			if tt.extraQuery != "" {
				if query != "" {
					query += "&"
				}
				query += tt.extraQuery
			}
			if query != "" {
				reqURL += "?" + query
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			if tt.key != "" {
				req.SetPathValue("key", tt.key)
			}
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))

			rr := httptest.NewRecorder()
			rt.getProjectMeasures(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %v, want %v", rr.Code, tt.wantStatus)
			}
		})
	}
}

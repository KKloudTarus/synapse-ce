package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

func TestProjectHandlers(t *testing.T) {
	svc := projectuc.NewService(memory.NewProjectRepository(), fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{})
	rt := &Router{log: discardLog(), projects: svc}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(`{"name":"Synapse","key":"synapse","source_binding":{"Kind":"local","Value":"/repo"}}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.createProject(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: code=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/synapse", nil)
	req.SetPathValue("key", "synapse")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	rt.getProject(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["Key"] != "synapse" {
		t.Fatalf("body=%v err=%v", body, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/synapse", nil)
	req.SetPathValue("key", "synapse")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "bob", TenantID: "tenant-b"}))
	rec = httptest.NewRecorder()
	rt.getProject(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant: got %d, want 404", rec.Code)
	}
}

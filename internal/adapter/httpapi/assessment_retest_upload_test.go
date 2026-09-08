package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
)

func TestAssessmentRetestUploadedRevisionIsExplicitOwnedAndIdempotent(t *testing.T) {
	router, _, _ := newAssessmentCycleHTTPRouter(t, true, func(string) bool { return true })
	sources := sourceupload.NewStore(blob.NewMemory(), 0)
	router.eng.SetSourceStore(sources)
	handler := router.routes()
	upload := func(path, key, tenant, metadata, content string) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		if err := form.WriteField("metadata", metadata); err != nil {
			t.Fatal(err)
		}
		file, err := form.CreateFormFile("source", "source.zip")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, content); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		request := cycleRequest(http.MethodPost, path, "", userdom.RoleConsultant, tenant)
		request.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		request.ContentLength = int64(body.Len())
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	created := upload("/api/v1/engagements", "root-source", "source-tenant", `{"name":"Uploaded root"}`, "original revision")
	if created.Code != http.StatusCreated {
		t.Fatalf("initial=%d %s", created.Code, created.Body.String())
	}
	var root engagementView
	if err := json.Unmarshal(created.Body.Bytes(), &root); err != nil {
		t.Fatal(err)
	}
	for _, status := range []engdom.Status{engdom.StatusActive, engdom.StatusCompleted} {
		if _, err := router.eng.Transition(context.Background(), "consultant", "source-tenant", shared.ID(root.ID), status); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/v1/engagements/" + root.ID + "/retests"
	missing := cycleRequest(http.MethodPost, path, `{}`, userdom.RoleConsultant, "source-tenant")
	missing.Header.Set("Idempotency-Key", "missing-source")
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest || !strings.Contains(missingResponse.Body.String(), "source_package_required_for_retest") {
		t.Fatalf("missing=%d %s", missingResponse.Code, missingResponse.Body.String())
	}
	metadata := `{"name":"Updated revision","planned_date":"2026-09-08"}`
	retest := upload(path, "new-revision", "source-tenant", metadata, "updated revision")
	if retest.Code != http.StatusCreated {
		t.Fatalf("retest=%d %s", retest.Code, retest.Body.String())
	}
	var result struct {
		Engagement engagementView `json:"engagement"`
	}
	if err := json.Unmarshal(retest.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	stored, err := sources.Get(context.Background(), "source-tenant", shared.ID(result.Engagement.ID))
	if err != nil || len(result.Engagement.Scope.InScope) != 1 || result.Engagement.Scope.InScope[0].Value != stored.Target() || stored.Target() == root.Scope.InScope[0].Value {
		t.Fatalf("new source not bound: %+v err=%v", result, err)
	}
	replayed := upload(path, "new-revision", "source-tenant", metadata, "updated revision")
	if replayed.Code != http.StatusCreated || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != retest.Body.String() {
		t.Fatalf("replay=%d %s", replayed.Code, replayed.Body.String())
	}
	changed := upload(path, "new-revision", "source-tenant", metadata, "different bytes")
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed digest replay=%d %s", changed.Code, changed.Body.String())
	}
	other := upload(path, "foreign", "other-tenant", metadata, "updated revision")
	if other.Code != http.StatusNotFound {
		t.Fatalf("cross tenant=%d %s", other.Code, other.Body.String())
	}
}

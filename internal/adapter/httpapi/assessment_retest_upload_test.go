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
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
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
	jsonRequest := func(key, tenant, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := cycleRequest(http.MethodPost, path, body, userdom.RoleConsultant, tenant)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	original, err := sources.Get(context.Background(), "source-tenant", shared.ID(root.ID))
	if err != nil || original.VersionID.IsZero() {
		t.Fatalf("initial source has no immutable version: %+v err=%v", original, err)
	}
	decodeResult := func(response *httptest.ResponseRecorder) struct {
		Engagement      engagementView                 `json:"engagement"`
		SourceSelection *cycleuc.RetestSourceSelection `json:"source_selection"`
	} {
		t.Helper()
		var result struct {
			Engagement      engagementView                 `json:"engagement"`
			SourceSelection *cycleuc.RetestSourceSelection `json:"source_selection"`
		}
		if response.Code != http.StatusCreated {
			t.Fatalf("create=%d %s", response.Code, response.Body.String())
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(response.Body.String(), "engagement-sources/") || strings.Contains(response.Body.String(), "Locator") {
			t.Fatal("retained response exposed internal storage locator")
		}
		return result
	}
	for _, test := range []struct {
		key, body, code string
		status          int
	}{
		{"unknown-strategy", `{"source_strategy":"other"}`, "invalid_source_strategy", http.StatusBadRequest},
		{"empty-reuse", `{"source_strategy":"reuse_current","scope_strategy":"empty"}`, "source_selection_requires_copied_scope", http.StatusBadRequest},
		{"missing-new-file", `{"source_strategy":"upload_new"}`, "source_upload_required", http.StatusBadRequest},
		{"stale-version", `{"source_strategy":"reuse_current","source_version_id":"stale"}`, "source_version_mismatch", http.StatusConflict},
		{"wrong-predecessor", `{"source_strategy":"reuse_current","predecessor_assessment_id":"other"}`, "invalid_predecessor_assessment", http.StatusBadRequest},
	} {
		response := jsonRequest(test.key, "source-tenant", test.body)
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
			t.Fatalf("%s=%d %s", test.key, response.Code, response.Body.String())
		}
	}
	contradictory := upload(path, "reuse-with-file", "source-tenant", `{"source_strategy":"reuse_current"}`, "unused archive")
	if contradictory.Code != http.StatusBadRequest || !strings.Contains(contradictory.Body.String(), "source_strategy_file_conflict") {
		t.Fatalf("file+reuse=%d %s", contradictory.Code, contradictory.Body.String())
	}
	defaultReuse := jsonRequest("default-reuse", "source-tenant", `{}`)
	defaultResult := decodeResult(defaultReuse)
	if defaultResult.SourceSelection == nil || defaultResult.SourceSelection.Strategy != "reuse_current" || defaultResult.SourceSelection.ReusedFromVersionID != original.VersionID || defaultResult.SourceSelection.SourceAssessmentID != shared.ID(root.ID) || defaultResult.SourceSelection.SHA256 != original.SHA256 {
		t.Fatalf("default source reuse not explicit in response: %+v", defaultResult.SourceSelection)
	}
	reusedSource, err := sources.Get(context.Background(), "source-tenant", shared.ID(defaultResult.Engagement.ID))
	if err != nil || reusedSource.VersionID == original.VersionID || reusedSource.VersionID != defaultResult.SourceSelection.VersionID || reusedSource.EngagementID == original.EngagementID || reusedSource.Locator == original.Locator || reusedSource.SHA256 != original.SHA256 || reusedSource.CreatedBy != original.CreatedBy || !reusedSource.CreatedAt.Equal(original.CreatedAt) {
		t.Fatalf("reused source is not child owned: %+v err=%v", reusedSource, err)
	}
	defaultReplay := jsonRequest("default-reuse", "source-tenant", `{}`)
	if defaultReplay.Code != http.StatusCreated || defaultReplay.Body.String() != defaultReuse.Body.String() || defaultReplay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("reuse replay=%d %s", defaultReplay.Code, defaultReplay.Body.String())
	}
	changedSelection := jsonRequest("default-reuse", "source-tenant", `{"source_strategy":"upload_new"}`)
	if changedSelection.Code != http.StatusConflict {
		t.Fatalf("source strategy change reused idempotency key: %d", changedSelection.Code)
	}
	explicit := jsonRequest("explicit-reuse", "source-tenant", `{"source_strategy":"reuse_current","source_version_id":"`+original.VersionID.String()+`"}`)
	if result := decodeResult(explicit); result.SourceSelection == nil || result.SourceSelection.ReusedFromVersionID != original.VersionID {
		t.Fatalf("explicit version not pinned: %+v", result)
	}
	foreignReuse := jsonRequest("foreign-reuse", "other-tenant", `{"source_strategy":"reuse_current","source_version_id":"`+original.VersionID.String()+`"}`)
	if foreignReuse.Code != http.StatusNotFound {
		t.Fatalf("foreign version accessible: %d %s", foreignReuse.Code, foreignReuse.Body.String())
	}
	foreignVersion := jsonRequest("child-version", "source-tenant", `{"source_strategy":"reuse_current","source_version_id":"`+reusedSource.VersionID.String()+`"}`)
	if foreignVersion.Code != http.StatusConflict {
		t.Fatalf("sibling version selected from predecessor: %d %s", foreignVersion.Code, foreignVersion.Body.String())
	}
	wrongUploadVersion := upload(path, "new-file-wrong-parent-version", "source-tenant", `{"source_strategy":"upload_new","source_version_id":"`+reusedSource.VersionID.String()+`"}`, "new source")
	if wrongUploadVersion.Code != http.StatusConflict {
		t.Fatalf("new archive bypassed predecessor version pin: %d %s", wrongUploadVersion.Code, wrongUploadVersion.Body.String())
	}
	if len(defaultResult.Engagement.Scope.InScope) != 1 || defaultResult.Engagement.Scope.InScope[0].Value != original.Target() || defaultResult.Engagement.Status != string(engdom.StatusDraft) {
		t.Fatalf("reuse changed source scope or draft state: %+v", defaultResult.Engagement)
	}
	metadata := `{"name":"Updated revision","planned_date":"2026-09-08"}`
	retest := upload(path, "new-revision", "source-tenant", metadata, "updated revision")
	if retest.Code != http.StatusCreated {
		t.Fatalf("retest=%d %s", retest.Code, retest.Body.String())
	}
	result := decodeResult(retest)
	stored, err := sources.Get(context.Background(), "source-tenant", shared.ID(result.Engagement.ID))
	if err != nil || len(result.Engagement.Scope.InScope) != 1 || result.Engagement.Scope.InScope[0].Value != stored.Target() || stored.Target() == root.Scope.InScope[0].Value {
		t.Fatalf("new source not bound: %+v err=%v", result, err)
	}
	if result.SourceSelection == nil || result.SourceSelection.Strategy != "upload_new" || result.SourceSelection.VersionID != stored.VersionID || result.SourceSelection.SHA256 != stored.SHA256 || !result.SourceSelection.ReusedFromVersionID.IsZero() {
		t.Fatalf("uploaded revision selection missing: %+v", result.SourceSelection)
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

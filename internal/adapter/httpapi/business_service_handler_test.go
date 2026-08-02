package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	assessmentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentuc"
	assetuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
)

func TestBusinessServiceManagementRoutes(t *testing.T) {
	services := memory.NewAssetInventoryRepository()
	engagements := memory.NewEngagementRepository()
	assets, err := assetuc.New(services, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	assessments, err := assessmentuc.New(memory.NewAssessmentRepository(services, engagements), services, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetBusinessServices(assets)
	rt.SetAssessments(assessments)
	do := func(tenant, role, method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req = req.WithContext(shared.WithTenant(context.WithValue(req.Context(), principalKey, Principal{ID: "operator", Role: role, TenantID: tenant}), shared.ID(tenant)))
		rec := httptest.NewRecorder()
		rt.routes().ServeHTTP(rec, req)
		return rec
	}
	created := do("tenant-a", "consultant", http.MethodPost, "/api/v1/appsec/business-services", `{"name":"Payments","description":"Old","criticality":"medium","lifecycle":"planned"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	var service struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &service); err != nil || service.ID == "" {
		t.Fatalf("service=%s err=%v", created.Body.String(), err)
	}
	updated := do("tenant-a", "consultant", http.MethodPut, "/api/v1/appsec/business-services/"+service.ID, `{"name":"Payments v2","description":"Updated","criticality":"high","lifecycle":"active"}`)
	if updated.Code != http.StatusOK || !bytes.Contains(updated.Body.Bytes(), []byte(`"name":"Payments v2"`)) {
		t.Fatalf("update=%d %s", updated.Code, updated.Body.String())
	}
	if got := do("tenant-a", "readonly", http.MethodPut, "/api/v1/appsec/business-services/"+service.ID, `{}`).Code; got != http.StatusForbidden {
		t.Fatalf("readonly put=%d", got)
	}
	if got := do("tenant-b", "consultant", http.MethodGet, "/api/v1/appsec/business-services/"+service.ID, "").Code; got != http.StatusNotFound {
		t.Fatalf("cross tenant get=%d", got)
	}
	if got := do("tenant-a", "consultant", http.MethodPost, "/api/v1/appsec/business-services/missing/assessments", `{"name":"A","engagements":[{"name":"E"}]}`).Code; got != http.StatusNotFound {
		t.Fatalf("missing parent create=%d", got)
	}
	if got := do("tenant-a", "consultant", http.MethodPost, "/api/v1/appsec/business-services/"+service.ID+"/assessments", `{"name":"A","engagements":[]}`).Code; got != http.StatusBadRequest {
		t.Fatalf("zero children=%d", got)
	}
	assessment := do("tenant-a", "consultant", http.MethodPost, "/api/v1/appsec/business-services/"+service.ID+"/assessments", `{"name":"A","engagements":[{"name":"E","client":"Client"}]}`)
	if assessment.Code != http.StatusCreated {
		t.Fatalf("assessment=%d %s", assessment.Code, assessment.Body.String())
	}
	var createdAssessment struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(assessment.Body.Bytes(), &createdAssessment); err != nil {
		t.Fatal(err)
	}
	other := do("tenant-a", "consultant", http.MethodPost, "/api/v1/appsec/business-services", `{"name":"Other","criticality":"medium","lifecycle":"planned"}`)
	var otherService struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(other.Body.Bytes(), &otherService)
	if got := do("tenant-a", "readonly", http.MethodGet, "/api/v1/appsec/business-services/"+otherService.ID+"/assessments/"+createdAssessment.ID, "").Code; got != http.StatusNotFound {
		t.Fatalf("wrong parent get=%d", got)
	}
	if got := do("tenant-a", "consultant", http.MethodDelete, "/api/v1/appsec/business-services/"+service.ID, "").Code; got != http.StatusConflict {
		t.Fatalf("delete populated=%d", got)
	}
	if got := do("tenant-a", "consultant", http.MethodDelete, "/api/v1/appsec/business-services/"+otherService.ID, "").Code; got != http.StatusNoContent {
		t.Fatalf("delete empty=%d", got)
	}
	if got := do("tenant-a", "readonly", http.MethodGet, "/api/v1/appsec/assets", "").Code; got != http.StatusNotFound {
		t.Fatalf("assets route=%d", got)
	}
}

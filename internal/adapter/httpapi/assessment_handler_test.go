package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	assessmentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentuc"
)

func TestAssessmentRoutesRequireNestedTenantContext(t *testing.T) {
	services := memory.NewAssetInventoryRepository()
	engagements := memory.NewEngagementRepository()
	svc, err := assessmentuc.New(memory.NewAssessmentRepository(services, engagements), services, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	if err := services.CreateBusinessService(shared.WithTenant(context.Background(), "tenant-a"), asset.BusinessService{ID: "service-a", TenantID: "tenant-a", Name: "Service", Criticality: asset.CriticalityMedium, Lifecycle: asset.LifecyclePlanned}); err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetAssessments(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/appsec/business-services/service-a/assessments", strings.NewReader(`{"name":"Release","engagements":[{"name":"Transfer"}]}`))
	req = req.WithContext(shared.WithTenant(context.WithValue(req.Context(), principalKey, Principal{ID: "admin", Role: "admin", TenantID: "tenant-a"}), "tenant-a"))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

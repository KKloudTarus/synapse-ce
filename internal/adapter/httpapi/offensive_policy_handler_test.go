package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
)

func TestOffensivePolicyRouteShowsTheLoadedRegister(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/redteam/policy", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("route registered before SetOffensivePolicy: %d", rec.Code)
	}

	reg, err := offensivepolicy.Load()
	if err != nil {
		t.Fatalf("embedded register must validate: %v", err)
	}
	rt.SetOffensivePolicy(reg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/redteam/policy", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "viewer", Role: "viewer", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	rt.getOffensivePolicy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body offensivePolicyDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Techniques) != len(reg.TechniqueIDs()) || len(body.Techniques) == 0 {
		t.Fatalf("techniques = %d, register has %d", len(body.Techniques), len(reg.TechniqueIDs()))
	}
	prohibited := 0
	for _, tq := range body.Techniques {
		p, ok := reg.Lookup(tq.Technique)
		if !ok {
			t.Fatalf("unknown technique in response: %s", tq.Technique)
		}
		if tq.Prohibited != (p.RiskClass == offensivepolicy.RiskProhibited) || tq.ProductionSafe != p.ProductionSafe || tq.RiskClass != string(p.RiskClass) {
			t.Fatalf("technique %s misreported: %+v vs %+v", tq.Technique, tq, p)
		}
		if tq.Prohibited {
			prohibited++
		}
	}
	if body.Prohibited != prohibited || prohibited == 0 {
		t.Fatalf("prohibited count = %d (rows %d); the shipped register prohibits techniques", body.Prohibited, prohibited)
	}
	if body.LegalReview.CounselReviewed != reg.LegalReview.CounselReviewed {
		t.Fatalf("legal review misreported: %+v", body.LegalReview)
	}
}

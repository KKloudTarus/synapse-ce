package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestScanSubmitRefusesALocalTargetBelowTheFloor pins #1701 at the HTTP edge: a local target the
// operator's floor refuses is answered 400 at submit, before a job is accepted.
func TestScanSubmitRefusesALocalTargetBelowTheFloor(t *testing.T) {
	for _, kind := range []string{"local", ""} {
		t.Run("kind="+kind, func(t *testing.T) {
			rt := newScanJobRouter(t)
			var checked string
			rt.SetLocalTargetCheck(func(path string) error {
				checked = path
				return fmt.Errorf("%w: local scan targets are disabled on this server", shared.ErrValidation)
			})
			target := t.TempDir()
			body := fmt.Sprintf(`{"engagement_id":"engA","kind":%q,"target":%q}`, kind, "  "+target+"  ")
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sca/scan", strings.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: "consultant", TenantID: "tenantA"}))
			rec := httptest.NewRecorder()
			rt.runSCAScan(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "disabled on this server") {
				t.Fatalf("status %d body %s; want 400 naming the floor", rec.Code, rec.Body.String())
			}
			if checked != target {
				t.Fatalf("floor saw %q, want the trimmed target", checked)
			}
		})
	}
}

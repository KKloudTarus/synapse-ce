package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	// The binaries embed the IANA database; tests embed it too so they pass on any host.
	_ "time/tzdata"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	tenancyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/tenancy"
)

type tenantSettingsAudit struct{ entries []ports.AuditEntry }

func (a *tenantSettingsAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type tenantSettingsClock struct{}

func (tenantSettingsClock) Now() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) }

func newTenantSettingsRouter(t *testing.T) (*Router, *tenantSettingsAudit) {
	t.Helper()
	audit := &tenantSettingsAudit{}
	svc, err := tenancyuc.NewService(memory.NewTenantSettingsStore(), audit, tenantSettingsClock{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetTenantSettings(svc)
	return rt, audit
}

func tenantSettingsRequest(t *testing.T, rt *Router, method, body string, ctx context.Context) (*httptest.ResponseRecorder, tenantSettingsView) {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/tenant/settings", strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	var view tenantSettingsView
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec, view
}

func TestTenantSettingsRouteAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec, _ := tenantSettingsRequest(t, rt, http.MethodGet, "", ctxAsUser("u", "admin", "tenant"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwired route = %d, want 404", rec.Code)
	}
}

func TestTenantSettingsReadDefaultsForAnyRole(t *testing.T) {
	rt, _ := newTenantSettingsRouter(t)
	for _, role := range []string{"admin", "member", "reviewer", "readonly"} {
		rec, view := tenantSettingsRequest(t, rt, http.MethodGet, "", ctxAsUser("u", role, "tenant"))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET as %s = %d %s", role, rec.Code, rec.Body)
		}
		if view.DefaultLocale != "en" || view.TimeZone != "UTC" || view.Revision != 0 || view.UpdatedAt != nil {
			t.Fatalf("GET as %s = %+v, want the defaults", role, view)
		}
		if len(view.Locales) != 2 || view.Locales[0] != "en" || view.Locales[1] != "vi" {
			t.Fatalf("locales = %v, want [en vi]", view.Locales)
		}
	}
}

func TestTenantSettingsWriteRequiresAdministrator(t *testing.T) {
	rt, audit := newTenantSettingsRouter(t)
	body := `{"default_locale":"vi","time_zone":"Asia/Ho_Chi_Minh","revision":0}`
	for _, role := range []string{"member", "reviewer", "readonly", "agent", "mcp", ""} {
		rec, _ := tenantSettingsRequest(t, rt, http.MethodPut, body, ctxAsUser("u", role, "tenant"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("PUT as %q = %d, want 403", role, rec.Code)
		}
	}
	if len(audit.entries) != 0 {
		t.Fatalf("a refused write was audited: %+v", audit.entries)
	}
}

func TestTenantSettingsSaveRoundTripsAndGuardsTheRevision(t *testing.T) {
	rt, audit := newTenantSettingsRouter(t)
	admin := ctxAsUser("admin-1", "admin", "tenant")
	rec, saved := tenantSettingsRequest(t, rt, http.MethodPut, `{"default_locale":"vi","time_zone":"Asia/Ho_Chi_Minh","revision":0}`, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	if saved.DefaultLocale != "vi" || saved.TimeZone != "Asia/Ho_Chi_Minh" || saved.Revision != 1 || saved.UpdatedAt == nil {
		t.Fatalf("saved = %+v", saved)
	}
	if len(audit.entries) != 1 || audit.entries[0].Actor != "admin-1" || audit.entries[0].Target != "tenant" {
		t.Fatalf("audit = %+v, want one entry by admin-1 on tenant", audit.entries)
	}
	_, read := tenantSettingsRequest(t, rt, http.MethodGet, "", ctxAsUser("reader", "readonly", "tenant"))
	if read.DefaultLocale != "vi" || read.Revision != 1 {
		t.Fatalf("read back = %+v", read)
	}
	rec, _ = tenantSettingsRequest(t, rt, http.MethodPut, `{"default_locale":"en","time_zone":"UTC","revision":0}`, admin)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale PUT = %d, want 409", rec.Code)
	}
	_, other := tenantSettingsRequest(t, rt, http.MethodGet, "", ctxAsUser("u", "admin", "other-tenant"))
	if other.DefaultLocale != "en" || other.Revision != 0 {
		t.Fatalf("another tenant sees %+v, want its own defaults", other)
	}
}

func TestTenantSettingsRejectsInvalidBodies(t *testing.T) {
	rt, _ := newTenantSettingsRouter(t)
	admin := ctxAsUser("admin-1", "admin", "tenant")
	for name, body := range map[string]string{
		"unsupported locale":       `{"default_locale":"fr","time_zone":"UTC","revision":0}`,
		"unknown zone":             `{"default_locale":"en","time_zone":"Mars/Olympus_Mons","revision":0}`,
		"server-local zone":        `{"default_locale":"en","time_zone":"Local","revision":0}`,
		"tenant named in the body": `{"default_locale":"en","time_zone":"UTC","revision":0,"tenant_id":"other-tenant"}`,
		"two objects":              `{"default_locale":"en","time_zone":"UTC","revision":0}{}`,
		"not JSON":                 `locale=en`,
		"body larger than the cap": `{"default_locale":"en","time_zone":"` + strings.Repeat("A", tenantSettingsBodyCap) + `","revision":0}`,
	} {
		rec, _ := tenantSettingsRequest(t, rt, http.MethodPut, body, admin)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d, want 400", name, rec.Code)
		}
	}
	_, view := tenantSettingsRequest(t, rt, http.MethodGet, "", admin)
	if view.Revision != 0 {
		t.Fatalf("an invalid PUT wrote settings: %+v", view)
	}
}

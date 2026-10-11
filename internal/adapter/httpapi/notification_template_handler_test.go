package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type templateHandlerAudit struct{ entries []ports.AuditEntry }

func (a *templateHandlerAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type templateHandlerIDs struct{ n int }

func (g *templateHandlerIDs) NewID() shared.ID { g.n++; return shared.ID("tpl-" + strconv.Itoa(g.n)) }

func templateRouter(t *testing.T) (*Router, *templateHandlerAudit) {
	t.Helper()
	audit := &templateHandlerAudit{}
	svc, err := notificationuc.NewService(&channelPatchRepo{}, handlerProtector{}, nil, audit, handlerClock{}, &templateHandlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	svc.SetBuiltinTemplates(notificationbuiltin.New())
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	return rt, audit
}

func TestNotificationBuiltinTemplatesListCopiesTheShippedEnglishAndVietnameseCatalog(t *testing.T) {
	rt, _ := templateRouter(t)
	response := templateCall(rt, "integration_admin", "tenant-a", http.MethodGet, "/api/v1/notifications/templates/builtins", "")
	if response.Code != http.StatusOK {
		t.Fatalf("list builtins = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Items []struct {
			EventType string            `json:"event_type"`
			Family    string            `json:"family"`
			Locale    string            `json:"locale"`
			Fields    map[string]string `json:"fields"`
		} `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	catalog := notificationbuiltin.New()
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		want, found := catalog.Builtin("scan.completed", "chat", locale)
		if !found {
			t.Fatalf("missing catalog template for %s", locale)
		}
		var got map[string]string
		for _, item := range body.Items {
			if item.EventType == "scan.completed" && item.Family == "chat" && item.Locale == string(locale) {
				got = item.Fields
				break
			}
		}
		if !reflect.DeepEqual(got, want.Fields) {
			t.Errorf("%s fields = %#v, want %#v", locale, got, want.Fields)
		}
	}
}

func templateCall(rt *Router, role, tenant, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := shared.WithTenant(req.Context(), shared.ID(tenant))
	req = req.WithContext(context.WithValue(ctx, principalKey, Principal{ID: role + "-user", Role: role, TenantID: tenant}))
	response := httptest.NewRecorder()
	rt.routes().ServeHTTP(response, req)
	return response
}

type templateResponse struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	Revision           int    `json:"revision"`
	LatestVersion      int    `json:"latest_version"`
	ActiveVersion      int    `json:"active_version"`
	EventType          string `json:"event_type"`
	Family             string `json:"family"`
	Locale             string `json:"locale"`
	ArchivedTemplateID string `json:"archived_template_id"`
	Latest             *struct {
		Version int               `json:"version"`
		Fields  map[string]string `json:"fields"`
	} `json:"latest"`
	Active *struct {
		Version int `json:"version"`
	} `json:"active"`
}

func decodeTemplate(t *testing.T, response *httptest.ResponseRecorder, want int) templateResponse {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status = %d, want %d: %s", response.Code, want, response.Body.String())
	}
	var out templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The whole template lifecycle over HTTP as an integration_admin, the role #1358 created for it.
func TestNotificationTemplateRoutesLifecycle(t *testing.T) {
	rt, audit := templateRouter(t)
	const role, tenant = "integration_admin", "tenant-a"
	base := "/api/v1/notifications/templates"

	created := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodPost, base,
		`{"name":"Scan done","event_type":"scan.completed","family":"chat","locale":"en","fields":{"title":"Scan finished","body":"See Synapse."}}`), http.StatusCreated)
	if created.Status != "draft" || created.LatestVersion != 1 || created.Latest == nil || created.Latest.Fields["body"] != "See Synapse." || created.Active != nil {
		t.Fatalf("created = %+v", created)
	}
	path := base + "/" + created.ID

	// A tenant-supplied field is refused: the tenant comes from the session.
	if response := templateCall(rt, role, tenant, http.MethodPost, base,
		`{"tenant_id":"tenant-b","name":"x","event_type":"*","family":"chat","locale":"en","fields":{"body":"x"}}`); response.Code != http.StatusBadRequest {
		t.Fatalf("tenant_id in body = %d", response.Code)
	}

	// An engine rejection names the field, event type, code and line, and never echoes the source.
	invalid := templateCall(rt, role, tenant, http.MethodPost, base,
		`{"name":"Bad","event_type":"incident.created","family":"email","locale":"vi","fields":{"subject":"ok","body":"Private LITERAL-91\n{{.nope}}"}}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid = %d %s", invalid.Code, invalid.Body.String())
	}
	var rejection struct {
		Error, Field, EventType, Code string
		Line                          int
	}
	if err := json.Unmarshal(invalid.Body.Bytes(), &rejection); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(invalid.Body.Bytes(), &raw)
	if raw["field"] != "body" || raw["event_type"] != "incident.created" || raw["code"] != "unknown_variable" || raw["line"] != float64(2) {
		t.Fatalf("rejection body = %s", invalid.Body.String())
	}
	if strings.Contains(invalid.Body.String(), "LITERAL-91") {
		t.Fatalf("rejection echoes the source: %s", invalid.Body.String())
	}

	got := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodGet, path, ""), http.StatusOK)
	if got.ID != created.ID || got.EventType != "scan.completed" || got.Family != "chat" || got.Locale != "en" {
		t.Fatalf("get = %+v", got)
	}
	if response := templateCall(rt, role, "tenant-b", http.MethodGet, path, ""); response.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d", response.Code)
	}

	updated := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodPatch, path,
		`{"fields":{"title":"Scan finished","body":"See Synapse now."},"revision":`+strconv.Itoa(created.Revision)+`}`), http.StatusOK)
	if updated.LatestVersion != 2 {
		t.Fatalf("updated = %+v", updated)
	}
	if response := templateCall(rt, role, tenant, http.MethodPatch, path, `{"fields":{"body":"x"},"revision":`+strconv.Itoa(created.Revision)+`}`); response.Code != http.StatusConflict {
		t.Fatalf("stale patch = %d %s", response.Code, response.Body.String())
	}

	active := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodPost, path+"/activate", `{"revision":`+strconv.Itoa(updated.Revision)+`}`), http.StatusOK)
	if active.Status != "active" || active.ActiveVersion != 2 || active.Active == nil || active.Active.Version != 2 {
		t.Fatalf("activated = %+v", active)
	}
	if response := templateCall(rt, role, tenant, http.MethodPost, path+"/activate", `{"revision":0}`); response.Code != http.StatusBadRequest {
		t.Fatalf("activate without revision = %d", response.Code)
	}

	var versions struct {
		Items []struct {
			Version int `json:"version"`
		} `json:"items"`
	}
	response := templateCall(rt, role, tenant, http.MethodGet, path+"/versions?limit=1", "")
	if err := json.Unmarshal(response.Body.Bytes(), &versions); err != nil || response.Code != http.StatusOK || len(versions.Items) != 1 || versions.Items[0].Version != 2 {
		t.Fatalf("versions = %d %s", response.Code, response.Body.String())
	}

	rolled := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodPost, path+"/rollback", `{"version":1,"revision":`+strconv.Itoa(active.Revision)+`}`), http.StatusOK)
	if rolled.ActiveVersion != 1 || rolled.LatestVersion != 2 {
		t.Fatalf("rolled back = %+v", rolled)
	}
	if response := templateCall(rt, role, tenant, http.MethodPost, path+"/rollback", `{"version":1,"revision":`+strconv.Itoa(rolled.Revision)+`}`); response.Code != http.StatusConflict {
		t.Fatalf("rollback to the active version = %d", response.Code)
	}

	var list struct {
		Items []templateResponse `json:"items"`
	}
	response = templateCall(rt, role, tenant, http.MethodGet, base+"?status=active&family=chat", "")
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Items) != 1 || list.Items[0].ID != created.ID {
		t.Fatalf("list = %d %s", response.Code, response.Body.String())
	}
	if response := templateCall(rt, role, tenant, http.MethodGet, base+"?status=bogus", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("bad status filter = %d", response.Code)
	}

	archived := decodeTemplate(t, templateCall(rt, role, tenant, http.MethodPost, path+"/archive", `{"revision":`+strconv.Itoa(rolled.Revision)+`}`), http.StatusOK)
	if archived.Status != "archived" {
		t.Fatalf("archived = %+v", archived)
	}

	actions := map[string]bool{}
	for _, entry := range audit.entries {
		actions[entry.Action] = true
		if entry.Actor != "integration_admin-user" || entry.Metadata["diff"] == "" && entry.Action != "notification.template.archived" {
			t.Fatalf("audit entry = %+v", entry)
		}
		for key, value := range entry.Metadata {
			if strings.Contains(value, "See Synapse") || strings.Contains(value, "{{") {
				t.Fatalf("%s metadata %s quotes template source", entry.Action, key)
			}
		}
	}
	for _, action := range []string{"notification.template.created", "notification.template.updated", "notification.template.activated", "notification.template.rolled_back", "notification.template.archived"} {
		if !actions[action] {
			t.Fatalf("missing %s audit; got %v", action, actions)
		}
	}
}

// Harness for #1370: only admin and integration_admin reach a template route. Machine roles and
// unauthenticated callers are refused before a handler runs.
func TestNotificationTemplateRoutesRefuseOtherRoles(t *testing.T) {
	rt, _ := templateRouter(t)
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/notifications/templates/builtins", ""},
		{http.MethodGet, "/api/v1/notifications/templates", ""},
		{http.MethodPost, "/api/v1/notifications/templates", `{"name":"x","event_type":"*","family":"chat","locale":"en","fields":{"body":"x"}}`},
		{http.MethodGet, "/api/v1/notifications/templates/tpl-1", ""},
		{http.MethodPatch, "/api/v1/notifications/templates/tpl-1", `{"fields":{"body":"x"},"revision":1}`},
		{http.MethodGet, "/api/v1/notifications/templates/tpl-1/versions", ""},
		{http.MethodPost, "/api/v1/notifications/templates/tpl-1/activate", `{"revision":1}`},
		{http.MethodPost, "/api/v1/notifications/templates/tpl-1/rollback", `{"version":1,"revision":1}`},
		{http.MethodPost, "/api/v1/notifications/templates/tpl-1/archive", `{"revision":1}`},
	}
	for _, route := range routes {
		for _, role := range []string{"member", "consultant", "readonly", "reviewer", "agent", "mcp", ""} {
			if response := templateCall(rt, role, "tenant-a", route.method, route.path, route.body); response.Code != http.StatusForbidden {
				t.Errorf("%s %s as %q = %d, want 403", route.method, route.path, role, response.Code)
			}
		}
		for _, role := range []string{"admin", "integration_admin"} {
			if response := templateCall(rt, role, "tenant-a", route.method, route.path, route.body); response.Code == http.StatusForbidden {
				t.Errorf("%s %s as %s = 403", route.method, route.path, role)
			}
		}
	}
}

// Without a template store the routes are not registered.
func TestNotificationTemplateRoutesNeedAStore(t *testing.T) {
	rt := &Router{log: discardLog()}
	rt.SetNotifications(&notificationuc.Service{})
	if response := templateCall(rt, "admin", "tenant-a", http.MethodGet, "/api/v1/notifications/templates", ""); response.Code != http.StatusNotFound {
		t.Fatalf("templates without a store = %d", response.Code)
	}
}

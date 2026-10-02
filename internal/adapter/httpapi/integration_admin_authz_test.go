package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	scmwebhookuc "github.com/KKloudTarus/synapse-ce/internal/usecase/scmwebhook"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

// integrationSurfacePrefixes are the route families integration_admin is about (#1358). Every route
// under them must be classified in integrationRoutePermissions, so a new route cannot land on the
// wrong side of the manage/administer line without a reviewer seeing it here.
var integrationSurfacePrefixes = []string{
	"/api/v1/notifications/",
	"/api/v1/integrations",
	"/api/v1/integration-operations/",
	"/api/v1/integration-providers",
	"/api/v1/siem/",
	"/api/v1/connectors",
	"/api/v1/alerts/",
}

// integrationRoutePermissions is the expected permission of every route on the integration surface.
// PermAdminister marks the destination-changing actions: creating a destination, changing its host,
// secret or credentials, raising a data class, allowing private networks.
var integrationRoutePermissions = map[string]string{
	"GET /api/v1/integration-providers":                            "PermView",
	"POST /api/v1/integrations":                                    "PermAdminister",
	"GET /api/v1/integrations":                                     "PermView",
	"GET /api/v1/integrations/{id}":                                "PermView",
	"PUT /api/v1/integrations/{id}":                                "PermAdminister",
	"POST /api/v1/integrations/{id}/enable":                        "PermManageIntegrations",
	"POST /api/v1/integrations/{id}/disable":                       "PermManageIntegrations",
	"POST /api/v1/integrations/{id}/archive":                       "PermManageIntegrations",
	"PUT /api/v1/integrations/{id}/credentials":                    "PermAdminister",
	"DELETE /api/v1/integrations/{id}/credentials":                 "PermAdminister",
	"POST /api/v1/integrations/{id}/operations":                    "PermManageIntegrations",
	"GET /api/v1/integrations/{id}/operations":                     "PermView",
	"GET /api/v1/integration-operations/{operationID}":             "PermView",
	"POST /api/v1/integration-operations/{operationID}/cancel":     "PermManageIntegrations",
	"POST /api/v1/integrations/{id}/bindings":                      "PermManageIntegrations",
	"GET /api/v1/integrations/{id}/bindings":                       "PermView",
	"DELETE /api/v1/integrations/{id}/bindings/{bindingID}":        "PermManageIntegrations",
	"GET /api/v1/integrations/{id}/external-runs":                  "PermView",
	"POST /api/v1/integrations/{id}/inbound-webhook":               "PermAdminister",
	"POST /api/v1/alerts/test":                                     "PermManageIntegrations",
	"GET /api/v1/notifications/event-types":                        "PermView",
	"GET /api/v1/notifications/channels":                           "PermManageIntegrations",
	"POST /api/v1/notifications/channels":                          "PermAdminister",
	"GET /api/v1/notifications/channels/{nid}":                     "PermManageIntegrations",
	"PATCH /api/v1/notifications/channels/{nid}":                   "PermManageIntegrations",
	"DELETE /api/v1/notifications/channels/{nid}":                  "PermManageIntegrations",
	"POST /api/v1/notifications/channels/{nid}/test":               "PermManageIntegrations",
	"POST /api/v1/notifications/channels/{nid}/resume":             "PermManageIntegrations",
	"GET /api/v1/notifications/channels/{nid}/health-events":       "PermManageIntegrations",
	"GET /api/v1/notifications/rules":                              "PermManageIntegrations",
	"POST /api/v1/notifications/rules":                             "PermManageIntegrations",
	"GET /api/v1/notifications/rules/{nid}":                        "PermManageIntegrations",
	"PATCH /api/v1/notifications/rules/{nid}":                      "PermManageIntegrations",
	"DELETE /api/v1/notifications/rules/{nid}":                     "PermManageIntegrations",
	"POST /api/v1/notifications/deliveries/{nid}/redrive":          "PermAdminister",
	"GET /api/v1/notifications/deliveries":                         "PermManageIntegrations",
	"GET /api/v1/notifications/quarantined-sources":                "PermManageIntegrations",
	"GET /api/v1/notifications/deliveries/{nid}":                   "PermManageIntegrations",
	"GET /api/v1/notifications/deliveries/{nid}/attempts":          "PermManageIntegrations",
	"GET /api/v1/notifications/templates":                          "PermManageIntegrations",
	"POST /api/v1/notifications/templates":                         "PermManageIntegrations",
	"GET /api/v1/notifications/templates/{nid}":                    "PermManageIntegrations",
	"PATCH /api/v1/notifications/templates/{nid}":                  "PermManageIntegrations",
	"GET /api/v1/notifications/templates/{nid}/versions":           "PermManageIntegrations",
	"POST /api/v1/notifications/templates/{nid}/activate":          "PermManageIntegrations",
	"POST /api/v1/notifications/templates/{nid}/rollback":          "PermManageIntegrations",
	"POST /api/v1/notifications/templates/{nid}/archive":           "PermManageIntegrations",
	"GET /api/v1/notifications/channels/{nid}/template-resolution": "PermManageIntegrations",
	"POST /api/v1/notifications/templates/preview":                 "PermManageIntegrations",
	"GET /api/v1/notifications/templates/preview/events":           "PermManageIntegrations",
	"GET /api/v1/siem/sinks":                                       "PermManageIntegrations",
	"POST /api/v1/siem/sinks":                                      "PermAdminister",
	"GET /api/v1/siem/sinks/{id}":                                  "PermManageIntegrations",
	"PATCH /api/v1/siem/sinks/{id}":                                "PermAdminister",
	"POST /api/v1/siem/sinks/{id}/secret":                          "PermAdminister",
	"POST /api/v1/siem/sinks/{id}/origin":                          "PermAdminister",
	"POST /api/v1/siem/sinks/{id}/pause":                           "PermManageIntegrations",
	"POST /api/v1/siem/sinks/{id}/resume":                          "PermManageIntegrations",
	"POST /api/v1/siem/sinks/{id}/test":                            "PermManageIntegrations",
	"GET /api/v1/siem/sinks/{id}/status":                           "PermManageIntegrations",
	"GET /api/v1/connectors":                                       "PermManageIntegrations",
	"POST /api/v1/connectors":                                      "PermAdminister",
	"DELETE /api/v1/connectors/{id}":                               "PermAdminister",
}

func onIntegrationSurface(pattern string) bool {
	_, path, _ := strings.Cut(pattern, " ")
	for _, prefix := range integrationSurfacePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// TestIntegrationSurfacePermissions pins the manage/administer split of #1358 against router.go.
func TestIntegrationSurfacePermissions(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range registeredRoutes(t) {
		if !onIntegrationSurface(route.Pattern) {
			continue
		}
		seen[route.Pattern] = true
		want, ok := integrationRoutePermissions[route.Pattern]
		if !ok {
			t.Errorf("route %s (router.go:%d) is on the integration surface but not classified; add it to integrationRoutePermissions", route.Pattern, route.Line)
			continue
		}
		if route.Guard != "rt.authz" || route.Permission != want {
			t.Errorf("route %s is guarded by %s(%s), want rt.authz(%s)", route.Pattern, route.Guard, route.Permission, want)
		}
	}
	var stale []string
	for pattern := range integrationRoutePermissions {
		if !seen[pattern] {
			stale = append(stale, pattern)
		}
	}
	sort.Strings(stale)
	for _, pattern := range stale {
		t.Errorf("classified route %s is not registered in router.go", pattern)
	}
}

// integrationSurfaceRouter registers every integration route. The services are empty: each request
// below is refused by rt.authz before a handler touches one.
func integrationSurfaceRouter() *Router {
	rt := &Router{log: discardLog()}
	notifications := &notificationuc.Service{}
	notifications.SetTemplateStore(memory.NewNotificationTemplateStore())
	rt.SetNotifications(notifications)
	rt.SetIntegrations(&integrationuc.Service{})
	rt.SetInboundWebhookAdmin(&scmwebhookuc.Service{})
	rt.SetSIEM(&siemuc.Service{})
	rt.SetConnectors(&fakeConnectors{})
	rt.SetAlerts(&fakeAlerts{})
	return rt
}

func concreteRoute(pattern string) (string, string) {
	method, path, _ := strings.Cut(pattern, " ")
	for strings.Contains(path, "{") {
		open := strings.Index(path, "{")
		closeAt := strings.Index(path, "}")
		path = path[:open] + "x" + path[closeAt+1:]
	}
	return method, path
}

func serveAs(rt *Router, method, path, role string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	if role != "" {
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "caller", Role: role, TenantID: "tenant"}))
	}
	response := httptest.NewRecorder()
	rt.routes().ServeHTTP(response, req)
	return response
}

// Hostile harness for #1358: integration_admin is refused every administer-only integration route,
// and no role other than admin and integration_admin reaches a manage_integrations route. Machine
// roles and unauthenticated callers are refused everything.
func TestIntegrationAdminHarness(t *testing.T) {
	rt := integrationSurfaceRouter()
	registered := 0
	for _, route := range registeredRoutes(t) {
		want, ok := integrationRoutePermissions[route.Pattern]
		if !ok {
			continue
		}
		registered++
		method, path := concreteRoute(route.Pattern)
		switch want {
		case "PermAdminister":
			for _, role := range []string{"integration_admin", "member", "consultant", "readonly", "reviewer", "agent", "mcp", ""} {
				response := serveAs(rt, method, path, role)
				if response.Code != wantDenied(role) {
					t.Errorf("%s as %q = %d, want %d", route.Pattern, role, response.Code, wantDenied(role))
				}
				if role == "integration_admin" && !strings.Contains(response.Body.String(), "administer") {
					t.Errorf("%s as integration_admin: 403 body %q does not name the administer capability", route.Pattern, response.Body.String())
				}
			}
		case "PermManageIntegrations":
			for _, role := range []string{"member", "consultant", "readonly", "reviewer", "agent", "mcp", ""} {
				if response := serveAs(rt, method, path, role); response.Code != wantDenied(role) {
					t.Errorf("%s as %q = %d, want %d", route.Pattern, role, response.Code, wantDenied(role))
				}
			}
			for _, role := range []userdom.Role{userdom.RoleIntegrationAdmin, userdom.RoleAdmin} {
				if !role.Can(userdom.PermManageIntegrations) {
					t.Errorf("%s: %s cannot pass its guard", route.Pattern, role)
				}
			}
		}
	}
	if registered != len(integrationRoutePermissions) {
		t.Fatalf("harness registered %d of %d integration routes; a service is not wired", registered, len(integrationRoutePermissions))
	}
}

// channelPatchRepo backs a real notification service for the PATCH split.
type channelPatchRepo struct {
	ports.NotificationRepository
	channel domain.Channel
	updates int
	audit   []ports.AuditEntry
}

func (r *channelPatchRepo) GetChannel(context.Context, shared.ID, shared.ID) (domain.Channel, error) {
	return r.channel, nil
}
func (r *channelPatchRepo) UpdateChannel(_ context.Context, c domain.Channel, _ string, _ bool) (domain.Channel, error) {
	r.updates++
	r.channel = c
	return c, nil
}
func (r *channelPatchRepo) Record(_ context.Context, e ports.AuditEntry) error {
	r.audit = append(r.audit, e)
	return nil
}

// An integration_admin may rename a channel over PATCH but gets 403 for a new URL and secret, which
// an administrator may still set. The audit entry names the actor and the masked host only.
func TestPatchChannelDestinationNeedsAdminister(t *testing.T) {
	repo := &channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "ops", Type: domain.ChannelWebhook, Enabled: true,
		Destination: "https://hooks.example.com/…", Revision: 1, SecretVersion: 1}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, repo, handlerClock{}, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	patch := func(role, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/notifications/channels/c1", strings.NewReader(body))
		req = req.WithContext(context.WithValue(shared.WithTenant(req.Context(), "tenant"), principalKey, Principal{ID: role + "-user", Role: role, TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		return response
	}
	repoint := `{"name":"ops","enabled":true,"url":"https://evil.example.net/p4th","secret":"0123456789abcdef","revision":%d}`
	if response := patch("integration_admin", strings.Replace(repoint, "%d", "1", 1)); response.Code != http.StatusForbidden || repo.updates != 0 {
		t.Fatalf("integration_admin re-point = %d %s, updates=%d", response.Code, response.Body.String(), repo.updates)
	} else if strings.Contains(response.Body.String(), "evil") || strings.Contains(response.Body.String(), "0123456789abcdef") {
		t.Fatalf("403 body echoes the request: %s", response.Body.String())
	}
	if response := patch("integration_admin", `{"name":"renamed","enabled":false,"revision":1}`); response.Code != http.StatusOK || repo.channel.Name != "renamed" {
		t.Fatalf("integration_admin rename = %d %s", response.Code, response.Body.String())
	}
	if response := patch("admin", strings.Replace(repoint, "%d", "2", 1)); response.Code != http.StatusOK || repo.channel.Destination != "https://evil.example.net/…" {
		t.Fatalf("admin re-point = %d %s", response.Code, response.Body.String())
	}
	var updates []ports.AuditEntry
	for _, entry := range repo.audit {
		if entry.Action == "notification.channel.updated" {
			updates = append(updates, entry)
		}
	}
	if len(updates) != 2 || updates[0].Actor != "integration_admin-user" || updates[0].Metadata["destination"] != "https://hooks.example.com" ||
		updates[1].Actor != "admin-user" || updates[1].Metadata["destination"] != "https://evil.example.net" || updates[1].Metadata["destination_changed"] != "true" {
		t.Fatalf("audit = %+v", updates)
	}
}

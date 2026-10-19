package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type jiraWebhookAdminFake struct {
	tenant, integration shared.ID
	actor               string
	calls               int
}

func (f *jiraWebhookAdminFake) ConfigureInboundWebhook(_ context.Context, tenant, integration shared.ID, actor, _ string) (ticketuc.WebhookConfiguration, error) {
	f.tenant, f.integration, f.actor = tenant, integration, actor
	f.calls++
	return ticketuc.WebhookConfiguration{Path: "/api/v1/hooks/redacted", Version: 1}, nil
}

func TestJiraWebhookAdminRequiresAdministratorAndDerivesAuthority(t *testing.T) {
	fake := &jiraWebhookAdminFake{}
	rt := &Router{log: discardLog(), jiraWebhookAdmin: fake}
	rt.SetTicketing(&ticketHTTPFake{})
	for _, role := range []string{"integration_admin", "consultant", "reviewer", "readonly", "agent", "mcp", ""} {
		out := serveAs(rt, "POST", "/api/v1/integrations/jira/jira/inbound-webhook", role)
		if out.Code != wantDenied(role) || fake.calls != 0 {
			t.Fatalf("role=%s status=%d calls=%d", role, out.Code, fake.calls)
		}
	}
	for _, body := range []string{`{"secret":"private","tenant_id":"other"}`, `{"secret":"private","actor":"other"}`} {
		req := httptest.NewRequest("POST", "/api/v1/integrations/jira/jira/inbound-webhook", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin", Role: "admin", TenantID: "tenant-a"}))
		out := httptest.NewRecorder()
		rt.routes().ServeHTTP(out, req)
		if out.Code != 400 || fake.calls != 0 {
			t.Fatal("accepted authority override")
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/integrations/jira/jira/inbound-webhook", strings.NewReader(`{"secret":"private"}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin", Role: "admin", TenantID: "tenant-a"}))
	out := httptest.NewRecorder()
	rt.routes().ServeHTTP(out, req)
	if out.Code != 200 || fake.calls != 1 || fake.tenant != "tenant-a" || fake.integration != "jira" || fake.actor != "admin" || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d fake=%+v", out.Code, fake)
	}
}

func TestJiraHookRequiresNativeBodySignatureAndDeliveryID(t *testing.T) {
	for _, provider := range []string{"jira-cloud", "jira-dc"} {
		t.Run(provider, func(t *testing.T) {
			h, store, receiver, _ := setupHook(t)
			endpoint := store.records[hookIDA]
			endpoint.Provider = provider
			store.records[hookIDA] = endpoint
			body := []byte(`{"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-1"}}`)
			if provider == "jira-dc" {
				body = []byte(`{"event":"jira:issue_updated","issue":{"key":"SEC-1"}}`)
			}
			for _, tc := range []struct {
				name, header, signature, delivery string
				code                              int
			}{
				{"valid", jiraSignatureHeader, webhookSig(hookSecret('a'), body), "delivery-1", 202},
				{"wrong header", inboundWebhookSignature, webhookSig(hookSecret('a'), body), "delivery-2", 401},
				{"tampered", jiraSignatureHeader, webhookSig(hookSecret('b'), body), "delivery-3", 401},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodPost, "/api/v1/hooks/"+hookIDA, bytes.NewReader(body))
					r.Header.Set(tc.header, tc.signature)
					if tc.delivery != "" {
						r.Header.Set("X-Atlassian-Webhook-Identifier", tc.delivery)
					}
					out := httptest.NewRecorder()
					h.ServeHTTP(out, r)
					assertHookCode(t, out, tc.code)
				})
			}
			seen := receiver.snapshot()
			if len(seen) != 1 || seen[0].provider != provider || !strings.HasPrefix(seen[0].eventID, "delivery:") || seen[0].eventID == "delivery-1" || seen[0].eventType != "jira:issue_updated" || seen[0].tenant != "tenant-A" {
				t.Fatalf("unexpected authenticated events: %+v", seen)
			}
		})
	}
}

func TestJiraMissingDeliveryRequiresCloudIdentifierAndUsesSignedDCBody(t *testing.T) {
	for _, provider := range []string{"jira-cloud", "jira-dc"} {
		h, store, receiver, _ := setupHook(t)
		endpoint := store.records[hookIDA]
		endpoint.Provider = provider
		store.records[hookIDA] = endpoint
		body := []byte(`{"webhookEvent":"jira:issue_updated"}`)
		r := httptest.NewRequest("POST", "/api/v1/hooks/"+hookIDA, bytes.NewReader(body))
		r.Header.Set(jiraSignatureHeader, webhookSig(hookSecret('a'), body))
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		if provider == "jira-cloud" {
			assertHookCode(t, out, 400)
			if len(receiver.snapshot()) != 0 {
				t.Fatal("cloud delivery without identifier admitted")
			}
		} else {
			assertHookCode(t, out, 202)
			seen := receiver.snapshot()
			if len(seen) != 1 || !strings.HasPrefix(seen[0].eventID, "body:") {
				t.Fatal("DC signed-body identity missing")
			}
		}
	}
}

func TestJiraHookMetadataRejectsDuplicateOrUnsafeDelivery(t *testing.T) {
	for _, values := range [][]string{{"a", "b"}, {" padded"}, {""}, {"line\nbreak"}} {
		h := make(http.Header)
		h[http.CanonicalHeaderKey("X-Atlassian-Webhook-Identifier")] = values
		if _, ok := jiraEventMetadata("jira-cloud", h, []byte(`{"webhookEvent":"comment_created"}`)); ok {
			t.Fatalf("accepted delivery %q", values)
		}
	}
	h := make(http.Header)
	h.Set("X-Atlassian-Webhook-Identifier", "delivery")
	event, ok := jiraEventMetadata("jira-cloud", h, []byte(`{"webhookEvent":"comment_created"}`))
	if !ok || len(event.PayloadSHA256) != 64 {
		t.Fatal("missing signed-body receipt")
	}
}

func TestJiraDataCenterEventMetadataUsesNativeEventField(t *testing.T) {
	for _, tc := range []struct {
		provider, body string
		accepted       bool
	}{
		{"jira-dc", `{"event":"jira:issue_updated"}`, true},
		{"jira-dc", `{"webhookEvent":"comment_created"}`, true},
		{"jira-dc", `{"event":"jira:issue_updated","webhookEvent":"comment_created"}`, false},
		{"jira-cloud", `{"event":"jira:issue_updated"}`, false},
	} {
		h := make(http.Header)
		if tc.provider == "jira-cloud" {
			h.Set("X-Atlassian-Webhook-Identifier", "delivery")
		}
		event, ok := jiraEventMetadata(tc.provider, h, []byte(tc.body))
		if ok != tc.accepted {
			t.Fatalf("provider=%s accepted=%v want=%v", tc.provider, ok, tc.accepted)
		}
		if ok && (event.EventType == "" || !strings.HasPrefix(event.EventID, "body:")) {
			t.Fatalf("invalid signed body identity: %+v", event)
		}
	}
}

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type emailHandlerRepo struct{ ports.NotificationRepository }
type emailHandlerProtector struct{}

func (emailHandlerProtector) Seal(v, _ []byte) (string, error)        { return string(v), nil }
func (emailHandlerProtector) Open(v string, _ []byte) ([]byte, error) { return []byte(v), nil }

type emailHandlerClock struct{}

func (emailHandlerClock) Now() time.Time { return time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) }

type emailHandlerIDs struct{}

func (emailHandlerIDs) NewID() shared.ID { return "email-id" }

type emailHandlerAudit struct{}

func (emailHandlerAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type emailHandlerTXT map[string][]string

func (f emailHandlerTXT) LookupTXT(_ context.Context, n string) ([]string, error) { return f[n], nil }

func TestNotificationEmailSettingsHTTPDoesNotReturnRelaySecrets(t *testing.T) {
	svc, err := notificationuc.NewService(&emailHandlerRepo{}, emailHandlerProtector{}, nil, emailHandlerAudit{}, emailHandlerClock{}, emailHandlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetEmailSettingsStore(memory.NewNotificationEmailSettingsStore())
	svc.SetSMTPAllowedHosts([]string{"smtp.example.test"})
	svc.SetNotificationTXTResolver(emailHandlerTXT{"_synapse-email.example.test": {"synapse-email-verification=tenant"}})
	rt := &Router{log: discardLog(), notifications: svc}
	request := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/notifications/email-settings", strings.NewReader(body))
		ctx := shared.WithTenant(r.Context(), "tenant")
		r = r.WithContext(context.WithValue(ctx, principalKey, Principal{ID: "admin", TenantID: "tenant", Role: "admin"}))
		w := httptest.NewRecorder()
		if method == http.MethodPut {
			rt.putNotificationEmailSettings(w, r)
		} else {
			rt.getNotificationEmailSettings(w, r)
		}
		return w
	}
	put := request(http.MethodPut, `{"revision":0,"relay":{"host":"smtp.example.test","port":465,"from":"alerts@example.test","username":"relay","password":"private-password"},"domains":["example.test"]}`)
	if put.Code != http.StatusOK || strings.Contains(put.Body.String(), "private-password") {
		t.Fatalf("put status=%d body=%s", put.Code, put.Body)
	}
	get := request(http.MethodGet, "")
	if get.Code != http.StatusOK || strings.Contains(get.Body.String(), "private-password") || !strings.Contains(get.Body.String(), `"dns_txt_value":"synapse-email-verification=tenant"`) {
		t.Fatalf("get status=%d body=%s", get.Code, get.Body)
	}
	unknown := request(http.MethodPut, `{"revision":1,"unknown":true}`)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", unknown.Code)
	}
}

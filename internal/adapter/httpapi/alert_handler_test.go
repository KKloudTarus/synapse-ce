package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	alertinguc "github.com/KKloudTarus/synapse-ce/internal/usecase/alerting"
)

type fakeAlerts struct {
	out   alertinguc.Outcome
	err   error
	actor string
}

func (f *fakeAlerts) Test(_ context.Context, actor string) (alertinguc.Outcome, error) {
	f.actor = actor
	return f.out, f.err
}

func TestAlertTestRouteRegisteredOnlyWhenWired(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/test", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("route registered before SetAlerts: %d", rec.Code)
	}
	rt.SetAlerts(&fakeAlerts{})
	rec = httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/test", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("route missing after SetAlerts")
	}
}

func TestTestAlertReportsOutcome(t *testing.T) {
	svc := &fakeAlerts{out: alertinguc.Outcome{Matched: true, Delivered: 1}}
	rt := &Router{log: discardLog(), alerts: svc}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin-1", Role: "admin", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.testAlert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct{ Outcome alertinguc.Outcome }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Outcome.Delivered != 1 || svc.actor != "admin-1" {
		t.Fatalf("outcome = %+v actor=%q", body.Outcome, svc.actor)
	}

	svc.out, svc.err = alertinguc.Outcome{Matched: true, Failed: 1}, alertinguc.ErrNoSinkAcknowledged
	rec = httptest.NewRecorder()
	rt.testAlert(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("no-sink status %d", rec.Code)
	}
	var failed struct {
		Error   string
		Outcome alertinguc.Outcome
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &failed); err != nil {
		t.Fatal(err)
	}
	if failed.Error == "" || failed.Outcome.Failed != 1 {
		t.Fatalf("failed body = %+v", failed)
	}
}

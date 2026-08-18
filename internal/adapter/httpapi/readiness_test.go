package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadinessEndpointReportsDependencyStateWithoutDetails(t *testing.T) {
	tests := []struct {
		name       string
		checks     map[string]ReadinessCheck
		wantCode   int
		wantStatus string
		wantChecks map[string]string
	}{
		{
			name:       "no external dependencies",
			wantCode:   http.StatusOK,
			wantStatus: "ready",
			wantChecks: map[string]string{},
		},
		{
			name: "ready", wantCode: http.StatusOK, wantStatus: "ready",
			checks: map[string]ReadinessCheck{
				"database":     func(context.Context) error { return nil },
				"migrations":   func(context.Context) error { return nil },
				"object_store": func(context.Context) error { return nil },
			},
			wantChecks: map[string]string{"database": "ok", "migrations": "ok", "object_store": "ok"},
		},
		{
			name: "database down", wantCode: http.StatusServiceUnavailable, wantStatus: "not_ready",
			checks: map[string]ReadinessCheck{
				"database":   func(context.Context) error { return errors.New("dial postgres://secret@db") },
				"migrations": func(context.Context) error { return nil },
			},
			wantChecks: map[string]string{"database": "failed", "migrations": "ok"},
		},
		{
			name: "migrations incomplete", wantCode: http.StatusServiceUnavailable, wantStatus: "not_ready",
			checks: map[string]ReadinessCheck{
				"database":   func(context.Context) error { return nil },
				"migrations": func(context.Context) error { return errors.New("102 of 103 applied") },
			},
			wantChecks: map[string]string{"database": "ok", "migrations": "failed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := &Router{}
			rt.SetReadinessChecks(tc.checks)
			recorder := httptest.NewRecorder()
			rt.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if recorder.Code != tc.wantCode {
				t.Fatalf("status code=%d, want %d; body=%s", recorder.Code, tc.wantCode, recorder.Body.String())
			}
			var response readinessResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Status != tc.wantStatus {
				t.Errorf("status=%q, want %q", response.Status, tc.wantStatus)
			}
			if !reflect.DeepEqual(response.Checks, tc.wantChecks) {
				t.Errorf("checks=%v, want %v", response.Checks, tc.wantChecks)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control=%q, want no-store", got)
			}
			if strings.Contains(recorder.Body.String(), "secret") || strings.Contains(recorder.Body.String(), "102") {
				t.Fatalf("readiness response leaked dependency details: %s", recorder.Body.String())
			}
		})
	}
}

func TestReadinessTimesOutAndRemainsPublic(t *testing.T) {
	rt := &Router{auth: NewAuthenticator(func(context.Context, string) (Principal, bool) {
		t.Fatal("public readiness probe attempted authentication")
		return Principal{}, false
	})}
	rt.readiness.timeout = 10 * time.Millisecond
	rt.SetReadinessChecks(map[string]ReadinessCheck{
		"database": func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	recorder := httptest.NewRecorder()
	rt.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"database":"failed"`) {
		t.Fatalf("timed-out readiness response code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthzRemainsConstantLivenessProbe(t *testing.T) {
	called := false
	rt := &Router{}
	rt.SetReadinessChecks(map[string]ReadinessCheck{
		"database": func(context.Context) error {
			called = true
			return errors.New("down")
		},
	})
	recorder := httptest.NewRecorder()
	rt.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK || called || recorder.Body.String() != "{\"service\":\"synapse-api\",\"status\":\"ok\"}\n" {
		t.Fatalf("liveness changed: code=%d called=%v body=%q", recorder.Code, called, recorder.Body.String())
	}
}

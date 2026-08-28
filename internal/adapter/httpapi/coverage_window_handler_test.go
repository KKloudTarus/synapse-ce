package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type coverageWindowReaderFake struct {
	windows []sensorstate.CoverageWindow
	queries []ports.CoverageWindowQuery
	tenants []shared.ID
}

func (f *coverageWindowReaderFake) ListCoverageWindows(ctx context.Context, query ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error) {
	tenant, _ := shared.TenantFrom(ctx)
	f.tenants = append(f.tenants, tenant)
	f.queries = append(f.queries, query)
	return append([]sensorstate.CoverageWindow(nil), f.windows...), nil
}

func TestCoverageWindowRouteUsesHumanRBACAndTenantContext(t *testing.T) {
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	reader := &coverageWindowReaderFake{windows: []sensorstate.CoverageWindow{{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: at, Until: at.Add(time.Hour),
		InputDigest: "input-digest-1", Revision: "revision-1", CreatedAt: at.Add(2 * time.Hour),
		States: []detection.ClassCoverage{{
			Class: detection.ClassNetwork, HostID: "host-1", AgentID: "agent-1",
			State: detection.StateDegraded, Reason: "signed gap", Since: at.Add(5 * time.Minute),
		}},
		SampledCount: 1, TruncatedCount: 2, DroppedCount: 3, GapCount: 4, BatchCount: 5,
		Vector: riskassessment.CoverageVector{
			Process: 80, Network: 60, File: 100, Privilege: 25,
			Reasons: []string{"telemetry_gap:4"},
		},
	}}}
	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{
		log: discardLog(),
		auth: NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
			switch token {
			case "viewer":
				return Principal{ID: "viewer", Role: "readonly", TenantID: "tenant-a"}, true
			case "agent":
				return Principal{ID: "agent", Role: "agent", TenantID: "tenant-a"}, true
			default:
				return Principal{}, false
			}
		}),
		aup: newTestAUP(aupStore, &fakeAudit{}),
	}
	rt.SetCoverageWindowReader(reader)
	handler := rt.Handler()
	path := "/api/v1/fleet/coverage-windows?agent_id=agent-1&asset_id=asset-1&host_id=host-1&since=" +
		at.Format(time.RFC3339Nano) + "&until=" + at.Add(time.Hour).Format(time.RFC3339Nano) + "&limit=7"

	call := func(token, requestPath string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, requestPath, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := call("", path); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if rec := call("agent", path); rec.Code != http.StatusForbidden {
		t.Fatalf("machine principal status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if len(reader.queries) != 0 {
		t.Fatalf("blocked requests reached reader: %+v", reader.queries)
	}

	rec := call("viewer", path)
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	windows, ok := body["coverage_windows"].([]any)
	if !ok || len(windows) != 1 {
		t.Fatalf("coverage_windows=%#v, want one window", body["coverage_windows"])
	}
	window, ok := windows[0].(map[string]any)
	if !ok {
		t.Fatalf("window=%#v, want object", windows[0])
	}
	assertJSONKeys(t, window,
		"asset_id", "agent_id", "host_id", "since", "until", "input_digest", "revision", "created_at",
		"states", "sampled_count", "truncated_count", "dropped_count", "gap_count", "batch_count", "coverage",
	)
	if window["revision"] != "revision-1" || window["input_digest"] != "input-digest-1" {
		t.Fatalf("window identity=%#v, want explicit immutable identity", window)
	}
	states, ok := window["states"].([]any)
	if !ok || len(states) != 1 {
		t.Fatalf("states=%#v, want one state", window["states"])
	}
	state, ok := states[0].(map[string]any)
	if !ok {
		t.Fatalf("state=%#v, want object", states[0])
	}
	assertJSONKeys(t, state, "class", "host_id", "agent_id", "state", "reason", "since")
	if state["class"] != "network" || state["state"] != "degraded" || state["reason"] != "signed gap" {
		t.Fatalf("state=%#v, want explicit class coverage", state)
	}
	coverage, ok := window["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("coverage=%#v, want object", window["coverage"])
	}
	assertJSONKeys(t, coverage, "process", "network", "file", "privilege", "reasons")
	if coverage["process"] != float64(80) || coverage["network"] != float64(60) {
		t.Fatalf("coverage=%#v, want deterministic scores", coverage)
	}
	for _, forbidden := range []string{"tenant_id", "TenantID", "AssetID", "InputDigest", "Vector", "payload", "Payload"} {
		if _, exists := window[forbidden]; exists {
			t.Fatalf("response exposed forbidden or unstable field %q: %#v", forbidden, window)
		}
	}
	if len(reader.tenants) != 1 || reader.tenants[0] != "tenant-a" {
		t.Fatalf("reader tenants=%v, want authenticated tenant-a", reader.tenants)
	}
	want := ports.CoverageWindowQuery{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "host-1",
		Since: at, Until: at.Add(time.Hour), Limit: 7,
	}
	if len(reader.queries) != 1 || reader.queries[0] != want {
		t.Fatalf("reader queries=%+v, want %+v", reader.queries, want)
	}

	for _, bad := range []string{
		"?since=bad",
		"?since=" + at.Format(time.RFC3339Nano) + "&until=" + at.Format(time.RFC3339Nano),
		"?limit=-1",
		"?limit=1001",
	} {
		before := len(reader.queries)
		rec := call("viewer", "/api/v1/fleet/coverage-windows"+bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q status=%d body=%s, want 400", bad, rec.Code, rec.Body.String())
		}
		if len(reader.queries) != before {
			t.Errorf("invalid query %q reached reader", bad)
		}
	}
}

func TestCoverageWindowRouteIsAbsentWhenReaderUnwired(t *testing.T) {
	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{
		log: discardLog(),
		auth: NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
			return Principal{ID: "viewer", Role: "readonly", TenantID: "tenant-a"}, token == "viewer"
		}),
		aup: newTestAUP(aupStore, &fakeAudit{}),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/coverage-windows", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwired status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
}

func assertJSONKeys(t *testing.T, value map[string]any, want ...string) {
	t.Helper()
	if len(value) != len(want) {
		t.Fatalf("JSON keys=%v, want exactly %v", jsonKeys(value), want)
	}
	for _, key := range want {
		if _, ok := value[key]; !ok {
			t.Fatalf("JSON keys=%v, missing %q", jsonKeys(value), key)
		}
	}
}

func jsonKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	coverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coverage"
)

type fakeCoverage struct {
	rows []coverageuc.CoverageRow
}

func (f fakeCoverage) Agents(context.Context, shared.ID, fleetcoverage.AgentHealth) ([]coverageuc.AgentRow, error) {
	return []coverageuc.AgentRow{{ID: "ag1", Health: fleetcoverage.AgentHealthy}}, nil
}
func (f fakeCoverage) AgentDetail(context.Context, shared.ID, shared.ID) (coverageuc.AgentRow, []coverageuc.OrderBrief, error) {
	return coverageuc.AgentRow{ID: "ag1"}, nil, nil
}
func (f fakeCoverage) Coverage(context.Context, shared.ID) ([]coverageuc.CoverageRow, error) {
	return f.rows, nil
}
func (f fakeCoverage) Summary(context.Context, shared.ID) (coverageuc.Summary, error) {
	return coverageuc.Summary{}, nil
}

func TestFleetCoverageRoutePresence(t *testing.T) {
	rt := &Router{log: discardLog()}
	call := func(p string) int {
		w := httptest.NewRecorder()
		rt.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		return w.Code
	}
	paths := []string{"/api/v1/fleet/agents", "/api/v1/fleet/coverage", "/api/v1/fleet/coverage/summary", "/api/v1/fleet/coverage/export"}
	for _, p := range paths {
		if code := call(p); code != http.StatusNotFound {
			t.Errorf("%s: expected 404 before SetFleetCoverage, got %d", p, code)
		}
	}
	rt.SetFleetCoverage(fakeCoverage{})
	for _, p := range paths {
		if code := call(p); code == http.StatusNotFound {
			t.Errorf("%s: expected route present after SetFleetCoverage, got 404", p)
		}
	}
}

func TestExportCoverageCSVMatchesRows(t *testing.T) {
	rows := []coverageuc.CoverageRow{
		{AssetID: "a1", Capability: "scan.host", Verdict: fleetcoverage.VerdictCovered, LastRun: time.Unix(1700000000, 0).UTC(), AgentID: "ag1"},
		{AssetID: "a2", Capability: "scan.host", Verdict: fleetcoverage.VerdictRefused, Detail: "out of scope"},
	}
	rt := &Router{log: discardLog()}
	rt.SetFleetCoverage(fakeCoverage{rows: rows})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/coverage/export", nil)
	w := httptest.NewRecorder()
	rt.exportFleetCoverage(w, req)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "asset_id,capability,verdict,detail,last_run,agent_id\n") {
		t.Fatalf("missing/incorrect CSV header: %q", body)
	}
	if !strings.Contains(body, "a1,scan.host,covered,,2023-11-14T22:13:20Z,ag1") {
		t.Fatalf("covered row not exported faithfully: %q", body)
	}
	if !strings.Contains(body, "a2,scan.host,refused,out of scope,,") {
		t.Fatalf("refused row (with reason, no last_run) not exported faithfully: %q", body)
	}
}

func TestExportCoverageNeutralizesFormulaInjection(t *testing.T) {
	// A hostile refuse-reason / capability must not become an executable spreadsheet formula in the
	// auditor-facing CSV. encoding/csv quotes delimiters but does not neutralize leading =,+,-,@.
	rows := []coverageuc.CoverageRow{
		{AssetID: "a1", Capability: "=SUM(A1)", Verdict: fleetcoverage.VerdictRefused, Detail: "=cmd|'/c calc'!A1", AgentID: "@evil"},
	}
	rt := &Router{log: discardLog()}
	rt.SetFleetCoverage(fakeCoverage{rows: rows})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/coverage/export", nil)
	w := httptest.NewRecorder()
	rt.exportFleetCoverage(w, req)
	body := w.Body.String()
	for _, danger := range []string{",=SUM", ",=cmd", ",@evil"} {
		if strings.Contains(body, danger) {
			t.Fatalf("formula-injectable field not neutralized: found %q in %q", danger, body)
		}
	}
	// The values are still present, just defused with a leading quote.
	if !strings.Contains(body, "'=SUM(A1)") || !strings.Contains(body, "'@evil") {
		t.Fatalf("defused values missing from export: %q", body)
	}
}

func TestListFleetAgentHealthRejectsBadStateFilter(t *testing.T) {
	rt := &Router{log: discardLog()}
	rt.SetFleetCoverage(fakeCoverage{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agents?state=bogus", nil)
	w := httptest.NewRecorder()
	rt.listFleetAgentHealth(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown state filter must be 400 (not silently all), got %d", w.Code)
	}
}

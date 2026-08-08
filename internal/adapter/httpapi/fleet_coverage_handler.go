package httpapi

import (
	"context"
	"encoding/csv"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	coverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coverage"
)

// coverageService is the narrow view of the fleet-coverage read model the HTTP layer needs (#413).
// Optional: when nil the coverage routes are not registered.
type coverageService interface {
	Agents(ctx context.Context, tenantID shared.ID, state fleetcoverage.AgentHealth) ([]coverageuc.AgentRow, error)
	AgentDetail(ctx context.Context, tenantID, agentID shared.ID) (coverageuc.AgentRow, []coverageuc.OrderBrief, error)
	Coverage(ctx context.Context, tenantID shared.ID) ([]coverageuc.CoverageRow, error)
	Summary(ctx context.Context, tenantID shared.ID) (coverageuc.Summary, error)
}

// SetFleetCoverage wires the coverage read model and enables the coverage/agent-view routes.
func (rt *Router) SetFleetCoverage(s coverageService) { rt.coverage = s }

func (rt *Router) listFleetAgentHealth(w http.ResponseWriter, r *http.Request) {
	// state filter is validated: an unknown value is rejected rather than silently returning all.
	state := fleetcoverage.AgentHealth(r.URL.Query().Get("state"))
	if state != "" && !state.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid state filter"})
		return
	}
	rows, err := rt.coverage.Agents(r.Context(), fleetTenant(r.Context()), state)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (rt *Router) getFleetAgentHealth(w http.ResponseWriter, r *http.Request) {
	row, orders, err := rt.coverage.AgentDetail(r.Context(), fleetTenant(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": row, "recent_work": orders})
}

func (rt *Router) listFleetCoverage(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.coverage.Coverage(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (rt *Router) fleetCoverageSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := rt.coverage.Summary(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// exportFleetCoverage streams the SAME coverage rows as CSV for an auditor. It reuses the projection,
// so the export can never disagree with the API for the same input.
func (rt *Router) exportFleetCoverage(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.coverage.Coverage(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fleet-coverage.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"asset_id", "capability", "verdict", "detail", "last_run", "agent_id"})
	for _, row := range rows {
		last := ""
		if !row.LastRun.IsZero() {
			last = row.LastRun.UTC().Format("2006-01-02T15:04:05Z")
		}
		// Neutralize spreadsheet formula injection on the externally-influenced text columns
		// (asset_id/capability/detail/agent_id derive from agent- and operator-supplied data): a
		// value opening with =,+,-,@ or a control char is executed as a formula when the auditor
		// opens the CSV. encoding/csv quotes delimiters but does NOT do this. verdict/last_run are
		// server-generated enums/timestamps and safe as-is.
		_ = cw.Write([]string{
			csvSafe(row.AssetID), csvSafe(row.Capability), string(row.Verdict),
			csvSafe(row.Detail), last, csvSafe(row.AgentID),
		})
	}
	cw.Flush()
}

// csvSafe prefixes a single quote to a value that could be interpreted as a spreadsheet formula, so an
// auditor's spreadsheet renders it as literal text rather than executing it (CSV/formula injection).
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

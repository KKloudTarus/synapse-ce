package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// endpointProcessStore is the B5 per-host running-process projection this API surfaces (#594): an operator
// (or a scanner/agent tool) reports the processes running on a host asset, and Exposure's
// running-vs-installed refinement reads them. ports.EndpointProcessStore satisfies it. Snapshots are
// tenant-scoped server-side (from ctx), never from a request field.
type endpointProcessStore interface {
	SaveProcesses(ctx context.Context, snapshots []ports.ProcessSnapshot) error
	ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error)
}

// SetEndpointProcesses wires the process-projection surface (nil ⇒ the routes are not registered).
func (rt *Router) SetEndpointProcesses(s endpointProcessStore) { rt.endpointProcesses = s }

const (
	// endpointProcessBodyLimit caps a process-report body. A host reports a bounded process list; a very
	// large body is refused rather than read unbounded.
	endpointProcessBodyLimit = 1 << 20
	maxEndpointProcesses     = 10000
)

type processReport struct {
	EntityID   string    `json:"entity_id"`
	PID        int       `json:"pid"`
	Comm       string    `json:"comm"`
	Path       string    `json:"path"`
	Running    bool      `json:"running"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type reportProcessesRequest struct {
	Processes []processReport `json:"processes"`
}

// reportEndpointProcesses upserts the reported running-process snapshots for one host asset (#594 B5). The
// tenant is the authenticated fleet tenant and the asset is the path id — never request fields, so a
// report cannot claim another tenant's or asset's processes.
func (rt *Router) reportEndpointProcesses(w http.ResponseWriter, r *http.Request) {
	var req reportProcessesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, endpointProcessBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	if len(req.Processes) > maxEndpointProcesses {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "too many processes in one report"})
		return
	}
	ctx := incidentTenantContext(r)
	tenant := fleetTenant(r.Context())
	assetID := shared.ID(r.PathValue("id"))
	snapshots := make([]ports.ProcessSnapshot, 0, len(req.Processes))
	for _, p := range req.Processes {
		snapshots = append(snapshots, ports.ProcessSnapshot{
			TenantID: tenant, AssetID: assetID, EntityID: shared.ID(p.EntityID),
			PID: p.PID, Comm: p.Comm, Path: p.Path, Running: p.Running, LastSeenAt: p.LastSeenAt,
		})
	}
	if err := rt.endpointProcesses.SaveProcesses(ctx, snapshots); err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"saved": len(snapshots)})
}

// listEndpointProcesses returns the currently-running processes for one host asset (#594 B5).
func (rt *Router) listEndpointProcesses(w http.ResponseWriter, r *http.Request) {
	running, err := rt.endpointProcesses.ListRunningByAsset(incidentTenantContext(r), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"processes": running})
}

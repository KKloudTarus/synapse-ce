package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
)

// fleetTelemetryCap bounds one agent telemetry batch body. It matches the agent spool's per-batch sizing
// so a full priority batch fits, while a malicious oversize body is rejected before decode.
const fleetTelemetryCap = 16 << 20 // 16 MiB

// fleetTelemetryIngest is the narrow agent-plane telemetry ingest surface the handler consumes. The
// usecase (telemetryingest.Service) satisfies it; defined here (consumer side) so the adapter depends on
// a minimal contract, not the whole service.
type fleetTelemetryIngest interface {
	Ingest(ctx context.Context, authAgentID shared.ID, req telemetryingest.IngestRequest) (telemetryingest.IngestResult, error)
}

// ingestTelemetry is the agent-plane endpoint (POST /api/v1/fleet/telemetry): an enrolled agent ships a
// signed TelemetryBatchManifest plus its events; the control plane verifies identity, signing key, and
// schema SERVER-SIDE (fail-closed), sequences the batch idempotently, derives gaps from the ACK snapshot, and returns the
// highest-contiguous ACK so the agent can delete acknowledged batches. Identity/key/schema failures map
// to 403/4xx via writeError; the agent id + tenant come from the authenticated credential, never the body.
func (f *fleetRouter) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var req telemetryingest.IngestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetTelemetryCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	res, err := f.telemetry.Ingest(r.Context(), agent.ID, req)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":   res.Accepted,
		"duplicate":  res.Duplicate,
		"ack":        res.ACK,
		"provenance": res.Provenance,
		"gap_open":   res.GapOpen,
	})
}

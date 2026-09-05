package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	detectledger "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
)

// fleetDetectionCap bounds one detection batch body. Detections carry a bounded evidence window each, so a
// batch is larger than a heartbeat but far smaller than a raw telemetry batch; an oversize body is rejected
// before decode.
const fleetDetectionCap = 8 << 20 // 8 MiB

// fleetDetectionIngest is the narrow agent-plane detection-ingest surface the handler consumes. The
// detectledger.Service satisfies it; defined here (consumer side) so the adapter depends on a minimal
// contract, not the whole ledger. authAgentID is passed from the credential so the usecase can enforce
// A0.1 server-authoritative identity (the batch cannot claim another agent).
type fleetDetectionIngest interface {
	IngestV2(ctx context.Context, authAgentID shared.ID, batch fleetagent.AgentBatchV2, items []fleetagent.DetectionBatchItemV2) (detectledger.IngestResult, error)
}

// ingestDetections is the agent-plane endpoint (POST /api/v1/fleet/detections): an enrolled agent ships a
// signed AgentBatch plus the detections it commits to; the ledger verifies identity (the batch agent must
// be the authenticated agent), the named signing key, and each detection's content digest SERVER-SIDE
// (fail-closed), seals each detection once into the evidence chain, and persists the projection. Identity
// failures map to 403, malformed/unverified to 4xx via writeError; the agent id + tenant come from the
// authenticated credential, never the body.
func (f *fleetRouter) ingestDetections(w http.ResponseWriter, r *http.Request) {
	if f.detections == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "detection ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var req struct {
		BatchV2 fleetagent.AgentBatchV2           `json:"batch_v2"`
		ItemsV2 []fleetagent.DetectionBatchItemV2 `json:"items_v2"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetDetectionCap))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid v2 detection batch body"})
		return
	}
	if req.BatchV2.Context == "" || len(req.ItemsV2) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "v2 detection batch and items are required"})
		return
	}
	res, err := f.detections.IngestV2(r.Context(), agent.ID, req.BatchV2, req.ItemsV2)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"engagement_id":         res.EngagementID.String(),
		"sealed":                len(res.SealedRecords),
		"skipped":               len(res.Skipped),
		"missing":               res.Gap.Missing,
		"replay":                res.Gap.Replay,
		"correlation_scheduled": res.CorrelationScheduled,
	})
}

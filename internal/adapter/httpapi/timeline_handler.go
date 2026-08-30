package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/retrohunt"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// endpointTimelineReader queries the B7 State Timeline (#594) for a host asset. endpointstate.Service
// satisfies it. retroHunter re-hunts a window of the timeline around a pivot; retrohunt.Service satisfies
// it. Both are read surfaces; tenant + asset are server-side (fleet tenant / path id).
type endpointTimelineReader interface {
	Query(ctx context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error)
}

type retroHunter interface {
	Hunt(ctx context.Context, req retrohunt.Request) (retrohunt.Result, error)
}

// SetEndpointTimeline wires the State-Timeline read surface (nil ⇒ the routes are not registered).
func (rt *Router) SetEndpointTimeline(r endpointTimelineReader) { rt.endpointTimeline = r }

// SetRetroHunter wires the retro-hunt surface (nil ⇒ the route is not registered).
func (rt *Router) SetRetroHunter(h retroHunter) { rt.retroHunter = h }

const (
	defaultTimelineLimit = 500
	maxTimelineLimit     = 5000
	retroHuntBodyLimit   = 4 << 10
)

func parseTimelineTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func timelineLimit(raw string) int {
	if raw == "" {
		return defaultTimelineLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return defaultTimelineLimit
	}
	if n > maxTimelineLimit {
		return maxTimelineLimit
	}
	return n
}

// queryEndpointTimeline returns the State-Timeline window for a host asset (#594 B7). Query params:
// from/to (RFC3339), entity, limit (1..5000, default 500).
func (rt *Router) queryEndpointTimeline(w http.ResponseWriter, r *http.Request) {
	from, err := parseTimelineTime(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid from (want RFC3339)"})
		return
	}
	to, err := parseTimelineTime(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid to (want RFC3339)"})
		return
	}
	entries, err := rt.endpointTimeline.Query(incidentTenantContext(r), ports.EndpointTimelineQuery{
		AssetID:  shared.ID(r.PathValue("id")),
		From:     from,
		To:       to,
		EntityID: shared.ID(r.URL.Query().Get("entity")),
		Limit:    timelineLimit(r.URL.Query().Get("limit")),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

type retroHuntRequest struct {
	Around        time.Time `json:"around"`
	BeforeSeconds int64     `json:"before_seconds"`
	AfterSeconds  int64     `json:"after_seconds"`
	EntityID      string    `json:"entity_id"`
	Limit         int       `json:"limit"`
}

// retroHuntEndpoint re-hunts the timeline window around a pivot time for a host asset (#594 B7/C retro).
func (rt *Router) retroHuntEndpoint(w http.ResponseWriter, r *http.Request) {
	var req retroHuntRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, retroHuntBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	res, err := rt.retroHunter.Hunt(incidentTenantContext(r), retrohunt.Request{
		AssetID:  shared.ID(r.PathValue("id")),
		Around:   req.Around,
		Before:   time.Duration(req.BeforeSeconds) * time.Second,
		After:    time.Duration(req.AfterSeconds) * time.Second,
		EntityID: shared.ID(req.EntityID),
		Limit:    req.Limit,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

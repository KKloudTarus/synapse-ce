package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type coverageWindowReader interface {
	ListCoverageWindows(context.Context, ports.CoverageWindowQuery) ([]sensorstate.CoverageWindow, error)
}

type coverageClassStateResponse struct {
	Class   string    `json:"class"`
	HostID  shared.ID `json:"host_id"`
	AgentID shared.ID `json:"agent_id"`
	State   string    `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Since   time.Time `json:"since"`
}

type coverageVectorResponse struct {
	Process   int      `json:"process"`
	Network   int      `json:"network"`
	File      int      `json:"file"`
	Privilege int      `json:"privilege"`
	Reasons   []string `json:"reasons"`
}

type coverageWindowResponse struct {
	AssetID        shared.ID                    `json:"asset_id"`
	AgentID        shared.ID                    `json:"agent_id"`
	HostID         shared.ID                    `json:"host_id"`
	Since          time.Time                    `json:"since"`
	Until          time.Time                    `json:"until"`
	InputDigest    string                       `json:"input_digest"`
	Revision       string                       `json:"revision"`
	CreatedAt      time.Time                    `json:"created_at"`
	States         []coverageClassStateResponse `json:"states"`
	SampledCount   int                          `json:"sampled_count"`
	TruncatedCount int                          `json:"truncated_count"`
	DroppedCount   int                          `json:"dropped_count"`
	GapCount       int                          `json:"gap_count"`
	BatchCount     int                          `json:"batch_count"`
	Coverage       coverageVectorResponse       `json:"coverage"`
}

func newCoverageWindowResponse(window sensorstate.CoverageWindow) coverageWindowResponse {
	states := make([]coverageClassStateResponse, len(window.States))
	for i, state := range window.States {
		states[i] = coverageClassStateResponse{
			Class: string(state.Class), HostID: state.HostID, AgentID: state.AgentID,
			State: string(state.State), Reason: state.Reason, Since: state.Since,
		}
	}
	return coverageWindowResponse{
		AssetID: window.AssetID, AgentID: window.AgentID, HostID: window.HostID,
		Since: window.Since, Until: window.Until, InputDigest: window.InputDigest,
		Revision: window.Revision, CreatedAt: window.CreatedAt, States: states,
		SampledCount: window.SampledCount, TruncatedCount: window.TruncatedCount,
		DroppedCount: window.DroppedCount, GapCount: window.GapCount, BatchCount: window.BatchCount,
		Coverage: coverageVectorResponse{
			Process: int(window.Vector.Process), Network: int(window.Vector.Network),
			File: int(window.Vector.File), Privilege: int(window.Vector.Privilege),
			Reasons: append([]string(nil), window.Vector.Reasons...),
		},
	}
}

func (rt *Router) SetCoverageWindowReader(reader coverageWindowReader) {
	if reader != nil {
		rt.coverageWindows = reader
	}
}

func (rt *Router) listCoverageWindows(w http.ResponseWriter, r *http.Request) {
	query, err := coverageWindowQuery(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	windows, err := rt.coverageWindows.ListCoverageWindows(r.Context(), query)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	response := make([]coverageWindowResponse, len(windows))
	for i, window := range windows {
		response[i] = newCoverageWindowResponse(window)
	}
	writeJSON(w, http.StatusOK, map[string]any{"coverage_windows": response})
}

func coverageWindowQuery(r *http.Request) (ports.CoverageWindowQuery, error) {
	values := r.URL.Query()
	query := ports.CoverageWindowQuery{
		AgentID: shared.ID(values.Get("agent_id")),
		AssetID: shared.ID(values.Get("asset_id")),
		HostID:  shared.ID(values.Get("host_id")),
	}
	var err error
	if value := values.Get("since"); value != "" {
		query.Since, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return ports.CoverageWindowQuery{}, fmt.Errorf("%w: invalid coverage-window since", shared.ErrValidation)
		}
	}
	if value := values.Get("until"); value != "" {
		query.Until, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return ports.CoverageWindowQuery{}, fmt.Errorf("%w: invalid coverage-window until", shared.ErrValidation)
		}
	}
	if value := values.Get("limit"); value != "" {
		query.Limit, err = strconv.Atoi(value)
		if err != nil {
			return ports.CoverageWindowQuery{}, fmt.Errorf("%w: invalid coverage-window limit", shared.ErrValidation)
		}
	}
	if !query.Valid() {
		return ports.CoverageWindowQuery{}, fmt.Errorf("%w: invalid coverage-window query", shared.ErrValidation)
	}
	return query, nil
}

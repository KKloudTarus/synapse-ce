package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	offensiveuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
)

// offensiveKillSwitch is the narrow consumer-side interface this handler needs.
type offensiveKillSwitch interface {
	Halt(ctx context.Context, tenantID shared.ID, actor, reason string) (offensiveuc.HaltResult, error)
}

// SetOffensiveKillSwitch wires the red-team halt route (#418). Left unset, the route is not registered:
// an endpoint that accepts a halt and does nothing would be the worst possible failure for this control.
func (rt *Router) SetOffensiveKillSwitch(ks offensiveKillSwitch) {
	if ks != nil {
		rt.offensiveHalt = ks
	}
}

type haltRequest struct {
	Reason string `json:"reason"`
}

type haltResponse struct {
	RequestedAt    time.Time         `json:"requested_at"`
	CompletedAt    time.Time         `json:"completed_at"`
	DurationMS     int64             `json:"duration_ms"`
	StatedBoundMS  int64             `json:"stated_bound_ms"`
	WithinBound    bool              `json:"within_bound"`
	Halted         bool              `json:"halted"`
	Cancelled      []string          `json:"cancelled"`
	Failed         map[string]string `json:"failed,omitempty"`
	ChainsHalted   []string          `json:"chains_halted,omitempty"`
	ChainsFailed   map[string]string `json:"chains_failed,omitempty"`
	ChainHaltError string            `json:"chain_halt_error,omitempty"`
	AuditRecorded  bool              `json:"audit_recorded"`
	EstateStopNote string            `json:"estate_stop_note"`
}

// haltOffensiveWork is the kill switch: one operator action that halts all in-flight offensive work.
//
// It reports the MEASURED duration against the stated bound rather than asserting compliance, and it
// reports partial failure as a failure. An operator who reads "halted" must be able to trust it.
func (rt *Router) haltOffensiveWork(w http.ResponseWriter, r *http.Request) {
	var req haltRequest
	// A halt is urgent, so an empty body is tolerated as far as decoding goes — but the reason is still
	// required below, because a halt nobody can explain afterwards defeats the chain of custody.
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	result, err := rt.offensiveHalt.Halt(r.Context(), requestTenant(r), PrincipalFrom(r.Context()), req.Reason)
	body := haltResponse{
		RequestedAt: result.RequestedAt, CompletedAt: result.CompletedAt,
		DurationMS: result.Duration.Milliseconds(), StatedBoundMS: offensiveuc.HaltBound.Milliseconds(),
		WithinBound: result.WithinBound, Halted: err == nil && result.Halted(),
		Cancelled: idStrings(result.Cancelled), Failed: failureStrings(result.Failed),
		ChainsHalted: idStrings(result.Chains.Halted), ChainsFailed: failureStrings(result.Chains.Failed),
		ChainHaltError: result.ChainHaltError,
		AuditRecorded:  !result.AuditFailed, EstateStopNote: result.EstateStopNote,
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, body)
	case errors.Is(err, shared.ErrValidation):
		writeError(w, rt.log, err)
	default:
		// A halt that did not fully succeed answers 500 with the partial result attached, so the operator
		// sees exactly which orders are still in flight instead of a bare error.
		rt.log.Error("offensive halt did not fully succeed", "err", err)
		writeJSON(w, http.StatusInternalServerError, body)
	}
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

func failureStrings(failed map[shared.ID]string) map[string]string {
	if len(failed) == 0 {
		return nil
	}
	out := make(map[string]string, len(failed))
	for id, reason := range failed {
		out[id.String()] = reason
	}
	return out
}

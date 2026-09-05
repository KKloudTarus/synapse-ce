package httpapi

import (
	"context"
	"errors"
	"net/http"

	alertinguc "github.com/KKloudTarus/synapse-ce/internal/usecase/alerting"
)

// alertService is the operator-facing slice of the alerting use case.
type alertService interface {
	Test(ctx context.Context, actor string) (alertinguc.Outcome, error)
}

// SetAlerts wires operator alerting and enables its routes.
func (rt *Router) SetAlerts(s alertService) { rt.alerts = s }

// testAlert delivers a synthetic alert to every configured sink so an operator can prove the alert path
// works before relying on it. 200 when at least one sink acknowledged; 502 when none did, with the same
// outcome body so the operator sees how many sinks failed.
func (rt *Router) testAlert(w http.ResponseWriter, r *http.Request) {
	out, err := rt.alerts.Test(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		if errors.Is(err, alertinguc.ErrNoSinkAcknowledged) {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "outcome": out})
			return
		}
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outcome": out})
}

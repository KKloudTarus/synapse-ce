package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const defaultReadinessTimeout = 2 * time.Second

// ReadinessCheck verifies one dependency required to serve production traffic.
// The endpoint exposes only the check name and pass/fail state, never the returned error.
type ReadinessCheck func(context.Context) error

type readinessConfig struct {
	checks  map[string]ReadinessCheck
	timeout time.Duration
}

type readinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// SetReadinessChecks replaces the dependency checks used by GET /readyz. It copies the map so
// startup wiring cannot mutate the live probe configuration after the server begins serving.
func (rt *Router) SetReadinessChecks(checks map[string]ReadinessCheck) {
	rt.readiness.checks = make(map[string]ReadinessCheck, len(checks))
	for name, check := range checks {
		if name = strings.TrimSpace(name); name != "" && check != nil {
			rt.readiness.checks[name] = check
		}
	}
}

func (rt *Router) ready(w http.ResponseWriter, r *http.Request) {
	checks := rt.readiness.checks
	states := make(map[string]string, len(checks))
	w.Header().Set("Cache-Control", "no-store")
	if len(checks) == 0 {
		writeJSON(w, http.StatusOK, readinessResponse{Status: "ready", Checks: states})
		return
	}

	timeout := rt.readiness.timeout
	if timeout <= 0 {
		timeout = defaultReadinessTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(checks))
	pending := make(map[string]struct{}, len(checks))
	for name, check := range checks {
		pending[name] = struct{}{}
		go func() {
			results <- result{name: name, err: check(ctx)}
		}()
	}

	isReady := true
	for len(pending) > 0 {
		select {
		case result := <-results:
			if _, ok := pending[result.name]; !ok {
				continue
			}
			delete(pending, result.name)
			if result.err != nil {
				states[result.name] = "failed"
				isReady = false
			} else {
				states[result.name] = "ok"
			}
		case <-ctx.Done():
			for name := range pending {
				states[name] = "failed"
			}
			isReady = false
			pending = nil
		}
	}

	if !isReady {
		writeJSON(w, http.StatusServiceUnavailable, readinessResponse{Status: "not_ready", Checks: states})
		return
	}
	writeJSON(w, http.StatusOK, readinessResponse{Status: "ready", Checks: states})
}

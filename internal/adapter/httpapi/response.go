package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error string `json:"error"`
}

func requestLogger(w http.ResponseWriter, fallback *slog.Logger) *slog.Logger {
	for w != nil {
		if carrier, ok := w.(requestLoggerResponseWriter); ok {
			if log := carrier.requestLogger(); log != nil {
				return log
			}
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = unwrapper.Unwrap()
	}
	return fallback
}

// writeError maps domain sentinel errors to HTTP status codes.
func writeError(w http.ResponseWriter, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		writeJSON(w, http.StatusBadRequest, errorBody{Error: err.Error()})
	case errors.Is(err, shared.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errorBody{Error: err.Error()})
	case errors.Is(err, shared.ErrConflict):
		writeJSON(w, http.StatusConflict, errorBody{Error: err.Error()})
	case errors.Is(err, shared.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{Error: err.Error()})
	case errors.Is(err, shared.ErrSaturated):
		// Default backoff hint; a caller that set a more specific Retry-After (e.g. the agent
		// admission path) keeps its value rather than being clobbered here.
		if w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "1")
		}
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: err.Error()})
	default:
		requestLogger(w, log).Error("request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal error"})
	}
}

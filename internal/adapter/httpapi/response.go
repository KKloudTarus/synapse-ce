package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identitybff"
)

// writeJSON writes v as the response. For an error status, an error body gains the contract
// fields (code, request_id, retryable) without changing its "error" text.
func writeJSON(w http.ResponseWriter, status int, v any) {
	v = completeErrorBody(w, status, v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
	// Infrastructure failures may wrap validation/conflict sentinels. Their
	// diagnostic Error() belongs in server logs, not a 4xx response body.
	var internalOnly interface{ InternalOnly() }
	if errors.As(err, &internalOnly) {
		requestLogger(w, log).Error("request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal error"})
		return
	}
	// Authentication classes are decided before the generic sentinels: an authentication error
	// may also wrap a storage error or ErrForbidden, and its class is what the client acts on.
	switch {
	case errors.Is(err, authz.ErrAuthenticationUnavailable):
		requestLogger(w, log).Warn("authentication dependency unavailable", "err", err)
		writeCodedError(w, CodeAuthenticationUnavailable, "authentication is temporarily unavailable; retry shortly")
		return
	case errors.Is(err, authz.ErrCSRFInvalid):
		writeCodedError(w, CodeCSRFInvalid, "CSRF token is missing or invalid")
		return
	case errors.Is(err, authz.ErrCredentialInvalid):
		writeCodedError(w, CodeAuthenticationInvalid, "authentication credential is invalid or expired")
		return
	case errors.Is(err, identitybff.ErrAccessDenied):
		writeCodedError(w, CodeAccessDenied, "access denied: this identity is not approved for Synapse")
		return
	}
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

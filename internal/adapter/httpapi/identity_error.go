package httpapi

import (
	"context"
	"errors"
	"net/http"

	identitydom "github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentityErrorCode is the bounded, client-actionable identity error vocabulary. HTTP status is
// still the transport mapping; clients use these codes only to decide whether credentials remain
// usable and whether retry is meaningful.
type IdentityErrorCode string

const (
	IdentityErrorAuthenticationInvalid IdentityErrorCode = "authentication_invalid"
	IdentityErrorAccessDenied          IdentityErrorCode = "identity_access_denied"
	IdentityErrorConflict              IdentityErrorCode = "identity_conflict"
	IdentityErrorDependencyUnavailable IdentityErrorCode = "dependency_unavailable"
	IdentityErrorCapacityLimited       IdentityErrorCode = "capacity_limited"
)

type identityErrorBody struct {
	Error     string            `json:"error"`
	Code      IdentityErrorCode `json:"code"`
	RequestID string            `json:"request_id"`
	Retryable bool              `json:"retryable"`
}

type identityErrorSpec struct {
	status    int
	message   string
	retryable bool
}

func identityErrorDetails(code IdentityErrorCode) identityErrorSpec {
	switch code {
	case IdentityErrorAuthenticationInvalid:
		return identityErrorSpec{status: http.StatusUnauthorized, message: "authentication failed"}
	case IdentityErrorAccessDenied:
		return identityErrorSpec{status: http.StatusForbidden, message: "identity access denied"}
	case IdentityErrorConflict:
		return identityErrorSpec{status: http.StatusConflict, message: "identity state conflict"}
	case IdentityErrorCapacityLimited:
		return identityErrorSpec{status: http.StatusServiceUnavailable, message: "identity service capacity limited", retryable: true}
	default:
		return identityErrorSpec{status: http.StatusServiceUnavailable, message: "identity service temporarily unavailable", retryable: true}
	}
}

// identityCodeFor maps an internal failure onto the deliberately small public vocabulary. Unknown
// failures are dependency failures rather than invalid credentials: an unavailable database must
// never cause a browser or bearer client to discard a credential that may still be valid.
func identityCodeFor(err error) IdentityErrorCode {
	switch {
	case errors.Is(err, identitydom.ErrAuthenticationInvalid):
		return IdentityErrorAuthenticationInvalid
	case errors.Is(err, identitydom.ErrAccessDenied), errors.Is(err, shared.ErrForbidden):
		return IdentityErrorAccessDenied
	case errors.Is(err, shared.ErrConflict):
		return IdentityErrorConflict
	case errors.Is(err, shared.ErrSaturated):
		return IdentityErrorCapacityLimited
	default:
		return IdentityErrorDependencyUnavailable
	}
}

func writeIdentityError(ctx context.Context, w http.ResponseWriter, code IdentityErrorCode, cause error) {
	spec := identityErrorDetails(code)
	if code == IdentityErrorAuthenticationInvalid {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if spec.retryable && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	requestID, _ := RequestIDFrom(ctx)
	if cause != nil && code == IdentityErrorDependencyUnavailable {
		if log := requestLogger(w, nil); log != nil {
			log.Error("identity dependency failed", "err", cause)
		}
	}
	writeJSON(w, spec.status, identityErrorBody{
		Error: spec.message, Code: code, RequestID: requestID, Retryable: spec.retryable,
	})
}

func writeIdentityFailure(ctx context.Context, w http.ResponseWriter, err error) {
	writeIdentityError(ctx, w, identityCodeFor(err), err)
}

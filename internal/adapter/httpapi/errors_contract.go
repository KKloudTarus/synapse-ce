package httpapi

import (
	"net/http"
)

// ErrorCode is a stable, machine-readable error class carried in every JSON error body next to
// the human-readable "error" text. The set is closed on the server; clients must tolerate codes
// they do not know yet and fall back on the HTTP status.
type ErrorCode string

const (
	// CodeAuthenticationRequired: no credential was presented. The client keeps whatever it has.
	CodeAuthenticationRequired ErrorCode = "authentication_required"
	// CodeAuthenticationInvalid: the credential is definitively invalid, revoked, expired, over its
	// lineage cap, or its user is disabled. This is the only code on which a client clears a
	// stored credential.
	CodeAuthenticationInvalid ErrorCode = "authentication_invalid"
	// CodeAuthenticationUnavailable: a storage or provider dependency failed while authenticating.
	// The credential may be valid; the client keeps it and retries.
	CodeAuthenticationUnavailable ErrorCode = "authentication_unavailable"
	// CodeCSRFInvalid: the cookie session is valid but the CSRF header is missing or wrong.
	CodeCSRFInvalid ErrorCode = "csrf_invalid"
	// CodeAUPRequired: the acceptable-use policy has not been accepted.
	CodeAUPRequired ErrorCode = "aup_required"
	// CodePermissionDenied: the authorization decision denied the action. It never changes the
	// caller's role or session.
	CodePermissionDenied ErrorCode = "permission_denied"
	// CodeAccessDenied: an OIDC callback subject has no approved link, or its user is unavailable.
	CodeAccessDenied     ErrorCode = "access_denied"
	CodeValidationFailed ErrorCode = "validation_failed"
	CodeNotFound         ErrorCode = "not_found"
	CodeConflict         ErrorCode = "conflict"
	CodeSaturated        ErrorCode = "saturated"
	CodeInternal         ErrorCode = "internal"
)

// errorCodeContract is the closed code table: each code's HTTP status and retry semantics.
var errorCodeContract = map[ErrorCode]struct {
	Status    int
	Retryable bool
}{
	CodeAuthenticationRequired:    {http.StatusUnauthorized, false},
	CodeAuthenticationInvalid:     {http.StatusUnauthorized, false},
	CodeAuthenticationUnavailable: {http.StatusServiceUnavailable, true},
	CodeCSRFInvalid:               {http.StatusForbidden, false},
	CodeAUPRequired:               {http.StatusForbidden, false},
	CodePermissionDenied:          {http.StatusForbidden, false},
	CodeAccessDenied:              {http.StatusForbidden, false},
	CodeValidationFailed:          {http.StatusBadRequest, false},
	CodeNotFound:                  {http.StatusNotFound, false},
	CodeConflict:                  {http.StatusConflict, false},
	CodeSaturated:                 {http.StatusServiceUnavailable, true},
	CodeInternal:                  {http.StatusInternalServerError, true},
}

// Retryable reports the code's retry semantics. An unknown code is not retryable.
func (c ErrorCode) Retryable() bool { return errorCodeContract[c].Retryable }

// defaultErrorCode classifies a status that a handler wrote without naming a code. Handlers that
// need a more specific class (authentication, CSRF, AUP, OIDC access) set it explicitly.
func defaultErrorCode(status int) ErrorCode {
	switch {
	case status == http.StatusUnauthorized:
		// Never authentication_invalid by default: that code clears client credentials, so only
		// the authenticator, which knows the credential is bad, may send it.
		return CodeAuthenticationRequired
	case status == http.StatusForbidden:
		return CodePermissionDenied
	case status == http.StatusNotFound || status == http.StatusGone:
		return CodeNotFound
	case status == http.StatusConflict || status == http.StatusPreconditionFailed:
		return CodeConflict
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return CodeSaturated
	case status >= 500:
		return CodeInternal
	default:
		return CodeValidationFailed
	}
}

// errorBody is the JSON error contract. "error" is the unchanged human-readable text; code,
// request_id and retryable are filled by writeJSON when a handler leaves them empty. A handler may
// set Retryable to mark one response retryable when its code is not retryable by default; it can
// never clear a code's default.
type errorBody struct {
	Error     string    `json:"error"`
	Code      ErrorCode `json:"code"`
	RequestID string    `json:"request_id"`
	Retryable bool      `json:"retryable"`
}

// completeErrorBody fills the contract fields of a JSON error response. The request id is the
// X-Request-ID that Instrument set on the response before any handler ran.
func completeErrorBody(w http.ResponseWriter, status int, v any) any {
	if status < 400 {
		return v
	}
	requestID := w.Header().Get("X-Request-ID")
	switch body := v.(type) {
	case errorBody:
		if body.Code == "" {
			body.Code = defaultErrorCode(status)
		}
		body.RequestID = requestID
		body.Retryable = body.Retryable || body.Code.Retryable()
		return body
	case *errorBody:
		if body == nil {
			return v
		}
		return completeErrorBody(w, status, *body)
	case map[string]any:
		if _, ok := body["error"]; !ok {
			return v
		}
		out := make(map[string]any, len(body)+3)
		for key, value := range body {
			out[key] = value
		}
		code, _ := out["code"].(ErrorCode)
		if name, ok := out["code"].(string); ok {
			code = ErrorCode(name)
		}
		if code == "" {
			code = defaultErrorCode(status)
		}
		out["code"], out["request_id"], out["retryable"] = code, requestID, code.Retryable()
		return out
	case map[string]string:
		if _, ok := body["error"]; !ok {
			return v
		}
		out := make(map[string]any, len(body)+3)
		for key, value := range body {
			out[key] = value
		}
		code := ErrorCode(body["code"])
		if code == "" {
			code = defaultErrorCode(status)
		}
		out["code"], out["request_id"], out["retryable"] = code, requestID, code.Retryable()
		return out
	}
	return v
}

// writeRetryableConflict writes a 409 conflict that the client should retry once, such as a lost
// race against a concurrent request for the same resource. Other 409s keep retryable false.
func writeRetryableConflict(w http.ResponseWriter, message string) {
	if w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, http.StatusConflict, errorBody{Error: message, Code: CodeConflict, Retryable: true})
}

// writeCodedError writes one error with an explicit code, using the code's contract status.
func writeCodedError(w http.ResponseWriter, code ErrorCode, message string) {
	status := errorCodeContract[code].Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if code.Retryable() && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, status, errorBody{Error: message, Code: code})
}

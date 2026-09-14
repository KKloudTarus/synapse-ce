package identity

import "errors"

// ErrAuthenticationInvalid means a presented human credential cannot authorize a request.
// It intentionally covers unknown, expired, revoked, disabled, and otherwise unusable
// credentials without exposing which condition matched.
var ErrAuthenticationInvalid = errors.New("authentication invalid")

// ErrAccessDenied means the credential itself remains valid but the requested identity action is
// not allowed (for example a missing/mismatched CSRF proof or a policy denial). Callers must not
// clear a still-valid credential merely because this error is returned.
var ErrAccessDenied = errors.New("identity access denied")

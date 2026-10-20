package documentproviders

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

func safeID(id string) bool { return idPattern.MatchString(id) }
func docError(status int, code string, ambiguous bool) error {
	return &ports.DocumentProviderError{Status: status, Code: code, Ambiguous: ambiguous}
}
func validateToken(token string) error {
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n\x00") {
		return shared.ErrValidation
	}
	return nil
}
func containsCredential(value, token string) bool {
	return token != "" && (strings.Contains(value, token) || redact.String(value, []string{token}) != value)
}
func readResponse(client *http.Client, req *http.Request, maxBytes int64, want ...int) ([]byte, http.Header, error) {
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return nil, nil, docError(0, "blocked_destination", false)
		}
		return nil, nil, docError(0, "network", req.Method != http.MethodGet)
	}
	defer func() { _ = response.Body.Close() }()
	ok := false
	for _, code := range want {
		if response.StatusCode == code {
			ok = true
		}
	}
	if !ok {
		code := "request_rejected"
		switch response.StatusCode {
		case 401, 403:
			code = "permission_denied"
		case 409, 412:
			code = "revision_conflict"
		case 429:
			code = "rate_limited"
		}
		return nil, nil, docError(response.StatusCode, code, response.StatusCode >= 500)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, nil, docError(response.StatusCode, "invalid_response", req.Method != http.MethodGet)
	}
	return data, response.Header, nil
}

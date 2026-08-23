package egressbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// GrantAuthority is the trusted control-plane boundary used by a non-root worker.
// It receives canonical rules only after the live use-case authorization check; the
// worker never receives the private signing key.
// GrantRequest binds an authorization to the exact Bubblewrap process and canonical
// policy the broker will configure. The authority must derive or verify Rules from
// authoritative execution state; it must not trust them merely because a worker sent them.
type GrantRequest = ports.EgressGrantRequest

type GrantAuthority interface {
	Authorize(context.Context, GrantRequest) (string, error)
}

type HTTPGrantAuthority struct {
	endpoint string
	token    string
	timeout  time.Duration
	client   *http.Client
}

type authorizeRequest struct {
	TenantID      string          `json:"tenant_id"`
	ExecutionKind string          `json:"execution_kind"`
	ExecutionID   string          `json:"execution_id"`
	RunID         string          `json:"run_id"`
	Slot          int             `json:"slot"`
	PID           int             `json:"pid"`
	Rules         []CanonicalRule `json:"rules"`
}

type authorizeResponse struct {
	Grant string `json:"grant"`
}

func NewHTTPGrantAuthority(endpoint, token string, timeout time.Duration) (*HTTPGrantAuthority, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("egress grant authority endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1") {
		return nil, errors.New("egress grant authority endpoint must use HTTPS")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("egress grant authority token is required")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPGrantAuthority{
		endpoint: parsed.String(),
		token:    token,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

func (a *HTTPGrantAuthority) Authorize(ctx context.Context, grantReq GrantRequest) (string, error) {
	body, err := json.Marshal(authorizeRequest{
		TenantID:      grantReq.TenantID,
		ExecutionKind: grantReq.ExecutionKind,
		ExecutionID:   grantReq.ExecutionID,
		RunID:         grantReq.RunID,
		Slot:          grantReq.Slot,
		PID:           grantReq.PID,
		Rules:         grantReq.Rules,
	})
	if err != nil {
		return "", fmt.Errorf("encode egress grant request: %w", err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create egress grant request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request egress grant: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
		return "", fmt.Errorf("egress grant authority returned status %d", res.StatusCode)
	}
	var decoded authorizeResponse
	decoder := json.NewDecoder(io.LimitReader(res.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode egress grant response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errors.New("egress grant authority returned trailing response data")
	}
	if strings.TrimSpace(decoded.Grant) == "" {
		return "", errors.New("egress grant authority returned an empty grant")
	}
	return decoded.Grant, nil
}

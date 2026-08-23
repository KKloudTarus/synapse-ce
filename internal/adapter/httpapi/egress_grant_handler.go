package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	EgressGrantPath              = "/internal/v1/egress-grants"
	maxEgressGrantIDLength       = 200
	maxEgressGrantKindLen        = 64
	maxEgressGrantRules          = 256
	egressGrantRequestsPerMinute = 600
)

type EgressGrantAuthorizer interface {
	Authorize(context.Context, ports.EgressGrantRequest) (string, error)
}

type egressGrantRequest struct {
	TenantID      string                      `json:"tenant_id"`
	ExecutionKind string                      `json:"execution_kind"`
	ExecutionID   string                      `json:"execution_id"`
	RunID         string                      `json:"run_id"`
	Slot          int                         `json:"slot"`
	PID           int                         `json:"pid"`
	Rules         []ports.CanonicalEgressRule `json:"rules"`
}

type egressGrantResponse struct {
	Grant string `json:"grant"`
}

type egressGrantLimiter struct {
	mu          sync.Mutex
	perMinute   int
	now         func() time.Time
	windowStart time.Time
	count       int
}

func (l *egressGrantLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.windowStart.IsZero() || now.Sub(l.windowStart) >= time.Minute {
		l.windowStart = now
		l.count = 0
	}
	if l.count >= l.perMinute {
		return false
	}
	l.count++
	return true
}

// NewEgressGrantHandler exposes one machine-authenticated issuance route. It is
// intended for a private listener and does not pass through human API or AUP auth.
func NewEgressGrantHandler(token string, authorizer EgressGrantAuthorizer) (http.Handler, error) {
	return newEgressGrantHandler(token, authorizer, egressGrantRequestsPerMinute, time.Now)
}

func newEgressGrantHandler(token string, authorizer EgressGrantAuthorizer, requestsPerMinute int, now func() time.Time) (http.Handler, error) {
	if strings.TrimSpace(token) == "" || authorizer == nil || requestsPerMinute <= 0 || now == nil {
		return nil, errors.New("egress grant handler requires a token, authorizer, and positive rate limit")
	}
	limiter := &egressGrantLimiter{perMinute: requestsPerMinute, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+EgressGrantPath, func(w http.ResponseWriter, r *http.Request) {
		provided, ok := bearerToken(r)
		if !ok || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			unauthorized(w)
			return
		}
		if !limiter.allow() {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "egress grant request rate exceeded"})
			return
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.EqualFold(strings.TrimSpace(strings.Split(contentType, ";")[0]), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: "egress grant request must be JSON"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		var body egressGrantRequest
		if err := decoder.Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid egress grant request"})
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid egress grant request"})
			return
		}
		body.TenantID = strings.TrimSpace(body.TenantID)
		body.ExecutionKind = strings.TrimSpace(body.ExecutionKind)
		body.ExecutionID = strings.TrimSpace(body.ExecutionID)
		body.RunID = strings.TrimSpace(body.RunID)
		if body.TenantID == "" || len(body.TenantID) > maxEgressGrantIDLength ||
			body.ExecutionKind == "" || len(body.ExecutionKind) > maxEgressGrantKindLen ||
			body.ExecutionID == "" || len(body.ExecutionID) > maxEgressGrantIDLength ||
			body.RunID == "" || len(body.RunID) > maxEgressGrantIDLength ||
			body.Slot < 0 || body.Slot >= 64 || body.PID <= 1 || len(body.Rules) > maxEgressGrantRules {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid egress grant request"})
			return
		}
		tenantID := shared.ID(body.TenantID)
		ctx := shared.WithTenant(r.Context(), tenantID)
		grant, err := authorizer.Authorize(ctx, ports.EgressGrantRequest{
			TenantID: body.TenantID, ExecutionKind: body.ExecutionKind,
			ExecutionID: body.ExecutionID, RunID: body.RunID, Slot: body.Slot,
			PID: body.PID, Rules: body.Rules,
		})
		if err != nil {
			writeJSON(w, http.StatusForbidden, errorBody{Error: "egress grant denied"})
			return
		}
		writeJSON(w, http.StatusOK, egressGrantResponse{Grant: grant})
	})
	return mux, nil
}

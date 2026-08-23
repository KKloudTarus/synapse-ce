// Package fleetclient is the agent-side HTTP client for the fleet transport (#410): it enrols,
// heartbeats, claims work and reports results against the control plane's /api/v1/fleet API. It is
// used by the synapse-agent binary. All requests carry the protocol version header and a bearer
// credential; the agent's certificate/token is supplied by the caller and never logged here.
package fleetclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const protoHeader = "X-Synapse-Fleet-Proto"
const protoVersion = "1"

// maxResponseBytes caps a decoded control-plane response body (memory-exhaustion guard).
const maxResponseBytes = 8 << 20

// Client talks to the control plane fleet API.
type Client struct {
	baseURL string
	http    *http.Client
}

// HTTPError preserves the response metadata the durable delivery loop needs to distinguish retryable
// backpressure/server failures from permanent 4xx failures and a revoked signing key. Body is a bounded,
// trimmed diagnostic snippet and must never contain the bearer credential (headers are not copied).
type HTTPError struct {
	Method     string
	Path       string
	StatusCode int
	RetryAfter string
	Body       string
}

// NetworkError distinguishes a request that never received an HTTP response from a permanent local
// validation/state failure. Durable shippers may retry it with bounded jitter.
type NetworkError struct {
	Method string
	Path   string
	Err    error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("fleetclient: %s %s: %v", e.Method, e.Path, e.Err)
}
func (e *NetworkError) Unwrap() error { return e.Err }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("fleetclient: %s %s: status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// ResponseStatus lets delivery use cases classify the response without depending on this adapter.
func (e *HTTPError) ResponseStatus() (int, string) { return e.StatusCode, e.RetryAfter }

// HTTPStatus returns the status metadata carried by an HTTPError.
func HTTPStatus(err error) (status int, retryAfter string, ok bool) {
	var target *HTTPError
	if !errors.As(err, &target) {
		return 0, "", false
	}
	return target.StatusCode, target.RetryAfter, true
}

// IsNetworkError reports whether the request failed before an HTTP response was available.
func IsNetworkError(err error) bool {
	var target *NetworkError
	return errors.As(err, &target)
}

// New builds a client for baseURL (e.g. https://control-plane). timeout bounds each request.
func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: timeout}}
}

// EnrolRequest is the agent's enrolment payload; CSRPEM is optional (certificate identity).
type EnrolRequest struct {
	Name         string   `json:"name"`
	Platform     string   `json:"platform"`
	OSVersion    string   `json:"os_version"`
	AgentVersion string   `json:"agent_version"`
	Capabilities []string `json:"capabilities"`
	CSRPEM       string   `json:"csr_pem,omitempty"`
}

// EnrolResponse carries the once-only credential material.
type EnrolResponse struct {
	AgentID        string `json:"agent_id"`
	Token          string `json:"token"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

// Order is the subset of a work order the agent needs to act. The tags are PascalCase deliberately:
// the control plane serialises domain/workorder.WorkOrder with NO json tags, so encoding/json emits
// the exact Go field names (ID, Capability, AssetID). Matching that here is what lets these decode;
// snake_case tags would silently zero these fields. Verified against the server's claim handler.
type Order struct {
	ID         string `json:"ID"`
	Capability string `json:"Capability"`
	AssetID    string `json:"AssetID"`
}

// Enrol exchanges an enrolment token for an agent credential.
func (c *Client) Enrol(ctx context.Context, enrolToken string, req EnrolRequest) (EnrolResponse, error) {
	var out EnrolResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/enrol", enrolToken, req, &out)
	return out, err
}

// HeartbeatResponse carries the control plane's version-skew signals (#412): its own version and the
// minimum agent version it will serve. An agent uses these to update itself or to refuse running
// against a control plane older than it requires.
type HeartbeatResponse struct {
	Proto                    string `json:"proto"`
	ControlPlaneVersion      string `json:"control_plane_version"`
	MinSupportedAgentVersion string `json:"min_supported_agent_version"`
}

// Heartbeat reports liveness and current attributes and returns the control plane's version-skew
// signals.
func (c *Client) Heartbeat(ctx context.Context, token string, req EnrolRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/heartbeat", token, req, &out)
	return out, err
}

// ClaimWork claims up to max orders addressed to this agent.
func (c *Client) ClaimWork(ctx context.Context, token string, max int) ([]Order, error) {
	var out []Order
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": max}, &out)
	return out, err
}

// Progress moves an order into the running state.
func (c *Client) Progress(ctx context.Context, token, orderID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/work/"+url.PathEscape(orderID)+"/progress", token, nil, nil)
}

// SubmitResult reports the terminal outcome of an order.
func (c *Client) SubmitResult(ctx context.Context, token, orderID, status, reason string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/work/"+url.PathEscape(orderID)+"/result", token,
		map[string]string{"status": status, "reason": reason}, nil)
}

// SendClusterInventory posts a collected Kubernetes cluster snapshot to the control plane, which maps
// and persists it into the asset model (#446). snap must be a JSON-tagged clusterinventory.Snapshot;
// the caller passes it as the marshalable value so this package keeps no domain dependency.
func (c *Client) SendClusterInventory(ctx context.Context, token string, snap any) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/inventory/cluster", token, snap, nil)
}

// SendHostInventory posts a collected VM host inventory to the control plane, which persists the host
// into the asset model (#446). inv must be a JSON-tagged hostinventory.HostInventory; the caller
// passes it as the marshalable value so this package keeps no domain dependency.
func (c *Client) SendHostInventory(ctx context.Context, token string, inv any) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/inventory/host", token, inv, nil)
}

// RegisterDetectionKey registers an agent-owned detection signing key with proof-of-possession. The
// private key never enters this adapter; only the public lifecycle record and its PoP signature cross
// the wire. Registration is idempotent server-side.
func (c *Client) RegisterDetectionKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error {
	body := map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
		"purpose":    string(key.Purpose), "not_before": key.NotBefore, "not_after": key.NotAfter,
		"proof": proof,
	}
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/keys", token, body, nil)
}

// SendDetectionBatch posts one signed detection batch. A 2xx response means the complete membership was
// durably admitted (or idempotently skipped), which is the point at which the caller may ACK its WAL.
func (c *Client) SendDetectionBatch(ctx context.Context, token string, batch fleetagent.AgentBatch, items []fleetagent.DetectionBatchItem) error {
	body := struct {
		Batch fleetagent.AgentBatch           `json:"batch"`
		Items []fleetagent.DetectionBatchItem `json:"items"`
	}{Batch: batch, Items: items}
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/detections", token, body, nil)
}

func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fleetclient: marshal: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("fleetclient: request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &NetworkError{Method: method, Path: path, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &HTTPError{Method: method, Path: path, StatusCode: resp.StatusCode,
			RetryAfter: resp.Header.Get("Retry-After"), Body: strings.TrimSpace(string(snippet))}
	}
	if out != nil {
		// Cap the decoded body: Timeout bounds time, not size, and the control plane is not fully
		// trusted by the agent. 8 MiB is far above any legitimate claim/enrol response. An empty 2xx
		// body (io.EOF) is tolerated — the caller keeps a zero-valued out rather than erroring.
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("fleetclient: decode: %w", err)
		}
	}
	return nil
}

var _ ports.DetectionTransport = (*Client)(nil)

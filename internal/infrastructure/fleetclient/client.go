// Package fleetclient is the agent-side HTTP client for the fleet transport (#410): it enrols,
// heartbeats, claims work and reports results against the control plane's /api/v1/fleet API. It is
// used by the synapse-agent binary. All requests carry the protocol version header and a bearer
// credential; the agent's certificate/token is supplied by the caller and never logged here.
package fleetclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
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

// Heartbeat reports liveness and current attributes.
func (c *Client) Heartbeat(ctx context.Context, token string, req EnrolRequest) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/heartbeat", token, req, nil)
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
		return fmt.Errorf("fleetclient: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("fleetclient: %s %s: status %d: %s", method, path, resp.StatusCode, string(snippet))
	}
	if out != nil {
		// Cap the decoded body: Timeout bounds time, not size, and the control plane is not fully
		// trusted by the agent. 8 MiB is far above any legitimate claim/enrol response.
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
			return fmt.Errorf("fleetclient: decode: %w", err)
		}
	}
	return nil
}

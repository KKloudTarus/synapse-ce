// Package fleetclient is the agent-side HTTP client for the fleet transport (#410): it enrols,
// heartbeats, claims work and reports results against the control plane's /api/v1/fleet API. It is
// used by the synapse-agent binary. Enrollment uses its one-time bearer credential; subsequent
// production traffic uses the issued client certificate and private key, which are never logged.
package fleetclient

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const protoHeader = "X-Synapse-Fleet-Proto"
const protoVersion = "1"

// maxResponseBytes caps a decoded control-plane response body (memory-exhaustion guard).
const maxResponseBytes = 8 << 20

// Client talks to the control plane fleet API.
type Client struct {
	baseURL           string
	enrollmentURL     string
	http              *http.Client
	clientCertificate bool
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
	return NewWithEnrollmentURL(baseURL, baseURL, timeout)
}

// NewWithEnrollmentURL separates the TLS-only one-time enrollment endpoint from the strict mTLS
// endpoint used after enrollment. Both URLs must identify the same control plane trust domain.
func NewWithEnrollmentURL(baseURL, enrollmentURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{baseURL: baseURL, enrollmentURL: enrollmentURL, http: &http.Client{Timeout: timeout}}
}

// ActivateCredential installs the enrolled agent's client certificate on the HTTP transport. A
// certificate-less bearer transport is retained only for an explicitly configured loopback control
// plane used by local development and tests.
func (c *Client) ActivateCredential(cred Credential, keyPEM []byte) error {
	if strings.TrimSpace(cred.CertificatePEM) == "" {
		u, err := url.Parse(c.baseURL)
		if err == nil && isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("fleetclient: enrolled control-plane credential has no client certificate")
	}
	pair, err := tls.X509KeyPair([]byte(cred.CertificatePEM), keyPEM)
	if err != nil {
		return fmt.Errorf("fleetclient: load enrolled client certificate: %w", err)
	}

	var transport *http.Transport
	current := c.http.Transport
	if current == nil {
		current = http.DefaultTransport
	}
	switch current := current.(type) {
	case *http.Transport:
		transport = current.Clone()
	default:
		return fmt.Errorf("fleetclient: client certificate requires an HTTP transport, got %T", current)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{pair}
	c.http.Transport = transport
	c.clientCertificate = true
	return nil
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
type PrivacyPolicy struct {
	Dispositions  map[string]string `json:"dispositions"`
	RedactSecrets bool              `json:"redact_secrets"`
	MaxArgLen     int               `json:"max_arg_len"`
	MaxArgCount   int               `json:"max_arg_count"`
	MaxPathLen    int               `json:"max_path_len"`
	HashSalt      string            `json:"hash_salt,omitempty"`
	Version       string            `json:"version"`
}

type PrivacyPolicyAssignment struct {
	TenantID  string        `json:"tenant_id"`
	Policy    PrivacyPolicy `json:"policy"`
	Digest    string        `json:"digest"`
	CreatedBy string        `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
}

type PrivacyPolicyResponse struct {
	Assignment PrivacyPolicyAssignment `json:"assignment"`
}

type Order struct {
	ID              string                                 `json:"ID"`
	Capability      string                                 `json:"Capability"`
	AssetID         string                                 `json:"AssetID"`
	IdempotencyKey  string                                 `json:"IdempotencyKey"`
	LeaseID         string                                 `json:"LeaseID"`
	LeaseUntil      time.Time                              `json:"LeaseUntil"`
	ResponseCommand *fleetagent.ResponseCommand            `json:"ResponseCommand,omitempty"`
	ResponseHalt    *fleetagent.ResponseHaltCommand        `json:"ResponseHalt,omitempty"`
	ResponseObserve *fleetagent.ResponseObservationRequest `json:"ResponseObserve,omitempty"`
}

// Enrol exchanges an enrolment token for an agent credential.
func (c *Client) Enrol(ctx context.Context, enrolToken string, req EnrolRequest) (EnrolResponse, error) {
	var out EnrolResponse
	err := c.doAtBase(ctx, c.enrollmentURL, http.MethodPost, "/api/v1/fleet/enrol", enrolToken, req, &out)
	return out, err
}

// HeartbeatResponse carries the control plane's version-skew signals (#412): its own version and the
// minimum agent version it will serve. An agent uses these to update itself or to refuse running
// against a control plane older than it requires.
type HeartbeatResponse struct {
	Proto                    string `json:"proto"`
	ControlPlaneVersion      string `json:"control_plane_version"`
	MinSupportedAgentVersion string `json:"min_supported_agent_version"`
	ResponseHalted           bool   `json:"response_halted"`
	ResponseHaltGeneration   int64  `json:"response_halt_generation"`
	ResponseObserverAssetID  string `json:"response_observer_asset_id"`
}

// Heartbeat reports liveness and current attributes and returns the control plane's version-skew
// signals.
func (c *Client) Heartbeat(ctx context.Context, token string, req EnrolRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/heartbeat", token, req, &out)
	return out, err
}

// ActivePrivacyPolicy fetches the tenant's active source-redaction policy for an authenticated agent.
func (c *Client) ActivePrivacyPolicy(ctx context.Context, token string) (PrivacyPolicyResponse, error) {
	var out PrivacyPolicyResponse
	err := c.do(ctx, http.MethodGet, "/api/v1/fleet/privacy-policy", token, nil, &out)
	return out, err
}

// ClaimWork claims up to max orders addressed to this agent.
func (c *Client) ClaimWork(ctx context.Context, token string, max int) ([]Order, error) {
	var out []Order
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": max}, &out)
	return out, err
}

// Progress moves an order into the running state.
func (c *Client) Progress(ctx context.Context, token, orderID, leaseID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/work/"+url.PathEscape(orderID)+"/progress", token, map[string]string{"lease_id": leaseID}, nil)
}

// SubmitResult reports the terminal outcome of an order.
func (c *Client) SubmitResult(ctx context.Context, token, orderID, leaseID, status, reason string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/work/"+url.PathEscape(orderID)+"/result", token,
		map[string]string{"status": status, "reason": reason, "lease_id": leaseID}, nil)
}

type ResponseResultRequest struct {
	Status         string                            `json:"status"`
	Reason         string                            `json:"reason"`
	AttemptKey     string                            `json:"attempt_key"`
	CommandDigest  string                            `json:"command_digest"`
	ExecutionState fleetagent.ResponseExecutionState `json:"execution_state"`
	ObservedRadius offensivepolicy.Radius            `json:"observed_radius"`
	AffectedCount  int                               `json:"affected_count"`
	AlreadyApplied bool                              `json:"already_applied"`
	CompletedAt    time.Time                         `json:"completed_at"`
	LeaseID        string                            `json:"lease_id"`
}

func (c *Client) SubmitResponseResult(ctx context.Context, token, orderID string, request ResponseResultRequest) error {
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/work/"+url.PathEscape(orderID)+"/result", token, request, nil)
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

// ReportedProcess is one running process the agent observed, in the wire shape the process-report
// endpoint accepts. The agent maps its OS enumeration to this; the client keeps no OS dependency.
type ReportedProcess struct {
	PID     int    `json:"pid"`
	Comm    string `json:"comm"`
	Path    string `json:"path"`
	Running bool   `json:"running"`
}

// ReportProcesses posts the host's running-process snapshot for the behavior baseline (#594 D). The
// control plane resolves the host asset from the authenticated agent, so no asset id crosses the wire.
func (c *Client) ReportProcesses(ctx context.Context, token string, procs []ReportedProcess, complete bool) error {
	body := struct {
		Processes []ReportedProcess `json:"processes"`
		Complete  bool              `json:"complete"`
	}{Processes: procs, Complete: complete}
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/processes", token, body, nil)
}

// RegisterSigningKey registers an agent-owned purpose-scoped signing key with proof-of-possession. The
// private key never enters this adapter; only the public lifecycle record and its PoP signature cross
// the wire. Registration is idempotent server-side.
func (c *Client) RegisterSigningKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error {
	body := map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
		"purpose":    string(key.Purpose), "not_before": key.NotBefore, "not_after": key.NotAfter,
		"proof": proof,
	}
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/keys", token, body, nil)
}

func (c *Client) RegisterDetectionKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error {
	return c.RegisterSigningKey(ctx, token, key, proof)
}

// SendDetectionBatch posts one signed detection batch. A 2xx response means the complete membership was
// durably admitted (or idempotently skipped), which is the point at which the caller may ACK its WAL.
func (c *Client) SendDetectionBatch(ctx context.Context, token string, batch fleetagent.AgentBatch, items []fleetagent.DetectionBatchItem) error {
	body := struct {
		Batch fleetagent.AgentBatch           `json:"batch"`
		Items []fleetagent.DetectionBatchItem `json:"items"`
	}{Batch: batch, Items: items}
	return translateDetectionBatchError(c.do(ctx, http.MethodPost, "/api/v1/fleet/detections", token, body, nil))
}

// SendDetectionBatchV2 posts the separately signed v2 attribution contract. The endpoint remains
// shared with v1 so enrolled agents retain one narrowly scoped delivery capability.
func (c *Client) SendDetectionBatchV2(ctx context.Context, token string, batch fleetagent.AgentBatchV2, items []fleetagent.DetectionBatchItemV2) error {
	body := struct {
		Batch fleetagent.AgentBatchV2           `json:"batch_v2"`
		Items []fleetagent.DetectionBatchItemV2 `json:"items_v2"`
	}{Batch: batch, Items: items}
	return translateDetectionBatchError(c.do(ctx, http.MethodPost, "/api/v1/fleet/detections", token, body, nil))
}

func translateDetectionBatchError(err error) error {
	status, _, ok := HTTPStatus(err)
	if ok && status == http.StatusForbidden {
		return fmt.Errorf("%w: %v", ports.ErrDetectionSigningKeyRejected, err)
	}
	return err
}

func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	return c.doAtBase(ctx, c.baseURL, method, path, token, body, out)
}

func (c *Client) doAtBase(ctx context.Context, baseURL, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fleetclient: marshal: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("fleetclient: request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", "application/json")
	c.setAuthorization(req, token, path == "/api/v1/fleet/enrol")
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

func (c *Client) setAuthorization(req *http.Request, token string, enrollment bool) {
	if token != "" && (enrollment || !c.clientCertificate) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

var _ ports.DetectionTransport = (*Client)(nil)
var _ ports.DetectionTransportV2 = (*Client)(nil)

package egressbroker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const defaultSocketPath = "/run/synapse-egress-broker/egress-broker.sock"

var (
	_ ports.EgressEnforcer  = (*Client)(nil)
	_ ports.EgressNamespace = (*Namespace)(nil)
)

type Client struct {
	socketPath string
	timeout    time.Duration
	authority  GrantAuthority
}

type Namespace struct {
	client  *Client
	runID   string
	rules   []ports.EgressRule
	cleaned bool
}

func NewClient(socketPath string, timeout time.Duration, authority ...GrantAuthority) (*Client, error) {
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("egress broker socket path must be absolute")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var grantAuthority GrantAuthority
	if len(authority) > 1 {
		return nil, errors.New("egress broker accepts at most one grant authority")
	}
	if len(authority) == 1 {
		grantAuthority = authority[0]
	}
	return &Client{socketPath: socketPath, timeout: timeout, authority: grantAuthority}, nil
}

func (c *Client) Probe(ctx context.Context) error {
	_, err := c.call(ctx, request{Version: protocolVersion, Action: "probe", RunID: "syn63"})
	return err
}

// WaitReady waits for the broker socket to accept protocol requests. systemd starts the
// root-owned broker before the worker, but Type=simple does not imply that the socket has
// already been bound when the dependent worker process starts.
func (c *Client) WaitReady(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	var lastErr error
	for {
		if err := c.Probe(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for egress broker readiness after last probe (%v): %w", lastErr, ctx.Err())
		case <-timer.C:
		}
	}
}

func (c *Client) Setup(ctx context.Context, runID string, slot, pid int, executionKind, executionID string, policy ports.EgressPolicy) (ports.EgressNamespace, error) {
	rules, err := canonicalPolicy(policy)
	if err != nil {
		return nil, err
	}
	if c.authority == nil {
		return nil, errors.New("egress grant authority is required")
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, errors.New("egress grant tenant context is required")
	}
	grant, err := c.authority.Authorize(ctx, GrantRequest{
		TenantID:      tenantID.String(),
		ExecutionKind: executionKind,
		ExecutionID:   executionID,
		RunID:         runID,
		Slot:          slot,
		PID:           pid,
		Rules:         rules,
	})
	if err != nil {
		return nil, fmt.Errorf("authorize egress policy: %w", err)
	}
	res, err := c.call(ctx, request{
		Version:       protocolVersion,
		Action:        "setup",
		RunID:         runID,
		Slot:          slot,
		PID:           pid,
		TenantID:      tenantID.String(),
		ExecutionKind: executionKind,
		ExecutionID:   executionID,
		Grant:         grant,
		Rules:         rules,
	})
	if err != nil {
		return nil, fmt.Errorf("setup egress namespace: %w", err)
	}
	allowed := make([]CanonicalRule, 0, len(res.Rules))
	for _, rule := range res.Rules {
		if rule.Allow {
			allowed = append(allowed, rule)
		}
	}
	parsed, err := parseRules(allowed)
	if err != nil {
		return nil, fmt.Errorf("parse broker allow rules: %w", err)
	}
	return &Namespace{client: c, runID: runID, rules: parsed}, nil
}

func (c *Client) call(ctx context.Context, req request) (response, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(callCtx, "unix", c.socketPath)
	if err != nil {
		return response{}, fmt.Errorf("%w: dial %s: %w", ErrUnavailable, c.socketPath, err)
	}
	defer conn.Close()
	if deadline, ok := callCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return response{}, fmt.Errorf("set broker deadline: %w", err)
		}
	}
	if err := encodeRequest(conn, req); err != nil {
		return response{}, fmt.Errorf("send broker request: %w", err)
	}
	res, err := decodeResponse(conn)
	if err != nil {
		return response{}, err
	}
	return res, nil
}

func (n *Namespace) NamespaceName() string { return n.runID }

func (n *Namespace) HostsPath() string { return "" }

func (n *Namespace) Rules() []ports.EgressRule {
	return append([]ports.EgressRule(nil), n.rules...)
}

func (n *Namespace) Teardown(ctx context.Context) error {
	if n.cleaned {
		return nil
	}
	_, err := n.client.call(ctx, request{Version: protocolVersion, Action: "cleanup", RunID: n.runID})
	if err == nil {
		n.cleaned = true
	}
	return err
}

func CheckSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat broker socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("egress broker path is not a Unix socket")
	}
	return nil
}

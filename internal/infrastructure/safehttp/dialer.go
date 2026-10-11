package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrBlockedDestination wraps every refusal by a Policy. Callers check it with errors.Is to tell a
// refused destination, which retrying cannot fix, from a network failure.
var ErrBlockedDestination = errors.New("safehttp: destination is not allowed")

const defaultDialTimeout = 30 * time.Second

type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer is the single vetting path for outbound TCP connections: HTTP clients built by this
// package use it, and non-HTTP transports (SMTP, syslog) call DialContext directly.
//
// It resolves the host once per connection, checks every candidate address against the policy,
// and dials the address it checked, never the name. A DNS answer that changes between the check
// and the connection therefore cannot redirect it (DNS rebinding).
type Dialer struct {
	policy Policy
	lookup lookupFunc
	dial   dialFunc
}

// NewDialer returns a Dialer for policy. A timeout of zero or less uses 30 seconds.
func NewDialer(policy Policy, timeout time.Duration) *Dialer {
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	return newDialer(policy, net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func newDialer(policy Policy, lookup lookupFunc, dial dialFunc) *Dialer {
	return &Dialer{policy: policy, lookup: lookup, dial: dial}
}

// DialContext connects to address ("host:port") over TCP if the policy admits the host and at least
// one of its addresses. A refusal wraps ErrBlockedDestination.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%w: network %q", ErrBlockedDestination, network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if !d.policy.permitsHost(host, port) {
		return nil, fmt.Errorf("%w: host is not on the allowlist", ErrBlockedDestination)
	}
	candidates, err := d.lookup(ctx, lookupNetwork(network), host)
	if err != nil {
		return nil, err
	}
	return d.dialFirstPermitted(ctx, network, port, candidates)
}

func (d *Dialer) dialFirstPermitted(ctx context.Context, network, port string, candidates []netip.Addr) (net.Conn, error) {
	var lastErr error
	for _, candidate := range candidates {
		candidate = candidate.Unmap()
		if !d.policy.permits(candidate) {
			lastErr = fmt.Errorf("%w: endpoint resolves to a disallowed address", ErrBlockedDestination)
			continue
		}
		connection, err := d.dial(ctx, network, net.JoinHostPort(candidate.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("endpoint has no usable address")
}

func lookupNetwork(network string) string {
	switch network {
	case "tcp4":
		return "ip4"
	case "tcp6":
		return "ip6"
	}
	return "ip"
}

package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)
type dialFunc func(context.Context, string, string) (net.Conn, error)

func New(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := net.Dialer{Timeout: 30 * time.Second}
	return newClient(timeout, allowPrivate, net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func newClient(timeout time.Duration, allowPrivate bool, lookup lookupFunc, dial dialFunc) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				addresses, err := lookup(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
				var lastErr error
				for _, address := range addresses {
					address = address.Unmap()
					if blocked(address, allowPrivate) {
						lastErr = fmt.Errorf("source endpoint resolves to a disallowed address")
						continue
					}
					connection, err := dial(ctx, network, net.JoinHostPort(address.String(), port))
					if err == nil {
						return connection, nil
					}
					lastErr = err
				}
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, fmt.Errorf("source endpoint has no usable address")
			},
			ForceAttemptHTTP2: true,
		},
	}
}

func blocked(address netip.Addr, allowPrivate bool) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || carrierGradeNAT.Contains(address) {
		return true
	}
	return !allowPrivate && address.IsPrivate()
}

package oidc

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const maxOIDCResponseBytes int64 = 1 << 20

// newSafeClient is intentionally private: callers cannot weaken the production
// OIDC destination policy. It ignores ambient proxy settings and never follows
// provider redirects, which would otherwise bypass the originally approved URL.
func newSafeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDialContext(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxConnsPerHost:       4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	return &http.Client{Transport: cappedTransport{next: transport}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type cappedTransport struct{ next http.RoundTripper }

func (t cappedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	if response.Header.Get("Content-Encoding") != "" {
		_ = response.Body.Close()
		return nil, fmt.Errorf("OIDC compressed responses are not accepted")
	}
	if response.ContentLength > maxOIDCResponseBytes {
		_ = response.Body.Close()
		return nil, fmt.Errorf("OIDC response exceeds %d-byte limit", maxOIDCResponseBytes)
	}
	response.Body = &limitedReadCloser{ReadCloser: response.Body, remaining: maxOIDCResponseBytes}
	return response, nil
}

type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
}

func (r *limitedReadCloser) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		var probe [1]byte
		if n, err := r.ReadCloser.Read(probe[:]); n == 0 {
			return 0, err
		}
		return 0, fmt.Errorf("OIDC response exceeds %d-byte limit", maxOIDCResponseBytes)
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func safeDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("OIDC dial address: %w", err)
		}
		ips, err := resolvePublic(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			// Revalidate every selected address immediately before dial so a
			// rebinding answer cannot become a private connection.
			if err := publicAddress(ip); err != nil {
				return nil, err
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("OIDC dial public addresses: %w", lastErr)
	}
}

func resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolvePublicWith(ctx, host, net.DefaultResolver)
}

type publicResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func resolvePublicWith(ctx context.Context, host string, resolver publicResolver) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := publicAddress(ip); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	resolved, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve OIDC host: %w", err)
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("OIDC host has no public addresses")
	}
	for _, ip := range resolved {
		if err := publicAddress(ip); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func publicAddress(ip netip.Addr) error {
	ip = ip.Unmap()
	if !(safehttp.Policy{}).AllowsAddress(ip) {
		return fmt.Errorf("OIDC destination address %s is not public", ip)
	}
	return nil
}

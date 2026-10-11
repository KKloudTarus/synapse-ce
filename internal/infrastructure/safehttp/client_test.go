package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestClientRejectsRedirects(t *testing.T) {
	client := New(time.Second, false)
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v, want ErrUseLastResponse", err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.IdleConnTimeout <= 0 || transport.MaxIdleConns <= 0 || transport.MaxIdleConnsPerHost <= 0 || transport.MaxConnsPerHost <= 0 {
		t.Fatalf("transport connection bounds are missing: %+v", transport)
	}
}

func TestClientRejectsInvalidTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(2*time.Second, newDialer(Policy{},
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
	))
	if _, err := client.Get("https://jenkins.example.com:" + strconv.Itoa(mustAtoi(t, port))); err == nil {
		t.Fatal("invalid TLS certificate was accepted")
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	number, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

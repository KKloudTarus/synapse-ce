package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBlockedAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		if !blocked(netip.MustParseAddr(value), true) {
			t.Fatalf("always-blocked address accepted: %s", value)
		}
	}
	for _, value := range []string{"10.0.0.1", "::ffff:10.0.0.1"} {
		if !blocked(netip.MustParseAddr(value), false) {
			t.Fatalf("private address accepted without internal-mirror approval: %s", value)
		}
		if blocked(netip.MustParseAddr(value), true) {
			t.Fatalf("approved internal mirror private address rejected: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
		if blocked(netip.MustParseAddr(value), false) {
			t.Fatalf("public address rejected: %s", value)
		}
	}
}

func TestClientRejectsRedirects(t *testing.T) {
	client := New(time.Second, false)
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v, want ErrUseLastResponse", err)
	}
}

func TestDialRevalidatesDNSAndBlocksRebinding(t *testing.T) {
	lookups := 0
	dials := 0
	client := newClient(time.Second, false, func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		dials++
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	dial := client.Transport.(*http.Transport).DialContext
	connection, err := dial(context.Background(), "tcp", "jenkins.example.com:443")
	if err != nil {
		t.Fatalf("first public dial: %v", err)
	}
	_ = connection.Close()
	if _, err := dial(context.Background(), "tcp", "jenkins.example.com:443"); err == nil || !strings.Contains(err.Error(), "disallowed address") {
		t.Fatalf("rebound dial error = %v", err)
	}
	if lookups != 2 || dials != 1 {
		t.Fatalf("lookups=%d dials=%d, want 2/1", lookups, dials)
	}
}

func TestPrivateNetworkRequiresExplicitOptIn(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	dialed := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}
	blockedClient := newClient(time.Second, false, lookup, dial)
	if _, err := blockedClient.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "jenkins.internal:443"); err == nil {
		t.Fatal("private address accepted without opt-in")
	}
	allowedClient := newClient(time.Second, true, lookup, dial)
	connection, err := allowedClient.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "jenkins.internal:443")
	if err != nil {
		t.Fatalf("private address rejected with opt-in: %v", err)
	}
	_ = connection.Close()
	if !dialed {
		t.Fatal("approved private address was not dialed")
	}
}

func TestClientRejectsInvalidTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(2*time.Second, false,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
	)
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

// Package outboundguard checks that an outbound HTTP client is built through safehttp: it follows no
// redirect, uses no proxy, never reaches a cloud metadata endpoint, and admits loopback and private-use
// addresses only when its endpoint is one an operator configured (#1698). It is test-only support code.
package outboundguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// Reach names the destinations, beyond globally reachable ones, a client is expected to admit.
type Reach int

const (
	// PublicOnly is the zero safehttp.Policy: the reach of a client left on its default public endpoint.
	PublicOnly Reach = iota
	// PrivateNetwork admits private-use addresses but not loopback (safehttp.New(timeout, true)).
	PrivateNetwork
	// Operator is safehttp.OperatorPolicy: private-use and loopback addresses, for an endpoint an
	// operator configured.
	Operator
)

// probeTimeout bounds a request to an address that is not listening, so a check never waits on a
// real connection attempt.
const probeTimeout = 500 * time.Millisecond

// metadataEndpoints are cloud instance-metadata addresses. They sit in link-local, shared (CGNAT) and
// unique-local space, so a guard that only knows loopback and link-local misses two of them.
var metadataEndpoints = []string{
	"http://169.254.169.254:1/latest/meta-data/",
	"http://100.100.100.200:1/latest/meta-data/",
	"http://[fd00:ec2::254]:1/latest/meta-data/",
}

// privateEndpoint is a private-use address nothing in a test environment listens on.
const privateEndpoint = "http://10.255.255.1:1/"

// Require fails t unless client behaves as a safehttp client with reach.
func Require(t testing.TB, client *http.Client, reach Reach) {
	t.Helper()
	if client == nil {
		t.Fatal("client is nil")
	}
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/followed", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	if reach == Operator {
		// A loopback endpoint is reachable, and the redirect it answers is handed back, not followed.
		resp, err := get(client, redirector.URL)
		if err != nil {
			t.Fatalf("loopback endpoint refused: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || reached.Load() != 0 {
			t.Fatalf("redirect followed: status %d, redirect target reached %d time(s)", resp.StatusCode, reached.Load())
		}
	} else if _, err := get(client, target.URL); !errors.Is(err, safehttp.ErrBlockedDestination) {
		t.Fatalf("loopback endpoint: error = %v, want %v", err, safehttp.ErrBlockedDestination)
	}
	if reached.Load() != 0 {
		t.Fatalf("loopback server reached %d time(s)", reached.Load())
	}

	_, err := get(client, privateEndpoint)
	switch blocked := errors.Is(err, safehttp.ErrBlockedDestination); {
	case reach == PublicOnly && !blocked:
		t.Fatalf("private-use endpoint: error = %v, want %v", err, safehttp.ErrBlockedDestination)
	case reach != PublicOnly && blocked:
		t.Fatalf("private-use endpoint refused: %v", err)
	}

	for _, endpoint := range metadataEndpoints {
		if _, err := get(client, endpoint); !errors.Is(err, safehttp.ErrBlockedDestination) {
			t.Fatalf("metadata endpoint %s: error = %v, want %v", endpoint, err, safehttp.ErrBlockedDestination)
		}
	}

	// A proxy would make the connection somewhere the policy never checked.
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Fatalf("client transport %T must be an *http.Transport with no proxy", client.Transport)
	}
}

func get(client *http.Client, url string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

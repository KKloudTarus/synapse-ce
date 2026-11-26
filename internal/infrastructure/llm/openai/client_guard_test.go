package openai

import (
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestClientIsGuarded pins #1698: the model endpoint is operator configuration and defaults to a
// local gateway, so loopback and internal networks stay reachable, but the client goes through
// safehttp and so never follows a redirect or reaches a metadata endpoint.
func TestClientIsGuarded(t *testing.T) {
	c, err := New("http://localhost:20128/v1", "", "m", 0)
	if err != nil {
		t.Fatal(err)
	}
	outboundguard.Require(t, c.http, outboundguard.Operator)
}

// TestClientDoesNotCapConnectionsPerHost keeps triage concurrency: SYNAPSE_FP_TRIAGE_CONCURRENCY
// allows up to 32 calls against one gateway, and a per-host connection cap below that would queue
// calls inside their own timeout.
func TestClientDoesNotCapConnectionsPerHost(t *testing.T) {
	c, err := New("http://localhost:20128/v1", "", "m", 0)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", c.http.Transport)
	}
	if transport.MaxConnsPerHost != 0 {
		t.Fatalf("MaxConnsPerHost = %d, want 0 (no cap)", transport.MaxConnsPerHost)
	}
}

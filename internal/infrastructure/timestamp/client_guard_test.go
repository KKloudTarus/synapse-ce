package timestamp

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestClientIsGuarded pins #1698: the timestamp authority is operator configuration
// (SYNAPSE_TSA_URL), so it may be on the host or an internal network, but its client goes through
// safehttp and so never follows a redirect or reaches a metadata endpoint.
func TestClientIsGuarded(t *testing.T) {
	c, err := NewClient("https://tsa.example.internal/tsr", 0)
	if err != nil {
		t.Fatal(err)
	}
	outboundguard.Require(t, c.httpClient, outboundguard.Operator)
}

package risk

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestDefaultClientIsGuarded pins #1698: the client used when the caller passes nil, which every
// composition root does, goes through safehttp. The default CISA and FIRST endpoints are public;
// a mirror the operator configured may be on the host or an internal network.
func TestDefaultClientIsGuarded(t *testing.T) {
	outboundguard.Require(t, New("", "", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, New("https://kev.mirror.internal/kev.json", "", nil).client, outboundguard.Operator)
	outboundguard.Require(t, New("", "https://epss.mirror.internal/epss", nil).client, outboundguard.Operator)
}

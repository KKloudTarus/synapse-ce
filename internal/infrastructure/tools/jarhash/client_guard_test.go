package jarhash

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestDefaultClientIsGuarded pins #1698: the client used when the caller passes nil, which every
// composition root does, goes through safehttp. Maven Central admits only public addresses; a
// service set with SYNAPSE_JARHASH_BASE_URL may be on the host or an internal network.
func TestDefaultClientIsGuarded(t *testing.T) {
	outboundguard.Require(t, New("", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, New("https://jarhash.mirror.internal/solrsearch/select", nil).client, outboundguard.Operator)
}

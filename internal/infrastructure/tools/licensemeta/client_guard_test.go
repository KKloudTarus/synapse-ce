package licensemeta

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestDefaultClientsAreGuarded pins #1698: the clients used when the caller passes nil, which every
// composition root does, go through safehttp. deps.dev and PyPI admit only public addresses; a
// mirror the operator configured may be on the host or an internal network.
func TestDefaultClientsAreGuarded(t *testing.T) {
	outboundguard.Require(t, New("", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, New("https://depsdev.mirror.internal", nil).client, outboundguard.Operator)
	outboundguard.Require(t, NewPyPI("", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, NewPyPI("https://pypi.mirror.internal", nil).client, outboundguard.Operator)
}

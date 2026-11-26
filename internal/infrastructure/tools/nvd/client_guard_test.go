package nvd

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestDefaultClientIsGuarded pins #1698: the client used when the caller passes nil, which every
// composition root does, goes through safehttp. The public NVD API admits only public addresses;
// a mirror set with SYNAPSE_NVD_API_URL may be on the host or an internal network.
func TestDefaultClientIsGuarded(t *testing.T) {
	outboundguard.Require(t, New("", "", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, New("https://nvd.mirror.internal/rest/json/cves/2.0", "", nil).client, outboundguard.Operator)
}

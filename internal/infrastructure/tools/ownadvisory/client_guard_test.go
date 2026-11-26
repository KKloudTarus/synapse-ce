package ownadvisory

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysource"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestDefaultFeedClientsAreGuarded pins #1698: the clients the feeds build when the caller passes
// nil go through safehttp, which also refuses the metadata endpoints in shared (CGNAT) and
// unique-local space that the hand-rolled transport admitted. The default public sources admit only
// public addresses; a mirror the operator configured may be on the host or an internal network.
func TestDefaultFeedClientsAreGuarded(t *testing.T) {
	outboundguard.Require(t, NewRemoteFeed("", nil, nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, NewRemoteFeed("https://osv.mirror.internal", nil, nil).client, outboundguard.Operator)
	outboundguard.Require(t, NewRemoteSecdbFeed("", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, NewRemoteSecdbFeed("https://secdb.mirror.internal", nil).client, outboundguard.Operator)
	// No operator setting names another gemnasium archive: a different URL only comes from a
	// vulnerability source row, so the default client stays public whatever the URL.
	outboundguard.Require(t, NewGitLabFeed("", nil).client, outboundguard.PublicOnly)
	outboundguard.Require(t, NewGitLabFeed("https://gemnasium.example/archive.tar.gz", nil).client, outboundguard.PublicOnly)
}

// TestSourceProvidersHonourAllowPrivateNetwork pins that a vulnerability source reaches a
// private-use address only when its allow_private_network option is set, which the registry admits
// only when the deployment enables private-network sources. The GitLab provider used to ignore the
// option and admit private addresses for every source.
func TestSourceProvidersHonourAllowPrivateNetwork(t *testing.T) {
	providers := map[vulnerabilitysource.AdapterType]func(vulnerabilitysource.Source) (*FeedProvider, error){
		vulnerabilitysource.AdapterOSV:    NewRemoteProvider,
		vulnerabilitysource.AdapterGitLab: NewGitLabProvider,
	}
	for adapter, build := range providers {
		for allow, want := range map[bool]outboundguard.Reach{false: outboundguard.PublicOnly, true: outboundguard.PrivateNetwork} {
			source := vulnerabilitysource.Source{
				ID:            shared.ID("source-1"),
				AdapterType:   adapter,
				Endpoint:      "https://feed.example/archive",
				AdapterConfig: json.RawMessage(fmt.Sprintf(`{"allow_private_network":%t}`, allow)),
			}
			provider, err := build(source)
			if err != nil {
				t.Fatalf("%s provider: %v", adapter, err)
			}
			t.Run(fmt.Sprintf("%s/allow_private_network=%t", adapter, allow), func(t *testing.T) {
				outboundguard.Require(t, feedClient(t, provider.feed), want)
			})
		}
	}
}

func feedClient(t *testing.T, feed ports.AdvisoryFeed) *http.Client {
	t.Helper()
	switch f := feed.(type) {
	case *RemoteFeed:
		return f.client
	case *GitLabFeed:
		return f.client
	}
	t.Fatalf("unexpected feed %T", feed)
	return nil
}

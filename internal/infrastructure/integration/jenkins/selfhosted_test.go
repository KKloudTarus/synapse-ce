package jenkins

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
)

func jenkinsIntegration(endpoint string, requestPrivate bool) integration.Integration {
	now := time.Now().UTC()
	return integration.Integration{
		ID: "integration-1", TenantID: "tenant-1", Provider: Provider, Name: "Jenkins", Endpoint: endpoint,
		Config: []byte(`{}`), AllowPrivateNetwork: requestPrivate, PollInterval: time.Minute, Version: 1,
		CreatedAt: now, UpdatedAt: now,
	}
}

var jenkinsCredentials = integration.CredentialBundle{"username": "reader", "api_token": "token"}

// The endpoints below are IP literals, so the dialer decides without DNS and nothing reaches the
// network: a refused address fails before any connection is attempted.
func TestTestConnectionAppliesOperatorRulesAtDialTime(t *testing.T) {
	narrowed := selfhosted.Rules{AllowPrivateNetwork: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	cases := []struct {
		name     string
		endpoint string
		request  bool
		rules    selfhosted.Rules
	}{
		// Saved while the operator allowed private networks, then the operator turned the switch off.
		{"operator switch turned off", "https://10.0.0.5", true, selfhosted.Rules{}},
		{"outside private CIDRs", "https://10.30.0.5", true, narrowed},
		{"tenant did not request private", "https://10.20.0.5", false, narrowed},
		{"metadata under every rule", "https://169.254.169.254", true, selfhosted.Rules{AllowPrivateNetwork: true}},
	}
	for _, tc := range cases {
		adapter, err := New(jenkinsIntegration(tc.endpoint, tc.request), jenkinsCredentials, tc.rules)
		if err != nil {
			t.Fatalf("%s: New: %v", tc.name, err)
		}
		err = adapter.(*Adapter).TestConnection(context.Background())
		adapter.(*Adapter).Close()
		var providerError *integration.ProviderError
		if !errors.As(err, &providerError) || integration.IsRetryable(err) || !strings.Contains(err.Error(), "operator's network rules") {
			t.Errorf("%s: err = %v, want a permanent refusal", tc.name, err)
		}
	}
}

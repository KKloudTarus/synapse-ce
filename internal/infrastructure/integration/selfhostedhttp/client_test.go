package selfhostedhttp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

func TestPolicyNeedsTenantRequestAndOperatorSwitchForPrivate(t *testing.T) {
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	for _, tc := range []struct {
		name      string
		rules     selfhosted.Rules
		requested bool
		want      bool
	}{
		{"operator off", selfhosted.Rules{}, true, false},
		{"tenant did not request", selfhosted.Rules{AllowPrivateNetwork: true}, false, false},
		{"both", selfhosted.Rules{AllowPrivateNetwork: true, PrivateCIDRs: cidrs}, true, true},
	} {
		policy := Policy(tc.rules, tc.requested)
		if policy.AllowPrivate != tc.want || policy.AllowLoopback {
			t.Errorf("%s: policy = %+v", tc.name, policy)
		}
		if len(policy.PrivateCIDRs) != len(tc.rules.PrivateCIDRs) {
			t.Errorf("%s: private CIDRs not carried over", tc.name)
		}
	}
}

func TestPolicyCarriesTheHostAllowlist(t *testing.T) {
	if Policy(selfhosted.Rules{}, false).AllowHost != nil {
		t.Fatal("an empty allowlist must not install a host predicate")
	}
	hosts, err := selfhosted.ParseHostAllowlist([]string{"jenkins.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy(selfhosted.Rules{Hosts: hosts}, false)
	if policy.AllowHost == nil || !policy.AllowHost("jenkins.corp.example", "443") || policy.AllowHost("evil.example", "443") {
		t.Fatal("host allowlist not applied")
	}
}

// The client refuses a host outside the allowlist before resolving it, so this test needs no
// network: the refusal comes from the dialer, not from a failed lookup.
func TestClientRefusesHostOutsideTheAllowlist(t *testing.T) {
	hosts, err := selfhosted.ParseHostAllowlist([]string{"jenkins.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(time.Second, selfhosted.Rules{Hosts: hosts}, false)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://not-listed.invalid/api/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, safehttp.ErrBlockedDestination) {
		t.Fatalf("err = %v, want ErrBlockedDestination", err)
	}
}

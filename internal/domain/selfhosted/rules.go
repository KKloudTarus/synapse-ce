package selfhosted

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Rules are the operator's rules for self-hosted provider endpoints. The zero value admits any
// public host and no private address, which is the default deployment.
type Rules struct {
	// AllowPrivateNetwork is the operator switch that lets a tenant request private-use endpoints.
	AllowPrivateNetwork bool
	// Hosts, when not empty, is the only set of hosts a self-hosted provider may reach.
	Hosts HostAllowlist
	// PrivateCIDRs, when set, limits private-network integrations to these ranges.
	PrivateCIDRs []netip.Prefix
}

// NewRules builds Rules and refuses a combination that cannot mean what the operator intended:
// private CIDRs without the private-network switch would narrow something that is off.
func NewRules(allowPrivate bool, hosts HostAllowlist, privateCIDRs []netip.Prefix) (Rules, error) {
	if len(privateCIDRs) > 0 && !allowPrivate {
		return Rules{}, errors.New("private CIDRs are set but private-network integrations are disabled")
	}
	return Rules{AllowPrivateNetwork: allowPrivate, Hosts: hosts, PrivateCIDRs: privateCIDRs}, nil
}

// PrivateAllowed reports whether an integration that requested private-network access gets it.
// Both the tenant's request and the operator switch are required, and the switch is read at dial
// time, so turning it off also stops integrations saved while it was on.
func (r Rules) PrivateAllowed(requested bool) bool {
	return requested && r.AllowPrivateNetwork
}

// CheckSave validates an endpoint and private-network request when an integration is created or
// updated. endpoint must already be canonical (integration.CanonicalEndpoint).
func (r Rules) CheckSave(endpoint string, requestPrivate bool) error {
	if err := r.CheckPrivateRequest(requestPrivate); err != nil {
		return err
	}
	return r.CheckEndpoint(endpoint, requestPrivate)
}

// CheckPrivateRequest refuses a request for private-network access while the operator switch is
// off. It applies to every provider, SaaS ones included; the host rules apply to self-hosted ones.
func (r Rules) CheckPrivateRequest(requestPrivate bool) error {
	if requestPrivate && !r.AllowPrivateNetwork {
		return fmt.Errorf("%w: private-network integrations are disabled by the operator", shared.ErrValidation)
	}
	return nil
}

// CheckEndpoint validates an endpoint before an adapter is built for it. It checks what can be
// decided without DNS: the host allowlist, and an IP-literal host against the private-network
// rules. Names are resolved and checked on every connection by the dialer.
//
// Errors name the host, never the full URL, so a path that carries a token is not echoed.
func (r Rules) CheckEndpoint(endpoint string, requestPrivate bool) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("%w: integration endpoint is invalid", shared.ErrValidation)
	}
	host := parsed.Hostname()
	if !r.Hosts.Permits(host, EffectivePort(parsed)) {
		return fmt.Errorf("%w: integration host %q is not on the operator's allowlist", shared.ErrValidation, host)
	}
	if address, err := netip.ParseAddr(host); err == nil && isPrivateUse(address) && !r.privateAddressAllowed(address, requestPrivate) {
		return fmt.Errorf("%w: integration host %q is a private address the operator does not allow", shared.ErrValidation, host)
	}
	return nil
}

// CheckListedEndpoint is CheckEndpoint for an endpoint that is allowed only when the operator has
// named its host: a self-hosted forge API base a tenant attaches to a source-control connector. An
// empty allowlist admits nothing here, unlike CheckEndpoint, so a deployment that has not set
// SYNAPSE_INTEGRATION_HOST_ALLOWLIST cannot send a forge token to a tenant-chosen host.
func (r Rules) CheckListedEndpoint(endpoint string, requestPrivate bool) error {
	if r.Hosts.Empty() {
		return fmt.Errorf("%w: a self-hosted endpoint needs its host on the operator's allowlist (SYNAPSE_INTEGRATION_HOST_ALLOWLIST), which is not set", shared.ErrValidation)
	}
	return r.CheckEndpoint(endpoint, requestPrivate)
}

func (r Rules) privateAddressAllowed(address netip.Addr, requestPrivate bool) bool {
	if !r.PrivateAllowed(requestPrivate) {
		return false
	}
	if len(r.PrivateCIDRs) == 0 {
		return true
	}
	address = address.Unmap()
	for _, prefix := range r.PrivateCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

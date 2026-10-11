// Package selfhostedhttp builds the HTTP client a self-hosted provider adapter (Jenkins, Jira Data
// Center, Confluence Data Center) uses to reach the endpoint a tenant configured. It turns the
// operator's selfhosted.Rules into a safehttp.Policy, so every such adapter applies the host
// allowlist, the private-network switch and the private CIDRs on every connection in the same way.
package selfhostedhttp

import (
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// NewClient returns a client for an integration that requested private-network access when
// requestPrivate is set.
func NewClient(timeout time.Duration, rules selfhosted.Rules, requestPrivate bool) *http.Client {
	return safehttp.NewClient(timeout, Policy(rules, requestPrivate))
}

// Policy is the dialer policy for an integration under rules. Private addresses need both the
// tenant's request and the operator switch; loopback is never allowed for a tenant endpoint.
func Policy(rules selfhosted.Rules, requestPrivate bool) safehttp.Policy {
	policy := safehttp.Policy{
		AllowPrivate: rules.PrivateAllowed(requestPrivate),
		PrivateCIDRs: rules.PrivateCIDRs,
	}
	if !rules.Hosts.Empty() {
		policy.AllowHost = rules.Hosts.Permits
	}
	return policy
}

package scmdecoration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/integration/selfhostedhttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Option configures a decorator built by ForProvider or NewMultiplexDecorator.
type Option func(*options)

type options struct {
	rules      selfhosted.Rules
	rulesSet   bool
	httpClient *http.Client // test seam for the self-hosted client
}

// WithSelfHostedRules lets the GitHub and GitLab adapters reach a self-hosted forge (GitHub Enterprise
// Server, self-managed GitLab) through the API base stored on that host's connector. Every call
// re-checks the base against the operator's rules: it must be on the host allowlist (an empty
// allowlist admits no self-hosted forge), and a private address needs the private-network switch
// and, when set, a matching private CIDR. Without this option only the public SaaS APIs are used.
func WithSelfHostedRules(rules selfhosted.Rules) Option {
	return func(o *options) {
		o.rules = rules
		o.rulesSet = true
	}
}

// withSelfHostedHTTPClient replaces the dial-guarded client for fake-server tests.
func withSelfHostedHTTPClient(client *http.Client) Option {
	return func(o *options) { o.httpClient = client }
}

func collectOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// selfHostedAPI is how one adapter reaches a self-hosted instance of its forge. The HTTP client is
// built once from the operator's rules, so the host allowlist and the private-network rules are
// enforced again by the dialer on every connection.
type selfHostedAPI struct {
	provider scmconnector.Provider
	rules    selfhosted.Rules
	client   *http.Client
}

func newSelfHostedAPI(provider scmconnector.Provider, o options) *selfHostedAPI {
	if !o.rulesSet {
		return nil
	}
	client := o.httpClient
	if client == nil {
		// A connector has no private-network request of its own: the operator's allowlist entry is
		// the request, and the operator switch and CIDRs still decide whether a private address is
		// reachable.
		client = selfhostedhttp.NewClient(30*time.Second, o.rules, true)
	}
	return &selfHostedAPI{provider: provider, rules: o.rules, client: client}
}

// clientFor validates a connector's stored API base again (shape, origin equal to the connector host,
// operator allowlist) and returns a JSON client for it. Errors name the host, never a credential.
func (s *selfHostedAPI) clientFor(host, apiBase string) (*jsonHTTPClient, error) {
	base, err := scmconnector.NormalizeAPIBase(s.provider, host, apiBase)
	if err != nil {
		return nil, err
	}
	if err := s.rules.CheckListedEndpoint(base, true); err != nil {
		return nil, err
	}
	return newJSONHTTPClient(s.client, base), nil
}

// resolveForgeEndpoint picks the credential and API for one decoration.
//
// The credential is looked up by the forge host the project's repository lives on. When the tenant's
// connector for that host carries an API base, the token goes to that base and nowhere else: the base
// shares the connector host's origin and is re-checked against the operator's rules here. Otherwise the
// adapter's public SaaS API is used with the SaaS host's credential, as before self-hosted support.
// The returned credential's token must be zeroed by the caller.
func resolveForgeEndpoint(ctx context.Context, credentials ports.GitCredentialResolver, saasHost string, saasAPI *jsonHTTPClient, selfHosted *selfHostedAPI, forgeHost, label string) (*jsonHTTPClient, ports.GitCredential, error) {
	host := strings.ToLower(strings.TrimSpace(forgeHost))
	if host != "" && host != saasHost {
		credential, ok, err := credentials.ResolveGitCredential(ctx, host)
		if err != nil {
			return nil, ports.GitCredential{}, fmt.Errorf("resolve %s decoration credential for %s: %w", label, host, err)
		}
		if ok && len(credential.Token) > 0 && credential.APIBase != "" {
			if selfHosted == nil {
				zeroToken(credential.Token)
				return nil, ports.GitCredential{}, fmt.Errorf("%w: self-hosted %s decoration for host %s is not enabled or not supported on this deployment", shared.ErrValidation, label, host)
			}
			api, err := selfHosted.clientFor(host, credential.APIBase)
			if err != nil {
				zeroToken(credential.Token)
				return nil, ports.GitCredential{}, err
			}
			return api, credential, nil
		}
		zeroToken(credential.Token)
	}
	credential, ok, err := credentials.ResolveGitCredential(ctx, saasHost)
	if err != nil {
		return nil, ports.GitCredential{}, fmt.Errorf("resolve %s decoration credential: %w", label, err)
	}
	if !ok || len(credential.Token) == 0 {
		return nil, ports.GitCredential{}, fmt.Errorf("%w: no %s credential is configured for decoration", shared.ErrValidation, label)
	}
	return saasAPI, credential, nil
}

func zeroToken(token []byte) {
	for i := range token {
		token[i] = 0
	}
}

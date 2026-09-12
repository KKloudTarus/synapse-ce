// Package secretverify implements opt-in active secret verification (EPIC #860 D6.3): given a detected
// credential and the rule that found it, it makes ONE minimal read-only API call to the issuing provider to
// determine whether the credential is currently live. It is the concrete ports.SecretVerifier.
//
// SAFETY (this package handles raw leaked credentials):
//   - The secret is sent only in the single provider request (an Authorization/token header, never a URL),
//     and never logged, sealed, or returned. Every error is scrubbed of the secret with redact before it
//     leaves Verify (defense-in-depth; Go's HTTP errors do not echo request headers, but a proxy/DNS error
//     could quote a URL, so the scrub is unconditional).
//   - A transport/DNS/timeout failure maps to SecretUnknown, NEVER to SecretUnverified: "could not reach the
//     provider" must not be confused with "the provider rejected the credential", or a network outage would
//     understate a live leak. Only an explicit provider rejection (401/403) is SecretUnverified.
//   - Outbound requests use SSRF-hardened safehttp clients (no proxy or redirects) and are rate-limited.
//     Public providers reject private destinations; an explicitly configured HTTPS Vault address may resolve
//     to RFC1918 space but still rejects loopback, link-local, multicast, and other special ranges.
//
// AWS is exposed through the optional ports.GroupedSecretVerifier extension because STS needs a correlated
// access-key/secret-key pair. Vault is registered only when an operator supplies a validated HTTPS address.
package secretverify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultTimeout = 8 * time.Second
	defaultRPS     = 5.0 // modest outbound rate; a scan verifies few distinct secrets
)

// provider verifies one credential family. check performs the single read-only call against baseURL using
// secret and maps the outcome to a verdict; it must not log or return the secret.
//
// rejectOn401 records whether a 401 from this provider's PUBLIC host proves the credential is dead. It is
// true ONLY for a provider with a single global host (OpenAI): a rejected sk- key is genuinely inactive.
// It is false for host-ambiguous families (GitHub, GitLab) whose tokens may belong to an enterprise or
// self-managed instance: a 401 from public github.com / gitlab.com then means "not this host", NOT "dead",
// so it maps to UNKNOWN rather than falsely stamping a live enterprise credential unverified. A 403 is
// always inconclusive (rate limit / abuse / SSO / permissions) and never a rejection.
type provider struct {
	name        string
	baseURL     string       // overridable in tests; defaults to the real provider host
	client      *http.Client // nil uses the verifier's public-only client
	rejectOn401 bool
	// eligible, when non-nil, gates whether a matched secret is actually sent to this provider. It narrows a
	// broad detector rule to only high-confidence shapes for THIS provider, so a foreign secret that merely
	// shares the rule's prefix is not transmitted to (and stamped by) the wrong host. nil = always eligible.
	eligible func(secret string) bool
	check    func(ctx context.Context, client *http.Client, baseURL, secret string, rejectOn401 bool) (ports.SecretVerdict, error)
}

// Verifier is the concrete ports.SecretVerifier: a per-rule registry of providers over one shared,
// SSRF-hardened, rate-limited HTTP client.
type Verifier struct {
	client      *http.Client
	vaultClient *http.Client
	limiter     *rate.Limiter
	byRule      map[string]*provider
	stsURL      string
	now         func() time.Time
}

var _ ports.SecretVerifier = (*Verifier)(nil)

// New returns a Verifier using the SSRF-hardened safehttp client (public hosts only, no proxy, no
// redirects). rps <= 0 uses the default outbound rate. The client is NOT caller-supplied on purpose: a
// caller cannot substitute an unhardened client that would follow a cross-host redirect and forward the
// secret header. Tests use newWithClient.
func New(rps float64) *Verifier {
	v, _ := NewWithVault(rps, "")
	return v
}

// NewWithVault extends the built-in public providers with an operator-supplied Vault base address. The
// address must be absolute HTTPS without userinfo; query and fragment are discarded, and the read-only
// token self-lookup path is appended. An empty address leaves Vault verification disabled.
func NewWithVault(rps float64, vaultAddr string) (*Verifier, error) {
	vaultURL, err := vaultLookupURL(vaultAddr)
	if err != nil {
		return nil, err
	}
	v := newWithClients(safehttp.New(defaultTimeout, false), safehttp.New(defaultTimeout, true), rps)
	if vaultURL != "" {
		v.byRule["vault-token"] = &provider{
			name: "vault", baseURL: vaultURL, client: v.vaultClient, rejectOn401: true, check: checkVault,
		}
	}
	return v, nil
}

// newWithClient is the internal constructor that accepts an explicit client (tests inject an httptest
// client, since safehttp blocks loopback). Not exported so production egress cannot be un-hardened.
func newWithClient(client *http.Client, rps float64) *Verifier {
	return newWithClients(client, client, rps)
}

func newWithClients(client, vaultClient *http.Client, rps float64) *Verifier {
	if rps <= 0 {
		rps = defaultRPS
	}
	v := &Verifier{
		client:      client,
		vaultClient: vaultClient,
		limiter:     rate.NewLimiter(rate.Limit(rps), 1),
		byRule:      map[string]*provider{},
		stsURL:      awsSTSEndpoint,
		now:         time.Now,
	}
	v.register()
	return v
}

func vaultLookupURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("secret verifier: Vault address must be an absolute HTTPS URL without userinfo")
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/auth/token/lookup-self"
	return u.String(), nil
}

// register wires the built-in providers to the detector rule ids they can verify. GitHub and GitLab are
// host-ambiguous (enterprise/self-managed instances share the token shape), so a public-host rejection is
// inconclusive (rejectOn401 false); OpenAI has a single global host, so a rejection is a real inactive key.
func (v *Verifier) register() {
	github := &provider{name: "github", baseURL: "https://api.github.com", rejectOn401: false, check: checkGitHub}
	v.byRule["github-token"] = github
	v.byRule["github-fine-grained-pat"] = github

	v.byRule["gitlab-pat"] = &provider{name: "gitlab", baseURL: "https://gitlab.com", rejectOn401: false, check: checkGitLab}
	// The openai-api-key detector rule is broad (sk-[proj-]<20+ alnum>); other tools also use sk- prefixes.
	// Only send a high-confidence OpenAI shape to api.openai.com so a foreign sk- secret is not transmitted
	// there and then stamped "unverified" (OpenAI is the one rejectOn401 provider).
	v.byRule["openai-api-key"] = &provider{name: "openai", baseURL: "https://api.openai.com", rejectOn401: true, eligible: looksLikeOpenAIKey, check: checkOpenAI}
}

// looksLikeOpenAIKey narrows the broad sk- detector to shapes OpenAI actually issues: a project key
// ("sk-proj-…") or a legacy key ("sk-" then a long token). A short or non-sk- string that merely matched the
// rule is not sent to OpenAI.
func looksLikeOpenAIKey(secret string) bool {
	if strings.HasPrefix(secret, "sk-proj-") {
		return true
	}
	return strings.HasPrefix(secret, "sk-") && len(secret) >= 40 // legacy sk- keys are ~51 chars
}

// Verify selects the provider for ruleID and performs its single read-only call. It returns SecretUnknown
// (nil error) when no provider matches. A transport failure returns SecretUnknown with a secret-scrubbed
// error; an explicit provider rejection returns SecretUnverified. The secret is never logged or returned.
func (v *Verifier) Verify(ctx context.Context, ruleID string, secret []byte) (ports.SecretVerdict, error) {
	p, ok := v.byRule[ruleID]
	if !ok || len(secret) == 0 {
		return ports.SecretUnknown, nil // no provider for this rule, or nothing to check
	}
	if p.eligible != nil && !p.eligible(string(secret)) {
		return ports.SecretUnknown, nil // matched the rule but not a high-confidence shape for THIS provider; do not transmit
	}
	if err := v.limiter.Wait(ctx); err != nil {
		return ports.SecretUnknown, fmt.Errorf("secret verify rate-limit wait: %w", err) // ctx error; carries no secret
	}
	s := string(secret)
	client := p.client
	if client == nil {
		client = v.client
	}
	verdict, err := p.check(ctx, client, p.baseURL, s, p.rejectOn401)
	if err != nil {
		// Scrub the secret out of the error unconditionally, then map any failure to unknown (never to
		// unverified): a failed call is "did not confirm", not "confirmed dead".
		return ports.SecretUnknown, fmt.Errorf("secret verify %s: %s", p.name, redact.String(err.Error(), []string{s}))
	}
	return verdict, nil
}

// verdictForStatus maps an HTTP status from a read-only introspection call to a verdict. 2xx is a live
// credential. A 401 is a rejection ONLY when rejectOn401 is set (a single-global-host provider, where a
// rejection proves the key is dead); for a host-ambiguous provider a 401 is inconclusive (the token may be
// a live enterprise/self-managed credential rejected only by the public host), so it maps to unknown. A 403
// is ALWAYS inconclusive (rate limit / abuse / SSO / missing scope, not an authentication rejection), as is
// 429 and everything else. Nothing but a 401 at an unambiguous provider is ever "unverified".
func verdictForStatus(status int, rejectOn401 bool) ports.SecretVerdict {
	switch {
	case status >= 200 && status < 300:
		return ports.SecretVerified
	case status == http.StatusUnauthorized && rejectOn401:
		return ports.SecretUnverified
	default:
		return ports.SecretUnknown
	}
}

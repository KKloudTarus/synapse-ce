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
//   - Outbound requests use the SSRF-hardened safehttp client (no proxy, no redirects, public hosts only)
//     and are rate-limited. The whole feature is default-off; a nil verifier means no verification.
//
// Providers requiring more than a single bearer token are deliberately NOT verified here and return
// SecretUnknown: AWS needs the access-key-id + secret-access-key PAIR (SigV4), which a single-rule match
// does not carry, and HashiCorp Vault needs an operator-supplied address. Adding pair-aware AWS and
// configured-address Vault verification is a documented follow-up; returning SecretUnknown keeps the
// verifier honest rather than emitting a fabricated verdict.
package secretverify

import (
	"context"
	"fmt"
	"net/http"
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
	baseURL     string // overridable in tests; defaults to the real provider host
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
	client  *http.Client
	limiter *rate.Limiter
	byRule  map[string]*provider
}

var _ ports.SecretVerifier = (*Verifier)(nil)

// New returns a Verifier using the SSRF-hardened safehttp client (public hosts only, no proxy, no
// redirects). rps <= 0 uses the default outbound rate. The client is NOT caller-supplied on purpose: a
// caller cannot substitute an unhardened client that would follow a cross-host redirect and forward the
// secret header. Tests use newWithClient.
func New(rps float64) *Verifier {
	return newWithClient(safehttp.New(defaultTimeout, false), rps)
}

// newWithClient is the internal constructor that accepts an explicit client (tests inject an httptest
// client, since safehttp blocks loopback). Not exported so production egress cannot be un-hardened.
func newWithClient(client *http.Client, rps float64) *Verifier {
	if rps <= 0 {
		rps = defaultRPS
	}
	v := &Verifier{
		client:  client,
		limiter: rate.NewLimiter(rate.Limit(rps), 1),
		byRule:  map[string]*provider{},
	}
	v.register()
	return v
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
	verdict, err := p.check(ctx, v.client, p.baseURL, s, p.rejectOn401)
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

// Package safehttp builds outbound HTTP clients and dialers that refuse destinations an attacker
// could use to reach internal services: private networks unless a policy opens them, loopback,
// link-local and cloud metadata endpoints, and every other IANA special-purpose range. The check
// runs at dial time on the address actually dialed, so it holds across redirects and DNS
// rebinding.
package safehttp

import (
	"net/http"
	"time"
)

// New returns an HTTP client that admits public destinations and, when allowPrivate is set,
// private-use ones. It is NewClient with Policy{AllowPrivate: allowPrivate}.
func New(timeout time.Duration, allowPrivate bool) *http.Client {
	return NewClient(timeout, Policy{AllowPrivate: allowPrivate})
}

// NewClient returns an HTTP client whose every connection goes through a Dialer for policy. It
// follows no redirects and uses no proxy, so the dialed address is the one the policy checked.
func NewClient(timeout time.Duration, policy Policy) *http.Client {
	return newClient(timeout, NewDialer(policy, 0))
}

func newClient(timeout time.Duration, dialer *Dialer) *http.Client {
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     true,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   4,
			MaxConnsPerHost:       8,
			DialContext:           dialer.DialContext,
		},
	}
}

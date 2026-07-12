package engagement

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTargetValidate(t *testing.T) {
	valid := []Target{
		{Kind: TargetDomain, Value: "acme.io"},
		{Kind: TargetCIDR, Value: "10.0.0.0/24"},
		{Kind: TargetURL, Value: "https://x"},
		{Kind: TargetIP, Value: "1.2.3.4"},
		{Kind: TargetRepo, Value: "/srv/app"},
		{Kind: TargetImage, Value: "nginx:1"},
	}
	for _, tg := range valid {
		if err := tg.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", tg, err)
		}
	}
	invalid := []Target{
		{Kind: TargetDomain, Value: ""},
		{Kind: TargetDomain, Value: "   "},
		{Kind: TargetKind("bogus"), Value: "x"},
		{Kind: TargetCIDR, Value: "not-a-cidr"},
		{Kind: TargetCIDR, Value: "10.0.0.1"}, // missing prefix length
		{Kind: TargetIP, Value: "999.1.1.1"},
	}
	for _, tg := range invalid {
		if err := tg.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("Validate(%+v) = %v, want ErrValidation", tg, err)
		}
	}
}

func TestScopeAllows(t *testing.T) {
	s := Scope{
		InScope: []Target{
			{Kind: TargetRepo, Value: "/srv/app"},
			{Kind: TargetDomain, Value: "app.acme.io"},
		},
		OutOfScope: []Target{{Kind: TargetDomain, Value: "prod.acme.io"}},
	}
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"in scope, exact", "/srv/app", true},
		{"in scope, case-insensitive", "APP.ACME.IO", true},
		{"in scope, whitespace trimmed", "  /srv/app  ", true},
		{"out of scope", "prod.acme.io", false},
		{"not listed", "other.com", false},
		{"empty value", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.Allows(c.value); got != c.want {
				t.Errorf("Allows(%q) = %v, want %v", c.value, got, c.want)
			}
		})
	}
}

func TestScopeOutOfScopeWins(t *testing.T) {
	// A value that is both in and out of scope must be denied (fail closed).
	s := Scope{
		InScope:    []Target{{Kind: TargetDomain, Value: "x.acme.io"}},
		OutOfScope: []Target{{Kind: TargetDomain, Value: "x.acme.io"}},
	}
	if s.Allows("x.acme.io") {
		t.Error("out-of-scope must win over in-scope")
	}
}

func TestScopeOutOfScopeURLDeniesHostWide(t *testing.T) {
	s := Scope{
		InScope:    []Target{{Kind: TargetDomain, Value: "*.acme.io"}},
		OutOfScope: []Target{{Kind: TargetURL, Value: "https://payments.acme.io/"}},
	}
	cases := []Target{
		{Kind: TargetURL, Value: "https://payments.acme.io/checkout"},
		{Kind: TargetURL, Value: "http://payments.acme.io/checkout"},
		{Kind: TargetURL, Value: "https://payments.acme.io:8443/checkout"},
		{Kind: TargetDomain, Value: "payments.acme.io"},
	}
	for _, req := range cases {
		if s.AllowsTarget(req) {
			t.Errorf("out-of-scope URL host must deny %+v", req)
		}
	}
	if s.Allows("payments.acme.io") {
		t.Error("value-only matching must preserve the URL host carve-out")
	}
	if !s.Allows("api.acme.io") {
		t.Error("the carve-out must not deny a different in-scope host")
	}
}

func TestScopeInScopeURLRemainsSchemeAndPortSpecific(t *testing.T) {
	s := Scope{InScope: []Target{{Kind: TargetURL, Value: "https://app.acme.io/"}}}
	cases := []struct {
		req  Target
		want bool
	}{
		{req: Target{Kind: TargetURL, Value: "https://app.acme.io/other"}, want: true},
		{req: Target{Kind: TargetURL, Value: "https://app.acme.io:443/other"}, want: true},
		{req: Target{Kind: TargetURL, Value: "http://app.acme.io/other"}, want: false},
		{req: Target{Kind: TargetURL, Value: "https://app.acme.io:8443/other"}, want: false},
		{req: Target{Kind: TargetDomain, Value: "app.acme.io"}, want: false},
	}
	for _, tc := range cases {
		if got := s.AllowsTarget(tc.req); got != tc.want {
			t.Errorf("AllowsTarget(%+v) = %v, want %v", tc.req, got, tc.want)
		}
	}
}

func TestScopeMalformedEntriesFailClosed(t *testing.T) {
	malformedDeny := Scope{
		InScope:    []Target{{Kind: TargetDomain, Value: "*.acme.io"}},
		OutOfScope: []Target{{Kind: TargetURL, Value: "not-a-url"}},
	}
	if malformedDeny.Allows("api.acme.io") {
		t.Error("an unenforceable deny entry must deny every request")
	}

	malformedAllow := Scope{InScope: []Target{{Kind: TargetURL, Value: "not-a-url"}}}
	if malformedAllow.Allows("not-a-url") {
		t.Error("a malformed allow entry must grant nothing")
	}
}

func TestScopeOutOfScopeURLDeniesContainerRegistry(t *testing.T) {
	cases := []struct {
		image string
		host  string
	}{
		{image: "nginx:1", host: "docker.io"},
		{image: "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", host: "docker.io"},
		{image: "library/nginx:1", host: "docker.io"},
		{image: "registry.example/team/app:1", host: "registry.example"},
		{image: "registry.example:5000/app:1", host: "registry.example"},
		{image: "localhost:5000/app:1", host: "localhost"},
	}
	for _, tc := range cases {
		s := Scope{
			InScope:    []Target{{Kind: TargetImage, Value: tc.image}},
			OutOfScope: []Target{{Kind: TargetURL, Value: "https://" + tc.host + "/private"}},
		}
		if s.AllowsTarget(Target{Kind: TargetImage, Value: tc.image}) {
			t.Errorf("URL carve-out for %q must deny image %q", tc.host, tc.image)
		}
	}

	allowed := Scope{InScope: []Target{{Kind: TargetImage, Value: "nginx:1"}}}
	if !allowed.AllowsTarget(Target{Kind: TargetImage, Value: "nginx:1"}) {
		t.Error("image exact-match capability must remain available")
	}
}

func TestScopeCIDRRequests(t *testing.T) {
	s := Scope{
		InScope:    []Target{{Kind: TargetCIDR, Value: "10.0.0.0/16"}},
		OutOfScope: []Target{{Kind: TargetCIDR, Value: "10.0.1.0/24"}},
	}
	cases := []struct {
		value string
		want  bool
	}{
		{value: "10.0.0.0/16", want: false}, // overlaps the carved-out /24
		{value: "10.0.2.0/24", want: true},
		{value: "10.0.1.0/25", want: false},
		{value: "10.1.0.0/16", want: false},
	}
	for _, tc := range cases {
		if got := s.AllowsTarget(Target{Kind: TargetCIDR, Value: tc.value}); got != tc.want {
			t.Errorf("AllowsTarget(CIDR %q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestScopeAllowsLocalRepoChildPath(t *testing.T) {
	s := Scope{
		InScope:    []Target{{Kind: TargetRepo, Value: "/srv/app"}},
		OutOfScope: []Target{{Kind: TargetRepo, Value: "/srv/app/secret"}},
	}
	cases := []struct {
		name string
		req  Target
		want bool
	}{
		{"exact repo", Target{Kind: TargetRepo, Value: "/srv/app"}, true},
		{"child folder", Target{Kind: TargetRepo, Value: "/srv/app/services/api"}, true},
		{"sibling prefix is not child", Target{Kind: TargetRepo, Value: "/srv/app2"}, false},
		{"cleaned escape is sibling", Target{Kind: TargetRepo, Value: "/srv/app/../secret"}, false},
		{"out of scope child wins", Target{Kind: TargetRepo, Value: "/srv/app/secret/module"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.AllowsTarget(c.req); got != c.want {
				t.Errorf("AllowsTarget(%+v) = %v, want %v", c.req, got, c.want)
			}
		})
	}
}

func TestScopeAllowsTarget(t *testing.T) {
	// host-centric matching: CIDR containment, wildcard subdomains,
	// exact-host domains, IP and URL-by-host, with out-of-scope winning.
	s := Scope{
		InScope: []Target{
			{Kind: TargetCIDR, Value: "10.0.0.0/24"},
			{Kind: TargetDomain, Value: "*.acme.io"},
			{Kind: TargetDomain, Value: "host.example.com"},
			{Kind: TargetIP, Value: "192.168.1.5"},
			{Kind: TargetURL, Value: "https://app.acme.io/login"},
		},
		OutOfScope: []Target{
			{Kind: TargetIP, Value: "10.0.0.13"},          // a hole inside the in-scope CIDR
			{Kind: TargetDomain, Value: "secret.acme.io"}, // a subdomain carved out
		},
	}
	cases := []struct {
		name string
		req  Target
		want bool
	}{
		{"ip inside cidr", Target{Kind: TargetIP, Value: "10.0.0.42"}, true},
		{"ip outside cidr", Target{Kind: TargetIP, Value: "10.0.1.42"}, false},
		{"cidr hole is out of scope (deny wins)", Target{Kind: TargetIP, Value: "10.0.0.13"}, false},
		{"wildcard subdomain", Target{Kind: TargetDomain, Value: "api.acme.io"}, true},
		{"wildcard multi-level subdomain", Target{Kind: TargetDomain, Value: "a.b.acme.io"}, true},
		{"wildcard does not match apex", Target{Kind: TargetDomain, Value: "acme.io"}, false},
		{"carved-out subdomain (deny wins)", Target{Kind: TargetDomain, Value: "secret.acme.io"}, false},
		{"exact-host domain", Target{Kind: TargetDomain, Value: "host.example.com"}, true},
		{"subdomain of exact host not covered", Target{Kind: TargetDomain, Value: "x.host.example.com"}, false},
		{"exact ip", Target{Kind: TargetIP, Value: "192.168.1.5"}, true},
		{"url host falls inside cidr", Target{Kind: TargetURL, Value: "http://10.0.0.9:8080/x"}, true},
		{"url matches URL entry by scheme host and effective port", Target{Kind: TargetURL, Value: "https://app.acme.io/other"}, true},
		{"domain scope remains intentionally host-wide", Target{Kind: TargetURL, Value: "http://app.acme.io/other"}, true},
		{"userinfo is rejected", Target{Kind: TargetURL, Value: "https://app.acme.io@evil.com/x"}, false},
		{"unrelated host", Target{Kind: TargetDomain, Value: "evil.com"}, false},
		{"ipv6 not in v4 cidr", Target{Kind: TargetIP, Value: "::1"}, false},
		{"empty value", Target{Kind: TargetDomain, Value: ""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.AllowsTarget(c.req); got != c.want {
				t.Errorf("AllowsTarget(%+v) = %v, want %v", c.req, got, c.want)
			}
		})
	}
}

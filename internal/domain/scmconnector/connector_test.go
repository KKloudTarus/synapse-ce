package scmconnector

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var epoch = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func TestNewConnectorNormalizesHostAndDefaultsUsername(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		provider Provider
		user     string
		wantHost string
		wantUser string
	}{
		{"bare host, github default user", "GitHub.com", ProviderGitHub, "", "github.com", "x-access-token"},
		{"url host, gitlab default user", "https://gitlab.example.com/group", ProviderGitLab, "", "gitlab.example.com", "oauth2"},
		{"non-default port kept", "ghe.corp.io:8443", ProviderGeneric, "svc-scanner", "ghe.corp.io:8443", "svc-scanner"},
		{"explicit username kept", "github.com", ProviderGitHub, "octo-bot", "github.com", "octo-bot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConnector("c1", "t1", "prod", tc.provider, tc.host, tc.user, AuthPAT, epoch)
			if err != nil {
				t.Fatalf("NewConnector: %v", err)
			}
			if c.Host != tc.wantHost {
				t.Fatalf("host = %q, want %q", c.Host, tc.wantHost)
			}
			if c.Username != tc.wantUser {
				t.Fatalf("username = %q, want %q", c.Username, tc.wantUser)
			}
		})
	}
}

func TestNewConnectorRejectsInvalid(t *testing.T) {
	cases := []struct {
		name     string
		id       shared.ID
		tenant   shared.ID
		cname    string
		provider Provider
		host     string
		user     string
		auth     AuthKind
	}{
		{"no id", "", "t1", "prod", ProviderGitHub, "github.com", "", AuthPAT},
		{"no tenant", "c1", "", "prod", ProviderGitHub, "github.com", "", AuthPAT},
		{"bad name", "c1", "t1", "", ProviderGitHub, "github.com", "", AuthPAT},
		{"unknown provider", "c1", "t1", "prod", Provider("svn"), "github.com", "", AuthPAT},
		{"unsupported auth", "c1", "t1", "prod", ProviderGitHub, "github.com", "", AuthKind("ssh")},
		{"bare-label host refused", "c1", "t1", "prod", ProviderGitHub, "localhost", "", AuthPAT},
		{"empty host", "c1", "t1", "prod", ProviderGitHub, "", "", AuthPAT},
		{"bitbucket needs a username", "c1", "t1", "prod", ProviderBitbucket, "bitbucket.org", "", AuthPAT},
		{"username with @ refused", "c1", "t1", "prod", ProviderGeneric, "git.corp.io", "a@b", AuthPAT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewConnector(tc.id, tc.tenant, tc.cname, tc.provider, tc.host, tc.user, tc.auth, epoch)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestNormalizeHostMatchesCloneURL(t *testing.T) {
	// A connector added as "GitHub.com" must match a clone of the same host with scheme,
	// path and .git suffix, because the acquirer resolves the credential by normalized host.
	added, err := NormalizeHost("GitHub.com")
	if err != nil {
		t.Fatal(err)
	}
	cloneHost, err := NormalizeHost("https://github.com/org/repo.git")
	if err != nil {
		t.Fatal(err)
	}
	if added != cloneHost || added != "github.com" {
		t.Fatalf("normalize mismatch: added=%q clone=%q", added, cloneHost)
	}
}

func TestNormalizeHostAcceptsIPLiterals(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":            "127.0.0.1",
		"[2001:db8::1]":        "2001:db8::1",
		"2001:db8::1":          "2001:db8::1",          // bare IPv6, the form gitHost yields at clone time
		"[2001:DB8::0:1]:8443": "[2001:db8::1]:8443",   // a non-default port is kept, bracketed for v6
		"github.com:443":       "github.com",           // the https default port is dropped
		"git.example.com:8443": "git.example.com:8443", // a non-default port distinguishes the service
		"10.1.2.3":             "10.1.2.3",
	}
	for in, want := range cases {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// The bracketed operator input and the bare gitHost output must canonicalize to one key, or a stored
	// IPv6 connector would never match its own clone.
	a, _ := NormalizeHost("[2001:db8::1]")
	b, _ := NormalizeHost("2001:db8::1")
	if a != b {
		t.Fatalf("bracketed and bare IPv6 must match: %q vs %q", a, b)
	}
}

func TestIsInternalHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "fe80::1"} {
		if !IsInternalHost(h) {
			t.Fatalf("%q must be internal", h)
		}
	}
	// A DNS name is judged at clone time, and a routable/private IP is allowed (self-hosted git on 10.x).
	for _, h := range []string{"github.com", "8.8.8.8", "10.1.2.3", "ghe.corp.io"} {
		if IsInternalHost(h) {
			t.Fatalf("%q must not be internal", h)
		}
	}
}

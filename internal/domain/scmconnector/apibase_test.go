package scmconnector

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeAPIBaseAcceptsSelfHostedForges(t *testing.T) {
	cases := []struct {
		name     string
		provider Provider
		host     string
		raw      string
		want     string
	}{
		{"empty keeps SaaS", ProviderGitHub, "github.com", "  ", ""},
		{"GHES", ProviderGitHub, "ghe.corp.example", "https://GHE.corp.example/api/v3", "https://ghe.corp.example/api/v3"},
		{"trailing slash dropped", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3/", "https://ghe.corp.example/api/v3"},
		{"default port dropped", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example:443/api/v3", "https://ghe.corp.example/api/v3"},
		{"non-default port kept", ProviderGitLab, "gitlab.corp.example:8443", "https://gitlab.corp.example:8443/api/v4", "https://gitlab.corp.example:8443/api/v4"},
		{"GitLab relative root", ProviderGitLab, "corp.example", "https://corp.example/gitlab/api/v4", "https://corp.example/gitlab/api/v4"},
		{"IPv6 literal", ProviderGitLab, "2001:db8::1", "https://[2001:db8::1]/api/v4", "https://[2001:db8::1]/api/v4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeAPIBase(tc.provider, tc.host, tc.raw)
			if err != nil {
				t.Fatalf("NormalizeAPIBase: %v", err)
			}
			if got != tc.want {
				t.Fatalf("base = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeAPIBaseRejects(t *testing.T) {
	cases := []struct {
		name     string
		provider Provider
		host     string
		raw      string
	}{
		{"http", ProviderGitHub, "ghe.corp.example", "http://ghe.corp.example/api/v3"},
		{"userinfo", ProviderGitHub, "ghe.corp.example", "https://user:pw@ghe.corp.example/api/v3"},
		{"query", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3?x=1"},
		{"empty query", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3?"},
		{"fragment", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v3#frag"},
		{"not a URL", ProviderGitHub, "ghe.corp.example", "ghe.corp.example/api/v3"},
		{"other host", ProviderGitHub, "ghe.corp.example", "https://evil.example/api/v3"},
		{"other port", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example:8443/api/v3"},
		{"wrong GitHub path", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/api/v4"},
		{"wrong GitLab path", ProviderGitLab, "gitlab.corp.example", "https://gitlab.corp.example/api/v3"},
		{"partial segment", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/xapi/v3"},
		{"dot segment", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/x/../api/v3"},
		{"double slash", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example//api/v3"},
		{"encoded path", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/a%2Fb/api/v3"},
		{"root only", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example"},
		{"SaaS host", ProviderGitHub, "github.com", "https://github.com/api/v3"},
		{"Bitbucket Data Center", ProviderBitbucket, "bitbucket.corp.example", "https://bitbucket.corp.example/rest/api/1.0"},
		{"Azure DevOps", ProviderAzureDevOps, "ado.corp.example", "https://ado.corp.example/api/v3"},
		{"generic", ProviderGeneric, "git.corp.example", "https://git.corp.example/api/v3"},
		{"too long", ProviderGitHub, "ghe.corp.example", "https://ghe.corp.example/" + strings.Repeat("a/", 300) + "api/v3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NormalizeAPIBase(tc.provider, tc.host, tc.raw); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NormalizeAPIBase(%q) = %q, %v; want a validation error", tc.raw, got, err)
			}
		})
	}
}

func TestNormalizeAPIBaseErrorNeverEchoesCredentials(t *testing.T) {
	_, err := NormalizeAPIBase(ProviderGitHub, "ghe.corp.example", "https://bot:s3cret@ghe.corp.example/api/v3")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("err = %v", err)
	}
}

func TestConnectorSetAPIBaseUsesProviderAndHost(t *testing.T) {
	c, err := NewConnector("c1", "t1", "ghes", ProviderGitHub, "https://ghe.corp.example/org", "", AuthPAT, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetAPIBase("https://ghe.corp.example/api/v3"); err != nil || c.APIBase != "https://ghe.corp.example/api/v3" {
		t.Fatalf("SetAPIBase: base=%q err=%v", c.APIBase, err)
	}
	if err := c.SetAPIBase("https://other.example/api/v3"); err == nil {
		t.Fatal("an API base on another host was accepted")
	}
}

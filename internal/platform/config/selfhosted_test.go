package config

import (
	"strings"
	"testing"
)

func TestLoadReadsIntegrationSelfHostedRules(t *testing.T) {
	t.Setenv("SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK", "true")
	t.Setenv("SYNAPSE_INTEGRATION_HOST_ALLOWLIST", " jenkins.corp.example , *.ci.example:8443 ")
	t.Setenv("SYNAPSE_INTEGRATION_PRIVATE_CIDRS", "10.20.0.0/16")
	rules, err := Load().IntegrationSelfHostedRules()
	if err != nil {
		t.Fatal(err)
	}
	if !rules.AllowPrivateNetwork || len(rules.PrivateCIDRs) != 1 ||
		!rules.Hosts.Permits("jenkins.corp.example", "443") || !rules.Hosts.Permits("a.ci.example", "8443") ||
		rules.Hosts.Permits("other.example", "443") {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestIntegrationSelfHostedRulesDefaultsAdmitPublicHostsOnly(t *testing.T) {
	for _, key := range []string{"SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK", "SYNAPSE_INTEGRATION_HOST_ALLOWLIST", "SYNAPSE_INTEGRATION_PRIVATE_CIDRS"} {
		t.Setenv(key, "")
	}
	rules, err := Load().IntegrationSelfHostedRules()
	if err != nil {
		t.Fatal(err)
	}
	if rules.AllowPrivateNetwork || !rules.Hosts.Empty() || len(rules.PrivateCIDRs) != 0 {
		t.Fatalf("defaults = %+v", rules)
	}
}

func TestIntegrationSelfHostedRulesNameTheInvalidVariable(t *testing.T) {
	cases := []struct {
		config Config
		want   string
	}{
		{Config{IntegrationHostAllowlist: []string{"https://jenkins.corp.example"}}, "SYNAPSE_INTEGRATION_HOST_ALLOWLIST"},
		{Config{IntegrationAllowPrivateNetwork: true, IntegrationPrivateCIDRs: []string{"169.254.0.0/16"}}, "SYNAPSE_INTEGRATION_PRIVATE_CIDRS"},
		{Config{IntegrationPrivateCIDRs: []string{"10.20.0.0/16"}}, "SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK=true"},
	}
	for _, tc := range cases {
		if _, err := tc.config.IntegrationSelfHostedRules(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("err = %v, want a mention of %s", err, tc.want)
		}
	}
}

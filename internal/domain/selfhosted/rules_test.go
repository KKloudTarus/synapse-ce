package selfhosted

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewRulesRefusesPrivateCIDRsWithoutTheSwitch(t *testing.T) {
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	if _, err := NewRules(false, HostAllowlist{}, cidrs); err == nil {
		t.Fatal("private CIDRs without the private-network switch were accepted")
	}
	if _, err := NewRules(true, HostAllowlist{}, cidrs); err != nil {
		t.Fatalf("private CIDRs with the switch: %v", err)
	}
}

func TestPrivateAllowedNeedsTenantRequestAndOperatorSwitch(t *testing.T) {
	for _, tc := range []struct {
		operator, requested, want bool
	}{{false, false, false}, {false, true, false}, {true, false, false}, {true, true, true}} {
		if got := (Rules{AllowPrivateNetwork: tc.operator}).PrivateAllowed(tc.requested); got != tc.want {
			t.Errorf("operator=%v requested=%v: got %v", tc.operator, tc.requested, got)
		}
	}
}

func TestCheckSaveRefusesPrivateRequestWhenOperatorDisabled(t *testing.T) {
	err := Rules{}.CheckSave("https://ci.example", true)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "disabled by the operator") {
		t.Fatalf("err = %v", err)
	}
	if err := (Rules{}).CheckSave("https://ci.example", false); err != nil {
		t.Fatalf("public endpoint without allowlist: %v", err)
	}
}

func TestCheckEndpointAppliesTheHostAllowlist(t *testing.T) {
	rules := Rules{Hosts: mustAllowlist(t, "jenkins.corp.example", "jira.corp.example:8443")}
	for endpoint, want := range map[string]bool{
		"https://jenkins.corp.example":           true,
		"https://jenkins.corp.example/ci":        true,
		"https://jira.corp.example:8443":         true,
		"https://jira.corp.example":              false,
		"https://other.example":                  false,
		"https://jenkins.corp.example.evil.test": false,
	} {
		err := rules.CheckEndpoint(endpoint, false)
		if (err == nil) != want {
			t.Errorf("%s: err = %v, want allowed=%v", endpoint, err, want)
		}
	}
}

func TestCheckListedEndpointNeedsAnAllowlistEntry(t *testing.T) {
	if err := (Rules{}).CheckListedEndpoint("https://ghe.corp.example/api/v3", false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty allowlist: err = %v, want validation", err)
	}
	rules := Rules{Hosts: mustAllowlist(t, "ghe.corp.example")}
	if err := rules.CheckListedEndpoint("https://ghe.corp.example/api/v3", false); err != nil {
		t.Fatalf("listed host: %v", err)
	}
	if err := rules.CheckListedEndpoint("https://other.example/api/v3", false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unlisted host: err = %v, want validation", err)
	}
}

func TestCheckEndpointNamesTheHostNotTheURL(t *testing.T) {
	rules := Rules{Hosts: mustAllowlist(t, "jenkins.corp.example")}
	err := rules.CheckEndpoint("https://other.example/token-in-path/abc123", false)
	if err == nil || !strings.Contains(err.Error(), `"other.example"`) || strings.Contains(err.Error(), "abc123") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckEndpointChecksPrivateIPLiterals(t *testing.T) {
	narrowed := Rules{AllowPrivateNetwork: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	cases := []struct {
		name     string
		rules    Rules
		endpoint string
		request  bool
		want     bool
	}{
		{"public literal", Rules{}, "https://93.184.215.14", false, true},
		{"private literal without request", Rules{AllowPrivateNetwork: true}, "https://10.0.0.5", false, false},
		{"private literal with operator off", Rules{}, "https://10.0.0.5", true, false},
		{"private literal allowed", Rules{AllowPrivateNetwork: true}, "https://10.0.0.5", true, true},
		{"inside private CIDRs", narrowed, "https://10.20.3.4", true, true},
		{"outside private CIDRs", narrowed, "https://10.30.3.4", true, false},
		{"unique local outside CIDRs", narrowed, "https://[fd12::1]", true, false},
		{"name is left to the dialer", narrowed, "https://ci.internal", true, true},
	}
	for _, tc := range cases {
		if err := tc.rules.CheckEndpoint(tc.endpoint, tc.request); (err == nil) != tc.want {
			t.Errorf("%s: err = %v, want allowed=%v", tc.name, err, tc.want)
		}
	}
}

package oidc

import (
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

func TestHTTPSIssuer(t *testing.T) {
	for _, input := range []string{"http://issuer.example", "https://", "https://issuer.example/?x=1", "https://issuer.example/#x"} {
		if _, err := httpsIssuer(input); err == nil {
			t.Errorf("httpsIssuer(%q) succeeded", input)
		}
	}
	got, err := httpsIssuer("https://issuer.example/")
	if err != nil || got != "https://issuer.example" {
		t.Fatalf("httpsIssuer() = %q, %v", got, err)
	}
}

func TestGroupRoleMappingRejectsMissingUnknownAndAmbiguousGroups(t *testing.T) {
	roles, err := parseGroupRoleMapping([]string{"synapse-admins=admin", "synapse-readers=readonly"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{roles: roles}
	cases := []struct {
		name   string
		groups any
		want   user.Role
		ok     bool
	}{
		{name: "one allowed group", groups: []string{"synapse-admins"}, want: user.RoleAdmin, ok: true},
		{name: "missing groups", groups: []string{}, ok: false},
		{name: "unknown group", groups: []string{"synapse-admins", "other"}, ok: false},
		{name: "ambiguous roles", groups: []string{"synapse-admins", "synapse-readers"}, ok: false},
		{name: "duplicate group", groups: []string{"synapse-admins", "synapse-admins"}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.groups)
			if err != nil {
				t.Fatal(err)
			}
			got, err := provider.roleForGroups(raw)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("roleForGroups() = %q, %v; want %q, success=%v", got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestGroupRoleMappingRejectsMemberAlias(t *testing.T) {
	if _, err := parseGroupRoleMapping([]string{"synapse-members=member"}); err == nil {
		t.Fatal("member alias must not be configured for OIDC")
	}
}

func TestVerifiedEmailClaimRequiresBooleanTrue(t *testing.T) {
	for _, claim := range []json.RawMessage{nil, []byte(`null`), []byte(`false`), []byte(`"true"`), []byte(`1`)} {
		email, verified, err := verifiedEmailClaim("alice@example.com", claim)
		if err != nil || verified || email != "" {
			t.Fatalf("claim %s imported %q/%t: %v", claim, email, verified, err)
		}
	}
	email, verified, err := verifiedEmailClaim("Alice@EXAMPLE.COM", []byte(`true`))
	if err != nil || !verified || email != "Alice@example.com" {
		t.Fatalf("verified claim = %q/%t: %v", email, verified, err)
	}
	if _, _, err := verifiedEmailClaim("bad\r\nBcc: x@example.com", []byte(`true`)); err == nil {
		t.Fatal("accepted unsafe verified email")
	}
}

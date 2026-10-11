package config

import "testing"

func TestIdentityCutoverConfigRejectsUnsafeAllowlists(t *testing.T) {
	for _, c := range []Config{
		{IdentityCutoverReadTenants: []string{"a"}},
		{IdentityCutoverEnabled: true},
		{IdentityCutoverEnabled: true, IdentityCutoverReadTenants: []string{"a"}, IdentityCutoverMutationTenants: []string{"b"}},
		{IdentityCutoverEnabled: true, IdentityCutoverReadTenants: []string{"*"}},
		{IdentityCutoverEnabled: true, IdentityCutoverReadTenants: []string{"a", "a"}},
		{IdentityCutoverEnabled: true, IdentityCutoverReadTenants: []string{" a"}},
	} {
		if c.ValidateIdentityCutover() == nil {
			t.Fatalf("accepted unsafe config: %+v", c)
		}
	}
}
func TestIdentityCutoverConfigScopesMutationToRead(t *testing.T) {
	c := Config{IdentityCutoverEnabled: true, IdentityCutoverReadTenants: []string{"a"}, IdentityCutoverMutationTenants: []string{"a"}}
	if err := c.ValidateIdentityCutover(); err != nil {
		t.Fatal(err)
	}
	if !c.IdentityCutoverReadForTenant("a") || !c.IdentityCutoverMutationForTenant("a") || c.IdentityCutoverReadForTenant("b") {
		t.Fatal("tenant cutover scope mismatch")
	}
}

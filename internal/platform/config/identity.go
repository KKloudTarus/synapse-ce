package config

import (
	"errors"
	"strings"
)

// ValidateIdentityCutover rejects broad or disconnected activation. The durable cutover ledger
// still decides authority; these allowlists only limit which declared tenants a binary may serve.
func (c Config) ValidateIdentityCutover() error {
	if !c.IdentityCutoverEnabled {
		if len(c.IdentityCutoverReadTenants) != 0 || len(c.IdentityCutoverMutationTenants) != 0 {
			return errors.New("identity cutover tenant allowlists require SYNAPSE_IDENTITY_CUTOVER_ENABLED=true")
		}
		return nil
	}
	if len(c.IdentityCutoverReadTenants) == 0 {
		return errors.New("SYNAPSE_IDENTITY_CUTOVER_ENABLED requires SYNAPSE_IDENTITY_CUTOVER_READ_TENANTS")
	}
	for _, list := range [][]string{c.IdentityCutoverReadTenants, c.IdentityCutoverMutationTenants} {
		if len(list) > 100 {
			return errors.New("identity cutover requires at most 100 explicit tenants")
		}
		seen := map[string]bool{}
		for _, tenant := range list {
			if tenant == "" || strings.TrimSpace(tenant) != tenant || strings.ContainsAny(tenant, "*\r\n\t") || len(tenant) > 128 || seen[tenant] {
				return errors.New("identity cutover requires unique explicit tenant identifiers")
			}
			seen[tenant] = true
		}
	}
	if !tenantAllowlistCovers(c.IdentityCutoverReadTenants, c.IdentityCutoverMutationTenants) {
		return errors.New("SYNAPSE_IDENTITY_CUTOVER_MUTATION_TENANTS must be a subset of SYNAPSE_IDENTITY_CUTOVER_READ_TENANTS")
	}
	return nil
}

func (c Config) IdentityCutoverReadForTenant(tenantID string) bool {
	return tenantFeatureEnabled(c.IdentityCutoverEnabled, c.IdentityCutoverReadTenants, tenantID)
}
func (c Config) IdentityCutoverMutationForTenant(tenantID string) bool {
	return tenantFeatureEnabled(c.IdentityCutoverEnabled, c.IdentityCutoverMutationTenants, tenantID)
}

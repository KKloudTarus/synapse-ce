package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateSecretVerification rejects a malformed optional Vault endpoint before a
// server begins serving scans. An empty endpoint is valid: GitHub and AWS checks
// do not require an operator-supplied URL.
func (c Config) ValidateSecretVerification() error {
	vaultAddr := strings.TrimSpace(c.SecretVerifyVaultAddr)
	if !c.SecretVerifyEnabled || vaultAddr == "" {
		return nil
	}
	u, err := url.Parse(vaultAddr)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("SYNAPSE_SECRET_VERIFY_VAULT_ADDR must be an https URL without userinfo")
	}
	return nil
}

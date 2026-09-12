package config

import "testing"

func TestLoadSecretVerificationSettings(t *testing.T) {
	t.Setenv("SYNAPSE_SECRET_VERIFY_ENABLED", "true")
	t.Setenv("SYNAPSE_SECRET_VERIFY_VAULT_ADDR", " https://vault.internal:8200/ ")
	cfg := Load()
	if !cfg.SecretVerifyEnabled {
		t.Fatal("expected active verification enabled")
	}
	if cfg.SecretVerifyVaultAddr != "https://vault.internal:8200/" {
		t.Fatalf("vault addr = %q", cfg.SecretVerifyVaultAddr)
	}
}

func TestValidateSecretVerification(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		vault   string
		wantErr bool
	}{
		{name: "disabled ignores endpoint", enabled: false, vault: "http://vault.internal"},
		{name: "enabled without Vault", enabled: true},
		{name: "valid HTTPS Vault", enabled: true, vault: "https://vault.internal:8200"},
		{name: "HTTP Vault rejected", enabled: true, vault: "http://vault.internal", wantErr: true},
		{name: "userinfo rejected", enabled: true, vault: "https://user@vault.internal", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{SecretVerifyEnabled: tt.enabled, SecretVerifyVaultAddr: tt.vault}
			err := cfg.ValidateSecretVerification()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSecretVerification() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

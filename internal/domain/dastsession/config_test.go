package dastsession

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validConfig() Config {
	return Config{
		Scheme:       SchemeForm,
		Credentials:  []CredentialBinding{{Name: "username", Reference: "vault:operator-login"}},
		LoginRequest: Request{Method: "POST", Path: "/login"},
		Success:      SuccessSignal{StatusCode: 302},
		CheckRequest: Request{Method: "GET", Path: "/account"},
		MaxReauth:    DefaultMaxReauth,
	}
}

func TestConfigValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"unknown scheme":                      func(c *Config) { c.Scheme = "oauth" },
		"no binding":                          func(c *Config) { c.Credentials = nil },
		"credential value field cannot exist": func(c *Config) { c.Credentials[0].Reference = "" },
		"missing success":                     func(c *Config) { c.Success = SuccessSignal{} },
		"missing check":                       func(c *Config) { c.CheckRequest = Request{} },
		"negative reauth":                     func(c *Config) { c.MaxReauth = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			mutate(&c)
			if err := c.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Validate() = %v, want ErrValidation", err)
			}
		})
	}
}

func TestValidateRejectsUnsafeMethods(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"form login": func(c *Config) { c.LoginRequest.Method = "GET" },
		"login": func(c *Config) {
			c.Scheme = SchemeBearer
			c.Credentials = []CredentialBinding{{Name: "token", Reference: "vault:token"}}
			c.LoginRequest.Method = "DELETE"
		},
		"liveness": func(c *Config) { c.CheckRequest.Method = "DELETE" },
	} {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Validate err=%v", err)
			}
		})
	}
}

func TestConfigDeniesPath(t *testing.T) {
	c := validConfig()
	c.DenyPaths = []string{"/billing/remove"}
	for _, blocked := range []string{"/logout", "/account/sign-out", "/api/delete/user", "/billing/remove/card"} {
		if !c.DeniesPath(blocked) {
			t.Errorf("DeniesPath(%q) = false, want true", blocked)
		}
	}
	for _, allowed := range []string{"/logout-preview", "/billing/removal", "/account"} {
		if c.DeniesPath(allowed) {
			t.Errorf("DeniesPath(%q) = true, want false", allowed)
		}
	}
}

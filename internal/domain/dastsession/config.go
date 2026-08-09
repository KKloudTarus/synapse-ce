// Package dastsession defines secret-free authenticated DAST session configuration.
package dastsession

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const DefaultMaxReauth = 2

var bindingNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// Scheme is the supported authentication mechanism. Credential values are resolved
// only by the execution layer from their vault references.
type Scheme string

const (
	SchemeForm   Scheme = "form"
	SchemeBasic  Scheme = "basic"
	SchemeBearer Scheme = "bearer"
	SchemeHeader Scheme = "header"
	SchemeCookie Scheme = "cookie"
)

func (s Scheme) Valid() bool {
	switch s {
	case SchemeForm, SchemeBasic, SchemeBearer, SchemeHeader, SchemeCookie:
		return true
	}
	return false
}

// CredentialBinding identifies one credential by vault reference. It never carries
// plaintext credential material.
type CredentialBinding struct {
	Name      string
	Reference string
	Field     string
}

func (b CredentialBinding) Validate() error {
	if !bindingNameRE.MatchString(b.Name) {
		return fmt.Errorf("%w: credential binding name is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(b.Reference) == "" {
		return fmt.Errorf("%w: credential binding %q needs a vault reference", shared.ErrValidation, b.Name)
	}
	if b.Field != "" && !bindingNameRE.MatchString(b.Field) {
		return fmt.Errorf("%w: credential binding field is invalid", shared.ErrValidation)
	}
	return nil
}

// Request describes a secret-free request template. Path is an absolute URL path;
// request bodies and credential values stay in the vault-backed execution layer.
type Request struct {
	Method string
	Path   string
}

func (r Request) Validate() error {
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("%w: request method is required", shared.ErrValidation)
	}
	if !validPath(r.Path) {
		return fmt.Errorf("%w: request path must be absolute and clean", shared.ErrValidation)
	}
	return nil
}

// SuccessSignal is the deterministic assertion that proves an authentication attempt succeeded.
type SuccessSignal struct {
	StatusCode    int
	BodyContains  string
	HeaderPresent string
	CookiePresent string
}

func (s SuccessSignal) Validate() error {
	if s.StatusCode < 0 || s.StatusCode > 999 {
		return fmt.Errorf("%w: success status code is invalid", shared.ErrValidation)
	}
	if s.StatusCode == 0 && strings.TrimSpace(s.BodyContains) == "" && strings.TrimSpace(s.HeaderPresent) == "" && strings.TrimSpace(s.CookiePresent) == "" {
		return fmt.Errorf("%w: authentication success signal is required", shared.ErrValidation)
	}
	return nil
}

// Config defines an authenticated scan without credential values. CheckRequest is
// performed before probe batches; MaxReauth bounds retries after session loss.
type Config struct {
	Scheme       Scheme
	Credentials  []CredentialBinding
	LoginRequest Request
	Success      SuccessSignal
	CheckRequest Request
	DenyPaths    []string
	MaxReauth    int
}

func (c Config) Validate() error {
	if !c.Scheme.Valid() {
		return fmt.Errorf("%w: unsupported DAST auth scheme %q", shared.ErrValidation, c.Scheme)
	}
	if len(c.Credentials) == 0 {
		return fmt.Errorf("%w: at least one vault credential binding is required", shared.ErrValidation)
	}
	seen := make(map[string]struct{}, len(c.Credentials))
	for _, binding := range c.Credentials {
		if err := binding.Validate(); err != nil {
			return err
		}
		if _, ok := seen[binding.Name]; ok {
			return fmt.Errorf("%w: duplicate credential binding %q", shared.ErrValidation, binding.Name)
		}
		seen[binding.Name] = struct{}{}
	}
	if c.Scheme == SchemeBasic && len(c.Credentials) != 2 {
		return fmt.Errorf("%w: basic authentication requires username and password bindings", shared.ErrValidation)
	}
	if c.Scheme == SchemeBearer && len(c.Credentials) != 1 {
		return fmt.Errorf("%w: bearer authentication requires one credential binding", shared.ErrValidation)
	}
	if err := c.LoginRequest.Validate(); err != nil {
		return fmt.Errorf("validate login request: %w", err)
	}
	loginMethod := strings.ToUpper(c.LoginRequest.Method)
	if c.Scheme == SchemeForm {
		if loginMethod != "POST" {
			return fmt.Errorf("%w: form authentication requires a POST login request", shared.ErrValidation)
		}
	} else if loginMethod != "GET" && loginMethod != "HEAD" && loginMethod != "POST" {
		return fmt.Errorf("%w: login request method is not supported", shared.ErrValidation)
	}
	if err := c.Success.Validate(); err != nil {
		return err
	}
	if err := c.CheckRequest.Validate(); err != nil {
		return fmt.Errorf("validate session check request: %w", err)
	}
	checkMethod := strings.ToUpper(c.CheckRequest.Method)
	if checkMethod != "GET" && checkMethod != "HEAD" {
		return fmt.Errorf("%w: session check must use GET or HEAD", shared.ErrValidation)
	}
	if c.MaxReauth < 0 {
		return fmt.Errorf("%w: max reauthentication cannot be negative", shared.ErrValidation)
	}
	for _, p := range c.DenyPaths {
		if !validPath(p) {
			return fmt.Errorf("%w: deny path must be absolute and clean", shared.ErrValidation)
		}
	}
	return nil
}

// DeniesPath reports whether p is an operator-denied or default destructive path.
// Matching uses path segments so /logout does not deny /logout-preview.
func (c Config) DeniesPath(p string) bool {
	if !validPath(p) {
		return true
	}
	for _, denied := range c.DenyPaths {
		if pathPrefix(denied, p) {
			return true
		}
	}
	for segment := range strings.SplitSeq(strings.Trim(path.Clean(p), "/"), "/") {
		s := strings.ToLower(segment)
		if s == "logout" || s == "signout" || s == "sign-out" || s == "delete" || s == "purge" || s == "destroy" || s == "remove" {
			return true
		}
	}
	return false
}

func validPath(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return false
	}
	return path.Clean(u.Path) == u.Path
}

func pathPrefix(parent, child string) bool {
	parent, child = path.Clean(parent), path.Clean(child)
	return parent == "/" || child == parent || strings.HasPrefix(child, strings.TrimRight(parent, "/")+"/")
}

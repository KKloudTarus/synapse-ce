package fleetclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

// ValidateControlPlaneURL refuses a cleartext control-plane URL so the bearer credential cannot
// traverse plaintext HTTP. http is allowed only for a loopback host (local development/testing).
// Shared by every agent binary so the transport-security rule is enforced identically.
func ValidateControlPlaneURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid control-plane URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing cleartext http:// control-plane URL %q (the agent token would traverse plaintext); use https, or a loopback host for local testing", raw)
	default:
		return fmt.Errorf("unsupported control-plane URL scheme %q (want https)", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Credential is a persisted agent identity. Token is a secret: the file is written 0600 and its
// contents are never logged.
type Credential struct {
	AgentID        string `json:"agent_id"`
	Token          string `json:"token"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

// CredentialStore persists an agent credential + private key under a state directory. It is shared by
// every agent binary so the security-sensitive persistence (0600, chmod on rewrite) lives in one place.
type CredentialStore struct{ dir string }

// NewCredentialStore returns a store rooted at dir.
func NewCredentialStore(dir string) *CredentialStore { return &CredentialStore{dir: dir} }

func (s *CredentialStore) credentialPath() string { return filepath.Join(s.dir, "credential.json") }
func (s *CredentialStore) keyPath() string        { return filepath.Join(s.dir, "agent.key") }

// Load returns a stored credential, or ok=false when none is present/usable.
func (s *CredentialStore) Load() (Credential, bool) {
	b, err := os.ReadFile(s.credentialPath())
	if err != nil {
		return Credential{}, false
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil || c.Token == "" {
		return Credential{}, false
	}
	return c, true
}

// Persist writes the credential (and the private key, when supplied) with 0600 permissions.
func (s *CredentialStore) Persist(cred Credential, keyPEM []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if len(keyPEM) > 0 {
		if err := WriteSecret(s.keyPath(), keyPEM, 0o600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
	}
	b, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	if err := WriteSecret(s.credentialPath(), b, 0o600); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	return nil
}

// WriteSecret writes secret material and enforces the mode even if the file pre-existed with looser
// permissions (os.WriteFile applies the mode only on create). The explicit Chmod closes the window
// where a pre-seeded, world-readable file would keep its old mode after a rewrite. Exported so agent
// binaries reuse it for their own on-disk secrets (e.g. a buffered inventory) rather than duplicating it.
func WriteSecret(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// Enroller is the subset of the client EnsureEnrolled needs; *Client satisfies it, and an agent's
// test fake can too.
type Enroller interface {
	Enrol(ctx context.Context, enrolToken string, req EnrolRequest) (EnrolResponse, error)
}

// EnsureEnrolled returns a stored credential, or on first run generates a P-256 key + CSR, enrols via
// e using enrolToken, and persists the result. req carries the agent's name/platform/version/
// capabilities; its CSRPEM is filled in here (the private key never leaves the host — only the CSR is
// sent). It errors when there is neither a stored credential nor an enrolment token.
func EnsureEnrolled(ctx context.Context, e Enroller, store *CredentialStore, enrolToken string, req EnrolRequest) (Credential, error) {
	if cred, ok := store.Load(); ok {
		return cred, nil
	}
	if enrolToken == "" {
		return Credential{}, errors.New("fleetclient: no stored credential and no enrolment token provided")
	}
	csrPEM, keyPEM, err := GenerateKeyAndCSR(req.Name)
	if err != nil {
		return Credential{}, err
	}
	req.CSRPEM = string(csrPEM)
	resp, err := e.Enrol(ctx, enrolToken, req)
	if err != nil {
		return Credential{}, fmt.Errorf("fleetclient: enrol: %w", err)
	}
	cred := Credential(resp)
	if err := store.Persist(cred, keyPEM); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

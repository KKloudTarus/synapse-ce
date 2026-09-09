package responsekey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxSigningKeySize = 64 << 10

type signingKeyDocument struct {
	Version    int       `json:"version"`
	PrivateKey string    `json:"private_key"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
}

// Signer holds one bounded-lifetime response-command private key in control-plane memory.
type Signer struct {
	private ed25519.PrivateKey
	key     fleetagent.ResponseCommandSigningKey
}

var _ ports.ResponseCommandSigner = (*Signer)(nil)

// NewSigner validates and copies a response-command private key and its issuance window.
func NewSigner(private ed25519.PrivateKey, notBefore, notAfter time.Time) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: response command private key is malformed", shared.ErrValidation)
	}
	private = append(ed25519.PrivateKey(nil), private...)
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: response command private key has no Ed25519 public key", shared.ErrValidation)
	}
	key, err := fleetagent.NewResponseCommandSigningKey(public, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	return &Signer{private: private, key: key}, nil
}

// LoadSignerFile reads a strict, owner-only JSON private-key document. The private key may be a
// 32-byte seed or a 64-byte Ed25519 private key; it is never returned or logged.
func LoadSignerFile(path string) (*Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: response command signing-key path is required", shared.ErrValidation)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open response command signing key: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat response command signing key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: response command signing key is not a regular file", shared.ErrValidation)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: response command signing key must be owner-only", shared.ErrForbidden)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSigningKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("read response command signing key: %w", err)
	}
	if len(data) > maxSigningKeySize {
		return nil, fmt.Errorf("%w: response command signing key exceeds %d bytes", shared.ErrValidation, maxSigningKeySize)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document signingKeyDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode response command signing key: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode response command signing key: trailing content")
	}
	if document.Version != bundleVersion {
		return nil, fmt.Errorf("%w: response command signing key needs version %d", shared.ErrValidation, bundleVersion)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(document.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("%w: response command private key encoding is malformed", shared.ErrValidation)
	}
	if len(raw) == ed25519.SeedSize {
		raw = ed25519.NewKeyFromSeed(raw)
	}
	return NewSigner(ed25519.PrivateKey(raw), document.NotBefore, document.NotAfter)
}

// Sign binds the signer's fingerprint and signs a complete response command. Existing signatures
// are rejected so callers cannot silently replace an authority decision.
func (s *Signer) Sign(command fleetagent.ResponseCommand) (fleetagent.ResponseCommand, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return fleetagent.ResponseCommand{}, fmt.Errorf("%w: response command signer is unavailable", shared.ErrValidation)
	}
	if strings.TrimSpace(command.Signature) != "" {
		return fleetagent.ResponseCommand{}, fmt.Errorf("%w: response command is already signed", shared.ErrConflict)
	}
	if command.SigningKeyID != "" && command.SigningKeyID != s.key.KeyID {
		return fleetagent.ResponseCommand{}, fmt.Errorf("%w: response command names another signing key", shared.ErrForbidden)
	}
	command.SigningKeyID = s.key.KeyID
	if err := command.Validate(); err != nil {
		return fleetagent.ResponseCommand{}, err
	}
	if err := s.key.UsableAt(command.IssuedAt); err != nil {
		return fleetagent.ResponseCommand{}, err
	}
	if command.NotAfter.After(s.key.NotAfter) {
		return fleetagent.ResponseCommand{}, fmt.Errorf("%w: response command outlives its signing key", shared.ErrForbidden)
	}
	command.Signature = fleetagent.SignResponseCommand(s.private, command)
	return command, nil
}

// SignHalt binds the same dedicated key identity to an endpoint halt-fence command.
func (s *Signer) SignHalt(command fleetagent.ResponseHaltCommand) (fleetagent.ResponseHaltCommand, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return fleetagent.ResponseHaltCommand{}, fmt.Errorf("%w: response command signer is unavailable", shared.ErrValidation)
	}
	if strings.TrimSpace(command.Signature) != "" {
		return fleetagent.ResponseHaltCommand{}, fmt.Errorf("%w: response halt command is already signed", shared.ErrConflict)
	}
	if command.SigningKeyID != "" && command.SigningKeyID != s.key.KeyID {
		return fleetagent.ResponseHaltCommand{}, fmt.Errorf("%w: response halt command names another signing key", shared.ErrForbidden)
	}
	command.SigningKeyID = s.key.KeyID
	if err := command.Validate(); err != nil {
		return fleetagent.ResponseHaltCommand{}, err
	}
	if err := s.key.UsableAt(command.IssuedAt); err != nil {
		return fleetagent.ResponseHaltCommand{}, err
	}
	if command.NotAfter.After(s.key.NotAfter) {
		return fleetagent.ResponseHaltCommand{}, fmt.Errorf("%w: response halt command outlives its signing key", shared.ErrForbidden)
	}
	command.Signature = fleetagent.SignResponseHaltCommand(s.private, command)
	return command, nil
}

// PublicKey returns a defensive copy of the signer metadata used to build endpoint trust bundles.
func (s *Signer) PublicKey() fleetagent.ResponseCommandSigningKey {
	if s == nil {
		return fleetagent.ResponseCommandSigningKey{}
	}
	key := s.key
	key.PublicKey = append(ed25519.PublicKey(nil), s.key.PublicKey...)
	return key
}

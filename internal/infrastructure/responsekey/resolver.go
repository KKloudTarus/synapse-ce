// Package responsekey loads the endpoint's pinned control-plane response-command trust roots.
package responsekey

import (
	"bytes"
	"context"
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

const (
	bundleVersion = 1
	maxBundleSize = 1 << 20
)

type bundle struct {
	Version int         `json:"version"`
	Keys    []bundleKey `json:"keys"`
}

type bundleKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// Resolver is an immutable in-memory view of a validated trust bundle. Rotation is atomic at the
// deployment boundary: replace the file and restart the agent, rather than changing trust mid-command.
type Resolver struct {
	keys map[string]fleetagent.ResponseCommandSigningKey
}

var _ ports.ResponseCommandKeyResolver = (*Resolver)(nil)

// LoadFile reads and validates one pinned trust bundle. Public keys are not secret, but their integrity
// is authority: a group/world-writable bundle is rejected on platforms with Unix permission semantics.
func LoadFile(path string) (*Resolver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%w: response command trust-bundle path is required", shared.ErrValidation)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open response command trust bundle: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat response command trust bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: response command trust bundle is not a regular file", shared.ErrValidation)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: response command trust bundle must not be group/world writable", shared.ErrForbidden)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response command trust bundle: %w", err)
	}
	if len(data) > maxBundleSize {
		return nil, fmt.Errorf("%w: response command trust bundle exceeds %d bytes", shared.ErrValidation, maxBundleSize)
	}
	return New(data)
}

// New validates a trust bundle from bytes and returns an immutable resolver.
func New(data []byte) (*Resolver, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document bundle
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode response command trust bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode response command trust bundle: trailing content")
	}
	if document.Version != bundleVersion || len(document.Keys) == 0 {
		return nil, fmt.Errorf("%w: response command trust bundle needs version %d and at least one key", shared.ErrValidation, bundleVersion)
	}
	resolver := &Resolver{keys: make(map[string]fleetagent.ResponseCommandSigningKey, len(document.Keys))}
	for index, encoded := range document.Keys {
		public, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded.PublicKey))
		if err != nil || len(public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: response command trust key %d has malformed public key", shared.ErrValidation, index)
		}
		key, err := fleetagent.NewResponseCommandSigningKey(ed25519.PublicKey(public), encoded.NotBefore, encoded.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("validate response command trust key %d: %w", index, err)
		}
		if strings.TrimSpace(encoded.KeyID) != key.KeyID {
			return nil, fmt.Errorf("%w: response command trust key %d fingerprint mismatch", shared.ErrForbidden, index)
		}
		key.RevokedAt = encoded.RevokedAt.UTC()
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("validate response command trust key %d: %w", index, err)
		}
		if _, exists := resolver.keys[key.KeyID]; exists {
			return nil, fmt.Errorf("%w: duplicate response command trust key %s", shared.ErrConflict, key.KeyID)
		}
		resolver.keys[key.KeyID] = key
	}
	return resolver, nil
}

// ResolveResponseCommandKey returns a defensive copy of the exact pinned key named by the command.
func (r *Resolver) ResolveResponseCommandKey(ctx context.Context, keyID string) (fleetagent.ResponseCommandSigningKey, error) {
	if err := ctx.Err(); err != nil {
		return fleetagent.ResponseCommandSigningKey{}, err
	}
	key, ok := r.keys[strings.TrimSpace(keyID)]
	if !ok {
		return fleetagent.ResponseCommandSigningKey{}, shared.ErrNotFound
	}
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	return key, nil
}

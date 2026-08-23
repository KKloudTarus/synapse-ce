package fleetclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

const (
	telemetrySigningKeyLifetime     = 30 * 24 * time.Hour
	telemetrySigningKeyRotateBefore = 5 * time.Minute
)

var telemetrySignerMu sync.Mutex

type persistedTelemetrySigner struct {
	PrivateKeyB64 string    `json:"private_key"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

// TelemetrySigner is the private agent-side half plus the exact public lifecycle
// registration it proves possession of. The private key never crosses the API.
type TelemetrySigner struct {
	PrivateKey ed25519.PrivateKey
	Key        fleetagent.AgentSigningKey
}

// NeedsRotation reports whether the signer is absent or too close to expiry to
// safely start another transport cycle.
func (s TelemetrySigner) NeedsRotation(now time.Time) bool {
	if s.Key.KeyID == "" || s.Key.NotAfter.IsZero() {
		return true
	}
	return !now.UTC().Add(telemetrySigningKeyRotateBefore).Before(s.Key.NotAfter)
}

func (s *CredentialStore) telemetrySignerPath() string {
	return filepath.Join(s.dir, "telemetry-signing-key.json")
}

// EnsureTelemetrySigner loads a usable signer or creates one when the signer is
// absent, expired, or inside the bounded pre-expiry rotation window.
func (s *CredentialStore) EnsureTelemetrySigner(agentID string, now time.Time) (TelemetrySigner, error) {
	telemetrySignerMu.Lock()
	defer telemetrySignerMu.Unlock()

	if agentID == "" {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: telemetry signer requires agent id")
	}
	now = now.UTC()
	material, loadErr := s.loadTelemetrySigner(agentID)
	switch {
	case loadErr == nil && now.Before(material.Key.NotBefore):
		return TelemetrySigner{}, fmt.Errorf("fleetclient: persisted telemetry signer is not valid until %s", material.Key.NotBefore)
	case loadErr == nil && !material.NeedsRotation(now):
		return material, nil
	case loadErr != nil && !errors.Is(loadErr, fs.ErrNotExist):
		return TelemetrySigner{}, loadErr
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: generate telemetry signing key: %w", err)
	}
	notBefore := now.Add(-time.Minute).Truncate(time.Second)
	notAfter := now.Add(telemetrySigningKeyLifetime).Truncate(time.Second)
	key, err := BuildTelemetrySigningKey(agentID, priv, notBefore, notAfter)
	if err != nil {
		return TelemetrySigner{}, err
	}
	persisted := persistedTelemetrySigner{
		PrivateKeyB64: base64.StdEncoding.EncodeToString(priv), NotBefore: key.NotBefore, NotAfter: key.NotAfter,
	}
	// #nosec G117 -- this struct intentionally contains a private key. It is written
	// only to the permission-restricted agent state file below (0600) and is never
	// serialized into an HTTP request or log entry.
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: marshal telemetry signer: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: telemetry signer state dir: %w", err)
	}
	if err := WriteSecret(s.telemetrySignerPath(), data, 0o600); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: persist telemetry signer: %w", err)
	}
	return TelemetrySigner{PrivateKey: priv, Key: key}, nil
}

func (s *CredentialStore) loadTelemetrySigner(agentID string) (TelemetrySigner, error) {
	data, err := os.ReadFile(s.telemetrySignerPath())
	if err != nil {
		return TelemetrySigner{}, err
	}
	var persisted persistedTelemetrySigner
	if err := json.Unmarshal(data, &persisted); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: decode telemetry signer: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(persisted.PrivateKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: persisted telemetry private key is invalid")
	}
	priv := ed25519.PrivateKey(append([]byte(nil), raw...))
	key, err := BuildTelemetrySigningKey(agentID, priv, persisted.NotBefore, persisted.NotAfter)
	if err != nil {
		return TelemetrySigner{}, err
	}
	return TelemetrySigner{PrivateKey: priv, Key: key}, nil
}

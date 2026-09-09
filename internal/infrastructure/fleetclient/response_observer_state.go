package fleetclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var responseObserverStateMu sync.Mutex

type persistedResponseVerificationSigner struct {
	PrivateKeyB64 string    `json:"private_key"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

type ResponseVerificationSigner struct {
	PrivateKey ed25519.PrivateKey
	Key        fleetagent.AgentSigningKey
}

func (s ResponseVerificationSigner) NeedsRotation(now time.Time) bool {
	return s.Key.KeyID == "" || s.Key.NotAfter.IsZero() || !now.UTC().Add(telemetrySigningKeyRotateBefore).Before(s.Key.NotAfter)
}

func (s *CredentialStore) responseVerificationSignerPath() string {
	return filepath.Join(s.dir, "response-verification-signing-key.json")
}

func (s *CredentialStore) EnsureResponseVerificationSigner(agentID string, now time.Time) (ResponseVerificationSigner, error) {
	responseObserverStateMu.Lock()
	defer responseObserverStateMu.Unlock()
	if agentID == "" {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: response-verification signer requires agent id")
	}
	now = now.UTC()
	material, loadErr := s.loadResponseVerificationSigner(agentID)
	switch {
	case loadErr == nil && now.Before(material.Key.NotBefore):
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: persisted response-verification signer is not valid until %s", material.Key.NotBefore)
	case loadErr == nil && !material.NeedsRotation(now):
		return material, nil
	case loadErr != nil && !errors.Is(loadErr, fs.ErrNotExist):
		return ResponseVerificationSigner{}, loadErr
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: generate response-verification signing key: %w", err)
	}
	notBefore := now.Add(-time.Minute).Truncate(time.Second)
	notAfter := now.Add(telemetrySigningKeyLifetime).Truncate(time.Second)
	key, err := BuildResponseResultSigningKey(agentID, private, notBefore, notAfter)
	if err != nil {
		return ResponseVerificationSigner{}, err
	}
	persisted := persistedResponseVerificationSigner{
		PrivateKeyB64: base64.StdEncoding.EncodeToString(private), NotBefore: key.NotBefore, NotAfter: key.NotAfter,
	}
	// #nosec G117 -- this is intentionally private key material written only through the 0600 secret writer.
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: marshal response-verification signer: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: response-verification signer state dir: %w", err)
	}
	if err := WriteSecret(s.responseVerificationSignerPath(), data, 0o600); err != nil {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: persist response-verification signer: %w", err)
	}
	return ResponseVerificationSigner{PrivateKey: private, Key: key}, nil
}

func (s *CredentialStore) loadResponseVerificationSigner(agentID string) (ResponseVerificationSigner, error) {
	data, err := os.ReadFile(s.responseVerificationSignerPath())
	if err != nil {
		return ResponseVerificationSigner{}, err
	}
	var persisted persistedResponseVerificationSigner
	if err := json.Unmarshal(data, &persisted); err != nil {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: decode response-verification signer: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(persisted.PrivateKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return ResponseVerificationSigner{}, fmt.Errorf("fleetclient: persisted response-verification private key is invalid")
	}
	private := ed25519.PrivateKey(append([]byte(nil), raw...))
	key, err := BuildResponseResultSigningKey(agentID, private, persisted.NotBefore, persisted.NotAfter)
	if err != nil {
		return ResponseVerificationSigner{}, err
	}
	return ResponseVerificationSigner{PrivateKey: private, Key: key}, nil
}

func (s *CredentialStore) responseVerificationReportPath(attemptKey string) string {
	digest := sha256.Sum256([]byte(attemptKey))
	return filepath.Join(s.dir, "response-verification-outbox", hex.EncodeToString(digest[:])+".json")
}

func (s *CredentialStore) SaveResponseVerificationReport(report fleetagent.ResponseVerificationReport) error {
	if err := report.Validate(); err != nil {
		return err
	}
	responseObserverStateMu.Lock()
	defer responseObserverStateMu.Unlock()
	path := s.responseVerificationReportPath(report.AttemptKey)
	if existingData, err := os.ReadFile(path); err == nil {
		var existing fleetagent.ResponseVerificationReport
		if err := json.Unmarshal(existingData, &existing); err != nil {
			return fmt.Errorf("fleetclient: decode response-verification outbox: %w", err)
		}
		if existing.Signature != report.Signature || !bytes.Equal(fleetagent.ResponseVerificationMessage(existing), fleetagent.ResponseVerificationMessage(report)) {
			return fmt.Errorf("%w: response-verification outbox already contains different signed content", shared.ErrConflict)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("fleetclient: read response-verification outbox: %w", err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("fleetclient: marshal response-verification outbox: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("fleetclient: create response-verification outbox: %w", err)
	}
	if err := WriteSecret(path, data, 0o600); err != nil {
		return fmt.Errorf("fleetclient: persist response-verification outbox: %w", err)
	}
	return nil
}

func (s *CredentialStore) LoadResponseVerificationReport(attemptKey string) (fleetagent.ResponseVerificationReport, bool, error) {
	responseObserverStateMu.Lock()
	defer responseObserverStateMu.Unlock()
	data, err := os.ReadFile(s.responseVerificationReportPath(attemptKey))
	if errors.Is(err, fs.ErrNotExist) {
		return fleetagent.ResponseVerificationReport{}, false, nil
	}
	if err != nil {
		return fleetagent.ResponseVerificationReport{}, false, fmt.Errorf("fleetclient: read response-verification outbox: %w", err)
	}
	var report fleetagent.ResponseVerificationReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fleetagent.ResponseVerificationReport{}, false, fmt.Errorf("fleetclient: decode response-verification outbox: %w", err)
	}
	if err := report.Validate(); err != nil {
		return fleetagent.ResponseVerificationReport{}, false, fmt.Errorf("fleetclient: validate response-verification outbox: %w", err)
	}
	if report.AttemptKey != attemptKey {
		return fleetagent.ResponseVerificationReport{}, false, fmt.Errorf("%w: response-verification outbox attempt identity mismatch", shared.ErrForbidden)
	}
	return report, true, nil
}

func (s *CredentialStore) AcknowledgeResponseVerificationReport(attemptKey string) error {
	responseObserverStateMu.Lock()
	defer responseObserverStateMu.Unlock()
	err := os.Remove(s.responseVerificationReportPath(attemptKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("fleetclient: acknowledge response-verification outbox: %w", err)
	}
	return nil
}

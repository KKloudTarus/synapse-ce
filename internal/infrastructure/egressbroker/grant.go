package egressbroker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	grantVersion     = 1
	grantContext     = "synapse-egress-grant-v1"
	maxGrantLifetime = 5 * time.Minute
)

type grantClaims struct {
	Version       int             `json:"version"`
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	ExecutionKind string          `json:"execution_kind"`
	ExecutionID   string          `json:"execution_id"`
	RunID         string          `json:"run_id"`
	Slot          int             `json:"slot"`
	PID           int             `json:"pid"`
	IssuedAt      int64           `json:"issued_at"`
	ExpiresAt     int64           `json:"expires_at"`
	Rules         []CanonicalRule `json:"rules"`
}

// GrantSigner mints short-lived, one-execution authorizations. Its private key belongs
// only to the trusted control plane; workers and the root broker receive no signing key.
type GrantSigner struct {
	private ed25519.PrivateKey
}

// GrantVerifier verifies grants against one configured control-plane public key.
type GrantVerifier struct {
	public ed25519.PublicKey
}

func NewGrantSigner(seed []byte) (*GrantSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("egress grant seed must be %d bytes", ed25519.SeedSize)
	}
	return &GrantSigner{private: ed25519.NewKeyFromSeed(append([]byte(nil), seed...))}, nil
}

func NewGrantVerifier(encodedPublicKey string) (*GrantVerifier, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode egress grant public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("egress grant public key must be %d bytes", ed25519.PublicKeySize)
	}
	return &GrantVerifier{public: ed25519.PublicKey(append([]byte(nil), decoded...))}, nil
}

func (s *GrantSigner) PublicKey() string {
	public := s.private.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(public)
}

func (s *GrantSigner) Sign(req GrantRequest, now time.Time, lifetime time.Duration) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" || len(req.TenantID) > 200 {
		return "", errors.New("egress grant tenant id is required")
	}
	req.ExecutionKind = strings.TrimSpace(req.ExecutionKind)
	if req.ExecutionKind == "" || len(req.ExecutionKind) > 64 {
		return "", errors.New("egress grant execution kind is required")
	}
	req.ExecutionID = strings.TrimSpace(req.ExecutionID)
	if req.ExecutionID == "" || len(req.ExecutionID) > 200 {
		return "", errors.New("egress grant execution id is required")
	}
	if !runIDPattern.MatchString(req.RunID) {
		return "", errors.New("egress grant run id is invalid")
	}
	if req.Slot < 0 || req.Slot >= 64 {
		return "", errors.New("egress grant slot is invalid")
	}
	if req.PID <= 1 {
		return "", errors.New("egress grant sandbox pid is invalid")
	}
	if lifetime <= 0 || lifetime > maxGrantLifetime {
		return "", fmt.Errorf("egress grant lifetime must be between 1ns and %s", maxGrantLifetime)
	}
	for _, rule := range req.Rules {
		if _, err := parseWireRule(rule); err != nil {
			return "", fmt.Errorf("egress grant rule: %w", err)
		}
	}
	grantID := make([]byte, 16)
	if _, err := rand.Read(grantID); err != nil {
		return "", fmt.Errorf("generate egress grant id: %w", err)
	}
	claims := grantClaims{
		Version:       grantVersion,
		ID:            base64.RawURLEncoding.EncodeToString(grantID),
		TenantID:      req.TenantID,
		ExecutionKind: req.ExecutionKind,
		ExecutionID:   req.ExecutionID,
		RunID:         req.RunID,
		Slot:          req.Slot,
		PID:           req.PID,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(lifetime).Unix(),
		Rules:         append([]CanonicalRule(nil), req.Rules...),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode egress grant: %w", err)
	}
	signature := ed25519.Sign(s.private, grantMessage(payload))
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (v *GrantVerifier) Verify(token string, now time.Time) (grantClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return grantClaims{}, errors.New("malformed egress grant")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return grantClaims{}, errors.New("malformed egress grant payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return grantClaims{}, errors.New("malformed egress grant signature")
	}
	if !ed25519.Verify(v.public, grantMessage(payload), signature) {
		return grantClaims{}, errors.New("invalid egress grant signature")
	}
	var claims grantClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return grantClaims{}, errors.New("invalid egress grant claims")
	}
	if claims.Version != grantVersion || strings.TrimSpace(claims.ID) == "" ||
		strings.TrimSpace(claims.TenantID) == "" || strings.TrimSpace(claims.ExecutionKind) == "" ||
		strings.TrimSpace(claims.ExecutionID) == "" || !runIDPattern.MatchString(claims.RunID) ||
		claims.Slot < 0 || claims.Slot >= 64 || claims.PID <= 1 {
		return grantClaims{}, errors.New("invalid egress grant identity")
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > maxGrantLifetime {
		return grantClaims{}, errors.New("invalid egress grant lifetime")
	}
	if now.Before(issuedAt.Add(-30*time.Second)) || !now.Before(expiresAt) {
		return grantClaims{}, errors.New("egress grant is not currently valid")
	}
	if len(claims.Rules) > 256 {
		return grantClaims{}, errors.New("too many egress grant rules")
	}
	for _, rule := range claims.Rules {
		if _, err := parseWireRule(rule); err != nil {
			return grantClaims{}, fmt.Errorf("invalid egress grant rule: %w", err)
		}
	}
	return claims, nil
}

func grantMessage(payload []byte) []byte {
	message := make([]byte, 0, len(grantContext)+1+len(payload))
	message = append(message, grantContext...)
	message = append(message, 0)
	return append(message, payload...)
}

package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	ResponseHaltCommandProtocolVersion = 1
	responseHaltCommandDomain          = "synapse.response-halt-command.v1"
)

// ResponseHaltCommand durably raises one endpoint's monotonic response fence. It is separate from
// effect commands so a halt can carry no action or target that could itself change production state.
type ResponseHaltCommand struct {
	ProtocolVersion int
	CommandID       shared.ID
	TenantID        shared.ID
	AgentID         shared.ID
	AssetID         shared.ID
	Generation      int64
	AttemptKey      string
	IssuedAt        time.Time
	NotAfter        time.Time
	SigningKeyID    string
	Signature       string
}

func (c ResponseHaltCommand) Validate() error {
	if c.ProtocolVersion != ResponseHaltCommandProtocolVersion || c.CommandID.IsZero() || c.TenantID.IsZero() ||
		c.AgentID.IsZero() || c.AssetID.IsZero() || c.Generation <= 0 || c.IssuedAt.IsZero() ||
		c.NotAfter.IsZero() || !c.NotAfter.After(c.IssuedAt) || strings.TrimSpace(c.AttemptKey) == "" || strings.TrimSpace(c.SigningKeyID) == "" {
		return fmt.Errorf("%w: response halt command is incomplete", shared.ErrValidation)
	}
	return nil
}

func ResponseHaltCommandMessage(c ResponseHaltCommand) []byte {
	payload, _ := json.Marshal(struct {
		Domain          string
		ProtocolVersion int
		CommandID       shared.ID
		TenantID        shared.ID
		AgentID         shared.ID
		AssetID         shared.ID
		Generation      int64
		AttemptKey      string
		IssuedAt        string
		NotAfter        string
		SigningKeyID    string
	}{
		Domain: responseHaltCommandDomain, ProtocolVersion: c.ProtocolVersion, CommandID: c.CommandID,
		TenantID: c.TenantID, AgentID: c.AgentID, AssetID: c.AssetID, Generation: c.Generation, AttemptKey: c.AttemptKey,
		IssuedAt: c.IssuedAt.UTC().Format(time.RFC3339Nano), NotAfter: c.NotAfter.UTC().Format(time.RFC3339Nano),
		SigningKeyID: c.SigningKeyID,
	})
	return payload
}

func ResponseHaltCommandDigest(c ResponseHaltCommand) string {
	digest := sha256.Sum256(ResponseHaltCommandMessage(c))
	return hex.EncodeToString(digest[:])
}

func SignResponseHaltCommand(privateKey ed25519.PrivateKey, command ResponseHaltCommand) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, ResponseHaltCommandMessage(command)))
}

func VerifyResponseHaltCommand(publicKey ed25519.PublicKey, command ResponseHaltCommand) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || command.SigningKeyID != evidence.KeyFingerprint(publicKey) {
		return ErrBadResponseCommandSignature
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(command.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, ResponseHaltCommandMessage(command), signature) {
		return ErrBadResponseCommandSignature
	}
	return nil
}

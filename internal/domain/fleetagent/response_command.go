package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	ResponseCommandProtocolVersion = 2
	responseCommandDomain          = "synapse.response-command.v2"
)

var ErrBadResponseCommandSignature = errors.New("invalid response command signature")

// ResponseCommandSigningKey is one trusted control-plane command key. KeyID is the public-key
// fingerprint; bounded validity and monotonic revocation allow explicit overlap during rotation.
type ResponseCommandSigningKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt time.Time
}

func NewResponseCommandSigningKey(publicKey ed25519.PublicKey, notBefore, notAfter time.Time) (ResponseCommandSigningKey, error) {
	key := ResponseCommandSigningKey{
		KeyID: evidence.KeyFingerprint(publicKey), PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(),
	}
	if err := key.Validate(); err != nil {
		return ResponseCommandSigningKey{}, err
	}
	return key, nil
}

func (k ResponseCommandSigningKey) Validate() error {
	if len(k.PublicKey) != ed25519.PublicKeySize || k.KeyID != evidence.KeyFingerprint(k.PublicKey) ||
		k.NotBefore.IsZero() || k.NotAfter.IsZero() || !k.NotBefore.Before(k.NotAfter) ||
		(!k.RevokedAt.IsZero() && k.RevokedAt.Before(k.NotBefore)) {
		return fmt.Errorf("%w: response command signing key is malformed", shared.ErrValidation)
	}
	return nil
}

func (k ResponseCommandSigningKey) UsableAt(at time.Time) error {
	if err := k.Validate(); err != nil {
		return err
	}
	if at.Before(k.NotBefore) || !at.Before(k.NotAfter) || (!k.RevokedAt.IsZero() && !at.Before(k.RevokedAt)) {
		return fmt.Errorf("%w: response command signing key %s is not usable", shared.ErrForbidden, k.KeyID)
	}
	return nil
}

// ResponseCommand is the control-plane-authorized command accepted by the endpoint response actuator.
// The signature covers every field that can change what executes. The first protocol version deliberately
// supports process stop/restart only; other response kinds require their own target-resolution review.
type ResponseCommand struct {
	ProtocolVersion       int
	CommandID             shared.ID
	TenantID              shared.ID
	AgentID               shared.ID
	AssetID               shared.ID
	EngagementID          shared.ID
	Action                rdom.Action
	ActionDigest          string
	AttemptKey            string
	VerificationChallenge string
	AuthorizationTarget   engagement.Target
	Target                responsesaga.TargetFingerprint
	Reversal              bool
	HaltGeneration        int64
	IssuedAt              time.Time
	NotAfter              time.Time
	SigningKeyID          string
	Signature             string
}

func (c ResponseCommand) Validate() error {
	if c.ProtocolVersion != ResponseCommandProtocolVersion || c.CommandID.IsZero() || c.TenantID.IsZero() ||
		c.AgentID.IsZero() || c.AssetID.IsZero() || c.EngagementID.IsZero() || strings.TrimSpace(c.AttemptKey) == "" ||
		c.IssuedAt.IsZero() || c.NotAfter.IsZero() || !c.NotAfter.After(c.IssuedAt) || c.HaltGeneration < 0 {
		return fmt.Errorf("%w: response command is incomplete", shared.ErrValidation)
	}
	challenge, challengeErr := hex.DecodeString(strings.TrimSpace(c.VerificationChallenge))
	if challengeErr != nil || len(challenge) != sha256.Size || strings.TrimSpace(c.SigningKeyID) == "" {
		return fmt.Errorf("%w: response command has no verification challenge or signing key identity", shared.ErrValidation)
	}
	if err := c.Action.Validate(); err != nil {
		return err
	}
	if c.Action.Kind != rdom.KindStopProcess {
		return fmt.Errorf("%w: response command protocol v2 supports process stop/restart only", shared.ErrValidation)
	}
	if err := c.Target.Validate(); err != nil {
		return err
	}
	if err := c.AuthorizationTarget.Validate(); err != nil {
		return fmt.Errorf("%w: response command authorization target is invalid: %v", shared.ErrValidation, err)
	}
	if c.Target.Kind != responsesaga.FingerprintProcess || c.Target.ProcessAssetID != c.AssetID ||
		c.Action.Target != c.Target.ProcessEntityID || c.AuthorizationTarget.Value != c.Action.Target.String() {
		return fmt.Errorf("%w: response command target is not bound to its authoritative process asset", shared.ErrValidation)
	}
	digest, err := rdom.CanonicalDigest(c.Action)
	if err != nil {
		return err
	}
	if c.ActionDigest != digest {
		return fmt.Errorf("%w: response command action digest mismatch", shared.ErrValidation)
	}
	return nil
}

// ResponseCommandMessage returns the canonical domain-separated bytes signed by the control plane.
func ResponseCommandMessage(c ResponseCommand) []byte {
	payload, _ := json.Marshal(struct {
		Domain                string
		ProtocolVersion       int
		CommandID             shared.ID
		TenantID              shared.ID
		AgentID               shared.ID
		AssetID               shared.ID
		EngagementID          shared.ID
		Action                rdom.Action
		ActionDigest          string
		AttemptKey            string
		VerificationChallenge string
		AuthorizationTarget   engagement.Target
		Target                responsesaga.TargetFingerprint
		Reversal              bool
		HaltGeneration        int64
		IssuedAt              string
		NotAfter              string
		SigningKeyID          string
	}{
		Domain: responseCommandDomain, ProtocolVersion: c.ProtocolVersion, CommandID: c.CommandID,
		TenantID: c.TenantID, AgentID: c.AgentID, AssetID: c.AssetID, EngagementID: c.EngagementID,
		Action: c.Action, ActionDigest: c.ActionDigest, AttemptKey: c.AttemptKey,
		VerificationChallenge: c.VerificationChallenge, AuthorizationTarget: c.AuthorizationTarget, Target: c.Target,
		Reversal: c.Reversal, HaltGeneration: c.HaltGeneration,
		IssuedAt: c.IssuedAt.UTC().Format(time.RFC3339Nano), NotAfter: c.NotAfter.UTC().Format(time.RFC3339Nano),
		SigningKeyID: c.SigningKeyID,
	})
	return payload
}

func ResponseCommandDigest(c ResponseCommand) string {
	digest := sha256.Sum256(ResponseCommandMessage(c))
	return hex.EncodeToString(digest[:])
}

func SignResponseCommand(privateKey ed25519.PrivateKey, c ResponseCommand) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, ResponseCommandMessage(c)))
}

func VerifyResponseCommand(publicKey ed25519.PublicKey, c ResponseCommand) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: response command public key is malformed", shared.ErrValidation)
	}
	if c.SigningKeyID != evidence.KeyFingerprint(publicKey) {
		return fmt.Errorf("%w: response command signing key id does not match its public key", ErrBadResponseCommandSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, ResponseCommandMessage(c), sig) {
		return ErrBadResponseCommandSignature
	}
	return nil
}

type ResponseExecutionState string

const (
	ResponseExecutionPrepared       ResponseExecutionState = "prepared"
	ResponseExecutionExecuting      ResponseExecutionState = "executing"
	ResponseExecutionApplied        ResponseExecutionState = "applied"
	ResponseExecutionOutcomeUnknown ResponseExecutionState = "outcome_unknown"
)

func (s ResponseExecutionState) Valid() bool {
	switch s {
	case ResponseExecutionPrepared, ResponseExecutionExecuting, ResponseExecutionApplied, ResponseExecutionOutcomeUnknown:
		return true
	default:
		return false
	}
}

// ResponseExecutionResult is the local durable command outcome. It is not verification evidence;
// independent post-condition telemetry remains authoritative for VerifiedSucceeded.
type ResponseExecutionResult struct {
	AttemptKey     string
	CommandDigest  string
	LeaseID        string
	State          ResponseExecutionState
	ObservedRadius offensivepolicy.Radius
	AffectedCount  int
	AlreadyApplied bool
	CompletedAt    time.Time
}

func (r ResponseExecutionResult) Validate() error {
	decodedDigest, digestErr := hex.DecodeString(r.CommandDigest)
	if strings.TrimSpace(r.AttemptKey) == "" || strings.TrimSpace(r.LeaseID) == "" || digestErr != nil || len(decodedDigest) != sha256.Size || !r.State.Valid() {
		return fmt.Errorf("%w: response execution result is incomplete", shared.ErrValidation)
	}
	if r.State == ResponseExecutionApplied {
		if !r.ObservedRadius.Valid() || r.AffectedCount < 0 || r.CompletedAt.IsZero() {
			return fmt.Errorf("%w: applied response execution result has no observed effect", shared.ErrValidation)
		}
	} else if r.State == ResponseExecutionOutcomeUnknown {
		if r.CompletedAt.IsZero() {
			return fmt.Errorf("%w: ambiguous response execution result has no completion time", shared.ErrValidation)
		}
		if r.ObservedRadius != "" || r.AffectedCount != 0 || r.AlreadyApplied {
			return fmt.Errorf("%w: ambiguous response execution result cannot claim an observed effect", shared.ErrValidation)
		}
	}
	return nil
}

// SameResponseExecutionResult compares exact command-outcome identity while treating equivalent
// timestamp locations as the same instant.
func SameResponseExecutionResult(left, right ResponseExecutionResult) bool {
	return left.AttemptKey == right.AttemptKey && left.CommandDigest == right.CommandDigest &&
		left.LeaseID == right.LeaseID && left.State == right.State && left.ObservedRadius == right.ObservedRadius &&
		left.AffectedCount == right.AffectedCount && left.AlreadyApplied == right.AlreadyApplied &&
		left.CompletedAt.Equal(right.CompletedAt)
}

const ResponseExecutionJournalVersion = 1

type ResponseExecutionJournalEntry struct {
	Version            int
	Command            ResponseCommand
	CommandDigest      string
	LeaseID            string
	LeaseUntil         time.Time
	State              ResponseExecutionState
	Result             *ResponseExecutionResult
	ResultAcknowledged bool
}

func (e ResponseExecutionJournalEntry) Validate() error {
	if e.Version != ResponseExecutionJournalVersion || strings.TrimSpace(e.Command.Signature) == "" || strings.TrimSpace(e.LeaseID) == "" ||
		e.LeaseUntil.IsZero() || e.LeaseUntil.After(e.Command.NotAfter) || !e.State.Valid() {
		return fmt.Errorf("%w: response execution journal entry is incomplete", shared.ErrValidation)
	}
	if err := e.Command.Validate(); err != nil {
		return err
	}
	if e.CommandDigest != ResponseCommandDigest(e.Command) {
		return fmt.Errorf("%w: response execution journal command digest mismatch", shared.ErrValidation)
	}
	if e.State == ResponseExecutionApplied || e.State == ResponseExecutionOutcomeUnknown {
		if e.Result == nil || e.Result.State != e.State || e.Result.AttemptKey != e.Command.AttemptKey ||
			e.Result.CommandDigest != e.CommandDigest || e.Result.LeaseID != e.LeaseID {
			return fmt.Errorf("%w: terminal response execution journal entry has an unbound result", shared.ErrValidation)
		}
		return e.Result.Validate()
	}
	if e.Result != nil || e.ResultAcknowledged {
		return fmt.Errorf("%w: non-terminal response execution journal entry carries a result", shared.ErrValidation)
	}
	return nil
}

package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const responseVerificationContext = "synapse-response-verification:v1"

var ErrBadResponseVerificationSignature = fmt.Errorf("bad response-verification signature")

// ResponseVerificationReport is a purpose-signed P0 readiness observation produced by a response
// observer, never by the command result endpoint. It carries no verdict, process state, or coverage claim:
// the control plane derives those from accepted endpoint timeline and coverage records. A reversal may
// nominate the distinct replacement entity whose lifecycle the control plane must independently confirm.
type ResponseVerificationReport struct {
	ProtocolVersion            int
	ReportID                   shared.ID
	AgentID                    shared.ID
	HostID                     shared.ID
	AgentSessionID             SessionID
	AssetID                    shared.ID
	EngagementID               shared.ID
	ActionID                   shared.ID
	ActionDigest               string
	AttemptKey                 string
	VerificationChallenge      string
	ReceiptID                  shared.ID
	ReceiptDigest              string
	Target                     responsesaga.TargetFingerprint
	Reversal                   bool
	ObservedAt                 time.Time
	ReplacementProcessEntityID shared.ID
	KeyID                      string
	Signature                  string
}

// ObserverIdentity returns the content-signing principal persisted as source provenance. It is distinct
// from transport authentication and from the response executor identity.
func (r ResponseVerificationReport) ObserverIdentity() string {
	return "agent:" + r.AgentID.String() + ":response-observer:" + strings.TrimSpace(r.KeyID)
}

func (r ResponseVerificationReport) Validate() error {
	if r.ProtocolVersion != TelemetryProtocolVersion || r.ReportID.IsZero() || r.AgentID.IsZero() ||
		r.HostID.IsZero() || r.AgentSessionID == "" || r.AssetID.IsZero() || r.EngagementID.IsZero() || r.ActionID.IsZero() {
		return fmt.Errorf("%w: response-verification report has invalid identity or protocol", shared.ErrValidation)
	}
	challenge, challengeErr := hex.DecodeString(strings.TrimSpace(r.VerificationChallenge))
	receiptDigest, receiptErr := hex.DecodeString(strings.TrimSpace(r.ReceiptDigest))
	if strings.TrimSpace(r.AttemptKey) == "" || r.ReceiptID.IsZero() || challengeErr != nil || len(challenge) != sha256.Size || receiptErr != nil || len(receiptDigest) != sha256.Size ||
		r.ObservedAt.IsZero() || strings.TrimSpace(r.KeyID) == "" || r.Signature == "" {
		return fmt.Errorf("%w: response-verification report has incomplete required fields", shared.ErrValidation)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(r.ActionDigest))
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%w: response-verification report has an invalid action digest", shared.ErrValidation)
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if r.Target.Kind != responsesaga.FingerprintProcess {
		return fmt.Errorf("%w: response-verification protocol currently supports process targets only", shared.ErrValidation)
	}
	if r.AssetID != r.Target.ProcessAssetID {
		return fmt.Errorf("%w: response-verification report asset does not match the target asset", shared.ErrValidation)
	}
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: response-verification report has malformed signature", shared.ErrValidation)
	}
	if !r.Reversal {
		if !r.ReplacementProcessEntityID.IsZero() {
			return fmt.Errorf("%w: process apply readiness cannot nominate a replacement", shared.ErrValidation)
		}
		return nil
	}
	if !r.ReplacementProcessEntityID.IsZero() && r.ReplacementProcessEntityID == r.Target.ProcessEntityID {
		return fmt.Errorf("%w: process reversal readiness replacement must be a distinct entity", shared.ErrValidation)
	}
	return nil
}

// ResponseVerificationMessage is the canonical, domain-separated digest signed by the observer key.
func ResponseVerificationMessage(r ResponseVerificationReport) []byte {
	h := sha256.New()
	write := func(value string) { writeTelemetryCommitField(h, value) }
	write(responseVerificationContext)
	write(strconv.Itoa(r.ProtocolVersion))
	write(r.ReportID.String())
	write(r.AgentID.String())
	write(r.HostID.String())
	write(string(r.AgentSessionID))
	write(r.AssetID.String())
	write(r.EngagementID.String())
	write(r.ActionID.String())
	write(r.ActionDigest)
	write(r.AttemptKey)
	write(r.VerificationChallenge)
	write(r.ReceiptID.String())
	write(r.ReceiptDigest)
	write(string(r.Target.Kind))
	write(r.Target.ProcessAssetID.String())
	write(r.Target.ProcessEntityID.String())
	write(r.Target.FilePath)
	write(strconv.FormatUint(r.Target.FileDevice, 10))
	write(strconv.FormatUint(r.Target.FileInode, 10))
	write(r.Target.FileHash)
	write(r.Target.HostID.String())
	write(strconv.FormatInt(r.Target.NetpolGeneration, 10))
	write(strconv.FormatBool(r.Reversal))
	write(strconv.FormatInt(r.ObservedAt.UTC().UnixNano(), 10))
	write(r.ReplacementProcessEntityID.String())
	write(r.KeyID)
	return h.Sum(nil)
}

func SignResponseVerification(private ed25519.PrivateKey, report ResponseVerificationReport) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, ResponseVerificationMessage(report)))
}

func VerifyResponseVerification(public ed25519.PublicKey, report ResponseVerificationReport) error {
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadResponseVerificationSignature)
	}
	signature, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(public, ResponseVerificationMessage(report), signature) {
		return ErrBadResponseVerificationSignature
	}
	return nil
}

func VerifyResponseVerificationWithKey(key AgentSigningKey, now time.Time, report ResponseVerificationReport) error {
	if key.Purpose != PurposeResponseResult {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, key.KeyID, key.Purpose, PurposeResponseResult)
	}
	if key.AgentID != report.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, key.KeyID, key.AgentID, report.AgentID)
	}
	if report.KeyID != key.KeyID {
		return fmt.Errorf("%w: response report names key %s but was verified against %s", ErrBadResponseVerificationSignature, report.KeyID, key.KeyID)
	}
	if err := key.UsableAt(now); err != nil {
		return err
	}
	return VerifyResponseVerification(key.PublicKey, report)
}

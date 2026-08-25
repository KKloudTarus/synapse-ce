package fleetagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const telemetryGapContext = "synapse-telemetry-gap:v1"

var ErrBadTelemetryGapSignature = errors.New("telemetry gap report signature invalid")

// TelemetryGapReason is the stable wire vocabulary for durable A2 loss evidence.
// It intentionally mirrors the spool reasons without importing usecase ports into domain.
type TelemetryGapReason string

const (
	TelemetryGapQuotaEviction     TelemetryGapReason = "quota_eviction"
	TelemetryGapQuotaBackpressure TelemetryGapReason = "quota_backpressure"
	TelemetryGapCorruptFrame      TelemetryGapReason = "corrupt_frame"
	TelemetryGapTornWrite         TelemetryGapReason = "torn_write"
	TelemetryGapIOFailure         TelemetryGapReason = "io_failure"
	TelemetryGapUnsyncedTail      TelemetryGapReason = "unsynced_tail"
	TelemetryGapStateRecovery     TelemetryGapReason = "state_recovery"
)

func (r TelemetryGapReason) Valid() bool {
	switch r {
	case TelemetryGapQuotaEviction, TelemetryGapQuotaBackpressure, TelemetryGapCorruptFrame,
		TelemetryGapTornWrite, TelemetryGapIOFailure, TelemetryGapUnsyncedTail, TelemetryGapStateRecovery:
		return true
	default:
		return false
	}
}

// TelemetryGapReport is a signed, idempotent report of durable loss discovered by
// the agent spool. GapID is stable across retries and coalescing extensions. The
// server derives/validates AgentID, HostID, AgentSessionID, AssetID and StreamID
// against authenticated state before persisting it.
type TelemetryGapReport struct {
	ProtocolVersion int
	GapID           shared.ID
	AgentID         shared.ID
	HostID          shared.ID
	AgentSessionID  SessionID
	AssetID         shared.ID
	StreamID        shared.ID
	Priority        DeliveryPriority
	Epoch           uint64
	KnownSequence   bool
	FromSequence    uint64
	ToSequence      uint64
	Count           uint64
	Reason          TelemetryGapReason
	FromAt          time.Time
	ToAt            time.Time
	KeyID           string
	Signature       string
}

func (g TelemetryGapReport) Validate() error {
	if g.ProtocolVersion != TelemetryProtocolVersion {
		return fmt.Errorf("%w: unsupported telemetry gap protocol version %d", shared.ErrValidation, g.ProtocolVersion)
	}
	if g.GapID.IsZero() || g.AgentID.IsZero() || g.HostID.IsZero() || g.AssetID.IsZero() || g.StreamID.IsZero() || g.AgentSessionID == "" {
		return fmt.Errorf("%w: telemetry gap report requires gap, agent, host, session, asset and stream identity", shared.ErrValidation)
	}
	if !g.Priority.Valid() || g.Epoch == 0 || g.Epoch > maxTelemetrySequence {
		return fmt.Errorf("%w: telemetry gap report has invalid lane/epoch", shared.ErrValidation)
	}
	if !g.Reason.Valid() || g.Count == 0 {
		return fmt.Errorf("%w: telemetry gap report has invalid reason/count", shared.ErrValidation)
	}
	if g.KnownSequence {
		if g.FromSequence == 0 || g.ToSequence < g.FromSequence || g.ToSequence > maxTelemetrySequence {
			return fmt.Errorf("%w: telemetry gap report has invalid sequence range", shared.ErrValidation)
		}
		if want := g.ToSequence - g.FromSequence + 1; want != g.Count {
			return fmt.Errorf("%w: telemetry gap report count %d disagrees with range size %d", shared.ErrValidation, g.Count, want)
		}
	} else if g.FromSequence != 0 || g.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate telemetry gap cannot claim a sequence range", shared.ErrValidation)
	}
	if g.FromAt.IsZero() || g.ToAt.IsZero() || g.ToAt.Before(g.FromAt) {
		return fmt.Errorf("%w: telemetry gap report has invalid time bounds", shared.ErrValidation)
	}
	if g.KeyID == "" {
		return fmt.Errorf("%w: telemetry gap report has no signing key id", shared.ErrValidation)
	}
	return nil
}

// TelemetryGapMessage is purpose-separated from telemetry-batch signatures and
// length-prefixes every field, preventing free-form IDs/reasons from shifting boundaries.
func TelemetryGapMessage(g TelemetryGapReport) []byte {
	h := sha256.New()
	write := func(v string) { writeTelemetryCommitField(h, v) }
	write(telemetryGapContext)
	write(strconv.Itoa(g.ProtocolVersion))
	write(g.GapID.String())
	write(g.AgentID.String())
	write(g.HostID.String())
	write(string(g.AgentSessionID))
	write(g.AssetID.String())
	write(g.StreamID.String())
	write(strconv.Itoa(int(g.Priority)))
	write(strconv.FormatUint(g.Epoch, 10))
	write(strconv.FormatBool(g.KnownSequence))
	write(strconv.FormatUint(g.FromSequence, 10))
	write(strconv.FormatUint(g.ToSequence, 10))
	write(strconv.FormatUint(g.Count, 10))
	write(string(g.Reason))
	write(strconv.FormatInt(g.FromAt.UTC().UnixNano(), 10))
	write(strconv.FormatInt(g.ToAt.UTC().UnixNano(), 10))
	write(g.KeyID)
	return h.Sum(nil)
}

func SignTelemetryGap(priv ed25519.PrivateKey, g TelemetryGapReport) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, TelemetryGapMessage(g)))
}

func VerifyTelemetryGap(pub ed25519.PublicKey, g TelemetryGapReport) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrBadTelemetryGapSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(g.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadTelemetryGapSignature)
	}
	if !ed25519.Verify(pub, TelemetryGapMessage(g), sig) {
		return ErrBadTelemetryGapSignature
	}
	return nil
}

func VerifyTelemetryGapWithKey(k AgentSigningKey, now time.Time, g TelemetryGapReport) error {
	if k.Purpose != PurposeTelemetryBatch {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, k.KeyID, k.Purpose, PurposeTelemetryBatch)
	}
	if k.AgentID != g.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, k.KeyID, k.AgentID, g.AgentID)
	}
	if g.KeyID != k.KeyID {
		return fmt.Errorf("%w: gap report names key %s but was verified against %s", ErrBadTelemetryGapSignature, g.KeyID, k.KeyID)
	}
	if err := k.UsableAt(now); err != nil {
		return err
	}
	return VerifyTelemetryGap(k.PublicKey, g)
}

package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

const ResponseObservationProtocolVersion = 1

// ResponseObservationRequest asks an independently enrolled agent to emit a signed readiness report.
// It deliberately carries no verdict, process state, or coverage assertion.
type ResponseObservationRequest struct {
	ProtocolVersion       int
	RequestID             shared.ID
	TenantID              shared.ID
	ObserverAgentID       shared.ID
	AssetID               shared.ID
	EngagementID          shared.ID
	ActionID              shared.ID
	ActionDigest          string
	AttemptKey            string
	VerificationChallenge string
	ReceiptID             shared.ID
	ReceiptDigest         string
	Target                responsesaga.TargetFingerprint
	Reversal              bool
	AttemptedAt           time.Time
	IssuedAt              time.Time
	NotAfter              time.Time
}

func (r ResponseObservationRequest) Validate() error {
	if r.ProtocolVersion != ResponseObservationProtocolVersion || r.RequestID.IsZero() || r.TenantID.IsZero() ||
		r.ObserverAgentID.IsZero() || r.AssetID.IsZero() || r.EngagementID.IsZero() || r.ActionID.IsZero() {
		return fmt.Errorf("%w: response-observation request has invalid identity or protocol", shared.ErrValidation)
	}
	digest, digestErr := hex.DecodeString(strings.TrimSpace(r.ActionDigest))
	challenge, challengeErr := hex.DecodeString(strings.TrimSpace(r.VerificationChallenge))
	receiptDigest, receiptErr := hex.DecodeString(strings.TrimSpace(r.ReceiptDigest))
	if strings.TrimSpace(r.AttemptKey) == "" || r.ReceiptID.IsZero() || digestErr != nil || len(digest) != sha256.Size ||
		challengeErr != nil || len(challenge) != sha256.Size || receiptErr != nil || len(receiptDigest) != sha256.Size {
		return fmt.Errorf("%w: response-observation request has invalid action or challenge binding", shared.ErrValidation)
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if r.Target.Kind != responsesaga.FingerprintProcess || r.Target.ProcessAssetID != r.AssetID {
		return fmt.Errorf("%w: response-observation request is not bound to its process asset", shared.ErrValidation)
	}
	if r.AttemptedAt.IsZero() || r.IssuedAt.IsZero() || r.NotAfter.IsZero() ||
		r.IssuedAt.Before(r.AttemptedAt) || !r.IssuedAt.Before(r.NotAfter) {
		return fmt.Errorf("%w: response-observation request has an invalid authorization window", shared.ErrValidation)
	}
	return nil
}

// BoundedProcessObservation is one process lifecycle event independently retained from
// the local durable process sensor. It is intentionally an envelope fragment, not a
// claim about a response outcome.
type BoundedProcessObservation struct {
	BootID     shared.ID
	OccurredAt time.Time
	ObservedAt time.Time
	Process    telemetry.ProcessObservation
}

// ResponseObservation is the only process evidence an observer may submit for an
// addressed request. Forward observations contain an actual target exit. Reversal
// observations additionally contain the unique actual replacement observed later.
type ResponseObservation struct {
	TargetExit  BoundedProcessObservation
	Replacement *BoundedProcessObservation
}

func (o ResponseObservation) ValidateFor(request ResponseObservationRequest) error {
	if o.TargetExit.BootID.IsZero() || o.TargetExit.OccurredAt.IsZero() || o.TargetExit.ObservedAt.IsZero() ||
		o.TargetExit.OccurredAt.After(o.TargetExit.ObservedAt) || o.TargetExit.Process.Kind != "exit" ||
		o.TargetExit.Process.EntityID != request.Target.ProcessEntityID || !o.TargetExit.ObservedAt.After(request.AttemptedAt) {
		return fmt.Errorf("%w: response observation has no observed target exit", shared.ErrValidation)
	}
	if err := o.TargetExit.Process.Validate(); err != nil {
		return err
	}
	if !request.Reversal {
		if o.Replacement != nil {
			return fmt.Errorf("%w: forward response observation has a replacement", shared.ErrValidation)
		}
		return nil
	}
	if o.Replacement == nil || o.Replacement.BootID.IsZero() || o.Replacement.OccurredAt.IsZero() || o.Replacement.ObservedAt.IsZero() ||
		o.Replacement.OccurredAt.After(o.Replacement.ObservedAt) ||
		(o.Replacement.Process.Kind != "exec" && o.Replacement.Process.Kind != "fork") ||
		o.Replacement.Process.EntityID.IsZero() || o.Replacement.Process.EntityID == request.Target.ProcessEntityID ||
		o.Replacement.ObservedAt.Before(o.TargetExit.ObservedAt) || !o.Replacement.ObservedAt.After(request.AttemptedAt) {
		return fmt.Errorf("%w: response reversal has no unique observed replacement", shared.ErrValidation)
	}
	return o.Replacement.Process.Validate()
}

func ResponseObservationRequestDigest(r ResponseObservationRequest) string {
	h := sha256.New()
	write := func(value string) { writeTelemetryCommitField(h, value) }
	write("synapse-response-observation-request:v1")
	write(strconv.Itoa(r.ProtocolVersion))
	write(r.RequestID.String())
	write(r.TenantID.String())
	write(r.ObserverAgentID.String())
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
	write(strconv.FormatBool(r.Reversal))
	write(strconv.FormatInt(r.AttemptedAt.UTC().UnixNano(), 10))
	write(strconv.FormatInt(r.IssuedAt.UTC().UnixNano(), 10))
	write(strconv.FormatInt(r.NotAfter.UTC().UnixNano(), 10))
	return hex.EncodeToString(h.Sum(nil))
}

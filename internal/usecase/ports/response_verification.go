package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AcceptedResponseVerification is the immutable server receipt for one purpose-signed observer report.
type AcceptedResponseVerification struct {
	Report              fleetagent.ResponseVerificationReport
	ObserverID          string
	SignedContentDigest string
	RecordedAt          time.Time
}

func (o AcceptedResponseVerification) Validate() error {
	if err := o.Report.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(o.ObserverID) == "" || o.ObserverID != o.Report.ObserverIdentity() || o.RecordedAt.IsZero() ||
		o.RecordedAt.Before(o.Report.ObservedAt) {
		return fmt.Errorf("%w: accepted response verification has invalid server provenance", shared.ErrValidation)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(o.SignedContentDigest))
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("%w: accepted response verification has invalid signed-content digest", shared.ErrValidation)
	}
	want := sha256.Sum256(fleetagent.ResponseVerificationMessage(o.Report))
	if o.SignedContentDigest != hex.EncodeToString(want[:]) {
		return fmt.Errorf("%w: accepted response verification digest does not match its signed content", shared.ErrValidation)
	}
	return nil
}

func SameAcceptedResponseVerification(left, right AcceptedResponseVerification) bool {
	return left.Report.ReportID == right.Report.ReportID && left.Report.AttemptKey == right.Report.AttemptKey &&
		left.ObserverID == right.ObserverID && left.SignedContentDigest == right.SignedContentDigest
}

type ResponseVerificationStore interface {
	GetResponseVerification(ctx context.Context, attemptKey string) (AcceptedResponseVerification, bool, error)
}

// ResponseTargetEvidenceReceiptStore durably retains immutable server-generated target-primary snapshots.
type ResponseTargetEvidenceReceiptStore interface {
	GetResponseTargetEvidenceReceipt(ctx context.Context, attemptKey string) (fleetagent.ResponseTargetEvidenceReceipt, bool, error)
	AppendResponseTargetEvidenceReceipt(ctx context.Context, receipt fleetagent.ResponseTargetEvidenceReceipt) (fleetagent.ResponseTargetEvidenceReceipt, error)
}

// ResponseVerificationAuditStore atomically commits a signed observation and its audit obligation.
type ResponseVerificationAuditStore interface {
	ResponseVerificationStore
	FleetAuditIntentStore
	AppendResponseVerificationWithAudit(context.Context, AcceptedResponseVerification, FleetAuditIntent) (FleetAuditIntent, error)
}

// ResponseObserverBindingStore resolves server-authorized secondary observers without changing the
// primary host ownership recorded in TelemetryAssetBindingStore.
type ResponseObserverBindingStore interface {
	GetResponseObserverBinding(ctx context.Context, agentID shared.ID) (fleetagent.ResponseObserverBinding, error)
	ListResponseObserverBindings(ctx context.Context, assetID shared.ID) ([]fleetagent.ResponseObserverBinding, error)
}

// ResponseObservationTargetResolver authorizes an authenticated observer to report on a response target.
// Implementations must require both the observer's primary telemetry host binding and a live,
// tenant-owned, operator-assigned response-observer binding; the latter supplies the target asset and
// never changes the primary binding.
type ResponseObservationTargetResolver interface {
	ResolveResponseObservationAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}

// ResponseObserverBindingAuditStore commits an assignment and its exact audit obligation together.
type ResponseObserverBindingAuditStore interface {
	ResponseObserverBindingStore
	FleetAuditIntentStore
	SaveResponseObserverBindingWithAudit(ctx context.Context, binding fleetagent.ResponseObserverBinding, expectedVersion int, intent FleetAuditIntent) (fleetagent.ResponseObserverBinding, FleetAuditIntent, error)
}

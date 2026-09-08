// Package responseobservation runs the endpoint-side, independent response-observation workflow.
package responseobservation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type WorkOrder struct {
	ID         shared.ID
	AssetID    shared.ID
	LeaseID    string
	LeaseUntil time.Time
	Request    *fleetagent.ResponseObservationRequest
}

type Signer struct {
	PrivateKey ed25519.PrivateKey
	Key        fleetagent.AgentSigningKey
}

type SignerStore interface {
	EnsureResponseVerificationSigner(agentID shared.ID, now time.Time) (Signer, error)
}
type ReportOutbox interface {
	LoadResponseVerificationReport(attemptKey string) (fleetagent.ResponseVerificationReport, bool, error)
	SaveResponseVerificationReport(report fleetagent.ResponseVerificationReport) error
	AcknowledgeResponseVerificationReport(attemptKey string) error
}
type KeyRegistrar interface {
	RegisterSigningKey(context.Context, fleetagent.AgentSigningKey, string) error
}
type ReportTransport interface {
	ShipResponseVerification(context.Context, fleetagent.ResponseVerificationReport) error
}
type WorkReporter interface {
	Progress(context.Context, shared.ID, string) error
	SubmitResult(context.Context, shared.ID, string, workorder.State, string) error
}

type Service struct {
	signers SignerStore
	outbox  ReportOutbox
	keys    KeyRegistrar
	reports ReportTransport
	work    WorkReporter
	clock   ports.Clock
	delay   time.Duration
}

func NewService(signers SignerStore, outbox ReportOutbox, keys KeyRegistrar, reports ReportTransport, work WorkReporter, clock ports.Clock, delay time.Duration) (*Service, error) {
	if signers == nil || outbox == nil || keys == nil || reports == nil || work == nil || clock == nil || delay < 0 {
		return nil, fmt.Errorf("%w: response observation service has an incomplete dependency", shared.ErrValidation)
	}
	return &Service{signers: signers, outbox: outbox, keys: keys, reports: reports, work: work, clock: clock, delay: delay}, nil
}

// Observe completes one server-addressed observation. A command result is never
// sufficient: no actual, bounded process evidence means an unknown/failed work item.
func (s *Service) Observe(ctx context.Context, observerAgentID, primaryAssetID, assignedTargetAssetID shared.ID, order WorkOrder) error {
	request := order.Request
	if request == nil || order.ID.IsZero() || strings.TrimSpace(order.LeaseID) == "" || observerAgentID.IsZero() || primaryAssetID.IsZero() || assignedTargetAssetID.IsZero() || primaryAssetID == assignedTargetAssetID ||
		request.RequestID != order.ID || request.ObserverAgentID != observerAgentID || request.AssetID != assignedTargetAssetID || order.AssetID != assignedTargetAssetID {
		return s.fail(ctx, order, "response observation identity binding mismatch")
	}
	if err := request.Validate(); err != nil || request.NotAfter.After(order.LeaseUntil) {
		return s.fail(ctx, order, "invalid response observation request")
	}
	if err := s.work.Progress(ctx, order.ID, order.LeaseID); err != nil {
		return fmt.Errorf("progress response observation work: %w", err)
	}
	report, found, err := s.outbox.LoadResponseVerificationReport(request.AttemptKey)
	if err != nil {
		return fmt.Errorf("load response observation outbox: %w", err)
	}
	if !found {
		if !s.wait(ctx, request.NotAfter, order.LeaseUntil) {
			return fmt.Errorf("%w: response observation window elapsed", shared.ErrForbidden)
		}
		observedAt := s.clock.Now().UTC().Truncate(time.Microsecond)
		if !observedAt.After(request.AttemptedAt) || observedAt.After(request.NotAfter) {
			return fmt.Errorf("%w: response observation time is outside the request window", shared.ErrForbidden)
		}
		signer, err := s.signers.EnsureResponseVerificationSigner(observerAgentID, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("prepare response observer signer: %w", err)
		}
		proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
		if err := s.keys.RegisterSigningKey(ctx, signer.Key, proof); err != nil {
			return fmt.Errorf("register response observer key: %w", err)
		}
		report = fleetagent.ResponseVerificationReport{
			ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: request.RequestID, AgentID: observerAgentID, HostID: observerAgentID,
			AgentSessionID: fleetagent.CanonicalSessionID(observerAgentID), AssetID: request.AssetID, EngagementID: request.EngagementID, ActionID: request.ActionID,
			ActionDigest: request.ActionDigest, AttemptKey: request.AttemptKey, VerificationChallenge: request.VerificationChallenge, ReceiptID: request.ReceiptID, ReceiptDigest: request.ReceiptDigest, Target: request.Target,
			Reversal: request.Reversal, ObservedAt: observedAt, KeyID: signer.Key.KeyID,
		}
		report.Signature = fleetagent.SignResponseVerification(signer.PrivateKey, report)
		if err := s.outbox.SaveResponseVerificationReport(report); err != nil {
			return fmt.Errorf("persist response observation before delivery: %w", err)
		}
	} else if !MatchesRequest(report, *request) {
		return fmt.Errorf("%w: response observation outbox does not match addressed request", shared.ErrForbidden)
	}
	if err := s.reports.ShipResponseVerification(ctx, report); err != nil {
		if permanentlyRefused(err) {
			if deleteErr := s.outbox.AcknowledgeResponseVerificationReport(request.AttemptKey); deleteErr != nil {
				return fmt.Errorf("discard permanently refused response observation: %w", deleteErr)
			}
		}
		return fmt.Errorf("ship response observation: %w", err)
	}
	if err := s.work.SubmitResult(ctx, order.ID, order.LeaseID, workorder.StateSucceeded, "signed response observation accepted"); err != nil {
		return fmt.Errorf("submit response observation result: %w", err)
	}
	if err := s.outbox.AcknowledgeResponseVerificationReport(request.AttemptKey); err != nil {
		return fmt.Errorf("acknowledge response observation outbox: %w", err)
	}
	return nil
}

func (s *Service) fail(ctx context.Context, order WorkOrder, reason string) error {
	if err := s.work.SubmitResult(ctx, order.ID, order.LeaseID, workorder.StateFailed, reason); err != nil {
		return fmt.Errorf("submit failed response observation result: %w", err)
	}
	return nil
}
func (s *Service) wait(ctx context.Context, deadlines ...time.Time) bool {
	deadline := time.Time{}
	for _, candidate := range deadlines {
		if !candidate.IsZero() && (deadline.IsZero() || candidate.Before(deadline)) {
			deadline = candidate
		}
	}
	if s.delay <= 0 {
		return s.clock.Now().Before(deadline)
	}
	if !s.clock.Now().Add(s.delay).Before(deadline) {
		return false
	}
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type statusCoder interface{ ResponseStatusCode() int }

func permanentlyRefused(err error) bool {
	var status statusCoder
	return errors.As(err, &status) && status.ResponseStatusCode() == 410
}
func MatchesRequest(report fleetagent.ResponseVerificationReport, request fleetagent.ResponseObservationRequest) bool {
	return report.ReportID == request.RequestID && report.AgentID == request.ObserverAgentID && report.HostID == request.ObserverAgentID && report.AssetID == request.AssetID && report.EngagementID == request.EngagementID && report.ActionID == request.ActionID && report.ActionDigest == request.ActionDigest && strings.TrimSpace(report.AttemptKey) == strings.TrimSpace(request.AttemptKey) && report.VerificationChallenge == request.VerificationChallenge && report.ReceiptID == request.ReceiptID && report.ReceiptDigest == request.ReceiptDigest && report.Target == request.Target && report.Reversal == request.Reversal && report.ObservedAt.After(request.AttemptedAt) && !report.ObservedAt.After(request.NotAfter)
}

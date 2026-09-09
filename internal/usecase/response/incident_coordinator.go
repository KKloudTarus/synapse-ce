package response

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type incidentResponseAppender interface {
	Get(context.Context, shared.ID) (incident.Incident, error)
	Append(context.Context, shared.ID, int, []incident.IncidentEvent) (incident.Incident, error)
	ListPendingResponseLinks(context.Context) ([]incident.ResponseLink, error)
}

type incidentResponseApplier interface {
	PrepareIncidentResponse(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error)
	Apply(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error)
	VerifiedProvenance(context.Context, shared.ID) (VerificationProvenance, error)
}

// IncidentCoordinator binds the governed response lifecycle to the incident event log. Standalone
// response execution remains available for non-incident workflows, while incident-triggered execution
// cannot run unless its append-only ResponseRequested event is durable first.
type IncidentCoordinator struct {
	responses incidentResponseApplier
	incidents incidentResponseAppender
	clock     ports.Clock
}

func NewIncidentCoordinator(responses incidentResponseApplier, incidents incidentResponseAppender, clock ports.Clock) (*IncidentCoordinator, error) {
	if responses == nil || incidents == nil || clock == nil {
		return nil, fmt.Errorf("%w: incident response coordinator dependencies are required", shared.ErrValidation)
	}
	return &IncidentCoordinator{responses: responses, incidents: incidents, clock: clock}, nil
}

// Apply records the request before admission/execution, then records verification only after the response
// service accepts independently attested telemetry evidence. Retries do not duplicate incident events.
func (c *IncidentCoordinator) Apply(ctx context.Context, incidentID shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, actor string) (Record, error) {
	if incidentID.IsZero() || strings.TrimSpace(actor) == "" {
		return Record{}, fmt.Errorf("%w: incident response requires incident and actor", shared.ErrValidation)
	}
	inc, err := c.incidents.Get(ctx, incidentID)
	if err != nil {
		return Record{}, fmt.Errorf("load incident response provenance: %w", err)
	}
	if inc.EngagementID.IsZero() || inc.AssetID.IsZero() {
		return Record{}, fmt.Errorf("%w: incident lacks authoritative engagement or asset provenance", shared.ErrForbidden)
	}
	if err := action.Validate(); err != nil {
		return Record{}, err
	}
	if err := bindIncidentTarget(inc, action, fingerprint); err != nil {
		return Record{}, err
	}
	if target.Value != action.Target.String() {
		return Record{}, fmt.Errorf("%w: admitted target %q does not match the action target %q", shared.ErrForbidden, target.Value, action.Target)
	}
	requested := incident.ResponseRef{
		ActionID: action.ID, EngagementID: inc.EngagementID, ActionDigest: responseActionDigest(action), Target: fingerprint,
	}
	if _, err := c.responses.PrepareIncidentResponse(ctx, inc.EngagementID, action, target, fingerprint, actor); err != nil {
		return Record{}, fmt.Errorf("prepare incident response action: %w", err)
	}
	if err := c.appendResponseEvent(ctx, incidentID, requested, incident.EventResponseRequested, strings.TrimSpace(actor)); err != nil {
		return Record{}, fmt.Errorf("record incident response request: %w", err)
	}

	rec, applyErr := c.responses.Apply(ctx, inc.EngagementID, action, target, fingerprint, actor)
	if rec.Verification != VerificationSucceeded {
		return rec, applyErr
	}
	provenance, provenanceErr := c.responses.VerifiedProvenance(ctx, action.ID)
	if provenanceErr != nil {
		return rec, errors.Join(applyErr, fmt.Errorf("load verified response provenance: %w", provenanceErr))
	}
	verified, verifyErr := responseRefFromProvenance(provenance)
	if verifyErr != nil {
		return rec, errors.Join(applyErr, verifyErr)
	}
	if !sameIncidentResponseBinding(requested, verified) {
		return rec, errors.Join(applyErr, fmt.Errorf("%w: verified response provenance does not match the incident request", shared.ErrConflict))
	}
	verifiedErr := c.appendResponseEvent(ctx, incidentID, verified, incident.EventResponseVerified, verified.VerifierID)
	if verifiedErr != nil {
		verifiedErr = fmt.Errorf("record incident response verification: %w", verifiedErr)
	}
	return rec, errors.Join(applyErr, verifiedErr)
}

// ReconcileIncidentLinks repairs only the narrow crash window after a response saga durably succeeds
// verification but before the corresponding ResponseVerified event is appended. The link source is the
// append-only incident projection, and verification provenance is reloaded from the response service;
// neither the reconciliation input nor any stored client request can supply provenance.
func (c *IncidentCoordinator) ReconcileIncidentLinks(ctx context.Context) error {
	links, err := c.incidents.ListPendingResponseLinks(ctx)
	if err != nil {
		return fmt.Errorf("list pending incident response links: %w", err)
	}
	var errs []error
	for _, link := range links {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		provenance, err := c.responses.VerifiedProvenance(ctx, link.Response.ActionID)
		if err != nil {
			// A pending, unknown, failed, or otherwise unverified response has no verified provenance. It
			// remains request-only for a later reconciliation run rather than being promoted on inference.
			if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrNotFound) {
				continue
			}
			errs = append(errs, fmt.Errorf("load verified response provenance for incident %s action %s: %w", link.IncidentID, link.Response.ActionID, err))
			continue
		}
		verified, err := responseRefFromProvenance(provenance)
		if err != nil {
			errs = append(errs, fmt.Errorf("validate verified response provenance for incident %s action %s: %w", link.IncidentID, link.Response.ActionID, err))
			continue
		}
		if !sameIncidentResponseBinding(link.Response, verified) {
			errs = append(errs, fmt.Errorf("%w: incident %s response action %s verified provenance does not match the request", shared.ErrConflict, link.IncidentID, link.Response.ActionID))
			continue
		}
		if err := c.appendResponseEvent(ctx, link.IncidentID, verified, incident.EventResponseVerified, verified.VerifierID); err != nil {
			errs = append(errs, fmt.Errorf("record reconciled incident response verification for incident %s action %s: %w", link.IncidentID, link.Response.ActionID, err))
		}
	}
	return errors.Join(errs...)
}

func responseRefFromProvenance(provenance VerificationProvenance) (incident.ResponseRef, error) {
	if shared.IsMachineActor(provenance.VerifierID) {
		return incident.ResponseRef{}, fmt.Errorf("%w: response verification requires a non-machine verifier", shared.ErrForbidden)
	}
	return incident.ResponseRef{
		ActionID: provenance.ActionID, EngagementID: provenance.EngagementID,
		ActionDigest: provenance.ActionDigest, Target: provenance.Target, AttemptKey: provenance.AttemptKey,
		ExecutorID: provenance.ExecutorID, VerifierID: provenance.VerifierID, EvidenceID: provenance.EvidenceID, Verified: true,
	}, nil
}

func (c *IncidentCoordinator) appendResponseEvent(ctx context.Context, incidentID shared.ID, response incident.ResponseRef, kind incident.EventKind, actor string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := c.incidents.Get(ctx, incidentID)
		if err != nil {
			return err
		}
		for _, ref := range current.Responses {
			if ref.ActionID != response.ActionID {
				continue
			}
			if !sameIncidentResponseBinding(ref, response) {
				return fmt.Errorf("%w: incident response action %s has conflicting provenance", shared.ErrConflict, response.ActionID)
			}
			if kind == incident.EventResponseRequested || ref.Verified {
				return nil
			}
		}
		event := incident.IncidentEvent{
			IncidentID: incidentID, Kind: kind, At: c.clock.Now().UTC(), Actor: actor,
			ResponseActionID: response.ActionID, ResponseEngagementID: response.EngagementID,
			ResponseActionDigest: response.ActionDigest, ResponseTarget: response.Target,
			ResponseAttemptKey: response.AttemptKey, ResponseExecutorID: response.ExecutorID,
			ResponseVerifierID: response.VerifierID, ResponseEvidenceID: response.EvidenceID,
			Verified: kind == incident.EventResponseVerified,
		}
		if _, err := c.incidents.Append(ctx, incidentID, current.Revision, []incident.IncidentEvent{event}); err != nil {
			if errors.Is(err, shared.ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
}

func bindIncidentTarget(inc incident.Incident, action rdom.Action, fingerprint responsesaga.TargetFingerprint) error {
	switch action.Kind {
	case rdom.KindStopProcess:
		if fingerprint.Kind != responsesaga.FingerprintProcess || fingerprint.ProcessAssetID != inc.AssetID || fingerprint.ProcessEntityID != action.Target {
			return fmt.Errorf("%w: stop_process must bind the incident asset and process entity", shared.ErrForbidden)
		}
	case rdom.KindIsolateHost:
		if fingerprint.Kind != responsesaga.FingerprintHost || fingerprint.HostID != inc.AssetID || action.Target != inc.AssetID {
			return fmt.Errorf("%w: isolate_host must bind the incident host asset", shared.ErrForbidden)
		}
	case rdom.KindQuarantineFile:
		return fmt.Errorf("%w: quarantine_file is not supported for incident-scoped response without authoritative file asset provenance", shared.ErrForbidden)
	default:
		return fmt.Errorf("%w: unsupported incident response kind %q", shared.ErrForbidden, action.Kind)
	}
	return bindFingerprint(action, fingerprint)
}

func sameIncidentResponseBinding(left, right incident.ResponseRef) bool {
	return left.ActionID == right.ActionID && left.EngagementID == right.EngagementID &&
		left.ActionDigest == right.ActionDigest && left.Target == right.Target
}

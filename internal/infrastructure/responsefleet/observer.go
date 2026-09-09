package responsefleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const observerDispatcherIdentity = "control-plane:response-observation-dispatcher"

type ObserverDispatcher struct {
	work       workService
	agents     ports.FleetAgentStore
	bindings   ports.ResponseObserverBindingStore
	clock      ports.Clock
	ttl        time.Duration
	staleAfter time.Duration
	receipts   *TargetEvidenceReceiptBuilder
}

var _ ports.ResponseObservationDispatcher = (*ObserverDispatcher)(nil)

func NewObserverDispatcher(work workService, agents ports.FleetAgentStore, bindings ports.ResponseObserverBindingStore, clock ports.Clock, ttl, staleAfter time.Duration) (*ObserverDispatcher, error) {
	if work == nil || agents == nil || bindings == nil || clock == nil || ttl <= 0 || staleAfter <= 0 {
		return nil, fmt.Errorf("%w: response observer dispatcher is missing a dependency or positive timing bound", shared.ErrValidation)
	}
	return &ObserverDispatcher{work: work, agents: agents, bindings: bindings, clock: clock, ttl: ttl, staleAfter: staleAfter}, nil
}

func (d *ObserverDispatcher) SetTargetEvidenceReceiptBuilder(builder *TargetEvidenceReceiptBuilder) {
	d.receipts = builder
}

func (d *ObserverDispatcher) EnsureObservation(ctx context.Context, req ports.ResponseVerificationRequest) error {
	if req.TenantID.IsZero() || req.EngagementID.IsZero() || req.Action.ID.IsZero() || req.ExecutorAgentID.IsZero() ||
		req.Target.Kind != "process" || req.Target.ProcessAssetID.IsZero() || strings.TrimSpace(req.AttemptKey) == "" ||
		strings.TrimSpace(req.VerificationChallenge) == "" || req.AttemptedAt.IsZero() || req.DeadlineAt.IsZero() ||
		!req.DeadlineAt.After(req.AttemptedAt) {
		return fmt.Errorf("%w: response observation dispatch request is incomplete", shared.ErrValidation)
	}
	if tenantID, ok := shared.TenantFrom(ctx); !ok || tenantID != req.TenantID {
		return fmt.Errorf("%w: response observation dispatch tenant disagrees with context", shared.ErrForbidden)
	}
	if d.receipts == nil {
		return fmt.Errorf("%w: response observation dispatch lacks target evidence receipt builder", shared.ErrValidation)
	}
	receipt, err := d.receipts.Build(ctx, req)
	if err != nil {
		return fmt.Errorf("build target evidence receipt: %w", err)
	}
	bindings, err := d.bindings.ListResponseObserverBindings(ctx, req.Target.ProcessAssetID)
	if err != nil {
		return fmt.Errorf("list response observers: %w", err)
	}
	now := d.clock.Now().UTC().Truncate(time.Microsecond)
	var selected fleetagent.ResponseObserverBinding
	for _, binding := range bindings {
		if binding.TenantID != req.TenantID || binding.AssetID != req.Target.ProcessAssetID ||
			binding.AgentID == req.ExecutorAgentID || !binding.ActiveAt(now) {
			continue
		}
		agent, err := d.agents.GetAgent(ctx, req.TenantID, binding.AgentID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return fmt.Errorf("read response observer agent %s: %w", binding.AgentID, err)
		}
		if agent.State != fleetagent.StateActive || !agent.LastSeenAt.Add(d.staleAfter).After(now) ||
			!hasCapability(agent.Capabilities, workorder.CapabilityResponseObserve) {
			continue
		}
		if !selected.AgentID.IsZero() && selected.AgentID != binding.AgentID {
			return fmt.Errorf("%w: multiple active response observers are bound to asset %s", shared.ErrConflict, req.Target.ProcessAssetID)
		}
		selected = binding
	}
	if selected.AgentID.IsZero() {
		return fmt.Errorf("%w: no active independent response observer is bound to asset %s", shared.ErrNotFound, req.Target.ProcessAssetID)
	}
	notAfter := now.Add(d.ttl)
	if req.DeadlineAt.Before(notAfter) {
		notAfter = req.DeadlineAt.UTC()
	}
	if selected.ExpiresAt.Before(notAfter) {
		notAfter = selected.ExpiresAt.UTC()
	}
	if !now.Before(notAfter) {
		return fmt.Errorf("%w: response observer binding expires before dispatch", shared.ErrForbidden)
	}
	digest, err := rdom.CanonicalDigest(req.Action)
	if err != nil {
		return err
	}
	idempotencyKey := fmt.Sprintf("response-observation:v1:%s:%s", req.AttemptKey, selected.AgentID)
	if existing, getErr := d.work.GetByIdempotencyKey(ctx, req.TenantID, idempotencyKey); getErr == nil {
		if err := validateObservationOrder(existing, req, selected); err != nil {
			return err
		}
		// Replay the persisted request so a prior post-commit audit outage can be repaired without
		// changing the observation authorization window.
		_, err = d.work.Issue(ctx, observerDispatcherIdentity, ports.FleetWorkIssueInput{
			TenantID: existing.TenantID, AssetID: existing.AssetID, AgentID: existing.AgentID,
			Capability: existing.Capability, AuthorizationID: existing.AuthorizationID,
			IdempotencyKey: existing.IdempotencyKey, NotAfter: existing.NotAfter, TimeBucket: existing.TimeBucket,
			ResponseObserve: existing.ResponseObserve,
		})
		if err != nil {
			return fmt.Errorf("retry response observer work order: %w", err)
		}
		return nil
	} else if !errors.Is(getErr, shared.ErrNotFound) {
		return fmt.Errorf("read response observer work order: %w", getErr)
	}
	request := fleetagent.ResponseObservationRequest{
		ProtocolVersion: fleetagent.ResponseObservationProtocolVersion,
		RequestID:       deterministicCommandID("synapse.response-observation-work-order.v1", req.TenantID.String(), selected.AgentID.String(), req.AttemptKey),
		TenantID:        req.TenantID, ObserverAgentID: selected.AgentID, AssetID: req.Target.ProcessAssetID,
		EngagementID: req.EngagementID, ActionID: req.Action.ID, ActionDigest: digest,
		AttemptKey: req.AttemptKey, VerificationChallenge: req.VerificationChallenge, ReceiptID: receipt.ReceiptID, ReceiptDigest: receipt.Digest, Target: req.Target,
		Reversal: req.Reversal, AttemptedAt: req.AttemptedAt.UTC(), IssuedAt: now, NotAfter: notAfter,
	}
	order, err := d.work.Issue(ctx, observerDispatcherIdentity, ports.FleetWorkIssueInput{
		TenantID: req.TenantID, AssetID: request.AssetID, AgentID: request.ObserverAgentID,
		Capability: workorder.CapabilityResponseObserve, AuthorizationID: request.EngagementID,
		IdempotencyKey: idempotencyKey, NotAfter: request.NotAfter, TimeBucket: req.AttemptedAt.UnixNano(),
		ResponseObserve: &request,
	})
	if err != nil {
		return fmt.Errorf("issue response observer work order: %w", err)
	}
	if order.ResponseObserve == nil || fleetagent.ResponseObservationRequestDigest(*order.ResponseObserve) != fleetagent.ResponseObservationRequestDigest(request) {
		return fmt.Errorf("%w: response observer work-order retry returned different content", shared.ErrConflict)
	}
	return nil
}

func validateObservationOrder(order *workorder.WorkOrder, req ports.ResponseVerificationRequest, selected fleetagent.ResponseObserverBinding) error {
	if order == nil || order.ResponseObserve == nil || order.TenantID != req.TenantID || order.AssetID != req.Target.ProcessAssetID ||
		order.AgentID != selected.AgentID || order.AuthorizationID != req.EngagementID || order.Capability != workorder.CapabilityResponseObserve {
		return fmt.Errorf("%w: persisted response observer work order is not bound to the selected observer", shared.ErrConflict)
	}
	request := order.ResponseObserve
	digest, err := rdom.CanonicalDigest(req.Action)
	if err != nil {
		return err
	}
	if request.ObserverAgentID != selected.AgentID || request.AssetID != selected.AssetID || request.EngagementID != req.EngagementID ||
		request.ActionID != req.Action.ID || request.ActionDigest != digest || request.AttemptKey != req.AttemptKey ||
		request.VerificationChallenge != req.VerificationChallenge || request.Target != req.Target || request.Reversal != req.Reversal ||
		!request.AttemptedAt.Equal(req.AttemptedAt) || request.NotAfter.After(req.DeadlineAt) || request.NotAfter.After(selected.ExpiresAt) {
		return fmt.Errorf("%w: persisted response observer work order disagrees with the verification attempt", shared.ErrConflict)
	}
	return nil
}

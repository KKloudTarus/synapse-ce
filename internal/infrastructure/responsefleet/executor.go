// Package responsefleet dispatches governed response commands through the durable fleet work lane.
package responsefleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultCommandTTL   = 2 * time.Minute
	defaultPollInterval = 100 * time.Millisecond
	executorIdentity    = "control-plane:fleet-response-dispatcher"
)

var ErrEndpointOutcomeUnknown = errors.New("endpoint response execution outcome unknown")

type workService interface {
	Issue(context.Context, string, ports.FleetWorkIssueInput) (*workorder.WorkOrder, error)
	GetByID(context.Context, shared.ID, shared.ID) (*workorder.WorkOrder, error)
	GetByIdempotencyKey(context.Context, shared.ID, string) (*workorder.WorkOrder, error)
	FenceResponses(context.Context, string, shared.ID, int64, string) error
}

// Config bounds command authorization and endpoint-result waiting.
type Config struct {
	CommandTTL      time.Duration
	PollInterval    time.Duration
	AgentStaleAfter time.Duration
}

// Executor is the production response.Executor adapter over signed, leased fleet work orders.
type Executor struct {
	work     workService
	agents   ports.FleetAgentStore
	bindings ports.TelemetryAssetBindingLister
	signer   ports.ResponseCommandSigner
	clock    ports.Clock
	config   Config
}

var _ ports.ResponseExecutor = (*Executor)(nil)

func New(work workService, agents ports.FleetAgentStore, bindings ports.TelemetryAssetBindingLister, signer ports.ResponseCommandSigner, clock ports.Clock, config Config) (*Executor, error) {
	if work == nil || agents == nil || bindings == nil || signer == nil || clock == nil {
		return nil, fmt.Errorf("%w: fleet response executor is missing a dependency", shared.ErrValidation)
	}
	if config.CommandTTL <= 0 {
		config.CommandTTL = defaultCommandTTL
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.AgentStaleAfter <= 0 {
		return nil, fmt.Errorf("%w: fleet response executor requires a positive agent freshness window", shared.ErrValidation)
	}
	return &Executor{work: work, agents: agents, bindings: bindings, signer: signer, clock: clock, config: config}, nil
}

func (*Executor) Identity() string { return executorIdentity }

// Supports limits live fleet execution to the process response implemented by the endpoint actuator.
func (*Executor) Supports(kind rdom.Kind) bool { return kind == rdom.KindStopProcess }

// ResolveAgent chooses the single active, fresh, response-capable agent authoritatively bound to the
// process asset. A missing or ambiguous route fails closed.
func (e *Executor) ResolveAgent(ctx context.Context, tenantID shared.ID, target responsesaga.TargetFingerprint) (shared.ID, error) {
	if tenantID.IsZero() || target.Kind != responsesaga.FingerprintProcess || target.ProcessAssetID.IsZero() {
		return "", fmt.Errorf("%w: fleet response routing requires tenant and process asset identity", shared.ErrValidation)
	}
	if contextTenant, ok := shared.TenantFrom(ctx); ok && contextTenant != tenantID {
		return "", fmt.Errorf("%w: fleet response routing tenant disagrees with context", shared.ErrForbidden)
	}
	bindings, err := e.bindings.ListTelemetryAssetBindings(ctx)
	if err != nil {
		return "", fmt.Errorf("list fleet response asset bindings: %w", err)
	}
	now := e.clock.Now().UTC()
	var selected shared.ID
	for _, binding := range bindings {
		if binding.TenantID != tenantID || binding.AssetID != target.ProcessAssetID {
			continue
		}
		agent, err := e.agents.GetAgent(ctx, tenantID, binding.AgentID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return "", fmt.Errorf("read fleet response agent %s: %w", binding.AgentID, err)
		}
		if agent.State != fleetagent.StateActive || !agent.LastSeenAt.Add(e.config.AgentStaleAfter).After(now) ||
			!hasCapability(agent.Capabilities, workorder.CapabilityResponseProcess) {
			continue
		}
		if !selected.IsZero() && selected != agent.ID {
			return "", fmt.Errorf("%w: multiple response-capable agents are bound to asset %s", shared.ErrConflict, target.ProcessAssetID)
		}
		selected = agent.ID
	}
	if selected.IsZero() {
		return "", fmt.Errorf("%w: no active fresh response-capable agent is bound to asset %s", shared.ErrNotFound, target.ProcessAssetID)
	}
	return selected, nil
}

func (e *Executor) Execute(ctx context.Context, req ports.ResponseExecRequest) (ports.ResponseExecOutcome, error) {
	if err := validateRequest(req); err != nil {
		return ports.ResponseExecOutcome{}, err
	}
	agentID, err := e.ResolveAgent(ctx, req.TenantID, req.Fingerprint)
	if err != nil {
		return ports.ResponseExecOutcome{}, err
	}
	if agentID != req.AgentID {
		return ports.ResponseExecOutcome{}, fmt.Errorf("%w: response executor route changed before dispatch", shared.ErrConflict)
	}
	now := e.clock.Now().UTC()
	notAfter := req.DeadlineAt.UTC()
	if now.Before(req.IssuedAt) || !now.Before(notAfter) {
		return ports.ResponseExecOutcome{}, fmt.Errorf("%w: response dispatch is outside its authorization window", shared.ErrForbidden)
	}
	digest, err := rdom.CanonicalDigest(req.Action)
	if err != nil {
		return ports.ResponseExecOutcome{}, err
	}
	command := fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion,
		CommandID:       responseCommandID(req), TenantID: req.TenantID, AgentID: req.AgentID,
		AssetID: req.Fingerprint.ProcessAssetID, EngagementID: req.EngagementID,
		Action: req.Action, ActionDigest: digest, AttemptKey: req.IdempotencyKey,
		VerificationChallenge: req.VerificationChallenge, AuthorizationTarget: req.AuthorizationTarget,
		Target: req.Fingerprint, Reversal: req.IsReversal,
		HaltGeneration: req.HaltGeneration, IssuedAt: req.IssuedAt.UTC(), NotAfter: notAfter,
	}
	command, err = e.signer.Sign(command)
	if err != nil {
		return ports.ResponseExecOutcome{}, fmt.Errorf("sign fleet response command: %w", err)
	}
	order, err := e.work.Issue(ctx, e.Identity(), ports.FleetWorkIssueInput{
		TenantID: req.TenantID, AssetID: command.AssetID, AgentID: command.AgentID,
		Capability: workorder.CapabilityResponseProcess, AuthorizationID: req.EngagementID,
		IdempotencyKey: req.IdempotencyKey, NotAfter: command.NotAfter,
		TimeBucket: command.IssuedAt.UnixNano(), ResponseCommand: &command,
	})
	if err != nil {
		return ports.ResponseExecOutcome{}, fmt.Errorf("issue fleet response work order: %w", err)
	}
	return e.waitForResult(ctx, req, order.ID, notAfter.Sub(now))
}

// Halt cancels every lower-generation effect order before durably issuing highest-priority signed
// halt commands. Heartbeats independently repeat the monotonic fence for agents that reconnect later.
func (e *Executor) Halt(ctx context.Context, tenantID shared.ID, generation int64) error {
	if tenantID.IsZero() || generation <= 0 {
		return fmt.Errorf("%w: fleet response halt requires tenant and positive generation", shared.ErrValidation)
	}
	if contextTenant, ok := shared.TenantFrom(ctx); ok && contextTenant != tenantID {
		return fmt.Errorf("%w: fleet response halt tenant disagrees with context", shared.ErrForbidden)
	}
	reason := fmt.Sprintf("response halt generation %d", generation)
	if err := e.work.FenceResponses(ctx, e.Identity(), tenantID, generation, reason); err != nil {
		return err
	}
	targets, err := e.haltTargets(ctx, tenantID)
	if err != nil {
		return err
	}
	now := e.clock.Now().UTC()
	for _, target := range targets {
		attemptKey := fmt.Sprintf("response-halt:v1:%s:%d:%s", tenantID, generation, target.agentID)
		if _, err := e.work.GetByIdempotencyKey(ctx, tenantID, attemptKey); err == nil {
			continue
		} else if !errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("read existing response halt work order: %w", err)
		}
		command := fleetagent.ResponseHaltCommand{
			ProtocolVersion: fleetagent.ResponseHaltCommandProtocolVersion,
			CommandID:       deterministicCommandID("synapse.response-halt-work-order.v1", tenantID.String(), target.agentID.String(), attemptKey),
			TenantID:        tenantID, AgentID: target.agentID, AssetID: target.assetID,
			Generation: generation, AttemptKey: attemptKey, IssuedAt: now, NotAfter: now.Add(e.config.CommandTTL),
		}
		command, err = e.signer.SignHalt(command)
		if err != nil {
			return fmt.Errorf("sign fleet response halt command for agent %s: %w", target.agentID, err)
		}
		if _, err := e.work.Issue(ctx, e.Identity(), ports.FleetWorkIssueInput{
			TenantID: tenantID, AssetID: target.assetID, AgentID: target.agentID,
			Capability: workorder.CapabilityResponseHalt, AuthorizationID: shared.ID("response-halt:" + tenantID.String()),
			IdempotencyKey: attemptKey, NotAfter: command.NotAfter, TimeBucket: generation, ResponseHalt: &command,
		}); err != nil {
			return fmt.Errorf("issue response halt work order for agent %s: %w", target.agentID, err)
		}
	}
	return nil
}

func (e *Executor) waitForResult(ctx context.Context, req ports.ResponseExecRequest, orderID shared.ID, remaining time.Duration) (ports.ResponseExecOutcome, error) {
	ticker := time.NewTicker(e.config.PollInterval)
	defer ticker.Stop()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	for {
		order, err := e.work.GetByID(ctx, req.TenantID, orderID)
		if err != nil {
			return ports.ResponseExecOutcome{}, fmt.Errorf("read fleet response work order: %w", err)
		}
		if order.ResponseResult != nil {
			result := *order.ResponseResult
			if result.State == fleetagent.ResponseExecutionOutcomeUnknown {
				return ports.ResponseExecOutcome{}, ErrEndpointOutcomeUnknown
			}
			if result.State != fleetagent.ResponseExecutionApplied || order.State != workorder.StateSucceeded ||
				result.CompletedAt.IsZero() || !result.CompletedAt.Before(req.DeadlineAt) {
				return ports.ResponseExecOutcome{}, fmt.Errorf("%w: fleet response work order has an inconsistent terminal result", shared.ErrConflict)
			}
			return ports.ResponseExecOutcome{
				ObservedRadius: result.ObservedRadius, AffectedCount: result.AffectedCount,
				AlreadyApplied: result.AlreadyApplied, EnforcedHaltGeneration: req.HaltGeneration,
			}, nil
		}
		if order.State.Terminal() {
			return ports.ResponseExecOutcome{}, fmt.Errorf("%w: fleet response work order ended as %s without an execution result", shared.ErrConflict, order.State)
		}
		select {
		case <-ctx.Done():
			return ports.ResponseExecOutcome{}, ctx.Err()
		case <-timer.C:
			return ports.ResponseExecOutcome{}, fmt.Errorf("%w: fleet response work order expired before a durable result", shared.ErrConflict)
		case <-ticker.C:
		}
	}
}

func validateRequest(req ports.ResponseExecRequest) error {
	if req.TenantID.IsZero() || req.EngagementID.IsZero() || req.ActionID.IsZero() || req.AgentID.IsZero() ||
		strings.TrimSpace(req.IdempotencyKey) == "" || req.IssuedAt.IsZero() || req.DeadlineAt.IsZero() ||
		!req.DeadlineAt.After(req.IssuedAt) || req.HaltGeneration < 0 {
		return fmt.Errorf("%w: fleet response execution request is incomplete", shared.ErrValidation)
	}
	if err := req.Action.Validate(); err != nil {
		return err
	}
	if err := req.Fingerprint.Validate(); err != nil {
		return err
	}
	if err := req.AuthorizationTarget.Validate(); err != nil {
		return err
	}
	if req.Action.ID != req.ActionID || req.Action.Target != req.Target || req.Declared != req.Action.BlastRadius ||
		req.Fingerprint.Kind != responsesaga.FingerprintProcess || req.Fingerprint.ProcessEntityID != req.Target ||
		req.AuthorizationTarget.Value != req.Target.String() {
		return fmt.Errorf("%w: fleet response execution request is not bound to its action and process target", shared.ErrValidation)
	}
	wantArgv := req.Action.Argv
	if req.IsReversal {
		wantArgv = req.Action.Reversal.Argv
	}
	if !slices.Equal(req.Argv, wantArgv) {
		return fmt.Errorf("%w: fleet response execution argv differs from the governed action", shared.ErrForbidden)
	}
	return nil
}

func responseCommandID(req ports.ResponseExecRequest) shared.ID {
	return deterministicCommandID("synapse.response-work-order.v1", req.TenantID.String(), req.AgentID.String(), req.IdempotencyKey)
}

func deterministicCommandID(parts ...string) shared.ID {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return shared.ID("response-" + hex.EncodeToString(digest[:]))
}

type haltTarget struct {
	agentID shared.ID
	assetID shared.ID
}

func (e *Executor) haltTargets(ctx context.Context, tenantID shared.ID) ([]haltTarget, error) {
	bindings, err := e.bindings.ListTelemetryAssetBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list response halt asset bindings: %w", err)
	}
	now := e.clock.Now().UTC()
	targets := make([]haltTarget, 0, len(bindings))
	for _, binding := range bindings {
		if binding.TenantID != tenantID {
			continue
		}
		agent, err := e.agents.GetAgent(ctx, tenantID, binding.AgentID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("read response halt agent %s: %w", binding.AgentID, err)
		}
		if agent.State != fleetagent.StateActive || !agent.LastSeenAt.Add(e.config.AgentStaleAfter).After(now) ||
			!hasCapability(agent.Capabilities, workorder.CapabilityResponseHalt) {
			continue
		}
		targets = append(targets, haltTarget{agentID: agent.ID, assetID: binding.AssetID})
	}
	return targets, nil
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if strings.TrimSpace(capability) == want {
			return true
		}
	}
	return false
}

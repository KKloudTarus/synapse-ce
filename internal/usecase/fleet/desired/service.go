// Package fleetdesired reconciles operator-owned desired capabilities for canonical host/cluster
// assets against the latest server-authoritative agent bindings and observed fleet-agent state.
// Reconciliation is read-only: polling fleet health must not create database churn.
package fleetdesired

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssetReader interface {
	GetAssetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// CurrentBinding is the read projection of one server-authoritative agent -> asset binding. The
// reverse relation is intentionally not constrained here: more than one current agent may serve the
// same canonical asset (for example, distinct cluster components). One AgentID, however, may not be
// current for two assets at once.
type CurrentBinding struct {
	TenantID shared.ID
	AssetID  shared.ID
	AgentID  shared.ID
}

type BindingReader interface {
	ListCurrentBindings(ctx context.Context, tenantID shared.ID) ([]CurrentBinding, error)
}

type AgentReader interface {
	ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
}

type Service struct {
	store      ports.FleetDesiredStore
	assets     AssetReader
	bindings   BindingReader
	agents     AgentReader
	audit      ports.AuditLogger
	clock      ports.Clock
	ids        ports.IDGenerator
	staleAfter time.Duration
}

func NewService(store ports.FleetDesiredStore, assets AssetReader, bindings BindingReader, agents AgentReader, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, staleAfter time.Duration) (*Service, error) {
	if store == nil || assets == nil || bindings == nil || agents == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: fleet desired-state service needs store, asset reader, binding reader, agent reader, audit log, clock and id generator", shared.ErrValidation)
	}
	// Fail closed on the coverage window: fleetcoverage.AgentStateFrom treats a non-positive staleAfter as
	// "never stale", which would report a long-idle agent as Healthy/covered — the exact fail-open a
	// coverage-honesty tool must refuse. Require a positive window at construction rather than trust the
	// composition root to pass one.
	if staleAfter <= 0 {
		return nil, fmt.Errorf("%w: fleet desired-state service needs a positive stale-after window, got %s", shared.ErrValidation, staleAfter)
	}
	return &Service{store: store, assets: assets, bindings: bindings, agents: agents, audit: audit, clock: clock, ids: ids, staleAfter: staleAfter}, nil
}

type SetInput struct {
	TenantID     shared.ID
	AssetID      shared.ID
	Capabilities []string
	Actor        shared.ID
}

type ClearInput struct {
	TenantID shared.ID
	AssetID  shared.ID
	Actor    shared.ID
}

// SetDesiredCapabilities replaces one host/cluster asset's desired capability set. PolicyID is stable
// within one lifecycle; a clear followed by recreation receives a new ID. Store CAS on
// (PolicyID,Version) prevents both concurrent lost updates and delete/recreate ABA races.
func (s *Service) SetDesiredCapabilities(ctx context.Context, in SetInput) (*desireddom.State, error) {
	if in.TenantID.IsZero() || in.AssetID.IsZero() || strings.TrimSpace(in.Actor.String()) == "" {
		return nil, fmt.Errorf("%w: desired-state change needs tenant, canonical asset and actor", shared.ErrValidation)
	}
	caps, err := desireddom.NormalizeCapabilities(in.Capabilities)
	if err != nil {
		return nil, err
	}
	if len(caps) == 0 {
		return nil, fmt.Errorf("%w: desired capability set is empty; use ClearDesiredCapabilities", shared.ErrValidation)
	}

	var current *desireddom.State
	if got, getErr := s.store.Get(ctx, in.TenantID, in.AssetID); getErr == nil {
		if err := validateStoredState(got, in.TenantID, in.AssetID); err != nil {
			return nil, err
		}
		current = got
		if slices.Equal(current.Capabilities, caps) {
			return current, nil
		}
	} else if !errors.Is(getErr, shared.ErrNotFound) {
		return nil, fmt.Errorf("read current desired state: %w", getErr)
	}

	version := int64(1)
	policyID := shared.ID("")
	if current != nil {
		if current.Version == 1<<63-1 {
			return nil, fmt.Errorf("%w: desired state version exhausted for asset %s", shared.ErrConflict, in.AssetID)
		}
		version = current.Version + 1
		policyID = current.PolicyID
	}

	// Every semantic change re-validates the canonical subject. Clear remains available as the recovery
	// path if the asset registry is damaged or the observation disappeared.
	subject, err := s.assets.GetAssetByID(ctx, in.TenantID, in.AssetID)
	if err != nil {
		return nil, fmt.Errorf("load desired-state asset: %w", err)
	}
	if subject == nil {
		return nil, fmt.Errorf("%w: asset reader returned nil for asset %s", shared.ErrValidation, in.AssetID)
	}
	if subject.TenantID != in.TenantID || subject.ID != in.AssetID {
		return nil, fmt.Errorf("%w: asset reader returned identity %s/%s, want %s/%s",
			shared.ErrValidation, subject.TenantID, subject.ID, in.TenantID, in.AssetID)
	}
	if !desireddom.SupportedAssetKind(subject.Kind) {
		return nil, fmt.Errorf("%w: desired state may target only host/cluster assets, got %s kind %q",
			shared.ErrValidation, subject.ID, subject.Kind)
	}

	if current == nil {
		policyID = s.ids.NewID()
		if policyID.IsZero() {
			return nil, fmt.Errorf("%w: id generator returned an empty desired policy id", shared.ErrValidation)
		}
	}

	now := s.clock.Now().UTC()
	createdAt := now
	if current != nil {
		createdAt = current.Audit.CreatedAt
	}
	state := &desireddom.State{
		TenantID: in.TenantID, AssetID: in.AssetID, PolicyID: policyID,
		Capabilities: caps, UpdatedBy: in.Actor, Version: version,
		Audit: shared.Audit{CreatedAt: createdAt, UpdatedAt: now},
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if err := s.store.Put(ctx, state); err != nil {
		return nil, fmt.Errorf("store desired state: %w", err)
	}
	s.record(ctx, state, in.Actor, "fleet.desired_capabilities.set", map[string]string{
		"capabilities": strings.Join(caps, ","),
	}, now)
	return state, nil
}

func (s *Service) ClearDesiredCapabilities(ctx context.Context, in ClearInput) error {
	if in.TenantID.IsZero() || in.AssetID.IsZero() || strings.TrimSpace(in.Actor.String()) == "" {
		return fmt.Errorf("%w: desired-state clear needs tenant, canonical asset and actor", shared.ErrValidation)
	}
	current, err := s.store.Get(ctx, in.TenantID, in.AssetID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read desired state before clear: %w", err)
	}
	if err := validateStoredState(current, in.TenantID, in.AssetID); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, in.TenantID, in.AssetID, current.PolicyID, current.Version); err != nil {
		return fmt.Errorf("clear desired state: %w", err)
	}
	now := s.clock.Now().UTC()
	s.record(ctx, current, in.Actor, "fleet.desired_capabilities.clear", map[string]string{
		"previous_capabilities": strings.Join(current.Capabilities, ","),
	}, now)
	return nil
}

func (s *Service) Get(ctx context.Context, tenantID, assetID shared.ID) (*desireddom.State, error) {
	if tenantID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and asset", shared.ErrValidation)
	}
	state, err := s.store.Get(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if err := validateStoredState(state, tenantID, assetID); err != nil {
		return nil, err
	}
	return state, nil
}

type ReconciliationRow struct {
	AssetID       string `json:"asset_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int64  `json:"policy_version"`
	// AgentID is the deterministic witness that satisfied the capability, or the best available
	// representative when the capability is uncovered. Asset coverage does not imply reverse-unique
	// AssetID -> AgentID binding.
	AgentID    string                    `json:"agent_id,omitempty"`
	Capability string                    `json:"capability"`
	Health     fleetcoverage.AgentHealth `json:"agent_health,omitempty"`
	Covered    bool                      `json:"covered"`
	GapReason  desireddom.GapReason      `json:"gap_reason,omitempty"`
	Detail     string                    `json:"detail,omitempty"`
	LastSeen   time.Time                 `json:"last_seen,omitempty"`
}

type observedAgent struct {
	agent  *fleetagent.Agent
	health fleetcoverage.AgentHealth
	caps   map[string]struct{}
}

type bindingEvaluation struct {
	binding  CurrentBinding
	observed observedAgent
	hasAgent bool
	covered  bool
	reason   desireddom.GapReason
	detail   string
	rank     int
}

func (s *Service) Reconcile(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	return s.reconcile(ctx, tenantID, false)
}

func (s *Service) Gaps(ctx context.Context, tenantID shared.ID) ([]ReconciliationRow, error) {
	return s.reconcile(ctx, tenantID, true)
}

func (s *Service) reconcile(ctx context.Context, tenantID shared.ID, gapsOnly bool) ([]ReconciliationRow, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state reconciliation needs a tenant", shared.ErrValidation)
	}
	states, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list desired states: %w", err)
	}
	if len(states) == 0 {
		return []ReconciliationRow{}, nil
	}

	ordered := append([]*desireddom.State(nil), states...)
	desiredIDs := make(map[shared.ID]struct{}, len(ordered))
	rowCount := 0
	for i, desired := range ordered {
		if desired == nil {
			return nil, fmt.Errorf("%w: desired-state snapshot contains nil row at index %d", shared.ErrValidation, i)
		}
		if err := desired.Validate(); err != nil {
			return nil, fmt.Errorf("invalid desired-state snapshot for asset %s: %w", desired.AssetID, err)
		}
		if desired.TenantID != tenantID {
			return nil, fmt.Errorf("%w: desired-state snapshot for asset %s belongs to tenant %s, want %s",
				shared.ErrValidation, desired.AssetID, desired.TenantID, tenantID)
		}
		if _, duplicate := desiredIDs[desired.AssetID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate desired-state row for asset %s", shared.ErrValidation, desired.AssetID)
		}
		desiredIDs[desired.AssetID] = struct{}{}
		rowCount += len(desired.Capabilities)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].AssetID < ordered[j].AssetID })

	bindings, err := s.bindings.ListCurrentBindings(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list current agent bindings: %w", err)
	}
	bindingsByAsset := make(map[shared.ID][]CurrentBinding, min(len(bindings), len(ordered)))
	assetByAgent := make(map[shared.ID]shared.ID, len(bindings))
	for i, binding := range bindings {
		if binding.TenantID.IsZero() || binding.AssetID.IsZero() || binding.AgentID.IsZero() {
			return nil, fmt.Errorf("%w: binding snapshot contains empty identity at index %d", shared.ErrValidation, i)
		}
		if binding.TenantID != tenantID {
			return nil, fmt.Errorf("%w: binding %s/%s belongs to tenant %s, want %s",
				shared.ErrValidation, binding.AssetID, binding.AgentID, binding.TenantID, tenantID)
		}
		if other, duplicate := assetByAgent[binding.AgentID]; duplicate {
			if other == binding.AssetID {
				return nil, fmt.Errorf("%w: duplicate current binding for agent %s and asset %s",
					shared.ErrValidation, binding.AgentID, binding.AssetID)
			}
			return nil, fmt.Errorf("%w: current agent %s is bound to both assets %s and %s",
				shared.ErrValidation, binding.AgentID, other, binding.AssetID)
		}
		assetByAgent[binding.AgentID] = binding.AssetID
		if _, wanted := desiredIDs[binding.AssetID]; wanted {
			bindingsByAsset[binding.AssetID] = append(bindingsByAsset[binding.AssetID], binding)
		}
	}
	for assetID := range bindingsByAsset {
		if len(bindingsByAsset[assetID]) > 1 {
			sort.Slice(bindingsByAsset[assetID], func(i, j int) bool {
				return bindingsByAsset[assetID][i].AgentID < bindingsByAsset[assetID][j].AgentID
			})
		}
	}

	wantedByAgent := make(map[shared.ID]map[string]struct{}, len(bindings))
	for _, desired := range ordered {
		wanted := make(map[string]struct{}, len(desired.Capabilities))
		for _, capability := range desired.Capabilities {
			wanted[capability] = struct{}{}
		}
		for _, binding := range bindingsByAsset[desired.AssetID] {
			wantedByAgent[binding.AgentID] = wanted
		}
	}

	byID := make(map[shared.ID]observedAgent, len(wantedByAgent))
	if len(wantedByAgent) > 0 {
		agents, err := s.agents.ListAgents(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("list fleet agents: %w", err)
		}
		now := s.clock.Now().UTC()
		seenAgents := make(map[shared.ID]struct{}, len(agents))
		for i, agent := range agents {
			if agent == nil {
				return nil, fmt.Errorf("%w: observed-agent snapshot contains nil row at index %d", shared.ErrValidation, i)
			}
			if agent.ID.IsZero() {
				return nil, fmt.Errorf("%w: observed-agent snapshot contains an empty agent id at index %d", shared.ErrValidation, i)
			}
			if agent.TenantID != tenantID {
				return nil, fmt.Errorf("%w: observed agent %s belongs to tenant %s, want %s",
					shared.ErrValidation, agent.ID, agent.TenantID, tenantID)
			}
			if !agent.State.Valid() {
				return nil, fmt.Errorf("%w: observed agent %s has invalid lifecycle state %q",
					shared.ErrValidation, agent.ID, agent.State)
			}
			if _, duplicate := seenAgents[agent.ID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate observed-agent row for agent %s", shared.ErrValidation, agent.ID)
			}
			seenAgents[agent.ID] = struct{}{}
			wanted, relevant := wantedByAgent[agent.ID]
			if !relevant {
				continue
			}
			caps := make(map[string]struct{}, len(wanted))
			for _, raw := range agent.Capabilities {
				capability := strings.TrimSpace(raw)
				if _, keep := wanted[capability]; keep {
					caps[capability] = struct{}{}
				}
			}
			byID[agent.ID] = observedAgent{
				agent:  agent,
				health: fleetcoverage.AgentStateFrom(agent.LastSeenAt, now, s.staleAfter, agent.Revoked(), agent.Decommissioned()),
				caps:   caps,
			}
		}
	}

	outCap := rowCount
	if gapsOnly {
		outCap = 0
	}
	rows := make([]ReconciliationRow, 0, outCap)
	for _, desired := range ordered {
		assetBindings := bindingsByAsset[desired.AssetID]
		for _, capability := range desired.Capabilities {
			row := ReconciliationRow{
				AssetID: desired.AssetID.String(), PolicyID: desired.PolicyID.String(), PolicyVersion: desired.Version,
				Capability: capability,
			}
			if len(assetBindings) == 0 {
				row.GapReason = desireddom.GapAgentMissing
				row.Detail = "no current agent is bound to this desired asset"
				rows = append(rows, row)
				continue
			}
			evaluation, err := selectBindingForCapability(assetBindings, byID, capability)
			if err != nil {
				return nil, err
			}
			row.AgentID = evaluation.binding.AgentID.String()
			row.Covered = evaluation.covered
			row.GapReason = evaluation.reason
			row.Detail = evaluation.detail
			if evaluation.hasAgent {
				row.LastSeen = evaluation.observed.agent.LastSeenAt
				row.Health = evaluation.observed.health
			}
			if gapsOnly && row.Covered {
				continue
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// selectBindingForCapability implements presence semantics for one desired asset capability. Any
// healthy bound agent advertising the capability satisfies it. If none does, the deterministic
// representative is the most informative available state: healthy-but-missing capability, stale,
// missing registry row, revoked, then decommissioned; AgentID order breaks ties. Required replica/node
// cardinality is a separate topology policy and is deliberately not invented by this foundation.
func selectBindingForCapability(bindings []CurrentBinding, byID map[shared.ID]observedAgent, capability string) (bindingEvaluation, error) {
	var best bindingEvaluation
	for _, binding := range bindings {
		obs, exists := byID[binding.AgentID]
		if !exists {
			candidate := bindingEvaluation{
				binding: binding, reason: desireddom.GapAgentMissing, rank: 3,
				detail: "a current binding names an agent with no observed registry row",
			}
			if best.rank == 0 || candidate.rank < best.rank {
				best = candidate
			}
			continue
		}

		candidate := bindingEvaluation{binding: binding, observed: obs, hasAgent: true}
		switch obs.health {
		case fleetcoverage.AgentHealthy:
			if _, advertised := obs.caps[capability]; advertised {
				candidate.covered = true
				return candidate, nil
			}
			candidate.reason = desireddom.GapCapabilityMissing
			candidate.detail = "no healthy bound agent advertises the desired capability"
			candidate.rank = 1
		case fleetcoverage.AgentStale:
			candidate.reason = desireddom.GapAgentStale
			candidate.detail = "no healthy bound agent provides this capability; the selected bound agent heartbeat is stale"
			candidate.rank = 2
		case fleetcoverage.AgentRevoked:
			candidate.reason = desireddom.GapAgentRevoked
			candidate.detail = "no healthy bound agent provides this capability; the selected bound agent was revoked"
			candidate.rank = 4
		case fleetcoverage.AgentDecommissioned:
			candidate.reason = desireddom.GapAgentDecommissioned
			candidate.detail = "no healthy bound agent provides this capability; the selected bound agent was decommissioned"
			candidate.rank = 5
		default:
			return bindingEvaluation{}, fmt.Errorf("%w: derived invalid agent health %q for agent %s",
				shared.ErrValidation, obs.health, binding.AgentID)
		}
		if best.rank == 0 || candidate.rank < best.rank {
			best = candidate
		}
	}
	if best.rank == 0 {
		return bindingEvaluation{}, fmt.Errorf("%w: desired asset binding set is unexpectedly empty", shared.ErrValidation)
	}
	return best, nil
}

func validateStoredState(state *desireddom.State, tenantID, assetID shared.ID) error {
	if state == nil {
		return fmt.Errorf("%w: desired-state store returned a nil row", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("invalid current desired state: %w", err)
	}
	if state.TenantID != tenantID || state.AssetID != assetID {
		return fmt.Errorf("%w: desired-state store returned identity %s/%s, want %s/%s",
			shared.ErrValidation, state.TenantID, state.AssetID, tenantID, assetID)
	}
	return nil
}

// record is intentionally best-effort after a durable mutation. A separate audit sink cannot be made
// atomic with policy persistence here; rolling policy back after an audit failure would create a worse
// split-brain. The audit implementation is responsible for surfacing its delivery failures.
func (s *Service) record(ctx context.Context, state *desireddom.State, actor shared.ID, action string, extra map[string]string, at time.Time) {
	metadata := map[string]string{
		"tenant_id":      state.TenantID.String(),
		"asset_id":       state.AssetID.String(),
		"policy_id":      state.PolicyID.String(),
		"policy_version": fmt.Sprintf("%d", state.Version),
	}
	for k, v := range extra {
		if v != "" {
			metadata[k] = v
		}
	}
	// Audit persistence is tenant-context driven under RLS. Bind the durable policy tenant here rather
	// than trusting caller context so a missing or mismatched context cannot drop or misattribute the
	// audit entry after the desired-state mutation has already committed.
	ctx = shared.WithTenant(ctx, state.TenantID)
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor.String(), Action: action, Target: state.AssetID.String(), Metadata: metadata, At: at,
	})
}

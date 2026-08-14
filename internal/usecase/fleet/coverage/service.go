// Package coverage is the fleet coverage read model (#413, epic #405): a tenant-scoped PROJECTION
// over agents, work orders and the asset model that answers, for each (asset, capability), what the
// coverage verdict is — with unknown/stale/refused/unauthorized/agent-missing kept as distinct states
// (domain/fleetcoverage) rather than collapsed into "clean". It owns no table. A summary that does not
// reconcile with its detail is the exact failure this exists to prevent, so the summary is computed
// from the same rows and a test asserts they reconcile.
package coverage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Narrow consumer-side read ports; the memory/Postgres stores satisfy these.
type (
	AgentLister interface {
		ListAgents(ctx context.Context, tenantID shared.ID) ([]*fleetagent.Agent, error)
	}
	WorkOrderLister interface {
		ListByTenant(ctx context.Context, tenantID shared.ID) ([]*workorder.WorkOrder, error)
	}
	AssetLister interface {
		ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error)
	}
)

// Service computes the coverage read model.
type Service struct {
	agents      AgentLister
	orders      WorkOrderLister
	assets      AssetLister
	clock       ports.Clock
	staleAfter  time.Duration // agent staleness threshold
	freshTarget time.Duration // default per-capability freshness target (0 = no requirement)
}

// NewService validates its dependencies. staleAfter/freshTarget <= 0 disable the respective check.
func NewService(agents AgentLister, orders WorkOrderLister, assets AssetLister, clock ports.Clock, staleAfter, freshTarget time.Duration) (*Service, error) {
	if agents == nil || orders == nil || assets == nil || clock == nil {
		return nil, fmt.Errorf("%w: coverage requires agent/order/asset listers and a clock", shared.ErrValidation)
	}
	return &Service{agents: agents, orders: orders, assets: assets, clock: clock, staleAfter: staleAfter, freshTarget: freshTarget}, nil
}

// AgentRow is one row of the agent-health view.
type AgentRow struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	Platform     string                    `json:"platform"`
	Version      string                    `json:"agent_version"`
	Health       fleetcoverage.AgentHealth `json:"state"`
	LastSeen     time.Time                 `json:"last_seen"`
	Capabilities []string                  `json:"capabilities"`
	CurrentWork  int                       `json:"current_work"`
}

// CoverageRow is one (asset, capability) coverage verdict.
type CoverageRow struct {
	AssetID    string                `json:"asset_id"`
	Capability string                `json:"capability"`
	Verdict    fleetcoverage.Verdict `json:"verdict"`
	Detail     string                `json:"detail,omitempty"`
	LastRun    time.Time             `json:"last_run"`
	AgentID    string                `json:"agent_id,omitempty"`
}

// Summary is the fleet coverage summary; AssetsByVerdict counts coverage ROWS per verdict and MUST sum
// to the number of coverage rows (reconciliation).
type Summary struct {
	AgentsByState       map[fleetcoverage.AgentHealth]int `json:"agents_by_state"`
	RowsByVerdict       map[fleetcoverage.Verdict]int     `json:"rows_by_verdict"`
	OldestPerCapability map[string]time.Time              `json:"oldest_per_capability"`
	AssetsWithoutAgent  int                               `json:"assets_without_agent"`
}

// Agents returns the agent-health rows, optionally filtered to a single health state ("" = all).
func (s *Service) Agents(ctx context.Context, tenantID shared.ID, stateFilter fleetcoverage.AgentHealth) ([]AgentRow, error) {
	agents, err := s.agents.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: list agents: %w", err)
	}
	orders, err := s.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: list work orders: %w", err)
	}
	liveByAgent := map[shared.ID]int{}
	for _, wo := range orders {
		if isLive(wo.State) {
			liveByAgent[wo.AgentID]++
		}
	}
	now := s.clock.Now()
	out := make([]AgentRow, 0, len(agents))
	for _, a := range agents {
		row := AgentRow{
			ID: a.ID.String(), Name: a.Name, Platform: a.Platform, Version: a.AgentVersion,
			Health:       fleetcoverage.AgentStateFrom(a.LastSeenAt, now, s.staleAfter, a.Revoked(), a.Decommissioned()),
			LastSeen:     a.LastSeenAt,
			Capabilities: append([]string(nil), a.Capabilities...),
			CurrentWork:  liveByAgent[a.ID],
		}
		if stateFilter != "" && row.Health != stateFilter {
			continue
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// OrderBrief is a work order summarised for the agent-detail view.
type OrderBrief struct {
	ID         string          `json:"id"`
	Capability string          `json:"capability"`
	AssetID    string          `json:"asset_id"`
	State      workorder.State `json:"state"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// AgentDetail returns one agent's health row plus its recent work orders (most recent first).
// shared.ErrNotFound if the agent does not exist for the tenant.
func (s *Service) AgentDetail(ctx context.Context, tenantID, agentID shared.ID) (AgentRow, []OrderBrief, error) {
	rows, err := s.Agents(ctx, tenantID, "")
	if err != nil {
		return AgentRow{}, nil, err
	}
	var row AgentRow
	found := false
	for _, r := range rows {
		if r.ID == agentID.String() {
			row = r
			found = true
			break
		}
	}
	if !found {
		return AgentRow{}, nil, fmt.Errorf("%w: agent %s", shared.ErrNotFound, agentID)
	}
	orders, err := s.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		return AgentRow{}, nil, fmt.Errorf("coverage: list work orders: %w", err)
	}
	var recent []OrderBrief
	for _, wo := range orders {
		if wo.AgentID != agentID {
			continue
		}
		recent = append(recent, OrderBrief{
			ID: wo.ID.String(), Capability: wo.Capability, AssetID: wo.AssetID.String(),
			State: wo.State, UpdatedAt: wo.Audit.UpdatedAt,
		})
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].UpdatedAt.After(recent[j].UpdatedAt) })
	return row, recent, nil
}

// Coverage returns one row per (asset, capability) that the fleet has attempted (a work order exists),
// with the resolved verdict. Rows are deterministically ordered.
func (s *Service) Coverage(ctx context.Context, tenantID shared.ID) ([]CoverageRow, error) {
	agents, err := s.agents.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: list agents: %w", err)
	}
	orders, err := s.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: list work orders: %w", err)
	}
	assets, err := s.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: list assets: %w", err)
	}

	now := s.clock.Now()
	authorized := map[shared.ID]bool{} // an asset present in the tenant model is within authorization
	for _, a := range assets {
		authorized[a.ID] = true
	}
	liveCapabilities := map[string]bool{} // a capability advertised by at least one HEALTHY agent
	anyLiveAgent := false                 // is there any live agent at all (for assets with no work orders)?
	for _, a := range agents {
		if fleetcoverage.AgentStateFrom(a.LastSeenAt, now, s.staleAfter, a.Revoked(), a.Decommissioned()).Live() {
			anyLiveAgent = true
			for _, c := range a.Capabilities {
				liveCapabilities[c] = true
			}
		}
	}

	// Group orders by (asset, capability).
	type group struct {
		latest    *workorder.WorkOrder
		succeeded *workorder.WorkOrder
	}
	groups := map[[2]string]*group{}
	var order [][2]string
	for _, wo := range orders {
		key := [2]string{wo.AssetID.String(), wo.Capability}
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
			order = append(order, key)
		}
		if g.latest == nil || newer(wo, g.latest) {
			g.latest = wo
		}
		if wo.State == workorder.StateSucceeded && (g.succeeded == nil || newer(wo, g.succeeded)) {
			g.succeeded = wo
		}
	}

	rows := make([]CoverageRow, 0, len(order)+len(assets))
	assetHasRow := map[string]bool{}
	for _, key := range order {
		g := groups[key]
		assetID := shared.ID(key[0])
		capability := key[1]
		assetHasRow[key[0]] = true
		sig := fleetcoverage.Signals{
			Authorized:     authorized[assetID],
			AgentAvailable: liveCapabilities[capability],
			Refused:        g.latest.State == workorder.StateRefused,
			RefusedReason:  g.latest.RefuseReason,
			Complete:       true, // work orders carry no completeness flag; partial is a future signal
		}
		if g.succeeded != nil {
			sig.Assessed = true
			sig.LastAssessed = g.succeeded.Audit.UpdatedAt
			sig.Fresh = fleetcoverage.IsFresh(sig.LastAssessed, now, s.freshTarget)
		}
		verdict, detail := fleetcoverage.Resolve(sig)
		rows = append(rows, CoverageRow{
			AssetID: key[0], Capability: capability, Verdict: verdict, Detail: detail,
			LastRun: sig.LastAssessed, AgentID: g.latest.AgentID.String(),
		})
	}
	// An in-scope asset that has never had ANY work order must still be surfaced — otherwise a fleet
	// where whole assets were never assessed would look fully covered (the exact green-over-unassessed
	// failure this read model exists to prevent). Emit one honest, non-passing row per such asset:
	// agent_missing when no live agent could serve it, otherwise never. Capability "" means "any".
	for _, a := range assets {
		if assetHasRow[a.ID.String()] {
			continue
		}
		verdict, detail := fleetcoverage.Resolve(fleetcoverage.Signals{
			Authorized:     true, // it is in the tenant asset model
			AgentAvailable: anyLiveAgent,
			Complete:       true,
			Assessed:       false, // no work order ever ran
		})
		rows = append(rows, CoverageRow{AssetID: a.ID.String(), Capability: "", Verdict: verdict, Detail: detail})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].AssetID != rows[j].AssetID {
			return rows[i].AssetID < rows[j].AssetID
		}
		return rows[i].Capability < rows[j].Capability
	})
	return rows, nil
}

// Summary computes the fleet summary from the SAME projection rows, so it reconciles with the detail
// by construction (RowsByVerdict sums to len(Coverage rows)).
func (s *Service) Summary(ctx context.Context, tenantID shared.ID) (Summary, error) {
	agentRows, err := s.Agents(ctx, tenantID, "")
	if err != nil {
		return Summary{}, err
	}
	rows, err := s.Coverage(ctx, tenantID)
	if err != nil {
		return Summary{}, err
	}
	sum := Summary{
		AgentsByState:       map[fleetcoverage.AgentHealth]int{},
		RowsByVerdict:       map[fleetcoverage.Verdict]int{},
		OldestPerCapability: map[string]time.Time{},
	}
	for _, a := range agentRows {
		sum.AgentsByState[a.Health]++
	}
	assetsMissingAgent := map[string]bool{}
	for _, r := range rows {
		sum.RowsByVerdict[r.Verdict]++
		if r.Verdict == fleetcoverage.VerdictAgentMissing {
			assetsMissingAgent[r.AssetID] = true
		}
		if !r.LastRun.IsZero() {
			if cur, ok := sum.OldestPerCapability[r.Capability]; !ok || r.LastRun.Before(cur) {
				sum.OldestPerCapability[r.Capability] = r.LastRun
			}
		}
	}
	sum.AssetsWithoutAgent = len(assetsMissingAgent)
	return sum, nil
}

func isLive(st workorder.State) bool {
	return st == workorder.StateIssued || st == workorder.StateClaimed || st == workorder.StateRunning
}

// newer reports whether a is more recent than b by updated time, breaking ties by id for determinism.
func newer(a, b *workorder.WorkOrder) bool {
	if !a.Audit.UpdatedAt.Equal(b.Audit.UpdatedAt) {
		return a.Audit.UpdatedAt.After(b.Audit.UpdatedAt)
	}
	return a.ID > b.ID
}

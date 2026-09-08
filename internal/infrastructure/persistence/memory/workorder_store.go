package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WorkOrderStore is an in-memory ports.WorkOrderStore for dev and tests. It mirrors the Postgres
// store's idempotency, in-flight uniqueness and CAS-transition semantics.
type WorkOrderStore struct {
	mu            sync.Mutex
	byID          map[string]*workorder.WorkOrder // key: tenant|id
	byIdem        map[string]string               // key: tenant|idem -> id
	auditIntents  map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete map[fleetAuditKey]bool
}

// NewWorkOrderStore returns an empty in-memory work order store.
func NewWorkOrderStore() *WorkOrderStore {
	return &WorkOrderStore{
		byID: map[string]*workorder.WorkOrder{}, byIdem: map[string]string{},
		auditIntents: map[fleetAuditKey]ports.FleetAuditIntent{}, auditComplete: map[fleetAuditKey]bool{},
	}
}

var _ ports.WorkOrderAuditStore = (*WorkOrderStore)(nil)

func woKey(tenant, id shared.ID) string { return tenant.String() + "|" + id.String() }
func idemKey(tenant shared.ID, idem string) string {
	return tenant.String() + "|" + idem
}

// ListByTenant returns every work order for the tenant, ordered by id for determinism.
func (s *WorkOrderStore) ListByTenant(_ context.Context, tenantID shared.ID) ([]*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*workorder.WorkOrder
	for _, wo := range s.byID {
		if wo.TenantID == tenantID {
			cp := *wo
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Issue stores wo. It is idempotent by (tenant, idempotency key) and rejects a second live order
// for the same (tenant, asset, capability, time bucket) with shared.ErrConflict.
func (s *WorkOrderStore) Issue(ctx context.Context, wo *workorder.WorkOrder) (*workorder.WorkOrder, error) {
	return s.issue(ctx, wo, nil)
}

func (s *WorkOrderStore) issue(_ context.Context, wo *workorder.WorkOrder, intent *ports.FleetAuditIntent) (*workorder.WorkOrder, error) {
	if wo == nil || wo.TenantID.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueLocked(wo, intent)
}

func (s *WorkOrderStore) issueLocked(wo *workorder.WorkOrder, intent *ports.FleetAuditIntent) (*workorder.WorkOrder, error) {
	if existingID, ok := s.byIdem[idemKey(wo.TenantID, wo.IdempotencyKey)]; ok {
		existing := s.byID[woKey(wo.TenantID, shared.ID(existingID))]
		if !workorder.SameRequest(existing, wo) {
			return nil, shared.ErrConflict
		}
		if intent != nil {
			key := fleetAuditKey{tenant: wo.TenantID, id: intent.ID}
			if existingIntent, found := s.auditIntents[key]; found {
				intent.Entry.At = existingIntent.Entry.At
				if !ports.SameFleetAuditIntent(existingIntent, *intent) {
					return nil, shared.ErrConflict
				}
			} else {
				s.auditIntents[key] = cloneMemoryFleetAuditIntent(*intent)
			}
		}
		cp := *existing
		return &cp, nil
	}
	for _, o := range s.byID {
		if o.TenantID == wo.TenantID && o.AssetID == wo.AssetID && o.Capability == wo.Capability &&
			o.TimeBucket == wo.TimeBucket && isLive(o.State) {
			return nil, shared.ErrConflict
		}
	}
	cp := *wo
	s.byID[woKey(wo.TenantID, wo.ID)] = &cp
	s.byIdem[idemKey(wo.TenantID, wo.IdempotencyKey)] = wo.ID.String()
	if intent != nil {
		s.auditIntents[fleetAuditKey{tenant: wo.TenantID, id: intent.ID}] = cloneMemoryFleetAuditIntent(*intent)
	}
	out := *wo
	return &out, nil
}

// IssueWithAudit atomically persists a work order and its exact issuance audit obligation.
func (s *WorkOrderStore) IssueWithAudit(ctx context.Context, wo *workorder.WorkOrder, intent ports.FleetAuditIntent) (*workorder.WorkOrder, ports.FleetAuditIntent, error) {
	intent, err := intent.Normalize()
	if err != nil {
		return nil, ports.FleetAuditIntent{}, err
	}
	stored, err := s.issue(ctx, wo, &intent)
	if err != nil {
		return nil, ports.FleetAuditIntent{}, err
	}
	return stored, intent, nil
}

func (s *WorkOrderStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenant && !s.auditComplete[key] {
			out = append(out, cloneMemoryFleetAuditIntent(intent))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Entry.At.Equal(out[j].Entry.At) {
			return out[i].Entry.At.Before(out[j].Entry.At)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func workOrderAuditIntent(id, actor, action, target string, at time.Time, metadata map[string]string) (ports.FleetAuditIntent, error) {
	metadata["idempotency_key"] = id
	return (ports.FleetAuditIntent{ID: id, Entry: ports.AuditEntry{Actor: actor, Action: action, Target: target, At: at, Metadata: metadata}}).Normalize()
}

func (s *WorkOrderStore) ClaimWithAudit(_ context.Context, tenantID, agentID shared.ID, max int, now time.Time, leaseID string, leaseUntil time.Time, actor string) ([]*workorder.WorkOrder, []ports.FleetAuditIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var eligible []*workorder.WorkOrder
	for _, o := range s.byID {
		if o.TenantID != tenantID || o.AgentID != agentID {
			continue
		}
		if (o.State == workorder.StateClaimed || o.State == workorder.StateRunning) && !o.LeaseUntil.IsZero() && !o.LeaseUntil.After(now) && o.NotAfter.After(now) {
			o.State, o.LeaseID, o.LeaseUntil, o.Audit.UpdatedAt = workorder.StateIssued, "", time.Time{}, now
		}
		if (o.State == workorder.StateIssued || o.State == workorder.StateClaimed || o.State == workorder.StateRunning) && !o.NotAfter.After(now) {
			o.State, o.Audit.UpdatedAt = workorder.StateExpired, now
		}
		if o.State == workorder.StateIssued && o.NotAfter.After(now) {
			eligible = append(eligible, o)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if !eligible[i].Audit.CreatedAt.Equal(eligible[j].Audit.CreatedAt) {
			return eligible[i].Audit.CreatedAt.Before(eligible[j].Audit.CreatedAt)
		}
		return eligible[i].ID < eligible[j].ID
	})
	out := make([]*workorder.WorkOrder, 0, max)
	intents := make([]ports.FleetAuditIntent, 0, max)
	for _, o := range eligible {
		if len(out) >= max {
			break
		}
		o.State, o.LeaseID, o.LeaseUntil, o.Audit.UpdatedAt = workorder.StateClaimed, leaseID, leaseUntil, now
		if o.LeaseUntil.After(o.NotAfter) {
			o.LeaseUntil = o.NotAfter
		}
		key := "work_order.claimed:v1:" + tenantID.String() + ":" + o.ID.String() + ":" + leaseID
		intent, err := workOrderAuditIntent(key, actor, "work_order.claimed", o.ID.String(), now, map[string]string{"tenant_id": tenantID.String(), "agent_id": agentID.String()})
		if err != nil {
			return nil, nil, err
		}
		s.auditIntents[fleetAuditKey{tenant: tenantID, id: intent.ID}] = cloneMemoryFleetAuditIntent(intent)
		cp := *o
		out, intents = append(out, &cp), append(intents, intent)
	}
	return out, intents, nil
}

func (s *WorkOrderStore) TransitionLeasedWithAudit(_ context.Context, tenantID, id shared.ID, leaseID string, to workorder.State, reason string, expected workorder.State, now time.Time, actor string) (ports.FleetAuditIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.byID[woKey(tenantID, id)]
	if !found {
		return ports.FleetAuditIntent{}, shared.ErrNotFound
	}
	if o.State != expected || o.LeaseID != leaseID || (to == workorder.StateRunning && (!o.NotAfter.After(now) || !o.LeaseUntil.After(now))) {
		return ports.FleetAuditIntent{}, shared.ErrConflict
	}
	o.State, o.RefuseReason, o.Audit.UpdatedAt = to, reason, now
	intent, err := workOrderAuditIntent("work_order.transitioned:v1:"+tenantID.String()+":"+id.String()+":"+string(to), actor, "work_order.transitioned", id.String(), now, map[string]string{"tenant_id": tenantID.String(), "from": string(expected), "to": string(to), "reason": reason})
	if err != nil {
		return ports.FleetAuditIntent{}, err
	}
	s.auditIntents[fleetAuditKey{tenant: tenantID, id: intent.ID}] = cloneMemoryFleetAuditIntent(intent)
	return intent, nil
}

func (s *WorkOrderStore) CompleteResponseWithAudit(_ context.Context, tenantID, id shared.ID, result fleetagent.ResponseExecutionResult, reason string, now time.Time, actor string) (bool, ports.FleetAuditIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.byID[woKey(tenantID, id)]
	if !found {
		return false, ports.FleetAuditIntent{}, shared.ErrNotFound
	}
	changed, err := o.CompleteResponse(result, reason, now)
	if err != nil || !changed {
		return changed, ports.FleetAuditIntent{}, err
	}
	key := "work-order-response-completed:v1:" + tenantID.String() + ":" + id.String() + ":" + result.AttemptKey
	intent, err := workOrderAuditIntent(key, actor, "work_order.response_completed", id.String(), result.CompletedAt.UTC(), map[string]string{"tenant_id": tenantID.String(), "execution_state": string(result.State), "attempt_key": result.AttemptKey, "command_digest": result.CommandDigest, "reason": reason})
	if err != nil {
		return false, ports.FleetAuditIntent{}, err
	}
	s.auditIntents[fleetAuditKey{tenant: tenantID, id: intent.ID}] = cloneMemoryFleetAuditIntent(intent)
	return true, intent, nil
}

func (s *WorkOrderStore) CancelResponsesBelowGenerationWithAudit(_ context.Context, tenantID shared.ID, generation int64, reason string, now time.Time, actor string) (int, ports.FleetAuditIntent, error) {
	if generation <= 0 {
		return 0, ports.FleetAuditIntent{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cancelled := 0
	for _, order := range s.byID {
		if order.TenantID == tenantID && order.Capability == workorder.CapabilityResponseProcess && isLive(order.State) && order.ResponseCommand != nil && order.ResponseCommand.HaltGeneration < generation {
			order.State, order.RefuseReason, order.Audit.UpdatedAt = workorder.StateCancelled, reason, now
			cancelled++
		}
	}
	key := "work_order.responses_fenced:v1:" + tenantID.String() + ":" + fmt.Sprint(generation)
	intent, err := workOrderAuditIntent(key, actor, "work_order.responses_fenced", tenantID.String(), now, map[string]string{"tenant_id": tenantID.String(), "generation": fmt.Sprint(generation), "cancelled": fmt.Sprint(cancelled), "reason": reason})
	if err != nil {
		return 0, ports.FleetAuditIntent{}, err
	}
	s.auditIntents[fleetAuditKey{tenant: tenantID, id: intent.ID}] = cloneMemoryFleetAuditIntent(intent)
	return cancelled, intent, nil
}

func (s *WorkOrderStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fleetAuditKey{tenant: tenant, id: id}
	if _, found := s.auditIntents[key]; !found {
		return shared.ErrNotFound
	}
	s.auditComplete[key] = true
	return nil
}

// GetByID returns the order or shared.ErrNotFound.
func (s *WorkOrderStore) GetByID(_ context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[woKey(tenantID, id)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *o
	return &cp, nil
}

// GetByIdempotencyKey returns the order for an idempotency key or shared.ErrNotFound.
func (s *WorkOrderStore) GetByIdempotencyKey(_ context.Context, tenantID shared.ID, idempotencyKey string) (*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, found := s.byIdem[idemKey(tenantID, idempotencyKey)]
	if !found {
		return nil, shared.ErrNotFound
	}
	order, found := s.byID[woKey(tenantID, shared.ID(id))]
	if !found {
		return nil, shared.ErrNotFound
	}
	copy := *order
	return &copy, nil
}

// Claim atomically moves up to max unexpired issued orders addressed to agentID into claimed.
func (s *WorkOrderStore) Claim(_ context.Context, tenantID, agentID shared.ID, max int, now time.Time, leaseID string, leaseUntil time.Time) ([]*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var eligible []*workorder.WorkOrder
	for _, o := range s.byID {
		if o.TenantID != tenantID || o.AgentID != agentID {
			continue
		}
		if (o.State == workorder.StateClaimed || o.State == workorder.StateRunning) && !o.LeaseUntil.IsZero() && !o.LeaseUntil.After(now) && o.NotAfter.After(now) {
			o.State = workorder.StateIssued
			o.LeaseID = ""
			o.LeaseUntil = time.Time{}
			o.Audit.UpdatedAt = now
		}
		if (o.State == workorder.StateIssued || o.State == workorder.StateClaimed || o.State == workorder.StateRunning) && !o.NotAfter.After(now) {
			o.State = workorder.StateExpired
			o.Audit.UpdatedAt = now
		}
		if o.State == workorder.StateIssued && o.NotAfter.After(now) {
			eligible = append(eligible, o)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if !eligible[i].Audit.CreatedAt.Equal(eligible[j].Audit.CreatedAt) {
			return eligible[i].Audit.CreatedAt.Before(eligible[j].Audit.CreatedAt)
		}
		return eligible[i].ID < eligible[j].ID
	})
	var out []*workorder.WorkOrder
	for _, o := range eligible {
		if len(out) >= max {
			break
		}
		o.State = workorder.StateClaimed
		o.LeaseID = leaseID
		o.LeaseUntil = leaseUntil
		if o.LeaseUntil.After(o.NotAfter) {
			o.LeaseUntil = o.NotAfter
		}
		o.Audit.UpdatedAt = now
		cp := *o
		out = append(out, &cp)
	}
	return out, nil
}

// Transition applies to with an optimistic expected-state check: shared.ErrNotFound when the order
// does not exist under the tenant, shared.ErrConflict when its state no longer matches expected.
func (s *WorkOrderStore) Transition(_ context.Context, tenantID, id shared.ID, to workorder.State, reason string, expected workorder.State, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[woKey(tenantID, id)]
	if !ok {
		return shared.ErrNotFound
	}
	if o.State != expected {
		return shared.ErrConflict
	}
	o.State = to
	o.RefuseReason = reason
	o.Audit.UpdatedAt = now
	return nil
}

// TransitionLeased applies a transition only while the presented lease still owns the order.
func (s *WorkOrderStore) TransitionLeased(_ context.Context, tenantID, id shared.ID, leaseID string, to workorder.State, reason string, expected workorder.State, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.byID[woKey(tenantID, id)]
	if !found {
		return shared.ErrNotFound
	}
	if order.State != expected || order.LeaseID != leaseID {
		return shared.ErrConflict
	}
	if to == workorder.StateRunning && (!order.NotAfter.After(now) || !order.LeaseUntil.After(now)) {
		return shared.ErrConflict
	}
	order.State = to
	order.RefuseReason = reason
	order.Audit.UpdatedAt = now
	return nil
}

// CompleteResponse records an exact response execution result under the current lease.
func (s *WorkOrderStore) CompleteResponse(_ context.Context, tenantID, id shared.ID, result fleetagent.ResponseExecutionResult, reason string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.byID[woKey(tenantID, id)]
	if !found {
		return false, shared.ErrNotFound
	}
	return order.CompleteResponse(result, reason, now)
}

// CancelResponsesBelowGeneration cancels live response commands carrying an older halt generation.
func (s *WorkOrderStore) CancelResponsesBelowGeneration(_ context.Context, tenantID shared.ID, generation int64, reason string, now time.Time) (int, error) {
	if generation <= 0 {
		return 0, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cancelled := 0
	for _, order := range s.byID {
		if order.TenantID == tenantID && order.Capability == workorder.CapabilityResponseProcess && isLive(order.State) &&
			order.ResponseCommand != nil && order.ResponseCommand.HaltGeneration < generation {
			order.State = workorder.StateCancelled
			order.RefuseReason = reason
			order.Audit.UpdatedAt = now
			cancelled++
		}
	}
	return cancelled, nil
}

// CancelForAgent cancels every live order addressed to agentID and returns the count.
func (s *WorkOrderStore) CancelForAgent(_ context.Context, tenantID, agentID shared.ID, reason string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.byID {
		if o.TenantID == tenantID && o.AgentID == agentID && isLive(o.State) {
			o.State = workorder.StateCancelled
			o.RefuseReason = reason
			o.Audit.UpdatedAt = now
			n++
		}
	}
	return n, nil
}

func isLive(s workorder.State) bool {
	return s == workorder.StateIssued || s == workorder.StateClaimed || s == workorder.StateRunning
}

package offensivepolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// HaltBound is the stated bound from the policy document 8: the control plane cancels every in-flight
// offensive work order within this long.
//
// Read the document before changing it. This bounds the CONTROL PLANE, not the estate: an agent already
// executing a technique learns of the cancellation on its next poll, so the estate-wide stop is this
// bound plus one agent poll interval. Claiming otherwise would be false during the one incident where
// the difference matters.
const HaltBound = 5 * time.Second

// OffensiveTechniques is the port the kill switch needs from a work order: whether it carries offensive
// work at all. A work order for an SBOM scan is not halted by the red-team kill switch.
type haltableStore interface {
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*workorder.WorkOrder, error)
	Transition(ctx context.Context, tenantID, id shared.ID, to workorder.State, reason string, expected workorder.State, now time.Time) error
}

// HaltResult is what the operator gets back. It reports partial failure honestly: a halt that cancelled
// nine of ten orders is not a clean halt, and saying so is the difference between an operator escalating
// and an operator believing the estate is safe.
type HaltResult struct {
	RequestedAt time.Time
	CompletedAt time.Time
	Duration    time.Duration
	WithinBound bool
	Cancelled   []shared.ID
	Failed      map[shared.ID]string
	AuditFailed bool
	// EstateStopNote states, in the response, what the bound does not cover. An operator reading only
	// this field must not conclude the estate has stopped.
	EstateStopNote string
}

// Halted reports whether every in-flight offensive order was cancelled.
func (r HaltResult) Halted() bool { return len(r.Failed) == 0 }

// KillSwitch halts all in-flight offensive work for a tenant.
type KillSwitch struct {
	orders      haltableStore
	audit       ports.AuditLogger
	isOffensive func(*workorder.WorkOrder) bool
	now         func() time.Time
}

// NewKillSwitch builds the kill switch. isOffensive decides which work orders this switch governs; when
// nil, every work order is treated as offensive.
//
// Defaulting to "everything is offensive" is deliberate. The alternative default — treat nothing as
// offensive until a classifier says so — would make a misconfigured kill switch silently halt nothing,
// and a kill switch that does less than the operator expects is the one failure this contract cannot
// have. Halting more than necessary is recoverable; halting nothing during an incident is not.
func NewKillSwitch(orders haltableStore, audit ports.AuditLogger, isOffensive func(*workorder.WorkOrder) bool, now func() time.Time) (*KillSwitch, error) {
	if orders == nil || audit == nil {
		return nil, fmt.Errorf("%w: kill switch requires a work order store and an audit log", shared.ErrValidation)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if isOffensive == nil {
		isOffensive = func(*workorder.WorkOrder) bool { return true }
	}
	return &KillSwitch{orders: orders, audit: audit, isOffensive: isOffensive, now: now}, nil
}

// Halt cancels every in-flight offensive work order for the tenant.
//
// It is a single operator action, it is audited with the operator identity and reason, and it reports the
// measured duration against the stated bound rather than asserting compliance.
func (k *KillSwitch) Halt(ctx context.Context, tenantID shared.ID, actor, reason string) (HaltResult, error) {
	if k == nil {
		return HaltResult{}, fmt.Errorf("%w: kill switch is not configured", shared.ErrValidation)
	}
	if strings.TrimSpace(actor) == "" {
		return HaltResult{}, fmt.Errorf("%w: a halt must name the operator", shared.ErrValidation)
	}
	if strings.TrimSpace(reason) == "" {
		// A halt with no reason cannot be explained afterwards, and the document requires the reason to
		// be part of the audit record.
		return HaltResult{}, fmt.Errorf("%w: a halt must carry a reason", shared.ErrValidation)
	}
	started := k.now()
	result := HaltResult{
		RequestedAt: started.UTC(),
		Failed:      map[shared.ID]string{},
		EstateStopNote: fmt.Sprintf(
			"control plane halted within %s; a technique already running on a host stops within one further agent poll interval",
			HaltBound),
	}

	orders, err := k.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		// The halt could not even enumerate what to stop. That is a failure to halt, and it must not
		// return a result that reads like success.
		k.recordAudit(ctx, actor, reason, tenantID, &result, "enumeration_failed")
		return result, fmt.Errorf("%w: halt could not enumerate work orders: %v", shared.ErrSaturated, err)
	}

	for _, order := range orders {
		if order == nil || order.State.Terminal() || !k.isOffensive(order) {
			continue
		}
		err := k.orders.Transition(ctx, tenantID, order.ID, workorder.StateCancelled,
			"offensive kill switch: "+reason, order.State, k.now().UTC())
		switch {
		case err == nil:
			result.Cancelled = append(result.Cancelled, order.ID)
		case errors.Is(err, shared.ErrConflict):
			// The order moved underneath us — it was claimed, completed or already cancelled between the
			// list and the transition. Re-read and retry once against its new state: a concurrent
			// claim must not leave work running just because it raced the halt.
			if retried := k.retryOnce(ctx, tenantID, order.ID, reason); retried != nil {
				result.Failed[order.ID] = retried.Error()
			} else {
				result.Cancelled = append(result.Cancelled, order.ID)
			}
		default:
			result.Failed[order.ID] = err.Error()
		}
	}

	sort.Slice(result.Cancelled, func(i, j int) bool { return result.Cancelled[i] < result.Cancelled[j] })
	result.CompletedAt = k.now().UTC()
	result.Duration = result.CompletedAt.Sub(result.RequestedAt)
	result.WithinBound = result.Duration <= HaltBound

	// Audit LAST, so the record carries the measured outcome — but note that the halt already happened.
	// A halt that cannot be audited is still a halt: stopping work matters more than recording it, and
	// the result says the audit failed rather than claiming a clean halt.
	k.recordAudit(ctx, actor, reason, tenantID, &result, "")
	if !result.Halted() {
		return result, fmt.Errorf("%w: halt failed for %d work order(s)", shared.ErrSaturated, len(result.Failed))
	}
	return result, nil
}

// retryOnce re-reads the order and cancels it from whatever state it now holds. It returns nil when the
// order no longer needs cancelling.
func (k *KillSwitch) retryOnce(ctx context.Context, tenantID, id shared.ID, reason string) error {
	orders, err := k.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, order := range orders {
		if order == nil || order.ID != id {
			continue
		}
		if order.State.Terminal() {
			return nil // it reached a terminal state on its own; nothing left to halt
		}
		return k.orders.Transition(ctx, tenantID, id, workorder.StateCancelled,
			"offensive kill switch: "+reason, order.State, k.now().UTC())
	}
	return nil // it is gone; nothing to halt
}

func (k *KillSwitch) recordAudit(ctx context.Context, actor, reason string, tenantID shared.ID, result *HaltResult, note string) {
	meta := map[string]string{
		"tenant":          tenantID.String(),
		"reason":          reason,
		"cancelled":       fmt.Sprint(len(result.Cancelled)),
		"failed":          fmt.Sprint(len(result.Failed)),
		"duration_ms":     fmt.Sprint(result.Duration.Milliseconds()),
		"within_bound":    fmt.Sprint(result.WithinBound),
		"stated_bound_ms": fmt.Sprint(HaltBound.Milliseconds()),
	}
	if note != "" {
		meta["note"] = note
	}
	if err := k.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "offensive.halt", Target: tenantID.String(), At: k.now().UTC(), Metadata: meta,
	}); err != nil {
		result.AuditFailed = true
	}
}

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

// ChainHaltSummary reports the outcome of halting the in-memory exploitation chains a process is
// running. It is kept separate from the work-order fields so an operator can see which layer of the kill
// switch stopped what: queued/claimed work orders, or chains executing in memory.
type ChainHaltSummary struct {
	Halted []shared.ID
	Failed map[shared.ID]string
}

// clean reports whether every running chain was halted (or there were none).
func (c ChainHaltSummary) clean() bool { return len(c.Failed) == 0 }

// ChainHalter halts every exploitation chain running IN THE CURRENT PROCESS for a tenant. It is the
// second layer of the kill switch: work orders cover queued and claimed offensive work, this covers a
// chain already executing in memory, which is not a work order and would otherwise be unreachable.
//
// It is optional. A deployment that never drives chains in-process wires nil, and the kill switch then
// covers work orders alone — honestly, because the response says so.
type ChainHalter interface {
	HaltChains(ctx context.Context, tenantID shared.ID, actor, reason string) (ChainHaltSummary, error)
}

// ResponseHalter halts pending/in-flight DEFENSIVE response actions for a tenant (#425): the kill switch
// stops response actions exactly as it stops offensive work — a defensive action that changes a
// production system must be as haltable as an offensive one. Optional; nil means no response layer.
type ResponseHalter interface {
	HaltResponses(ctx context.Context, tenantID shared.ID, actor, reason string) (int, error)
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
	// Chains reports the in-memory exploitation chains this halt stopped. Its zero value means the chain
	// layer was not wired (no ChainHalter) — distinct from "wired and found nothing running".
	Chains ChainHaltSummary
	// ChainHaltError is set when the chain layer could not be driven at all (not a per-chain failure,
	// which lands in Chains.Failed). It is a failure to halt and must not read like success.
	ChainHaltError string
	// ResponsesHalted counts the pending/in-flight defensive response actions this halt cancelled;
	// ResponseHaltError is set when that layer could not be driven at all.
	ResponsesHalted   int
	ResponseHaltError string
	// EstateStopNote states, in the response, what the bound does not cover. An operator reading only
	// this field must not conclude the estate has stopped.
	EstateStopNote string
}

// Halted reports whether every in-flight offensive order AND every running chain was cancelled. A halt
// that stopped every work order but left a chain running is not a clean halt.
func (r HaltResult) Halted() bool {
	return len(r.Failed) == 0 && r.Chains.clean() && r.ChainHaltError == "" && r.ResponseHaltError == ""
}

// KillSwitch halts all in-flight offensive work for a tenant.
type KillSwitch struct {
	orders      haltableStore
	audit       ports.AuditLogger
	isOffensive func(*workorder.WorkOrder) bool
	now         func() time.Time
	chains      ChainHalter
	responses   ResponseHalter
}

// SetChainHalter wires the in-process chain registry so a halt also stops exploitation chains executing
// in memory, not only work orders. Optional: left unset, the kill switch covers work orders alone and
// the result's Chains field stays zero to say so. Wired at the composition root, where the registry the
// chain machines register into is constructed.
func (k *KillSwitch) SetChainHalter(ch ChainHalter) {
	if k != nil {
		k.chains = ch
	}
}

// SetResponseHalter wires the defensive-response layer so a halt also cancels pending/in-flight response
// actions. Optional: left unset, the kill switch covers offensive work + chains alone.
func (k *KillSwitch) SetResponseHalter(rh ResponseHalter) {
	if k != nil {
		k.responses = rh
	}
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

	// Halt the in-memory exploitation chains FIRST, and unconditionally. This layer does not depend on
	// the work-order store, and a chain executing techniques in memory is the most dangerous thing the
	// kill switch must reach. Gating it behind the work-order enumeration would mean a degraded store —
	// exactly when an operator pulls the switch — leaves a running chain untouched while the result still
	// read as if chains were never in play. Done inside the measured window, because stopping a running
	// chain is part of the halt the operator asked for, not a follow-up.
	if k.chains != nil {
		summary, cerr := k.chains.HaltChains(ctx, tenantID, actor, reason)
		result.Chains = summary
		if cerr != nil {
			result.ChainHaltError = cerr.Error()
		}
	}
	// And the defensive-response layer: pending/in-flight response actions are halted like offensive work.
	if k.responses != nil {
		n, rerr := k.responses.HaltResponses(ctx, tenantID, actor, reason)
		result.ResponsesHalted = n
		if rerr != nil {
			result.ResponseHaltError = rerr.Error()
		}
	}

	orders, err := k.orders.ListByTenant(ctx, tenantID)
	if err != nil {
		// The halt could not even enumerate what to stop. That is a failure to halt, and it must not
		// return a result that reads like success. The chain layer above already ran, so its outcome is
		// carried in the result and the audit rather than being lost to this early return.
		result.CompletedAt = k.now().UTC()
		result.Duration = result.CompletedAt.Sub(result.RequestedAt)
		result.WithinBound = result.Duration <= HaltBound
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
		if result.ChainHaltError != "" {
			return result, fmt.Errorf("%w: halt failed for %d work order(s) and could not drive chain halt: %s",
				shared.ErrSaturated, len(result.Failed), result.ChainHaltError)
		}
		if result.ResponseHaltError != "" {
			return result, fmt.Errorf("%w: halt failed for %d work order(s) and could not drive response halt: %s",
				shared.ErrSaturated, len(result.Failed), result.ResponseHaltError)
		}
		return result, fmt.Errorf("%w: halt failed for %d work order(s) and %d chain(s)",
			shared.ErrSaturated, len(result.Failed), len(result.Chains.Failed))
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
		"tenant":           tenantID.String(),
		"reason":           reason,
		"cancelled":        fmt.Sprint(len(result.Cancelled)),
		"failed":           fmt.Sprint(len(result.Failed)),
		"chains_halted":    fmt.Sprint(len(result.Chains.Halted)),
		"chains_failed":    fmt.Sprint(len(result.Chains.Failed)),
		"responses_halted": fmt.Sprint(result.ResponsesHalted),
		"duration_ms":      fmt.Sprint(result.Duration.Milliseconds()),
		"within_bound":     fmt.Sprint(result.WithinBound),
		"stated_bound_ms":  fmt.Sprint(HaltBound.Milliseconds()),
	}
	if result.ChainHaltError != "" {
		meta["chain_halt_error"] = result.ChainHaltError
	}
	if result.ResponseHaltError != "" {
		meta["response_halt_error"] = result.ResponseHaltError
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

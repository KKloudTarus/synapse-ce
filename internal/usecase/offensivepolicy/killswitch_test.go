package offensivepolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
)

// fakeOrders is an in-memory work order store with a real mutex, so a test can run concurrent claims
// against a halt and observe the interleaving rather than assuming it.
type fakeOrders struct {
	mu         sync.Mutex
	orders     map[shared.ID]*workorder.WorkOrder
	listErr    error
	transDelay time.Duration
	transCalls int64
	transErr   map[shared.ID]error
}

func newFakeOrders(states ...workorder.State) *fakeOrders {
	f := &fakeOrders{orders: map[shared.ID]*workorder.WorkOrder{}, transErr: map[shared.ID]error{}}
	for i, st := range states {
		id := shared.ID(fmt.Sprintf("wo-%02d", i))
		f.orders[id] = &workorder.WorkOrder{ID: id, TenantID: "t1", State: st}
	}
	return f
}

func (f *fakeOrders) ListByTenant(_ context.Context, tenantID shared.ID) ([]*workorder.WorkOrder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*workorder.WorkOrder, 0, len(f.orders))
	for _, o := range f.orders {
		if o.TenantID != tenantID {
			continue
		}
		copied := *o
		out = append(out, &copied)
	}
	return out, nil
}

func (f *fakeOrders) Transition(_ context.Context, _, id shared.ID, to workorder.State, _ string, expected workorder.State, _ time.Time) error {
	atomic.AddInt64(&f.transCalls, 1)
	if f.transDelay > 0 {
		time.Sleep(f.transDelay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.transErr[id]; ok && err != nil {
		return err
	}
	order, ok := f.orders[id]
	if !ok {
		return shared.ErrNotFound
	}
	// Optimistic concurrency, exactly as the real store enforces it: a state that moved underneath the
	// caller is a conflict, not a silent overwrite.
	if order.State != expected {
		return fmt.Errorf("%w: work order %s is %s, expected %s", shared.ErrConflict, id, order.State, expected)
	}
	if !workorder.CanTransition(order.State, to) {
		return fmt.Errorf("%w: %s -> %s is not a legal transition", shared.ErrValidation, order.State, to)
	}
	order.State = to
	return nil
}

func (f *fakeOrders) state(id shared.ID) workorder.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.orders[id]; ok {
		return o.State
	}
	return ""
}

// TestHaltCancelsInFlightWithinBound is acceptance criterion 5: the kill switch halts in-flight work
// within the stated bound, MEASURED under concurrent work, and the halt is audited.
//
// The bound is measured from real elapsed time rather than a fake clock: the requirement is a bound on
// the operator's wait, and a fake clock could report any duration it liked.
func TestHaltCancelsInFlightWithinBound(t *testing.T) {
	// A mix of in-flight and already-terminal orders, so the halt has to select rather than cancel
	// everything blindly.
	orders := newFakeOrders(
		workorder.StateIssued, workorder.StateClaimed, workorder.StateRunning,
		workorder.StateIssued, workorder.StateRunning, workorder.StateClaimed,
		workorder.StateSucceeded, workorder.StateFailed, workorder.StateCancelled,
	)
	// A small per-transition delay so the halt is doing real concurrent work rather than completing
	// instantly and passing the bound trivially.
	orders.transDelay = 2 * time.Millisecond
	audit := &fakeAudit{}
	ks, err := NewKillSwitch(orders, audit, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent claims racing the halt: work continues to arrive while the operator pulls the switch.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = orders.Transition(context.Background(), "t1", "wo-00", workorder.StateClaimed, "racing claim", workorder.StateIssued, time.Now())
				time.Sleep(time.Millisecond)
			}
		}
	}()

	start := time.Now()
	result, err := ks.Halt(context.Background(), "t1", "operator@example.test", "customer requested an immediate stop")
	elapsed := time.Since(start)
	close(stop)
	wg.Wait()

	if err != nil {
		t.Fatalf("halt failed: %v (failed orders: %v)", err, result.Failed)
	}
	if elapsed > HaltBound {
		t.Fatalf("halt took %s, above the stated bound of %s", elapsed, HaltBound)
	}
	if !result.WithinBound {
		t.Errorf("result does not report itself within bound: duration=%s", result.Duration)
	}
	if len(result.Cancelled) != 6 {
		t.Fatalf("cancelled %d orders, want the 6 in-flight ones: %v", len(result.Cancelled), result.Cancelled)
	}
	// Every in-flight order is terminal now; the already-terminal ones were untouched.
	for _, id := range []shared.ID{"wo-00", "wo-01", "wo-02", "wo-03", "wo-04", "wo-05"} {
		if got := orders.state(id); got != workorder.StateCancelled {
			t.Errorf("%s = %s, want cancelled", id, got)
		}
	}
	if got := orders.state("wo-06"); got != workorder.StateSucceeded {
		t.Errorf("a succeeded order must not be touched by the halt, got %s", got)
	}

	// Audited with the operator identity, the reason, and the MEASURED duration against the bound.
	last := audit.last()
	if last.Action != "offensive.halt" || last.Actor != "operator@example.test" {
		t.Fatalf("halt audit = %+v", last)
	}
	if last.Metadata["reason"] == "" || last.Metadata["duration_ms"] == "" || last.Metadata["within_bound"] != "true" {
		t.Errorf("halt audit does not carry reason and measured duration: %+v", last.Metadata)
	}
	if last.Metadata["stated_bound_ms"] != fmt.Sprint(HaltBound.Milliseconds()) {
		t.Errorf("halt audit does not record the bound it was measured against: %+v", last.Metadata)
	}
	// The response must state what the bound does NOT cover, so an operator reading it cannot conclude
	// the estate has stopped.
	if result.EstateStopNote == "" {
		t.Error("the halt result does not state the estate-stop caveat")
	}
}

// TestHaltRetriesAnOrderThatRacedTheSwitch: an order claimed between the list and the transition must
// still be cancelled. Leaving work running because it raced the halt is the failure this contract cannot
// have.
func TestHaltRetriesAnOrderThatRacedTheSwitch(t *testing.T) {
	orders := newFakeOrders(workorder.StateIssued)
	audit := &fakeAudit{}
	ks, err := NewKillSwitch(orders, audit, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Move it out from under the halt exactly once, after the list and before the transition.
	orders.mu.Lock()
	orders.orders["wo-00"].State = workorder.StateIssued
	orders.mu.Unlock()
	go func() {
		time.Sleep(time.Millisecond)
		_ = orders.Transition(context.Background(), "t1", "wo-00", workorder.StateClaimed, "race", workorder.StateIssued, time.Now())
	}()
	orders.transDelay = 5 * time.Millisecond

	result, err := ks.Halt(context.Background(), "t1", "operator", "stop now")
	if err != nil {
		t.Fatalf("halt must recover from a racing claim: %v (failed: %v)", err, result.Failed)
	}
	if got := orders.state("wo-00"); got != workorder.StateCancelled {
		t.Fatalf("an order that raced the halt is %s, want cancelled", got)
	}
}

// TestHaltReportsPartialFailureRatherThanClaimingSuccess: nine of ten cancelled is not a clean halt, and
// an operator who believes it is will not escalate.
func TestHaltReportsPartialFailureRatherThanClaimingSuccess(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning, workorder.StateRunning)
	orders.transErr["wo-01"] = errors.New("database unreachable")
	audit := &fakeAudit{}
	ks, err := NewKillSwitch(orders, audit, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ks.Halt(context.Background(), "t1", "operator", "stop")
	if err == nil {
		t.Fatal("a halt that could not cancel every order must return an error")
	}
	if result.Halted() {
		t.Error("Halted() reports success while an order failed to cancel")
	}
	if len(result.Failed) != 1 {
		t.Errorf("failed = %v, want exactly wo-01", result.Failed)
	}
	if len(result.Cancelled) != 1 {
		t.Errorf("cancelled = %v, want the one that succeeded", result.Cancelled)
	}
	if got := audit.last().Metadata["failed"]; got != "1" {
		t.Errorf("the audit does not record the failure count, got %q", got)
	}
}

// TestHaltFailsWhenItCannotEnumerate: a halt that cannot list what to stop has not halted anything, and
// must not return a result that reads like success.
func TestHaltFailsWhenItCannotEnumerate(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning)
	orders.listErr = errors.New("database unreachable")
	audit := &fakeAudit{}
	ks, _ := NewKillSwitch(orders, audit, nil, nil)

	result, err := ks.Halt(context.Background(), "t1", "operator", "stop")
	if err == nil {
		t.Fatal("a halt that cannot enumerate work orders must fail")
	}
	if len(result.Cancelled) != 0 {
		t.Error("a failed enumeration must not report cancellations")
	}
	if got := audit.last().Metadata["note"]; got != "enumeration_failed" {
		t.Errorf("the audit does not say why the halt failed, got %q", got)
	}
}

// TestHaltIsStillPerformedWhenAuditFails: stopping work matters more than recording it, and the result
// says the audit failed rather than claiming a clean halt.
func TestHaltIsStillPerformedWhenAuditFails(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning)
	audit := &fakeAudit{err: errors.New("audit log unavailable")}
	ks, _ := NewKillSwitch(orders, audit, nil, nil)

	result, err := ks.Halt(context.Background(), "t1", "operator", "stop")
	if err != nil {
		t.Fatalf("the halt itself must succeed even when the audit fails: %v", err)
	}
	if got := orders.state("wo-00"); got != workorder.StateCancelled {
		t.Fatalf("work was not halted: %s", got)
	}
	if !result.AuditFailed {
		t.Error("the result must report that the halt could not be audited")
	}
}

// TestHaltRequiresAnOperatorAndAReason: a halt that cannot be explained afterwards defeats the chain of
// custody this policy claims.
func TestHaltRequiresAnOperatorAndAReason(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning)
	ks, _ := NewKillSwitch(orders, &fakeAudit{}, nil, nil)
	for name, call := range map[string]func() error{
		"no operator": func() error { _, err := ks.Halt(context.Background(), "t1", "  ", "stop"); return err },
		"no reason":   func() error { _, err := ks.Halt(context.Background(), "t1", "operator", " "); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want a validation error, got %v", err)
			}
			if got := orders.state("wo-00"); got != workorder.StateRunning {
				t.Errorf("a refused halt must not change work order state, got %s", got)
			}
		})
	}
}

// TestHaltOnlyTouchesOffensiveWork: an SBOM scan is not halted by the red-team kill switch.
func TestHaltOnlyTouchesOffensiveWork(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning, workorder.StateRunning)
	offensive := func(o *workorder.WorkOrder) bool { return o.ID == "wo-00" }
	ks, _ := NewKillSwitch(orders, &fakeAudit{}, offensive, nil)

	if _, err := ks.Halt(context.Background(), "t1", "operator", "stop"); err != nil {
		t.Fatal(err)
	}
	if got := orders.state("wo-00"); got != workorder.StateCancelled {
		t.Errorf("offensive order = %s, want cancelled", got)
	}
	if got := orders.state("wo-01"); got != workorder.StateRunning {
		t.Errorf("non-offensive order = %s, want untouched", got)
	}
}

// TestHaltDefaultsToTreatingEveryOrderAsOffensive pins the deliberate default: a misconfigured kill
// switch halts too much rather than nothing. Halting more than necessary is recoverable; halting nothing
// during an incident is not.
func TestHaltDefaultsToTreatingEveryOrderAsOffensive(t *testing.T) {
	orders := newFakeOrders(workorder.StateRunning, workorder.StateIssued)
	ks, _ := NewKillSwitch(orders, &fakeAudit{}, nil, nil)
	result, err := ks.Halt(context.Background(), "t1", "operator", "stop")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Cancelled) != 2 {
		t.Fatalf("with no classifier every in-flight order must be halted, cancelled %v", result.Cancelled)
	}
}

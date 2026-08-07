// Package leaderuc runs leader election over a fenced lease (#406, epic #405) so more than one
// control-plane instance can run while exactly one is the scheduler leader at a time. The Elector
// campaigns and renews on a timer, caches the current leadership view for non-blocking callers,
// and records every leadership transition in the audit log.
package leaderuc

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Elector holds leadership of a single resource for one instance.
type Elector struct {
	store      ports.LeaderStore
	audit      ports.AuditLogger
	clock      ports.Clock
	resource   string
	instanceID string
	term       time.Duration
	renew      time.Duration

	leader atomic.Bool
	fence  atomic.Int64
}

// NewElector validates its inputs. renew must be strictly less than term/2 so a single missed
// renewal cannot cause a spurious handover.
func NewElector(store ports.LeaderStore, audit ports.AuditLogger, clock ports.Clock, resource, instanceID string, term, renew time.Duration) (*Elector, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: elector needs store + audit + clock", shared.ErrValidation)
	}
	if resource == "" || instanceID == "" {
		return nil, fmt.Errorf("%w: elector needs a resource and an instance id", shared.ErrValidation)
	}
	if term <= 0 || renew <= 0 || renew >= term/2 {
		return nil, fmt.Errorf("%w: require 0 < renew < term/2 (term=%s renew=%s)", shared.ErrValidation, term, renew)
	}
	return &Elector{store: store, audit: audit, clock: clock, resource: resource, instanceID: instanceID, term: term, renew: renew}, nil
}

// IsLeader reports the cached leadership view without blocking.
func (e *Elector) IsLeader() bool { return e.leader.Load() }

// Fence returns the last observed fence token.
func (e *Elector) Fence() int64 { return e.fence.Load() }

// tick performs one acquire/renew and updates the cached view, auditing any transition. It is the
// unit the timer drives and the seam tests call directly with a controlled clock.
func (e *Elector) tick(ctx context.Context) error {
	held, fence, err := e.store.Acquire(ctx, e.resource, e.instanceID, e.term, e.clock.Now())
	if err != nil {
		// Fail-safe: on any error we cannot prove we still hold the lease, so we drop leadership
		// rather than risk two leaders. A recovered store re-acquires on the next tick.
		if e.leader.Swap(false) {
			e.record(ctx, "leader.lost", "acquire error")
		}
		return err
	}
	e.fence.Store(fence)
	if was := e.leader.Swap(held); held != was {
		if held {
			e.record(ctx, "leader.acquired", "")
		} else {
			e.record(ctx, "leader.lost", "lease taken over")
		}
	}
	return nil
}

// Run campaigns immediately, then renews every renew interval until ctx is done, at which point it
// resigns so a follower can take over without waiting for the term to expire.
func (e *Elector) Run(ctx context.Context) {
	_ = e.tick(ctx)
	t := time.NewTicker(e.renew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.resign()
			return
		case <-t.C:
			_ = e.tick(ctx)
		}
	}
}

// resign releases the lease on shutdown with a fresh, bounded context.
func (e *Elector) resign() {
	rbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = e.store.Resign(rbCtx, e.resource, e.instanceID, e.clock.Now())
	if e.leader.Swap(false) {
		e.record(rbCtx, "leader.resigned", "shutdown")
	}
}

// record writes a leadership transition to the audit log. It is best-effort: a background daemon
// must not lose (or falsely keep) leadership because the audit write failed, so an error is
// swallowed here rather than propagated.
func (e *Elector) record(ctx context.Context, action, reason string) {
	_ = e.audit.Record(ctx, ports.AuditEntry{
		Actor:    e.instanceID,
		Action:   action,
		Target:   e.resource,
		Metadata: map[string]string{"reason": reason, "fence": fmt.Sprintf("%d", e.fence.Load())},
		At:       e.clock.Now(),
	})
}

// Package ticketruntime runs bounded ticket polling in API development mode and
// the dedicated integration worker. The durable store remains the work source.
package ticketruntime

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type workflow interface {
	Tick(context.Context, shared.ID, int) (int, error)
}

type Runner struct {
	workflow workflow
	tenants  ports.TenantLister
	log      *slog.Logger
	// next is owned by the one Run goroutine. A tick rotates even when a tenant
	// exhausts the batch, so a busy tenant does not starve later tenants.
	next int
}

func New(work workflow, tenants ports.TenantLister, log *slog.Logger) (*Runner, error) {
	if work == nil || tenants == nil || log == nil {
		return nil, fmt.Errorf("%w: ticket polling dependencies are required", shared.ErrValidation)
	}
	return &Runner{workflow: work, tenants: tenants, log: log}, nil
}

func (r *Runner) Run(ctx context.Context) {
	r.tick(ctx)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tenants, err := r.tenants.ListTenantIDs(tickCtx)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("ticket tenant polling failed")
		}
		return
	}
	if len(tenants) == 0 {
		return
	}
	start := r.next % len(tenants)
	for n := 0; n < min(len(tenants), 10) && tickCtx.Err() == nil; n++ {
		index := (start + n) % len(tenants)
		r.next = (index + 1) % len(tenants)
		if _, err = r.workflow.Tick(tickCtx, shared.TenantOrDefault(tenants[index]), 10); err != nil && ctx.Err() == nil {
			r.log.Warn("ticket intent polling failed")
		}
	}
}

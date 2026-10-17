// Package composition contains process-root helpers for document publication.
package composition

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DocumentPublicationTicker is the worker-facing portion of document
// publishing. It has no publish operation, so background execution cannot
// create new remote content.
type DocumentPublicationTicker interface {
	Tick(context.Context, shared.ID, int) error
}

// DocumentPublicationRunner enumerates tenants through the established tenant
// store and advances a bounded number of already-approved document commands.
// It deliberately keeps tenant enumeration outside the use case.
type DocumentPublicationRunner struct {
	ticker  DocumentPublicationTicker
	tenants ports.TenantLister
	log     *slog.Logger
	next    int
}

func NewDocumentPublicationRunner(ticker DocumentPublicationTicker, tenants ports.TenantLister, log *slog.Logger) (*DocumentPublicationRunner, error) {
	if ticker == nil || tenants == nil || log == nil {
		return nil, fmt.Errorf("%w: document publication runner dependencies are required", shared.ErrValidation)
	}
	return &DocumentPublicationRunner{ticker: ticker, tenants: tenants, log: log}, nil
}

// Run polls immediately and thereafter on the same cadence as ticket intent
// reconciliation. Each pass has a deadline and rotates through at most ten
// tenant scopes, so one busy tenant cannot starve the others.
func (r *DocumentPublicationRunner) Run(ctx context.Context) {
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

func (r *DocumentPublicationRunner) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tenants, err := r.tenants.ListTenantIDs(tickCtx)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("document publication tenant polling failed")
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
		tenant := tenants[index]
		if tenant.IsZero() {
			continue
		}
		if err := r.ticker.Tick(tickCtx, tenant, 20); err != nil && ctx.Err() == nil {
			r.log.Warn("document publication polling failed")
		}
	}
}

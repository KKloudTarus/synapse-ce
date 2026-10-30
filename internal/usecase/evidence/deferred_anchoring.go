package evidence

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type deferredAnchorsKey struct{}
type deferredAnchor struct {
	service    *Service
	engagement shared.ID
	head       string
}
type deferredAnchors struct {
	mu    sync.Mutex
	items []deferredAnchor
}

func (d *deferredAnchors) add(service *Service, engagement shared.ID, head string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items = append(d.items, deferredAnchor{service, engagement, head})
}

// AnchorAfterCommit delays out-of-band timestamps until commit returns success.
// The callback must commit its transaction before returning nil. Rolled-back or
// uncertain commits leave no timestamp for an uncommitted head. Anchoring stays
// best effort; it never runs while the callback holds custody/audit locks.
func AnchorAfterCommit(ctx context.Context, commit func(context.Context) error) error {
	pending := &deferredAnchors{}
	if err := commit(context.WithValue(ctx, deferredAnchorsKey{}, pending)); err != nil {
		return err
	}
	pending.mu.Lock()
	items := append([]deferredAnchor(nil), pending.items...)
	pending.mu.Unlock()
	for _, item := range items {
		item.service.anchorSealedHead(ctx, item.engagement, item.head)
	}
	return nil
}

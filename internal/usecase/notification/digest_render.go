package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// renderDigestEvent retains immutable stored members while deriving every outgoing field
// from the same currently relevant, privacy-allowed subset. Only builders with a source
// relevance callback perform I/O; at most MaxDigestMembers callbacks run per aggregate.
func (s *Service) renderDigestEvent(ctx context.Context, in RenderInput, class domain.DataClass) (domain.Event, int, error) {
	event := in.Event
	if len(event.DigestItems) > domain.MaxDigestMembers {
		return domain.Event{}, 0, fmt.Errorf("%w: digest member limit exceeded", shared.ErrValidation)
	}
	var data domain.DigestData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return domain.Event{}, 0, fmt.Errorf("%w: invalid digest descriptor", shared.ErrValidation)
	}
	items := make([]domain.DigestItem, 0, len(event.DigestItems))
	for _, item := range event.DigestItems {
		if _, allowed := domain.EffectiveDataClass(class, item.Override); !allowed {
			continue
		}
		if _, known := domain.LookupEvent(item.Event.Type); !known || item.Event.Type == domain.EventDigest {
			continue
		}
		relevant, err := s.events.StillRelevant(ctx, s.repo, ports.NotificationWork{Channel: in.Channel, Event: item.Event, Engagement: item.Override})
		if err != nil {
			return domain.Event{}, 0, fmt.Errorf("check digest member relevance: %w", err)
		}
		if relevant {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Event.OccurredAt.Equal(items[j].Event.OccurredAt) {
			return items[i].Event.ID < items[j].Event.ID
		}
		return items[i].Event.OccurredAt.Before(items[j].Event.OccurredAt)
	})
	filtered, count, err := domain.BuildDigestContext(items, data.Cadence, data.WindowStart, data.WindowEnd, class)
	if err != nil {
		return domain.Event{}, 0, err
	}
	event.Context, err = filtered.Encode()
	if err != nil {
		return domain.Event{}, 0, err
	}
	visible := min(len(items), len(filtered.Lists["items"]))
	data.EventIDs = make([]shared.ID, 0, visible)
	for _, item := range items[:visible] {
		data.EventIDs = append(data.EventIDs, item.Event.ID)
	}
	data.TotalCount = count
	event.Data, err = json.Marshal(data)
	if err != nil {
		return domain.Event{}, 0, err
	}
	event.DigestItems, event.Severity = items, domain.DigestSeverity(items)
	return event, count, nil
}

package ports

import (
	"context"
	"fmt"
)

// TelemetryAgentGapReader exposes durable agent-origin loss through the same
// time-window coverage shape used by retro-hunt. It is separate from delivery
// reconciliation so a later sequence fill cannot erase local-loss provenance.
type TelemetryAgentGapReader interface {
	QueryAgentGaps(ctx context.Context, q TelemetryGapQuery) ([]TelemetryGap, error)
}

// CombinedTelemetryGapReader presents delivery holes and agent-origin durable
// loss as one conservative coverage reader. The two sources intentionally remain
// distinct in persistence; composition happens only on the read side. Exact
// overlaps are de-duplicated so this adapter stays safe when the delivery reader
// already includes durable agent-origin loss as required by its contract.
type CombinedTelemetryGapReader struct {
	Delivery TelemetryDeliveryGapReader
	Agent    TelemetryAgentGapReader
}

func (r CombinedTelemetryGapReader) QueryDeliveryGaps(ctx context.Context, q TelemetryGapQuery) ([]TelemetryGap, error) {
	if r.Delivery == nil || r.Agent == nil {
		return nil, fmt.Errorf("combined telemetry gap reader requires delivery and agent readers")
	}
	delivery, err := r.Delivery.QueryDeliveryGaps(ctx, q)
	if err != nil {
		return nil, err
	}
	agent, err := r.Agent.QueryAgentGaps(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]TelemetryGap, 0, len(delivery)+len(agent))
	seen := make(map[TelemetryGap]struct{}, len(delivery)+len(agent))
	for _, gap := range append(delivery, agent...) {
		if _, ok := seen[gap]; ok {
			continue
		}
		seen[gap] = struct{}{}
		out = append(out, gap)
	}
	return out, nil
}

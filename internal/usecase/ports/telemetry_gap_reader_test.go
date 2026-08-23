package ports

import (
	"context"
	"testing"
	"time"
)

type testDeliveryGapReader struct{ gaps []TelemetryGap }

func (r testDeliveryGapReader) QueryDeliveryGaps(context.Context, TelemetryGapQuery) ([]TelemetryGap, error) {
	return append([]TelemetryGap(nil), r.gaps...), nil
}

type testAgentGapReader struct{ gaps []TelemetryGap }

func (r testAgentGapReader) QueryAgentGaps(context.Context, TelemetryGapQuery) ([]TelemetryGap, error) {
	return append([]TelemetryGap(nil), r.gaps...), nil
}

func TestCombinedTelemetryGapReaderDeduplicatesExactOverlap(t *testing.T) {
	gap := TelemetryGap{
		AgentID: "agent-1", AssetID: "asset-1", StreamID: "stream-1",
		Epoch: 1, FromAt: time.Unix(10, 0).UTC(), ToAt: time.Unix(20, 0).UTC(), DetectedAt: time.Unix(30, 0).UTC(),
	}
	reader := CombinedTelemetryGapReader{
		Delivery: testDeliveryGapReader{gaps: []TelemetryGap{gap}},
		Agent:    testAgentGapReader{gaps: []TelemetryGap{gap}},
	}
	got, err := reader.QueryDeliveryGaps(context.Background(), TelemetryGapQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != gap {
		t.Fatalf("combined gaps = %+v, want one exact gap", got)
	}
}

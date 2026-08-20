package agentspool

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRecordCoveragePersistsAggregateAndPerClassP0(t *testing.T) {
	durable := &captureSpool{}
	coverage := []detection.ClassCoverage{
		{Class: detection.ClassProcess, HostID: "host-1", AgentID: "agent-1", State: detection.StateActive, Since: adapterNow.Add(-time.Minute)},
		{Class: detection.ClassFile, HostID: "host-1", AgentID: "agent-1", State: detection.StateFailed, Reason: "attach refused", Since: adapterNow.Add(-time.Minute)},
	}
	if err := RecordCoverage(context.Background(), durable, coverage, adapterNow); err != nil {
		t.Fatal(err)
	}
	items := durable.snapshot()
	if len(items) != 3 {
		t.Fatalf("items = %d, want aggregate + 2 states", len(items))
	}
	for index, item := range items {
		if item.Priority != fleetagent.PriorityP0 || !item.MustNotShed || item.EventID.IsZero() {
			t.Errorf("item[%d] classification = %#v", index, item)
		}
	}
	if items[0].Kind != ports.SpoolRecordCoverage || items[1].Kind != ports.SpoolRecordSensorState || items[2].Kind != ports.SpoolRecordSensorState {
		t.Fatalf("kinds = %s, %s, %s", items[0].Kind, items[1].Kind, items[2].Kind)
	}
	var snapshot CoverageSnapshot
	if err := json.Unmarshal(items[0].Payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || len(snapshot.Classes) != 2 || !snapshot.ObservedAt.Equal(adapterNow) {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestRecordCoverageIsDeterministicAndValidates(t *testing.T) {
	durable := &captureSpool{}
	coverage := []detection.ClassCoverage{{Class: detection.ClassNetwork, HostID: "host", State: detection.StateActive}}
	if err := RecordCoverage(context.Background(), durable, coverage, adapterNow); err != nil {
		t.Fatal(err)
	}
	if err := RecordCoverage(context.Background(), durable, coverage, adapterNow); err != nil {
		t.Fatal(err)
	}
	items := durable.snapshot()
	if items[0].EventID != items[2].EventID || items[1].EventID != items[3].EventID {
		t.Fatal("identical health snapshots did not derive stable ids")
	}
	if err := RecordCoverage(context.Background(), durable, coverage, time.Time{}); err == nil {
		t.Fatal("zero timestamp accepted")
	}
	invalid := []detection.ClassCoverage{{Class: "future", HostID: "host", State: detection.StateActive}}
	if err := RecordCoverage(context.Background(), durable, invalid, adapterNow); err == nil {
		t.Fatal("invalid coverage accepted")
	}
	if err := RecordCoverage(context.Background(), nil, coverage, adapterNow); err == nil {
		t.Fatal("nil spool accepted")
	}
}

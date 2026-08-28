package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func testSensorObservation(reportID shared.ID, at time.Time) sensorstate.Observation {
	return sensorstate.Observation{
		ReportID: reportID, AgentID: "agent-1", HostID: "agent-1", AssetID: "asset-1", Kind: sensorstate.RecordSensorState,
		ObservedAt: at, RecordedAt: at, SchemaVersion: 1,
		PayloadDigest:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SignedContentDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		States:              []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "agent-1", AgentID: "agent-1", State: detection.StateActive, Since: at}},
	}
}

func TestSensorStateStoreIsAppendOnlyAndTenantScoped(t *testing.T) {
	store := NewSensorStateStore()
	at := time.Date(2026, 8, 26, 12, 0, 0, 987_654_321, time.FixedZone("minus-five", -5*60*60))
	observation := testSensorObservation("report-1", at)
	tenantA := shared.WithTenant(context.Background(), "tenant-a")
	if err := store.AppendSensorState(tenantA, observation); err != nil {
		t.Fatalf("append observation: %v", err)
	}

	retry := observation
	retry.RecordedAt = retry.RecordedAt.Add(time.Second + 123*time.Nanosecond)
	if err := store.AppendSensorState(tenantA, retry); err != nil {
		t.Fatalf("append later server-clock retry: %v", err)
	}

	conflict := observation
	conflict.SignedContentDigest = "fedcba0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := store.AppendSensorState(tenantA, conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("append equivocation error = %v, want conflict", err)
	}

	rows, err := store.ListSensorStates(tenantA, ports.SensorStateQuery{})
	if err != nil {
		t.Fatalf("list tenant A: %v", err)
	}
	if len(rows) != 1 || rows[0].ReportID != observation.ReportID {
		t.Fatalf("tenant A rows = %#v, want one report", rows)
	}
	if got, want := rows[0].RecordedAt, observation.RecordedAt.UTC().Truncate(time.Microsecond); !got.Equal(want) {
		t.Fatalf("recorded at = %s, want first acceptance %s", got, want)
	}
	if got, want := rows[0].ObservedAt, observation.ObservedAt.UTC().Truncate(time.Microsecond); !got.Equal(want) {
		t.Fatalf("observed at = %s, want normalized %s", got, want)
	}
	if got, want := rows[0].States[0].Since, observation.States[0].Since.UTC().Truncate(time.Microsecond); !got.Equal(want) {
		t.Fatalf("state since = %s, want normalized %s", got, want)
	}
	rows[0].States[0].Reason = "mutated"
	rows, err = store.ListSensorStates(tenantA, ports.SensorStateQuery{})
	if err != nil || rows[0].States[0].Reason != "" {
		t.Fatalf("returned states leaked mutable backing storage: rows=%#v err=%v", rows, err)
	}

	rows, err = store.ListSensorStates(shared.WithTenant(context.Background(), "tenant-b"), ports.SensorStateQuery{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("tenant B rows = %#v, err=%v; want empty", rows, err)
	}
}

func TestSensorStateStoreSortsAndFilters(t *testing.T) {
	store := NewSensorStateStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	late := testSensorObservation("report-b", at.Add(time.Minute))
	early := testSensorObservation("report-a", at)
	if err := store.AppendSensorState(ctx, late); err != nil {
		t.Fatalf("append late: %v", err)
	}
	if err := store.AppendSensorState(ctx, early); err != nil {
		t.Fatalf("append early: %v", err)
	}
	rows, err := store.ListSensorStates(ctx, ports.SensorStateQuery{Since: at, Until: at.Add(30 * time.Second)})
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if len(rows) != 1 || rows[0].ReportID != "report-a" {
		t.Fatalf("filtered rows = %#v, want report-a", rows)
	}
}

func TestSensorStateStoreUsesHalfOpenUpperBoundAndHostFilter(t *testing.T) {
	store := NewSensorStateStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	atSince := testSensorObservation("at-since", since)
	atUntil := testSensorObservation("at-until", since.Add(time.Minute))
	otherHost := testSensorObservation("other-host", since.Add(30*time.Second))
	otherHost.HostID = "host-2"
	otherHost.States[0].HostID = "host-2"
	for _, observation := range []sensorstate.Observation{atUntil, otherHost, atSince} {
		if err := store.AppendSensorState(ctx, observation); err != nil {
			t.Fatalf("append %s: %v", observation.ReportID, err)
		}
	}

	rows, err := store.ListSensorStates(ctx, ports.SensorStateQuery{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "agent-1",
		Since: since, Until: since.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("list half-open window: %v", err)
	}
	if len(rows) != 1 || rows[0].ReportID != atSince.ReportID {
		t.Fatalf("rows = %#v, want only report at Since", rows)
	}
}

func TestSensorStateStoreReturnsEffectiveAndInWindowCoverageFacts(t *testing.T) {
	store := NewSensorStateStore()
	tenantA := shared.WithTenant(t.Context(), "tenant-a")
	tenantB := shared.WithTenant(t.Context(), "tenant-b")
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	observations := []sensorstate.Observation{
		testSensorObservation("stale", since.Add(-2*time.Minute)),
		testSensorObservation("effective", since.Add(-time.Minute)),
		testSensorObservation("at-since", since),
		testSensorObservation("inside", since.Add(time.Minute)),
		testSensorObservation("at-until", since.Add(2*time.Minute)),
	}
	for _, observation := range observations {
		if err := store.AppendSensorState(tenantA, observation); err != nil {
			t.Fatalf("append %s: %v", observation.ReportID, err)
		}
	}
	if err := store.AppendSensorState(tenantB, testSensorObservation("other-tenant", since.Add(30*time.Second))); err != nil {
		t.Fatalf("append other tenant: %v", err)
	}

	query := ports.CoverageSensorStateQuery{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "agent-1",
		Since: since, Until: since.Add(2 * time.Minute),
	}
	rows, err := store.ListCoverageSensorStates(tenantA, query)
	if err != nil {
		t.Fatalf("list coverage sensor states: %v", err)
	}
	want := []shared.ID{"effective", "at-since", "inside"}
	if len(rows) != len(want) {
		t.Fatalf("report count = %d, want %d: %#v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i].ReportID != want[i] {
			t.Fatalf("report[%d] = %q, want %q", i, rows[i].ReportID, want[i])
		}
	}
	other, err := store.ListCoverageSensorStates(tenantB, query)
	if err != nil {
		t.Fatalf("list other tenant: %v", err)
	}
	if len(other) != 1 || other[0].ReportID != "other-tenant" {
		t.Fatalf("other tenant rows = %#v", other)
	}
}

func TestSensorStateStoreReturnsEffectivePreWindowFactPerClass(t *testing.T) {
	store := NewSensorStateStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	since := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	process := testSensorObservation("process-active", since.Add(-time.Hour))
	process.States[0].Since = process.ObservedAt
	network := testSensorObservation("network-degraded", since.Add(-30*time.Minute))
	network.States = []detection.ClassCoverage{{
		Class: detection.ClassNetwork, HostID: network.HostID, AgentID: network.AgentID,
		State: detection.StateDegraded, Reason: "capture backlog", Since: network.ObservedAt,
	}}
	for _, observation := range []sensorstate.Observation{process, network} {
		if err := store.AppendSensorState(ctx, observation); err != nil {
			t.Fatalf("append %s: %v", observation.ReportID, err)
		}
	}

	rows, err := store.ListCoverageSensorStates(ctx, ports.CoverageSensorStateQuery{
		AgentID: "agent-1", AssetID: "asset-1", HostID: "agent-1",
		Since: since, Until: since.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("list coverage sensor states: %v", err)
	}
	want := []shared.ID{"process-active", "network-degraded"}
	if len(rows) != len(want) {
		t.Fatalf("report count = %d, want %d: %#v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i].ReportID != want[i] {
			t.Fatalf("report[%d] = %q, want %q", i, rows[i].ReportID, want[i])
		}
	}
}

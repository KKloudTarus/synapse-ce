package endpointstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	svcTenant = shared.ID("tenant-s")
	svcAsset  = shared.ID("asset-s")
)

var svcBase = time.Unix(1_800_000_000, 0).UTC()

func procEnv(eventID string, occ time.Time, entityID shared.ID) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       shared.ID(eventID),
		EventType:     "process.exec",
		EventClass:    detection.ClassProcess,
		AgentID:       shared.ID("agent-s"), AssetID: svcAsset, BootID: shared.ID("boot-s"),
		OccurredAt: occ, ObservedAt: occ,
		Event: telemetry.TelemetryEvent{Class: detection.ClassProcess, Process: &telemetry.ProcessObservation{
			Kind: "exec", PID: 100, EntityID: entityID, Comm: "app", Path: "/usr/bin/app",
		}},
	}
}

func newService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	svc, err := NewService(memory.NewEndpointTimelineStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, shared.WithTenant(context.Background(), svcTenant)
}

func TestNewServiceRequiresStore(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil store must be rejected, got %v", err)
	}
}

func TestRecordPersistsAndIsIdempotent(t *testing.T) {
	svc, ctx := newService(t)
	env := procEnv("e1", svcBase, shared.ID("pe1"))
	rec, err := svc.Record(ctx, env)
	if err != nil || len(rec) != 1 {
		t.Fatalf("record: entries=%d err=%v", len(rec), err)
	}
	// Re-record the same envelope: no duplicate persisted.
	if _, err := svc.Record(ctx, env); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Query(ctx, ports.EndpointTimelineQuery{AssetID: svcAsset})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EventID != "e1" || got[0].EntityID != "pe1" {
		t.Fatalf("query after idempotent record wrong: %+v", got)
	}
}

func TestRecordFailsClosed(t *testing.T) {
	svc, ctx := newService(t)
	// Missing tenant.
	if _, err := svc.Record(context.Background(), procEnv("e1", svcBase, "pe1")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant must be rejected, got %v", err)
	}
	// Malformed envelope (no schema version).
	bad := procEnv("e2", svcBase, "pe1")
	bad.SchemaVersion = 0
	if _, err := svc.Record(ctx, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed envelope must be rejected, got %v", err)
	}
	// Nothing was persisted by the rejected calls.
	got, _ := svc.Query(ctx, ports.EndpointTimelineQuery{AssetID: svcAsset})
	if len(got) != 0 {
		t.Fatalf("rejected records must persist nothing, got %d", len(got))
	}
}

func TestRecordMultipleClassesQueryable(t *testing.T) {
	svc, ctx := newService(t)
	mustRecord(t, svc, ctx, procEnv("e1", svcBase, shared.ID("pe1")))
	// A second process event at a later time.
	mustRecord(t, svc, ctx, procEnv("e2", svcBase.Add(time.Second), shared.ID("pe2")))
	got, err := svc.Query(ctx, ports.EndpointTimelineQuery{AssetID: svcAsset})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].EventID != "e1" || got[1].EventID != "e2" {
		t.Fatalf("query wrong: %+v", got)
	}
}

func mustRecord(t *testing.T, svc *Service, ctx context.Context, env telemetry.TelemetryEnvelope) {
	t.Helper()
	if _, err := svc.Record(ctx, env); err != nil {
		t.Fatalf("record %s: %v", env.EventID, err)
	}
}

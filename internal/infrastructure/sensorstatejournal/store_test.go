package sensorstatejournal

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestStoreReplacesStateAtomically(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	store, err := New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	first := validState(t)
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("save first state: %v", err)
	}
	second := ports.SensorStateDeliveryState{Version: ports.SensorStateDeliveryStateVersion}
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("replace state: %v", err)
	}
	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("load replaced state: %v", err)
	}
	if loaded.Pending != nil {
		t.Fatalf("replaced state retained pending report: %+v", loaded)
	}
	entries, err := os.ReadDir(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(store.path) {
		t.Fatalf("atomic replacement left unexpected files: %+v", entries)
	}
}

func TestStoreRejectsInvalidState(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), ports.SensorStateDeliveryState{Version: ports.SensorStateDeliveryStateVersion + 1}); err == nil {
		t.Fatal("invalid state version unexpectedly persisted")
	}
}

func validState(t *testing.T) ports.SensorStateDeliveryState {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	report := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		ReportID:        "report-1", AgentID: "agent-1", HostID: "agent-1",
		AgentSessionID: fleetagent.CanonicalSessionID("agent-1"), AssetID: "asset-1",
		Kind: "coverage", ObservedAt: at, SchemaVersion: 1,
		PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		States:        []detection.ClassCoverage{{Class: detection.ClassProcess, AgentID: "agent-1", HostID: "agent-1", State: detection.StateActive, Since: at}},
		KeyID:         "key-1",
	}
	report.Signature = fleetagent.SignSensorState(privateKey, report)
	return ports.SensorStateDeliveryState{
		Version: ports.SensorStateDeliveryStateVersion,
		Pending: &ports.PendingSensorStateReport{Epoch: 1, WALThrough: 1, Report: report},
	}
}

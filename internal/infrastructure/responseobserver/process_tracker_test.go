package responseobserver

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func TestProcessTrackerReturnsExactTargetExitAndReplacementFromTargetAsset(t *testing.T) {
	at := time.Unix(1_000, 0).UTC()
	tracker := NewProcessTracker()
	target := detection.ProcessEvent{Kind: "exec", PID: 100, StartTimeNanos: 10, Path: "/usr/bin/service", Comm: "service"}
	request := observationRequest(false, at, telemetry.ProcessEntityID("target-asset", "boot-1", target.PID, target.StartTimeNanos))
	tracker.ObserveProcessAt("target-asset", "boot-1", at.Add(time.Second), target)
	tracker.ObserveProcessAt("target-asset", "boot-1", at.Add(2*time.Second), detection.ProcessEvent{Kind: "exit", PID: target.PID, StartTimeNanos: target.StartTimeNanos})
	observation, ok := tracker.ObservationFor(request)
	if !ok || observation.TargetExit.Process.EntityID != request.Target.ProcessEntityID || observation.TargetExit.Process.PID != target.PID || observation.Replacement != nil {
		t.Fatalf("forward observation=%+v ok=%t", observation, ok)
	}
	request.Reversal = true
	tracker.ObserveProcessAt("target-asset", "boot-1", at.Add(3*time.Second), detection.ProcessEvent{Kind: "exec", PID: 101, StartTimeNanos: 11, Path: target.Path, Comm: target.Comm})
	observation, ok = tracker.ObservationFor(request)
	want := telemetry.ProcessEntityID("target-asset", "boot-1", 101, 11)
	if !ok || observation.Replacement == nil || observation.Replacement.Process.EntityID != want || strings.Contains(observation.Replacement.Process.EntityID.String(), "observer-primary") {
		t.Fatalf("reversal observation=%+v ok=%t want replacement %q", observation, ok, want)
	}
}

func TestProcessTrackerRefusesPrimaryHostRelabeling(t *testing.T) {
	at := time.Unix(1_000, 0).UTC()
	tracker := NewProcessTracker()
	target := detection.ProcessEvent{Kind: "exec", PID: 100, StartTimeNanos: 10, Path: "/svc", Comm: "svc"}
	request := observationRequest(false, at, telemetry.ProcessEntityID("target-asset", "boot-1", target.PID, target.StartTimeNanos))
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(time.Second), target)
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(2*time.Second), detection.ProcessEvent{Kind: "exit", PID: target.PID, StartTimeNanos: target.StartTimeNanos})
	if _, ok := tracker.ObservationFor(request); ok {
		t.Fatal("primary-host event was relabeled as target-asset evidence")
	}
}

func TestProcessTrackerRefusesAbsentAndAmbiguousEvidence(t *testing.T) {
	at := time.Unix(1_000, 0).UTC()
	tracker := NewProcessTracker()
	request := observationRequest(false, at, telemetry.ProcessEntityID("target-asset", "boot-1", 100, 10))
	if _, ok := tracker.ObservationFor(request); ok {
		t.Fatal("fabricated observation")
	}
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(time.Second), detection.ProcessEvent{Kind: "exit", PID: 100, StartTimeNanos: 10})
	if _, ok := tracker.ObservationFor(request); ok {
		t.Fatal("exit without local observed process nominated")
	}
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(time.Second), detection.ProcessEvent{Kind: "exec", PID: 100, StartTimeNanos: 10, Path: "/svc", Comm: "svc"})
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(2*time.Second), detection.ProcessEvent{Kind: "exit", PID: 100, StartTimeNanos: 10})
	request.Reversal = true
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(3*time.Second), detection.ProcessEvent{Kind: "exec", PID: 101, StartTimeNanos: 11, Path: "/svc", Comm: "svc"})
	tracker.ObserveProcessAt("observer-primary", "boot-1", at.Add(4*time.Second), detection.ProcessEvent{Kind: "exec", PID: 102, StartTimeNanos: 12, Path: "/svc", Comm: "svc"})
	if _, ok := tracker.ObservationFor(request); ok {
		t.Fatal("ambiguous replacement nominated")
	}
}

func observationRequest(reversal bool, at time.Time, entityID shared.ID) fleetagent.ResponseObservationRequest {
	return fleetagent.ResponseObservationRequest{AssetID: "target-asset", Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "target-asset", ProcessEntityID: entityID}, Reversal: reversal, AttemptedAt: at}
}

package responseobserver

import (
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

const maxTrackedProcesses = 4096

type observedProcess struct {
	sourceAssetID  shared.ID
	bootID         shared.ID
	pid            int
	startTime      uint64
	path           string
	comm           string
	sequence       uint64
	exitSequence   uint64
	observedAt     time.Time
	exitObservedAt time.Time
	exited         bool
}

// ProcessTracker retains bounded, actually observed lifecycle facts from the local
// sensor. It never treats a command result as a process observation.
type ProcessTracker struct {
	mu      sync.Mutex
	entries map[shared.ID]observedProcess
	order   uint64
}

func NewProcessTracker() *ProcessTracker {
	return &ProcessTracker{entries: make(map[shared.ID]observedProcess)}
}

// ObserveProcess is retained for lifecycle-observer compatibility. Callers that
// have a sensor timestamp must use ObserveProcessAt.
func (t *ProcessTracker) ObserveProcess(assetID, bootID shared.ID, event detection.ProcessEvent) {
	t.ObserveProcessAt(assetID, bootID, time.Now().UTC(), event)
}

// ObserveProcessAt records one actual process lifecycle event after its matching
// canonical telemetry event reached the local WAL.
func (t *ProcessTracker) ObserveProcessAt(assetID, bootID shared.ID, observedAt time.Time, event detection.ProcessEvent) {
	if assetID.IsZero() || bootID.IsZero() || event.PID <= 1 || event.StartTimeNanos == 0 || observedAt.IsZero() {
		return
	}
	entityID := telemetry.ProcessEntityID(assetID, bootID, event.PID, event.StartTimeNanos)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.order++
	if event.Kind == "exit" {
		entry, found := t.entries[entityID]
		// An exit without a prior local start carries insufficient identity/path
		// facts to nominate a target or replacement.
		if !found {
			return
		}
		entry.exited = true
		entry.exitSequence = t.order
		entry.exitObservedAt = observedAt.UTC()
		t.entries[entityID] = entry
		return
	}
	if event.Kind != "" && event.Kind != "exec" && event.Kind != "fork" {
		return
	}
	t.entries[entityID] = observedProcess{
		sourceAssetID: assetID, bootID: bootID, pid: event.PID, startTime: event.StartTimeNanos,
		path: strings.TrimSpace(event.Path), comm: strings.TrimSpace(event.Comm), sequence: t.order,
		observedAt: observedAt.UTC(),
	}
	t.evictLocked()
}

// ObservationFor returns only target-asset evidence observed by an authenticated
// target-asset sensor. It never rebinds local or primary-host observations to a
// different asset: sourceAssetID is the authoritative asset boundary.
// Missing facts or competing replacements fail closed by returning no observation.
func (t *ProcessTracker) ObservationFor(request fleetagent.ResponseObservationRequest) (fleetagent.ResponseObservation, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var target observedProcess
	found := false
	for _, entry := range t.entries {
		if entry.sourceAssetID != request.AssetID || !entry.exited || entry.exitObservedAt.IsZero() || !entry.exitObservedAt.After(request.AttemptedAt) {
			continue
		}
		if telemetry.ProcessEntityID(entry.sourceAssetID, entry.bootID, entry.pid, entry.startTime) != request.Target.ProcessEntityID {
			continue
		}
		if found { // Never select among duplicate local observations.
			return fleetagent.ResponseObservation{}, false
		}
		target, found = entry, true
	}
	if !found {
		return fleetagent.ResponseObservation{}, false
	}
	targetExit := bounded(target, target.sourceAssetID, "exit", target.exitObservedAt)
	observation := fleetagent.ResponseObservation{TargetExit: targetExit}
	if !request.Reversal {
		return observation, observation.ValidateFor(request) == nil
	}

	var replacement *observedProcess
	for _, entry := range t.entries {
		if entry.sourceAssetID != request.AssetID || entry.exited || entry.sequence <= target.exitSequence || !entry.observedAt.After(target.exitObservedAt) ||
			entry.path == "" || entry.path != target.path {
			continue
		}
		if replacement != nil {
			return fleetagent.ResponseObservation{}, false
		}
		candidate := entry
		replacement = &candidate
	}
	if replacement == nil {
		return fleetagent.ResponseObservation{}, false
	}
	replacementEvent := bounded(*replacement, replacement.sourceAssetID, "exec", replacement.observedAt)
	observation.Replacement = &replacementEvent
	return observation, observation.ValidateFor(request) == nil
}

func bounded(entry observedProcess, targetAssetID shared.ID, kind string, observedAt time.Time) fleetagent.BoundedProcessObservation {
	process := telemetry.ProcessObservation{
		Kind: kind, PID: entry.pid, StartTimeNanos: entry.startTime, Comm: entry.comm, Path: entry.path,
	}
	process.EntityID = telemetry.ProcessEntityID(targetAssetID, entry.bootID, process.PID, process.StartTimeNanos)
	return fleetagent.BoundedProcessObservation{BootID: entry.bootID, OccurredAt: observedAt, ObservedAt: observedAt, Process: process}
}

func (t *ProcessTracker) evictLocked() {
	for len(t.entries) > maxTrackedProcesses {
		var oldestID shared.ID
		oldestSequence := ^uint64(0)
		for id, entry := range t.entries {
			if entry.sequence < oldestSequence {
				oldestID, oldestSequence = id, entry.sequence
			}
		}
		delete(t.entries, oldestID)
	}
}

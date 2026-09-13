package main

import (
	"context"
	"log"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	runtimeevidence "github.com/KKloudTarus/synapse-ce/internal/infrastructure/runtimeevidence"
)

const (
	// minRuntimeReachInterval floors the ship cadence so a misconfigured interval cannot busy-loop the
	// collector (which reads the package database each tick).
	minRuntimeReachInterval = time.Minute
	// maxObservedLoads bounds the set of distinct loaded objects the agent accumulates between ships, so a
	// host that loads a great many distinct libraries cannot grow the set without limit. It is far above the
	// distinct shared objects a real host loads; beyond it, further loads are dropped (raise-only: a missed
	// load only forgoes an urgency raise).
	maxObservedLoads = 8192
)

// libraryLoadSensor is the eBPF observer the sweep drains. *ebpf.LibraryLoadSensor satisfies it; a fake
// drives the loop in tests without eBPF or root.
type libraryLoadSensor interface {
	Start(ctx context.Context) error
	Events() <-chan ebpf.LibraryLoadEvent
	Close() error
}

// newLibraryLoadSensor is overridable in tests. In production it returns the real eBPF sensor (a no-op stub
// off Linux).
var newLibraryLoadSensor = func() libraryLoadSensor { return ebpf.NewLibraryLoadSensor() }

// startRuntimeReachabilitySweep launches the runtime-reachability producer (#1060/#1061): it starts the
// eBPF library-load sensor and, on a cadence, resolves the OS packages that own the observed loads and
// ships them. It is best-effort and raise-only: if the sensor cannot run (no privilege / kernel / not
// Linux) it ships a single coverage-gap report so the gap is visible server-side, then stops.
func (r *runner) startRuntimeReachabilitySweep(ctx context.Context, cred fleetclient.Credential) {
	if !r.cfg.runtimeReachEnabled {
		return
	}
	sensor := newLibraryLoadSensor()
	if err := sensor.Start(ctx); err != nil {
		// The sensor is unavailable; declare the coverage gap once so the control plane records that this
		// host reports no runtime evidence (honest gap, never a silent partial), then stop.
		_ = r.api.SendRuntimeEvidence(ctx, cred.Token, runtimereach.Report{
			Coverage: []runtimereach.CoverageReason{runtimereach.CoverageSensorUnavailable},
		})
		log.Printf("runtime reachability: library-load sensor unavailable (%v); no runtime evidence collected", err)
		return
	}
	go r.runRuntimeReachLoop(ctx, cred, sensor, clampRuntimeReachInterval(r.cfg.runtimeReachInterval))
}

// clampRuntimeReachInterval floors the configured ship cadence at minRuntimeReachInterval so a
// misconfigured (or zero) interval cannot busy-loop the collector, which reads the package database each
// tick.
func clampRuntimeReachInterval(interval time.Duration) time.Duration {
	if interval < minRuntimeReachInterval {
		return minRuntimeReachInterval
	}
	return interval
}

// runRuntimeReachLoop drains the sensor into a bounded set of observed load paths and, every interval,
// resolves and ships them. It re-ships the accumulated set each tick; the control plane's join is
// idempotent (supersede-only), so a re-ship raises nothing new, and a re-ship is what lets a host whose
// first scan had not produced findings converge once they exist. It never resets the set: a library loaded
// once at process start stays relevant, so dropping it would forgo a real urgency raise.
//
// The collect-and-ship runs in a single-flight goroutine, not inline: reading the package database and
// stat'ing files takes up to a second or two on a large host, and doing it inline would stop draining the
// sensor for that whole window, overflowing the bounded event channel and dropping loads. Snapshotting the
// paths and shipping off the loop keeps the drain hot; a tick that arrives while a ship is still running is
// skipped (the next tick re-ships the same-or-larger set), so ships never pile up.
func (r *runner) runRuntimeReachLoop(ctx context.Context, cred fleetclient.Credential, sensor libraryLoadSensor, interval time.Duration) {
	defer func() { _ = sensor.Close() }()
	observed := map[string]struct{}{}
	truncated := false
	events := sensor.Events()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	shipping := false
	shipped := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return // sensor drain stopped
			}
			if ev.Path == "" {
				continue
			}
			if len(observed) >= maxObservedLoads {
				truncated = true // the observed set is full; further distinct loads are dropped (raise-only)
				continue
			}
			observed[ev.Path] = struct{}{}
		case <-shipped:
			shipping = false
		case <-ticker.C:
			if len(observed) == 0 || shipping {
				continue // nothing observed yet, or a ship is still in flight; no empty report, no pile-up
			}
			paths := make([]string, 0, len(observed))
			for p := range observed {
				paths = append(paths, p)
			}
			wasTruncated := truncated
			shipping = true
			go func() {
				defer func() { shipped <- struct{}{} }()
				report := runtimeevidence.NewCollector(r.cfg.root).Collect(paths)
				if wasTruncated {
					// The observed set hit its cap and dropped distinct loads; declare it so the join knows the
					// runtime evidence is partial rather than reading the shipped set as the whole truth.
					report.Coverage = append(report.Coverage, runtimereach.CoverageTruncated)
				}
				if err := r.api.SendRuntimeEvidence(ctx, cred.Token, report); err != nil {
					log.Printf("runtime reachability: ship evidence: %v", err)
				}
			}()
		}
	}
}

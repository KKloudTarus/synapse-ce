package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

// minInventorySweepInterval floors the sweep cadence: enumerating installed OS packages + language deps
// over the real filesystem is heavier than a heartbeat, so a misconfigured tiny interval must not busy-loop
// the collector. A 1-minute floor is well below any realistic advisory-freshness need.
const minInventorySweepInterval = time.Minute

// envEnabledDefaultTrue parses a boolean env var that defaults to ON when unset: only an explicit
// false/0/no/off disables. Used so the continuous sweep is ingest-on by default (#629) yet operator-
// disableable.
func envEnabledDefaultTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

// startInventorySweep launches the continuous host-inventory sweep (#629, A8) as a background goroutine. It
// ships one inventory promptly, then re-sweeps on the configured cadence, until the context is cancelled.
// Every ship is idempotent server-side (host upsert-by-natural-key), so a re-sweep of an unchanged host is
// a no-op, and a fresh inventory lets the continuous-exposure engine re-flag it against new advisories with
// no re-scan. It is best-effort: a collect/ship error is logged and retried on the next cadence, never
// blocking the agent.
func (r *runner) startInventorySweep(ctx context.Context, cred fleetclient.Credential) {
	if r.cfg.once {
		// A one-shot diagnostic run (`--once`) does a single work-order cycle and exits; starting a
		// continuous background stream that races process teardown would be surprising and pointless.
		return
	}
	if !r.cfg.inventorySweepEnabled {
		log.Print("inventory sweep: disabled (SYNAPSE_INVENTORY_SWEEP_ENABLED=false)")
		return
	}
	interval := resolveSweepInterval(r.cfg.inventorySweepInterval)
	if interval != r.cfg.inventorySweepInterval {
		log.Printf("inventory sweep: interval %s below the %s floor; using the floor", r.cfg.inventorySweepInterval, minInventorySweepInterval)
	}
	go r.runSweepLoop(ctx, cred, interval)
}

// resolveSweepInterval clamps the configured cadence to the floor so a misconfiguration cannot busy-loop
// the collector.
func resolveSweepInterval(d time.Duration) time.Duration {
	if d < minInventorySweepInterval {
		return minInventorySweepInterval
	}
	return d
}

// runSweepLoop sweeps once promptly (so a freshly-started agent is not dark until the first tick), then
// re-sweeps every interval until the context is cancelled. It blocks; startInventorySweep runs it in a
// goroutine.
func (r *runner) runSweepLoop(ctx context.Context, cred fleetclient.Credential, interval time.Duration) {
	r.sweepOnce(ctx, cred)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweepOnce(ctx, cred)
		}
	}
}

// sweepOnce collects the host inventory and ships it to the control plane. Best-effort: errors are logged,
// not returned — the next cadence is the retry, and the server ingest is idempotent so a repeated ship of
// an unchanged host produces no churn.
func (r *runner) sweepOnce(ctx context.Context, cred fleetclient.Credential) {
	if err := ctx.Err(); err != nil {
		return
	}
	inv, err := r.collect(ctx, r.cfg.root)
	if err != nil {
		log.Printf("inventory sweep: collect: %v", err)
		return
	}
	if err := r.api.SendHostInventory(ctx, cred.Token, inv); err != nil {
		log.Printf("inventory sweep: report inventory: %v", err)
		return
	}
	// A degraded inventory is still shipped — the control plane records the coverage/degraded flags on the
	// asset (coverage honesty), so a partial sweep is a visible gap, never silence — but note it locally.
	if inv.Degraded() {
		log.Print("inventory sweep: shipped a DEGRADED inventory (package data incomplete); coverage recorded server-side")
	}
}

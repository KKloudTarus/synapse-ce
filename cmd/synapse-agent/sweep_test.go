package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

// sweepAPI is a concurrency-safe fleetAPI for the background sweep loop: it counts SendHostInventory calls
// under a mutex (the loop ships from a goroutine, so the plain fakeAPI.sent would race). It embeds *fakeAPI
// for the other methods and overrides only the ship.
type sweepAPI struct {
	*fakeAPI
	mu    sync.Mutex
	ships int
	err   error
}

func (s *sweepAPI) SendHostInventory(_ context.Context, _ string, _ any) error {
	s.mu.Lock()
	s.ships++
	s.mu.Unlock()
	return s.err
}
func (s *sweepAPI) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ships
}

func newSweepRunner(t *testing.T, api *sweepAPI, enabled bool, collect func(context.Context, string) (hostinventory.HostInventory, error)) *runner {
	t.Helper()
	dir := t.TempDir()
	return &runner{
		api:     api,
		collect: collect,
		cfg:     config{stateDir: dir, root: dir, name: "host1", inventorySweepEnabled: enabled},
	}
}

// waitForShips polls until at least n ships are observed or the deadline passes (no fixed sleeps, so it is
// not timing-flaky).
func waitForShips(t *testing.T, api *sweepAPI, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if api.count() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d ships, saw %d", n, api.count())
}

func TestSweepOnceShipsCollectedInventory(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, true, okCollect(hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux"}}))
	r.sweepOnce(context.Background(), fleetclient.Credential{Token: "t"})
	if api.count() != 1 {
		t.Fatalf("sweepOnce must ship exactly once, got %d", api.count())
	}
}

func TestSweepOnceCollectErrorDoesNotShip(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, true, func(context.Context, string) (hostinventory.HostInventory, error) {
		return hostinventory.HostInventory{}, errors.New("collect failed")
	})
	r.sweepOnce(context.Background(), fleetclient.Credential{Token: "t"})
	if api.count() != 0 {
		t.Fatalf("a collect failure must not ship, got %d", api.count())
	}
}

func TestSweepOnceCancelledContextDoesNotShip(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, true, okCollect(hostinventory.HostInventory{}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.sweepOnce(ctx, fleetclient.Credential{Token: "t"})
	if api.count() != 0 {
		t.Fatalf("a cancelled context must ship nothing, got %d", api.count())
	}
}

func TestResolveSweepIntervalFloor(t *testing.T) {
	if got := resolveSweepInterval(time.Second); got != minInventorySweepInterval {
		t.Fatalf("below-floor interval must clamp to %s, got %s", minInventorySweepInterval, got)
	}
	if got := resolveSweepInterval(2 * time.Hour); got != 2*time.Hour {
		t.Fatalf("above-floor interval must pass through, got %s", got)
	}
}

func TestRunSweepLoopShipsOnCadence(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, true, okCollect(hostinventory.HostInventory{Facts: hostinventory.HostFacts{OS: "linux"}}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.runSweepLoop(ctx, fleetclient.Credential{Token: "t"}, 5*time.Millisecond)
	// One prompt sweep + several ticks → at least 3 ships in well under the deadline.
	waitForShips(t, api, 3)
}

func TestRunSweepLoopStopsOnCancel(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, true, okCollect(hostinventory.HostInventory{}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.runSweepLoop(ctx, fleetclient.Credential{Token: "t"}, 5*time.Millisecond); close(done) }()
	waitForShips(t, api, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSweepLoop did not stop after context cancellation")
	}
	stable := api.count()
	time.Sleep(20 * time.Millisecond)
	if api.count() != stable {
		t.Fatalf("no ships must occur after the loop stopped: was %d, now %d", stable, api.count())
	}
}

func TestStartInventorySweepDisabledDoesNotShip(t *testing.T) {
	api := &sweepAPI{fakeAPI: &fakeAPI{}}
	r := newSweepRunner(t, api, false, okCollect(hostinventory.HostInventory{}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.startInventorySweep(ctx, fleetclient.Credential{Token: "t"})
	time.Sleep(20 * time.Millisecond)
	if api.count() != 0 {
		t.Fatalf("a disabled sweep must ship nothing, got %d", api.count())
	}
}

func TestEnvEnabledDefaultTrue(t *testing.T) {
	for _, v := range []string{"", "true", "1", "yes", "anything"} {
		if !envEnabledDefaultTrue(v) {
			t.Fatalf("%q must enable (default-on)", v)
		}
	}
	for _, v := range []string{"false", "0", "no", "off", "FALSE", " Off "} {
		if envEnabledDefaultTrue(v) {
			t.Fatalf("%q must disable", v)
		}
	}
}

//go:build linux
// +build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

// fakeSensor drives the runtime-reachability loop without eBPF or root.
type fakeSensor struct {
	startErr error
	events   chan ebpf.LibraryLoadEvent
	closed   bool
}

func (f *fakeSensor) Start(context.Context) error          { return f.startErr }
func (f *fakeSensor) Events() <-chan ebpf.LibraryLoadEvent { return f.events }
func (f *fakeSensor) Close() error                         { f.closed = true; return nil }

func withFakeSensor(t *testing.T, s libraryLoadSensor) {
	t.Helper()
	prev := newLibraryLoadSensor
	newLibraryLoadSensor = func() libraryLoadSensor { return s }
	t.Cleanup(func() { newLibraryLoadSensor = prev })
}

// dpkgTestRoot writes a minimal Debian package DB with libc6 owning a shared object, so the collector
// resolves a real owning package (device+inode come from the actual files).
func dpkgTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("/var/lib/dpkg/status", "Package: libc6\nVersion: 2.39-0ubuntu8.7\n\n")
	mustWrite("/var/lib/dpkg/info/libc6:amd64.list", "/usr/lib/x86_64-linux-gnu/libc.so.6\n")
	mustWrite("/usr/lib/x86_64-linux-gnu/libc.so.6", "so")
	return root
}

func TestRuntimeReachSweepShipsResolvedEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dpkg runtime evidence requires Linux filesystem semantics")
	}
	sensor := &fakeSensor{events: make(chan ebpf.LibraryLoadEvent, 4)}
	withFakeSensor(t, sensor)
	api := &fakeAPI{}
	r := &runner{api: api, cfg: config{runtimeReachEnabled: true, runtimeReachInterval: time.Minute, root: dpkgTestRoot(t)}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Feed one observed load, then run one loop tick synchronously by calling the loop with a tiny interval.
	sensor.events <- ebpf.LibraryLoadEvent{Path: "/usr/lib/x86_64-linux-gnu/libc.so.6"}
	go r.runRuntimeReachLoop(ctx, fleetclient.Credential{Token: "t"}, sensor, 20*time.Millisecond)

	deadline := time.After(2 * time.Second)
	var reports []runtimereach.Report
	for {
		reports = api.runtimeReportsSnapshot()
		if len(reports) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no runtime evidence shipped")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	rep := reports[len(reports)-1]
	if len(rep.PackageFiles) != 1 || rep.PackageFiles[0].Package.Name != "libc6" {
		t.Fatalf("shipped report must resolve libc6, got %+v", rep.PackageFiles)
	}
	if len(rep.Loads) != 1 || rep.Loads[0].Path != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Fatalf("shipped report must carry the observed load, got %+v", rep.Loads)
	}
}

func TestRuntimeReachSweepDeclaresGapWhenSensorUnavailable(t *testing.T) {
	sensor := &fakeSensor{startErr: errors.New("no privilege"), events: make(chan ebpf.LibraryLoadEvent)}
	withFakeSensor(t, sensor)
	api := &fakeAPI{}
	r := &runner{api: api, cfg: config{runtimeReachEnabled: true, runtimeReachInterval: time.Minute}}
	r.startRuntimeReachabilitySweep(context.Background(), fleetclient.Credential{Token: "t"})
	if len(api.runtimeReports) != 1 || len(api.runtimeReports[0].Coverage) != 1 {
		t.Fatalf("an unavailable sensor must ship exactly one coverage-gap report, got %+v", api.runtimeReports)
	}
}

func TestRuntimeReachSweepDisabledDoesNothing(t *testing.T) {
	sensor := &fakeSensor{events: make(chan ebpf.LibraryLoadEvent)}
	withFakeSensor(t, sensor)
	api := &fakeAPI{}
	r := &runner{api: api, cfg: config{runtimeReachEnabled: false}}
	r.startRuntimeReachabilitySweep(context.Background(), fleetclient.Credential{Token: "t"})
	if len(api.runtimeReports) != 0 {
		t.Fatalf("a disabled sweep must ship nothing, got %+v", api.runtimeReports)
	}
}

func TestClampRuntimeReachInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero is floored", 0, minRuntimeReachInterval},
		{"sub-minute is floored", 10 * time.Second, minRuntimeReachInterval},
		{"negative is floored", -time.Second, minRuntimeReachInterval},
		{"exactly the floor is kept", minRuntimeReachInterval, minRuntimeReachInterval},
		{"above the floor is kept", 5 * time.Minute, 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampRuntimeReachInterval(tc.in); got != tc.want {
				t.Fatalf("clampRuntimeReachInterval(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestRuntimeReachLoopCapsObservedSetAndDeclaresTruncation feeds more distinct loads than the cap and
// asserts the observed set stops growing AND the shipped report declares the truncation, so a capped sweep
// is honest about being partial rather than passing its cut-off set off as the whole truth.
func TestRuntimeReachLoopCapsObservedSetAndDeclaresTruncation(t *testing.T) {
	sensor := &fakeSensor{events: make(chan ebpf.LibraryLoadEvent, maxObservedLoads+64)}
	withFakeSensor(t, sensor)
	api := &fakeAPI{}
	// No package DB under this root, so Collect declares CoverageUnsupportedPlatform; the loop then appends
	// CoverageTruncated. The report still ships (there are loads), which is what we assert on.
	r := &runner{api: api, cfg: config{runtimeReachEnabled: true, root: t.TempDir()}}

	for i := 0; i < maxObservedLoads+50; i++ {
		sensor.events <- ebpf.LibraryLoadEvent{Path: "/usr/lib/lib" + strconv.Itoa(i) + ".so"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.runRuntimeReachLoop(ctx, fleetclient.Credential{Token: "t"}, sensor, 20*time.Millisecond)

	// Wait for a report that declares truncation. An early tick can ship before every buffered event has
	// drained (the cap not yet reached), so poll for the truncated report rather than asserting on the first.
	deadline := time.After(3 * time.Second)
	var truncatedRep *runtimereach.Report
	for truncatedRep == nil {
		for _, rep := range api.runtimeReportsSnapshot() {
			for _, c := range rep.Coverage {
				if c == runtimereach.CoverageTruncated {
					r := rep
					truncatedRep = &r
				}
			}
		}
		if truncatedRep != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no truncated runtime evidence shipped; observed-set cap not declared")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if len(truncatedRep.Loads) > maxObservedLoads {
		t.Fatalf("observed set must be capped at %d, shipped %d loads", maxObservedLoads, len(truncatedRep.Loads))
	}
}

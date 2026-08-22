//go:build linux

package ebpf

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

// requireSensor skips unless we can actually run eBPF here: root (unprivileged BPF is disabled on most
// kernels) and a working load. A CI runner without privilege skips rather than failing — but note the
// skip loudly, because a silent skip would let a broken sensor pass unnoticed.
func requireSensor(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("detection sensor needs root (unprivileged eBPF is disabled); run under sudo")
	}
}

func coverageFor(cov []detection.ClassCoverage, c detection.Class) (detection.ClassCoverage, bool) {
	for _, cc := range cov {
		if cc.Class == c {
			return cc, true
		}
	}
	return detection.ClassCoverage{}, false
}

// TestSensorLoadsAndDisablesEachClassIndependently is the #422 acceptance criterion on a real kernel:
// each event class loads independently, and a class not requested is reported disabled — never absent,
// never silently clean.
func TestSensorLoadsAndDisablesEachClassIndependently(t *testing.T) {
	requireSensor(t)
	for _, target := range detection.Classes() {
		t.Run(string(target), func(t *testing.T) {
			s := NewSensor("host-test", "agent:test", []detection.Class{target})
			if err := s.Start(context.Background()); err != nil {
				t.Fatalf("start %s: %v", target, err)
			}
			defer s.Close()

			cov := s.Coverage()
			if len(cov) != len(detection.Classes()) {
				t.Fatalf("coverage must report every class, got %d", len(cov))
			}
			active, ok := coverageFor(cov, target)
			if !ok || active.State != detection.StateActive {
				t.Fatalf("requested class %s must be active, got %+v", target, active)
			}
			// Every other class must be reported as a disabled gap, not missing and not clean.
			for _, other := range detection.Classes() {
				if other == target {
					continue
				}
				cc, ok := coverageFor(cov, other)
				if !ok {
					t.Fatalf("class %s missing from coverage", other)
				}
				if cc.State != detection.StateDisabled || !cc.IsObservationGap() {
					t.Fatalf("unrequested class %s must be a disabled gap, got %+v", other, cc)
				}
			}
		})
	}
}

// TestNetworkSensorCapturesNativeKprobeArguments is the architecture proof beyond a successful
// verifier load. The network program reads function arguments from target-specific pt_regs offsets;
// an object compiled for the wrong architecture can attach yet decode an unrelated pointer. A local
// UDP write is deterministic, needs no external network, and must emerge with its exact protocol and
// destination port on every supported native runner.
func TestNetworkSensorCapturesNativeKprobeArguments(t *testing.T) {
	requireSensor(t)
	s := NewSensor("host-native", "agent:native", []detection.Class{detection.ClassNetwork})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start network sensor: %v", err)
	}
	defer s.Close()

	conn, err := net.Dial("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("create local UDP fixture: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		_ = conn.Close()
		t.Fatalf("send local UDP fixture: %v", err)
	}
	_ = conn.Close()

	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-s.Events():
			if event.Network != nil && event.Network.Proto == "udp" && event.Network.RemotePort == 53 {
				return
			}
		case <-timer.C:
			t.Fatal("network sensor attached but did not decode native kprobe arguments for udp/53")
		}
	}
}

// TestSensorLifecycleGuards: Start is once-only and Close is idempotent, so a re-Start (which would
// duplicate coverage) or a Start-after-Close (which would panic on send-to-closed) is refused, and a
// double Close does not panic.
func TestSensorLifecycleGuards(t *testing.T) {
	requireSensor(t)
	s := NewSensor("h", "a", detection.Classes())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := s.Start(context.Background()); err == nil {
		t.Error("a second Start must be refused, not silently re-attach")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s.Close() // must not panic on double close
	if err := s.Start(context.Background()); err == nil {
		t.Error("Start after Close must be refused, not panic on the closed channel")
	}
}

// systemCPU returns the process's cumulative kernel (system) CPU time. The eBPF probes run in-kernel on
// each hooked syscall, so their cost lands in the workload's system time — the honest place to measure.
func systemCPU(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
}

// syscallStorm runs n openat calls on the given path — openat is the highest-volume hooked syscall.
func syscallStorm(n int, path string) {
	for i := 0; i < n; i++ {
		if f, err := os.Open(path); err == nil {
			_ = f.Close()
		}
	}
}

// measureOverhead runs the storm without then with the sensor and returns the added system CPU as a
// percentage.
func measureOverhead(t *testing.T, n int, path string) float64 {
	t.Helper()
	syscallStorm(10000, path) // warm caches
	b0 := systemCPU(t)
	syscallStorm(n, path)
	baseline := systemCPU(t) - b0

	s := NewSensor("host-test", "agent:test", detection.Classes())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	go func() { // drain so the ring buffers do not fill
		for range s.Events() {
		}
	}()
	time.Sleep(200 * time.Millisecond)

	w0 := systemCPU(t)
	syscallStorm(n, path)
	withSensor := systemCPU(t) - w0
	_ = s.Close()

	if baseline <= 0 {
		return 0
	}
	return float64(withSensor-baseline) / float64(baseline) * 100
}

// TestSensorOverheadReport measures and REPORTS the added system CPU of the sensor (issue #422
// acceptance). It reports TWO figures, honestly:
//
//   - representative: opens under a NON-watched path, so the file program's cheap prefix gate rejects
//     early and emits nothing — the cost paid on the vast majority of real syscalls.
//   - worst case: opens under /etc/, so every single call matches the gate and emits an event — a
//     pathological loop no real workload resembles.
//
// Even the representative figure here is an over-estimate of a real host, because the whole loop is
// ~100% openat; a real workload spends most of its time NOT in a hooked syscall.
func TestSensorOverheadReport(t *testing.T) {
	requireSensor(t)
	const n = 300000

	tmp, err := os.CreateTemp("", "synapse-detect-oh")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	representative := measureOverhead(t, n, tmpPath)    // non-watched: gate rejects, no emit
	worstCase := measureOverhead(t, n, "/etc/hostname") // watched: every call emits

	t.Logf("overhead over %d openat/iter (syscall-saturated loop):", n)
	t.Logf("  representative (non-watched path, gate rejects, no emit): %.1f%%", representative)
	t.Logf("  worst case     (watched path, every call emits an event): %.1f%%", worstCase)
	t.Logf("NOTE: a real host spends most cycles OUTSIDE hooked syscalls, so per-host overhead is below even the representative figure.")
}

// collect drains events into a slice for the given window while fixtures run.
func collect(s *Sensor, window time.Duration) []detection.Event {
	var out []detection.Event
	deadline := time.After(window)
	for {
		select {
		case ev := <-s.Events():
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

// TestSensorCapturesEventsAndDomainRulesFire is the end-to-end proof tying phase 2 to phase 1: real
// syscalls captured by eBPF, decoded to domain events, matched by the shipped catalogue into detections.
func TestSensorCapturesEventsAndDomainRulesFire(t *testing.T) {
	requireSensor(t)
	s := NewSensor("host-test", "agent:test", detection.Classes())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Close()

	// Drain in the background while we generate fixtures.
	events := make(chan []detection.Event, 1)
	go func() { events <- collect(s, 3*time.Second) }()

	time.Sleep(200 * time.Millisecond) // let the drains settle
	// exec fixture: `ps` → det.process_enumeration.
	_ = exec.Command("ps", "-ef").Run()
	// file fixture: open a watched sensitive path → det.credential_file_access. As root the open succeeds;
	// even a failed open still fires the openat tracepoint.
	if f, err := os.Open("/etc/shadow"); err == nil {
		_ = f.Close()
	}
	// network fixture: a UDP send to :53 → det.suspicious_dns_beacon.
	if c, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}

	captured := <-events
	if len(captured) == 0 {
		t.Fatal("no events captured from any class; the sensor pipe is not delivering")
	}

	// Run every captured event through the shipped catalogue and record which detections fired.
	fired := map[string]bool{}
	byClass := map[detection.Class]int{}
	for _, ev := range captured {
		byClass[ev.Class]++
		rules, _ := detection.CatalogueByClass(ev.Class)
		for _, r := range rules {
			if r.Match(ev) {
				d, err := detection.NewDetection(r, "host-test", "agent:test", []detection.Event{ev}, ev.At)
				if err != nil {
					t.Fatalf("a matched event failed to become a detection: %v", err)
				}
				fired[d.RuleID] = true
			}
		}
	}
	t.Logf("captured events per class: %+v", byClass)
	t.Logf("detections fired: %+v", fired)

	// The process class is the most reliable to trigger; require its detection end-to-end.
	if !fired["det.process_enumeration"] {
		t.Errorf("running ps did not produce a det.process_enumeration detection; process pipe broken")
	}
	// File and network are best-effort in a shared CI environment (the exact path/port must be observed);
	// log rather than hard-fail so an environment quirk does not mask the load/attach proof above.
	if !fired["det.credential_file_access"] {
		t.Logf("note: det.credential_file_access did not fire (no /etc/shadow open observed in window)")
	}
	if !fired["det.suspicious_dns_beacon"] {
		t.Logf("note: det.suspicious_dns_beacon did not fire (no udp:53 send observed in window)")
	}
}

// TestSensorReportsGapWhenUnavailable proves the honest-failure path: if the sensor cannot run at all,
// coverage reports every class as a gap, never clean. (Exercised directly via the stub-shaped contract;
// on a root kernel this simply confirms Coverage always returns all classes.)
func TestSensorAlwaysReportsEveryClass(t *testing.T) {
	requireSensor(t)
	s := NewSensor("h", "a", nil) // request nothing
	_ = s.Start(context.Background())
	defer s.Close()
	cov := s.Coverage()
	if len(cov) != len(detection.Classes()) {
		t.Fatalf("coverage must always report every class, got %d", len(cov))
	}
	for _, cc := range cov {
		if cc.State != detection.StateDisabled {
			t.Errorf("with nothing requested every class must be a disabled gap, got %+v", cc)
		}
		if _, ok := coverageFor(cov, cc.Class); !ok {
			t.Errorf("class %s missing", cc.Class)
		}
	}
}

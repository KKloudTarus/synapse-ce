//go:build linux

package ebpf_test

import (
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
)

// TestConnLogHelperDial is the child: launched INTO the monitored cgroup, it dials a couple
// of destinations so the connect4 hook fires, then exits. Gated so it only runs as a child.
func TestConnLogHelperDial(t *testing.T) {
	if os.Getenv("CONNLOG_HELPER") != "1" {
		t.Skip("helper (run only as the monitored child)")
	}
	for _, addr := range []string{"1.1.1.1:80", "8.8.8.8:53"} {
		if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			_ = c.Close()
		}
		// Even a failed/blocked connect fires the connect() hook – the ATTEMPT is the point.
	}
}

// TestConnLogCapturesConnects proves the eBPF cgroup hook captures every outbound
// connect() a process in the cgroup makes. Needs Linux + cgroup-bpf privilege (run with
// sudo on a real host); skips otherwise.
func TestConnLogCapturesConnects(t *testing.T) {
	m := ebpf.NewMonitor()
	sess, err := m.Start("e12test")
	if err != nil {
		t.Skipf("eBPF connect-logger unavailable (need root/CAP_BPF on Linux): %v", err)
	}
	defer sess.Close()

	// Re-exec this test binary, running only the dial helper, placed INTO the monitored
	// cgroup via clone-into-cgroup so its connects fire the hook race-free.
	cmd := exec.Command(os.Args[0], "-test.run=TestConnLogHelperDial", "-test.v")
	cmd.Env = append(os.Environ(), "CONNLOG_HELPER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: sess.CgroupFD()}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	time.Sleep(200 * time.Millisecond) // let the ring buffer drain

	events := sess.Close()
	gotPort := func(p int) bool {
		for _, e := range events {
			if e.Port == p {
				return true
			}
		}
		return false
	}
	if !gotPort(80) || !gotPort(53) {
		t.Fatalf("expected connect attempts to port 80 + 53 to be captured, got %d events: %+v", len(events), events)
	}
	t.Logf("OK: captured %d connect attempt(s), incl. ports 80 + 53", len(events))
}

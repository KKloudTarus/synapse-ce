package sandbox_test

import (
	"context"
	"net/netip"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestSandboxEgressConnectLog proves end-to-end that a sandboxed egress run captures
// every outbound connect() attempt (incl. the out-of-scope one the kernel drops) and
// labels each allowed/denied against the scope. Needs Linux + bwrap + curl + CAP_NET_ADMIN
// + cgroup-bpf (run with sudo on a real host); skips otherwise.
func TestSandboxEgressConnectLog(t *testing.T) {
	requireSandboxIntegration(t)
	if runtime.GOOS != "linux" {
		t.Skip("sandbox/eBPF are Linux-only")
	}
	for _, bin := range []string{"bwrap", "curl", "sh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	sb, err := sandbox.NewRunner(60*time.Second, 16<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	app, err := egress.NewApplier()
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	ctx := context.Background()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := app.Probe(pctx)
	cancel()
	if perr != nil {
		t.Skipf("egress not usable (run with sudo): %v", perr)
	}
	sb.SetEgress(app)
	sb.SetConnMonitor(ebpf.NewMonitor())

	// In scope: 1.1.1.1 only. The run connects to 1.1.1.1:80 (allowed) and 8.8.8.8:53
	// (out-of-scope → the SYN is kernel-dropped, but the connect() ATTEMPT is still logged).
	policy := ports.EgressPolicy{Rules: []ports.EgressRule{{Allow: true, Net: netip.MustParsePrefix("1.1.1.1/32")}}}
	spec := ports.ToolSpec{
		Name:         "sh",
		Args:         []string{"-c", "curl -s --connect-timeout 4 -o /dev/null http://1.1.1.1/ ; curl -s --connect-timeout 4 -o /dev/null http://8.8.8.8:53/ ; true"},
		EgressPolicy: &policy,
		Timeout:      40 * time.Second,
	}
	res, err := sb.Run(ctx, spec)
	if err != nil {
		t.Fatalf("sandboxed egress run: %v", err)
	}
	var inScope, outScope *ports.ConnEvent
	for i := range res.ConnectLog {
		switch res.ConnectLog[i].IP {
		case "1.1.1.1":
			inScope = &res.ConnectLog[i]
		case "8.8.8.8":
			outScope = &res.ConnectLog[i]
		}
	}
	if inScope == nil || !inScope.Allowed {
		t.Fatalf("in-scope connect to 1.1.1.1 not captured/allowed; log=%+v", res.ConnectLog)
	}
	if outScope == nil || outScope.Allowed {
		t.Fatalf("out-of-scope connect to 8.8.8.8 not captured/denied; log=%+v", res.ConnectLog)
	}
	t.Logf("connect log OK: %d attempts captured; 1.1.1.1:%d allowed=%v, 8.8.8.8:%d allowed=%v",
		len(res.ConnectLog), inScope.Port, inScope.Allowed, outScope.Port, outScope.Allowed)
}

package recon_test

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	egressinfra "github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	egresspolicy "github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
)

// TestNaabuSandboxedEgressContainment is the P3 acceptance demo (#387): the capability-
// sensitive tool naabu runs in the sandbox (cap-drop ALL + scoped CAP_NET_RAW, read-only
// root, scoped workdir) under a scope-derived default-deny egress. The SAME authorized
// target (scanme.nmap.org) is scanned twice: in the allowlist its open ports are found;
// out of the allowlist its SYN packets are KERNEL-DROPPED (no ports). Needs naabu +
// bubblewrap + CAP_NET_ADMIN (run with sudo on a real Linux host).
func TestNaabuSandboxedEgressContainment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox + egress are Linux-only")
	}
	for _, bin := range []string{"naabu", "bwrap"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	sb, err := sandbox.NewRunner(2*time.Minute, 8<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	app, err := egressinfra.NewApplier()
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	ctx := context.Background()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := app.Probe(pctx)
	cancel()
	if perr != nil {
		t.Skipf("egress not usable (run with sudo for CAP_NET_ADMIN): %v", perr)
	}
	sb.SetEgress(app)

	const scanme = "45.33.32.156" // scanme.nmap.org – Nmap's authorized scan target (22/80 open)

	// Build the naabu spec exactly as the recon adapter does (incl. CapAdd=CAP_NET_RAW),
	// then attach a scope-derived egress policy that allows allowIP only.
	scan := func(allowIP string) string {
		spec, err := recon.Naabu{}.BuildArgs(engagement.Target{Kind: engagement.TargetIP, Value: scanme})
		if err != nil {
			t.Fatal(err)
		}
		// The adapter already sets -s s (connect scan, uses the granted CAP_NET_RAW). -Pn skips
		// host discovery (its ping would stall on a fully-blackholed/out-of-scope target);
		// tight retries/timeout so the dropped case gives up instead of stalling.
		spec.Args = append(spec.Args, "-p", "22,80", "-Pn", "-retries", "1", "-timeout", "1000", "-disable-update-check")
		spec.Timeout = 60 * time.Second
		policy := egresspolicy.Compile(engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetIP, Value: allowIP}}})
		spec.EgressPolicy = &policy
		res, err := sb.Run(ctx, spec)
		if err != nil {
			// A timeout/error on the OUT-OF-SCOPE run is itself consistent with the drop
			// (nothing reachable); only fail if the in-scope run can't complete.
			if allowIP == scanme {
				t.Fatalf("in-scope naabu run failed: %v", err)
			}
			t.Logf("out-of-scope run errored (consistent with kernel-drop): %v", err)
			return ""
		}
		return string(res.Stdout)
	}

	hasPort := func(out string) bool {
		return strings.Contains(out, `"port":22`) || strings.Contains(out, `"port":80`)
	}

	// In scope: scanme is allowed → the sandboxed CAP_NET_RAW connect scan finds open ports.
	inScope := scan(scanme)
	if !hasPort(inScope) {
		t.Fatalf("in-scope scan found no open ports – sandboxed naabu/CAP_NET_RAW/egress broken:\n%s", inScope)
	}
	// Out of scope: egress allows only 192.0.2.1 (TEST-NET-1), so scanme's SYNs are
	// default-DENIED by the kernel → no ports. This is the #387 kernel-drop.
	outScope := scan("192.0.2.1")
	if hasPort(outScope) {
		t.Fatalf("out-of-scope scan still reached scanme – egress did NOT kernel-drop it:\n%s", outScope)
	}
	t.Logf("#387 OK: in-scope connect scan found open ports; out-of-scope connect scan was kernel-dropped (no ports)")
}

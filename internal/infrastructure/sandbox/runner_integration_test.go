package sandbox

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestSandboxIsolationLive runs a real probe inside the sandbox and asserts the
// confinement actually holds: read-only host root, a writable scoped workdir, dropped
// capabilities, and NO network egress (the fresh netns). It needs bubblewrap + bash, so
// it skips on hosts without them (e.g. macOS dev) and runs on the Linux test box.
func TestSandboxIsolationLive(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed – sandbox integration test skipped")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available for the probe")
	}
	r, err := NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Fatalf("new sandbox runner: %v", err)
	}
	work := t.TempDir()
	probe := `
set +e
touch /etc/synapse_sandbox_probe 2>/dev/null && echo ETC_WRITABLE || echo etc_readonly
touch "` + work + `/ok" 2>/dev/null && echo WORKDIR_WRITABLE || echo workdir_readonly
grep CapEff /proc/self/status
exec 3<>/dev/tcp/1.1.1.1/53 2>/dev/null && echo EGRESS_OPEN || echo egress_blocked
echo PROBE_DONE
`
	res, err := r.Run(context.Background(), ports.ToolSpec{
		Name:    "bash",
		Args:    []string{"-c", probe},
		Workdir: work,
	})
	if err != nil {
		t.Fatalf("sandbox run: %v (stderr: %s)", err, res.Stderr)
	}
	out := string(res.Stdout)
	t.Logf("sandbox probe output:\n%s", out)

	if !strings.Contains(out, "PROBE_DONE") {
		t.Fatalf("probe did not complete: %s", out)
	}
	if strings.Contains(out, "ETC_WRITABLE") || !strings.Contains(out, "etc_readonly") {
		t.Error("host root must be READ-ONLY inside the sandbox")
	}
	if !strings.Contains(out, "WORKDIR_WRITABLE") {
		t.Error("the scoped workdir must be writable inside the sandbox")
	}
	if !strings.Contains(out, "CapEff:\t0000000000000000") {
		t.Error("all capabilities must be dropped (CapEff = 0)")
	}
	if strings.Contains(out, "EGRESS_OPEN") || !strings.Contains(out, "egress_blocked") {
		t.Error("network egress must be DENIED by default (fresh netns)")
	}
}

// TestSandboxCapNetRawGranted proves naabu's CAP_NET_RAW is re-added (and only it).
func TestSandboxCapNetRawGranted(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	r, err := NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	res, err := r.Run(context.Background(), ports.ToolSpec{
		Name:   "bash",
		Args:   []string{"-c", "grep CapEff /proc/self/status"},
		CapAdd: []string{"CAP_NET_RAW"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// CAP_NET_RAW is bit 13 → effective mask must be exactly 0x2000, nothing else.
	if !strings.Contains(string(res.Stdout), "CapEff:\t0000000000002000") {
		t.Errorf("expected only CAP_NET_RAW (0x2000) effective, got: %s", res.Stdout)
	}
}

// TestSandboxSecretInjection proves the E11 contract end-to-end: a {{secret:NAME}}
// resolves into the tool's ENVIRONMENT (verified via a file the tool writes, since the
// secret would otherwise be scrubbed from stdout), the worker's env does NOT leak, the
// secret never appears in the child's cmdline, and a secret the tool echoes is REDACTED
// from the captured output.
func TestSandboxSecretInjection(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// Plant a worker-only secret in THIS process's env; it must not pass through.
	t.Setenv("SYNAPSE_VAULT_MASTER_KEY", "WORKER_ONLY_DO_NOT_LEAK")

	c, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	mv := vault.NewMemoryVault(c, nil)
	if err := mv.Put(context.Background(), "eng1", "TOK", []byte("INJECTED_SECRET")); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Fatal(err)
	}
	r.SetVault(mv)

	work := t.TempDir()
	// The tool writes $TOK to a file (host-readable, NOT part of stdout → not scrubbed) so
	// we can confirm the env delivery; it also echoes $TOK to stdout to exercise scrubbing.
	probe := `
echo "TOK=$TOK"
echo "LEAK=${SYNAPSE_VAULT_MASTER_KEY:-none}"
printf '%s' "$TOK" > "` + work + `/tok.out"
printf 'CMDLINE='; tr '\0' ' ' < /proc/self/cmdline; echo
`
	res, err := r.Run(context.Background(), ports.ToolSpec{
		Name:         "bash",
		Args:         []string{"-c", probe},
		Env:          []string{"TOK={{secret:TOK}}"},
		EngagementID: "eng1",
		Workdir:      work,
	})
	if err != nil {
		t.Fatalf("run: %v (stderr %s)", err, res.Stderr)
	}
	out := string(res.Stdout)
	t.Logf("probe:\n%s", out)

	// 1. The secret reached the tool's environment (read the file the tool wrote).
	if got, _ := os.ReadFile(filepath.Join(work, "tok.out")); string(got) != "INJECTED_SECRET" {
		t.Errorf("the secret must reach the tool via its environment, file=%q", got)
	}
	// 2. The worker's environment did not pass through.
	if !strings.Contains(out, "LEAK=none") {
		t.Error("the worker's environment must NOT pass through to the tool")
	}
	// 3. The echoed secret is scrubbed from the captured output.
	if strings.Contains(out, "INJECTED_SECRET") {
		t.Error("an echoed secret must be REDACTED from the captured output")
	}
	if !strings.Contains(out, "TOK="+redact.Placeholder) {
		t.Errorf("expected the echoed secret to be redacted, got: %s", out)
	}
	// 4. The secret never entered the child's cmdline.
	_, cmdline, ok := strings.Cut(out, "CMDLINE=")
	if !ok {
		t.Fatalf("probe did not report its cmdline: %q", out)
	}
	if strings.Contains(cmdline, "INJECTED_SECRET") {
		t.Error("the resolved secret must NEVER appear in the child's argv/cmdline")
	}
}

// TestSandboxEgressEnforced proves the E9+E12 integration: a run carrying an EgressPolicy
// executes inside a netns whose kernel filter allows only in-scope destinations – the
// sandboxed tool reaches an in-scope address but an out-of-scope one is dropped, while
// bwrap's isolation still holds. Needs Linux + bwrap + bash + ip/iptables + sudo.
func TestSandboxEgressEnforced(t *testing.T) {
	for _, bin := range []string{"bwrap", "bash", "ip", "iptables", "sudo"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo not available")
	}
	app, err := egress.NewApplier("sudo")
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	r, err := NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Fatal(err)
	}
	r.SetEgress(app)
	_ = exec.Command("sudo", "ip", "netns", "del", "syn1").Run() // defensive pre-clean (idx starts at 1)

	// In scope: 1.1.1.1 only.
	policy := &ports.EgressPolicy{Rules: []ports.EgressRule{
		{Allow: true, Net: netip.MustParsePrefix("1.1.1.1/32")},
	}}
	probe := `
(timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null && echo INSCOPE=connected || echo INSCOPE=blocked)
(timeout 5 bash -c 'exec 3<>/dev/tcp/8.8.8.8/443' 2>/dev/null && echo OUTSCOPE=connected || echo OUTSCOPE=blocked)
echo caps=$(grep CapEff /proc/self/status | awk '{print $2}')
`
	res, err := r.Run(context.Background(), ports.ToolSpec{
		Name:         "bash",
		Args:         []string{"-c", probe},
		EgressPolicy: policy,
	})
	if err != nil {
		t.Fatalf("egress-enforced run: %v (stderr %s)", err, res.Stderr)
	}
	out := string(res.Stdout)
	t.Logf("probe:\n%s", out)
	if !strings.Contains(out, "INSCOPE=connected") {
		t.Error("an in-scope destination must be reachable through the egress allowlist")
	}
	if !strings.Contains(out, "OUTSCOPE=blocked") {
		t.Error("an out-of-scope destination must be DROPPED by the egress netns")
	}
	if !strings.Contains(out, "caps=0000000000000000") {
		t.Error("bubblewrap isolation must still hold (caps dropped) in egress mode")
	}
}

// TestSandboxEgressDomainPinning covers domain-scoped egress: a domain-scoped egress policy is enforced
// by pre-resolving the in-scope domain, pinning its IP, and giving the tool a pinned
// /etc/hosts (with NO DNS egress) – so the tool resolves + reaches the in-scope domain
// but cannot resolve (or reach) an out-of-scope one.
func TestSandboxEgressDomainPinning(t *testing.T) {
	for _, bin := range []string{"bwrap", "bash", "ip", "iptables", "sudo", "getent"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo not available")
	}
	app, err := egress.NewApplier("sudo")
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	r, err := NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Fatal(err)
	}
	r.SetEgress(app)
	for _, ns := range []string{"syn1", "syn2", "syn3"} {
		_ = exec.Command("sudo", "ip", "netns", "del", ns).Run()
	}

	// In scope: one.one.one.one (Cloudflare's name for 1.1.1.1). dns.google is out of scope.
	policy := &ports.EgressPolicy{AllowDomains: []string{"one.one.one.one"}}
	probe := `
(getent hosts one.one.one.one >/dev/null 2>&1 && echo PINNED=yes || echo PINNED=no)
(timeout 6 bash -c 'exec 3<>/dev/tcp/one.one.one.one/443' 2>/dev/null && echo INSCOPE=connected || echo INSCOPE=blocked)
(timeout 6 bash -c 'exec 3<>/dev/tcp/dns.google/443' 2>/dev/null && echo OUTSCOPE=connected || echo OUTSCOPE=blocked)
`
	res, err := r.Run(context.Background(), ports.ToolSpec{Name: "bash", Args: []string{"-c", probe}, EgressPolicy: policy})
	if err != nil {
		t.Fatalf("run: %v (stderr %s)", err, res.Stderr)
	}
	out := string(res.Stdout)
	t.Logf("probe:\n%s", out)
	if !strings.Contains(out, "PINNED=yes") {
		t.Error("the in-scope domain must resolve via the pinned /etc/hosts")
	}
	if !strings.Contains(out, "INSCOPE=connected") {
		t.Error("the in-scope domain must be reachable")
	}
	if !strings.Contains(out, "OUTSCOPE=blocked") {
		t.Error("an out-of-scope domain must be unresolvable + unreachable (no DNS egress)")
	}
}

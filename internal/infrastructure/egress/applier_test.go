package egress

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	egresspolicy "github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPinnedHostsAreDeterministic(t *testing.T) {
	got := pinnedHosts(map[string][]netip.Addr{
		"b.example": {netip.MustParseAddr("203.0.113.2")},
		"a.example": {netip.MustParseAddr("203.0.113.3"), netip.MustParseAddr("203.0.113.1")},
	})
	want := "203.0.113.1 a.example\n203.0.113.3 a.example\n203.0.113.2 b.example\n"
	if got != want {
		t.Fatalf("pinnedHosts()=%q want=%q", got, want)
	}
}

func TestLinkAddrsDistinctPerIndex(t *testing.T) {
	h0, p0, s0 := linkAddrs(0)
	h1, _, s1 := linkAddrs(1)
	if h0 == "" || p0 == "" || s0 == "" {
		t.Fatal("empty addressing")
	}
	if s0 == s1 || h0 == h1 {
		t.Errorf("concurrent runs must get distinct subnets: idx0=%s idx1=%s", s0, s1)
	}
	if h0 != "10.210.0.1/30" || p0 != "10.210.0.2/30" || s0 != "10.210.0.0/30" {
		t.Errorf("unexpected idx0 addressing: host=%s peer=%s subnet=%s", h0, p0, s0)
	}
}

func TestSetupRejectsUnresolvedDomainAuthorityBeforePrivilegedOperations(t *testing.T) {
	for name, policy := range map[string]ports.EgressPolicy{
		"allow domains":      {AllowDomains: []string{"api.example.com"}},
		"deny domains":       {DenyDomains: []string{"blocked.example.com"}},
		"allow domain rules": {AllowDomainRules: []ports.DomainRule{{Host: "api.example.com"}}},
		"deny domain rules":  {DenyDomainRules: []ports.DomainRule{{Host: "blocked.example.com"}}},
	} {
		t.Run(name, func(t *testing.T) {
			a := &Applier{}
			if _, err := a.setup(context.Background(), "test", 0, policy, nil); err == nil {
				t.Fatal("unresolved domain authority must fail before privileged setup")
			}
		})
	}
}

func TestRecoverStaleOnlyRemovesBrokerOwnedNamespaces(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"syn3", "syn63", "synprobe", "other"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var commands []string
	a := &Applier{
		ip:       "/usr/sbin/ip",
		iptables: "/usr/sbin/iptables",
		netnsDir: dir,
		commandHook: func(_ context.Context, args []string) error {
			commands = append(commands, strings.Join(args, " "))
			return nil
		},
	}
	if err := a.RecoverStale(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syn3", "syn63", "synprobe"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("managed namespace %q was not removed: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "other")); err != nil {
		t.Fatalf("unmanaged namespace was modified: %v", err)
	}
	joined := strings.Join(commands, "\n")
	for _, want := range []string{"-C FORWARD -d 10.210.0.12/30", "vh-syn3", "-C FORWARD -d 10.210.0.252/30", "vh-syn63", "vh-synprobe"} {
		if !strings.Contains(joined, want) {
			t.Errorf("recovery commands missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "other") {
		t.Errorf("recovery touched unmanaged namespace:\n%s", joined)
	}
}

// TestEgressEnforcesPolicyLive builds a real egress-filtered netns from a Policy and
// proves the allowlist holds: an in-scope address is reachable, an out-of-scope one is
// dropped. Needs Linux + ip/iptables + (passwordless) sudo, so it skips elsewhere.
func TestEgressEnforcesPolicyLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress enforcement is Linux-only")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo not available for the unprivileged test driver")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo not available")
	}
	// Baseline reachability: the netns NATs out through the host's uplink, so this live test
	// needs real external ICMP connectivity. CI sandboxes (e.g. GitHub Actions) permit ip +
	// sudo but BLOCK ICMP to the internet – when the HOST itself can't ping the in-scope IP,
	// the in-scope assertion below would fail for an environmental reason, not a policy
	// regression. Skip there; this stays a host-validation test (runs on a real Linux box).
	if exec.Command("sudo", "ping", "-c1", "-W2", "1.1.1.1").Run() != nil {
		t.Skip("no external ICMP connectivity from the host (CI sandbox?) – egress enforcement is host-validated")
	}

	a, err := NewApplier("sudo")
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	ctx := context.Background()
	const name = "e12test"
	_ = exec.Command("sudo", "ip", "netns", "del", name).Run() // defensive pre-clean

	// In scope: 1.1.1.1 only → everything else is default-denied.
	p := egresspolicy.Compile(engagement.Scope{InScope: []engagement.Target{
		{Kind: engagement.TargetIP, Value: "1.1.1.1"},
	}})
	ns, err := a.Setup(ctx, name, 0, p)
	if err != nil {
		t.Fatalf("setup egress netns: %v", err)
	}
	defer func() {
		if err := ns.Teardown(ctx); err != nil {
			t.Errorf("teardown: %v", err)
		}
		// After teardown the netns must be gone.
		if exec.Command("sudo", "ip", "netns", "pids", name).Run() == nil {
			t.Errorf("netns %q still exists after teardown", name)
		}
	}()

	reachable := func(ip string) bool {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return exec.CommandContext(c, "sudo", "ip", "netns", "exec", name, "ping", "-c1", "-W2", ip).Run() == nil
	}

	if !reachable("1.1.1.1") {
		t.Error("an in-scope destination (1.1.1.1) must be REACHABLE through the allowlist")
	}
	if reachable("8.8.8.8") {
		t.Error("an out-of-scope destination (8.8.8.8) must be DROPPED by default-deny")
	}
}

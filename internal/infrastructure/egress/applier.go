// Package egress applies a compiled egress.Policy as a real, kernel-enforced network
// namespace. It is the structural scope-enforcement backstop: the gate refuses to
// LAUNCH an out-of-scope run; this makes the kernel DROP any out-of-scope packet a tool
// emits. Setup builds a per-run netns with a veth to the host, NAT, and a default-DENY
// egress filter that ACCEPTs only the policy's in-scope destinations; Teardown removes it.
//
// It is argv-only: every step is an `ip`/`iptables` argv invocation, no
// shell. The host validated the recipe (allowed dest reachable, denied dropped, coexists
// with Docker's FORWARD DROP). Privileged operations need CAP_NET_ADMIN (the worker runs
// with it in prod; CmdPrefix lets a dev/test driver prepend "sudo").
//
// Scope/limits of THIS layer: it enforces IP/CIDR (+ optional ports) allow/deny on
// RESOLVED addresses, never on a hostname string. Policy domains (AllowDomains) need
// run-start DNS resolution + a pinning proxy and are not yet wired here.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnavailable means egress enforcement cannot run here (no `ip`/`iptables`, i.e. not
// Linux). Callers fail closed for egress-required runs rather than running unfiltered.
var ErrUnavailable = errors.New("egress enforcement unavailable: ip/iptables not found")

// Applier creates + tears down egress-filtered network namespaces.
type Applier struct {
	ip        string   // resolved `ip` path
	iptables  string   // resolved `iptables` path
	ip6tables string   // resolved `ip6tables` path ("" if absent) – IPv6 default-drop fail-closed
	sysctl    string   // resolved `sysctl` path ("" if absent) – IPv6 disable fail-closed
	cmdPrefix []string // prepended to every privileged command (e.g. {"sudo"}); empty when already privileged
}

// NewApplier resolves the `ip` + `iptables` binaries (Linux only). cmdPrefix is prepended
// to each command – pass {"sudo"} from an unprivileged dev/test driver, nil in prod where
// the worker holds CAP_NET_ADMIN.
func NewApplier(cmdPrefix ...string) (*Applier, error) {
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return nil, fmt.Errorf("%w: `ip` not found (egress enforcement is Linux-only)", ErrUnavailable)
	}
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		return nil, fmt.Errorf("%w: `iptables` not found", ErrUnavailable)
	}
	sysctlBin, _ := exec.LookPath("sysctl") // IPv6 fail-closed (disable_ipv6)
	ip6Bin, _ := exec.LookPath("ip6tables") // IPv6 fail-closed (default-DROP); one of the two must work
	return &Applier{ip: ipBin, iptables: ipt, ip6tables: ip6Bin, sysctl: sysctlBin, cmdPrefix: cmdPrefix}, nil
}

// Probe verifies egress enforcement actually works here – i.e. the process has enough
// privilege (CAP_NET_ADMIN + CAP_SYS_ADMIN) to build a netns + veth + NAT + iptables – by
// creating and tearing down a throwaway namespace. Returns nil when usable, so the
// composition root can enable egress only when it will succeed (else degrade to isolated).
func (a *Applier) Probe(ctx context.Context) error {
	ns, err := a.Setup(ctx, "synprobe", 63, ports.EgressPolicy{})
	if err != nil {
		return err
	}
	return ns.Teardown(ctx)
}

// ExecPrefix returns the argv prefix that enters netns `name` to run a command:
// `[<cmdPrefix>] ip netns exec <name>`. Entering an existing netns needs CAP_SYS_ADMIN,
// so the same privilege prefix (sudo / caps) as Setup applies. The SandboxRunner prepends
// this to the bwrap invocation for an egress-enforced run.
func (a *Applier) ExecPrefix(name string) []string {
	return append(append([]string{}, a.cmdPrefix...), a.ip, "netns", "exec", name)
}

// Netns is a live egress-filtered namespace. Run a tool inside it with
// `ip netns exec <Name> …`; always Teardown when done (the steps reverse Setup, even on
// partial failure).
type Netns struct {
	Name string
	// HostsFile is a pinned /etc/hosts (in-scope domain → allowed IP) the caller binds
	// into the sandboxed tool so it resolves in-scope names without any DNS egress.
	// Empty when the policy has no resolvable in-scope domains.
	HostsFile string
	// AllowedRules is the resolved allow-set this netns enforces (scope rules + pinned
	// domain IPs). Exposed so the connect-logger can label each captured attempt
	// allowed/denied against the same set the kernel filters on.
	AllowedRules []ports.EgressRule
	hostVeth     string
	subnet       string // e.g. 10.211.0.0/30
	a            *Applier
	cleanup      [][]string // reverse-order teardown steps (argv, or {rmSentinel, path})
}

// rmSentinel marks a cleanup entry as "remove this file" rather than an argv command.
const rmSentinel = "__synapse_rm__"

// host/peer addressing for the /30 link. Derived per-netns from a small index so two
// concurrent runs don't collide.
func linkAddrs(idx int) (host, peer, subnet string) {
	// 10.210.<idx*4.. >/30 blocks; idx in [0,63] → 10.210.0.0/30 … 10.210.0.252/30.
	base := (idx % 64) * 4
	host = fmt.Sprintf("10.210.0.%d/30", base+1)
	peer = fmt.Sprintf("10.210.0.%d/30", base+2)
	subnet = fmt.Sprintf("10.210.0.%d/30", base)
	return
}

// Setup builds the filtered netns from p. idx disambiguates concurrent runs' subnets.
func (a *Applier) Setup(ctx context.Context, name string, idx int, p ports.EgressPolicy) (*Netns, error) {
	hostAddr, peerAddr, subnet := linkAddrs(idx)
	hostVeth, peerVeth := "vh-"+name, "vp-"+name
	if len(hostVeth) > 15 || len(peerVeth) > 15 {
		return nil, fmt.Errorf("%w: netns name %q too long for a veth name (max ~12)", shared.ErrValidation, name)
	}
	ns := &Netns{Name: name, hostVeth: hostVeth, subnet: subnet, a: a}

	// Each entry: the command to run, and (optionally) the teardown to register on success.
	steps := []struct {
		args     []string
		teardown []string
	}{
		{[]string{a.ip, "netns", "add", name}, []string{a.ip, "netns", "del", name}},
		{[]string{a.ip, "link", "add", hostVeth, "type", "veth", "peer", "name", peerVeth}, []string{a.ip, "link", "del", hostVeth}},
		{[]string{a.ip, "link", "set", peerVeth, "netns", name}, nil},
		{[]string{a.ip, "addr", "add", hostAddr, "dev", hostVeth}, nil},
		{[]string{a.ip, "link", "set", hostVeth, "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "addr", "add", peerAddr, "dev", peerVeth}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "link", "set", peerVeth, "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "link", "set", "lo", "up"}, nil},
		{[]string{a.ip, "netns", "exec", name, a.ip, "route", "add", "default", "via", trimPrefix(hostAddr)}, nil},
		// NAT for the netns subnet + FORWARD allow (coexists with Docker's FORWARD DROP).
		{[]string{a.iptables, "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}, []string{a.iptables, "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}},
		{[]string{a.iptables, "-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"}, []string{a.iptables, "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT"}},
		{[]string{a.iptables, "-I", "FORWARD", "-d", subnet, "-j", "ACCEPT"}, []string{a.iptables, "-D", "FORWARD", "-d", subnet, "-j", "ACCEPT"}},
		// Always allow loopback egress inside the netns.
		{[]string{a.ip, "netns", "exec", name, a.iptables, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}, nil},
	}
	for _, s := range steps {
		if err := a.run(ctx, s.args); err != nil {
			_ = ns.Teardown(context.Background()) // best-effort unwind
			return nil, fmt.Errorf("egress setup %q: %w", strings.Join(s.args[len(a.cmdPrefix):], " "), err)
		}
		if s.teardown != nil {
			ns.cleanup = append(ns.cleanup, s.teardown)
		}
	}

	// IPv6 fail-closed, UNCONDITIONAL (re-audit fix): the v4 rules above don't touch v6, and
	// a fresh netns autoconfigures an IPv6 link-local. We do not yet compile v6 allow rules,
	// so v6 must be locked down. Apply BOTH available mechanisms and require at least one to
	// succeed – never silently leave v6 open: (1) sysctl disable_ipv6 (flushes addresses),
	// (2) ip6tables default-DROP on OUTPUT+FORWARD. If neither tool exists, FAIL the setup.
	v6Locked := false
	if a.sysctl != "" {
		if err := a.run(ctx, []string{a.ip, "netns", "exec", name, a.sysctl, "-w",
			"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1", "net.ipv6.conf.lo.disable_ipv6=1"}); err == nil {
			v6Locked = true
		}
	}
	if a.ip6tables != "" {
		okOut := a.run(ctx, []string{a.ip, "netns", "exec", name, a.ip6tables, "-P", "OUTPUT", "DROP"}) == nil
		okFwd := a.run(ctx, []string{a.ip, "netns", "exec", name, a.ip6tables, "-P", "FORWARD", "DROP"}) == nil
		if okOut && okFwd {
			v6Locked = true
		}
	}
	if !v6Locked {
		_ = ns.Teardown(context.Background())
		return nil, fmt.Errorf("egress: cannot lock down IPv6 in the netns (need sysctl or ip6tables) – refusing to run with unfiltered v6")
	}

	// resolve in-scope domains on the host (where DNS works) and PIN them – their
	// IPs become allow rules + a pinned /etc/hosts the tool reads, while NO DNS egress is
	// opened. So the tool reaches an in-scope domain (via the pinned host entry → an
	// allowed IP) but cannot resolve anything else and has no DNS channel to exfiltrate
	// through (the market lesson). Wildcards can't be pre-resolved (a documented gap;
	// dynamic subdomain pinning is a follow-up).
	denyRules := filterRules(p.Rules, false)
	allowRules := filterRules(p.Rules, true)
	hosts, allowDomainRules := a.resolvePins(ctx, p.AllowDomains)
	allowRules = append(allowRules, allowDomainRules...)
	ns.AllowedRules = allowRules // expose the resolved allow-set for the connection-observer verdict
	if _, deny := a.resolvePins(ctx, p.DenyDomains); len(deny) > 0 {
		denyRules = append(denyRules, deny...)
	}

	// Deny first (out-of-scope wins), then allow, then default DROP.
	for _, r := range denyRules {
		if err := a.outputRule(ctx, name, "DROP", r); err != nil {
			_ = ns.Teardown(context.Background())
			return nil, err
		}
	}
	for _, r := range allowRules {
		if err := a.outputRule(ctx, name, "ACCEPT", r); err != nil {
			_ = ns.Teardown(context.Background())
			return nil, err
		}
	}
	if err := a.run(ctx, []string{a.ip, "netns", "exec", name, a.iptables, "-P", "OUTPUT", "DROP"}); err != nil {
		_ = ns.Teardown(context.Background())
		return nil, err
	}

	// Write the pinned /etc/hosts (the SandboxRunner binds it into the tool). The netns
	// has no DNS egress, so this is the ONLY way the tool resolves an in-scope name.
	if hosts != "" {
		hf, herr := writeHostsFile(hosts)
		if herr != nil {
			_ = ns.Teardown(context.Background())
			return nil, fmt.Errorf("egress pinned hosts: %w", herr)
		}
		ns.HostsFile = hf
		ns.cleanup = append(ns.cleanup, []string{rmSentinel, hf}) // Teardown removes the file
	}
	return ns, nil
}

// resolvePins resolves each non-wildcard domain on the host and returns pinned
// /etc/hosts lines + the matching allow-by-IP rules. A domain that fails to resolve is
// skipped (fail-closed: it simply stays unreachable). Wildcards can't be pre-resolved.
func (a *Applier) resolvePins(ctx context.Context, domains []string) (hosts string, rules []ports.EgressRule) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || strings.ContainsAny(d, "*") {
			continue
		}
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", d)
		if err != nil {
			continue
		}
		for _, ip := range addrs {
			ip = ip.Unmap()
			rules = append(rules, ports.EgressRule{Allow: true, Net: netip.PrefixFrom(ip, ip.BitLen())})
			line := ip.String() + " " + d
			if !seen[line] {
				b.WriteString(line + "\n")
				seen[line] = true
			}
		}
	}
	return b.String(), rules
}

// writeHostsFile writes a pinned hosts file (with the usual localhost entries) to a temp
// path, world-readable so the sandboxed tool (any uid) can read it.
func writeHostsFile(pinned string) (string, error) {
	f, err := os.CreateTemp("", "synapse-hosts-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("127.0.0.1 localhost\n::1 localhost\n" + pinned); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// filterRules returns the rules with the given Allow value, preserving order.
func filterRules(rules []ports.EgressRule, allow bool) []ports.EgressRule {
	var out []ports.EgressRule
	for _, r := range rules {
		if r.Allow == allow {
			out = append(out, r)
		}
	}
	return out
}

// outputRule appends an OUTPUT rule for one policy rule (per-port when set, else all
// protocols to the destination). IPv6 rules are skipped here (iptables is v4; ip6tables
// is the v6 sibling – a follow-up).
func (a *Applier) outputRule(ctx context.Context, ns, verdict string, r ports.EgressRule) error {
	if !r.Net.Addr().Is4() {
		return nil // v4 enforcement only in this layer
	}
	dst := r.Net.String()
	if len(r.Ports) == 0 {
		return a.run(ctx, []string{a.ip, "netns", "exec", ns, a.iptables, "-A", "OUTPUT", "-d", dst, "-j", verdict})
	}
	for _, port := range r.Ports {
		for _, proto := range []string{"tcp", "udp"} {
			if err := a.run(ctx, []string{a.ip, "netns", "exec", ns, a.iptables, "-A", "OUTPUT", "-d", dst, "-p", proto, "--dport", strconv.Itoa(int(port)), "-j", verdict}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Teardown reverses Setup (registered steps, in reverse order). Best-effort: it attempts
// every step even if some fail, so a partial setup is fully cleaned.
func (n *Netns) Teardown(ctx context.Context) error {
	var firstErr error
	for i := len(n.cleanup) - 1; i >= 0; i-- {
		step := n.cleanup[i]
		if len(step) == 2 && step[0] == rmSentinel {
			if err := os.Remove(step[1]); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := n.a.run(ctx, step); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	n.cleanup = nil
	return firstErr
}

func (a *Applier) run(ctx context.Context, args []string) error {
	full := append(append([]string{}, a.cmdPrefix...), args...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args[:min(3, len(args))], " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func trimPrefix(addr string) string {
	if pfx, err := netip.ParsePrefix(addr); err == nil {
		return pfx.Addr().String()
	}
	return addr
}

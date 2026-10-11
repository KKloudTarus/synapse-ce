package safehttp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// fakeNet records lookups and dials and hands out closed pipes, so a test observes the dialer's
// decisions without touching the network.
type fakeNet struct {
	answers [][]netip.Addr
	lookups int
	dialed  []string
}

func (f *fakeNet) lookup(context.Context, string, string) ([]netip.Addr, error) {
	answer := f.answers[min(f.lookups, len(f.answers)-1)]
	f.lookups++
	return answer, nil
}

func (f *fakeNet) dial(_ context.Context, _, address string) (net.Conn, error) {
	f.dialed = append(f.dialed, address)
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func addrs(values ...string) []netip.Addr {
	out := make([]netip.Addr, len(values))
	for i, value := range values {
		out[i] = netip.MustParseAddr(value)
	}
	return out
}

func TestDialerRefusesMetadataEndpoints(t *testing.T) {
	for _, policy := range []Policy{{}, {AllowPrivate: true}, OperatorPolicy()} {
		for _, metadata := range []string{"169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254", "100.100.100.200"} {
			f := &fakeNet{answers: [][]netip.Addr{addrs(metadata)}}
			_, err := newDialer(policy, f.lookup, f.dial).DialContext(context.Background(), "tcp", "metadata.example:80")
			if !errors.Is(err, ErrBlockedDestination) || len(f.dialed) != 0 {
				t.Errorf("policy %+v reached %s: err=%v dialed=%v", policy, metadata, err, f.dialed)
			}
		}
	}
}

func TestDialerDialsTheCheckedAddressAndBlocksRebinding(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("8.8.8.8"), addrs("127.0.0.1")}}
	dialer := newDialer(Policy{}, f.lookup, f.dial)
	connection, err := dialer.DialContext(context.Background(), "tcp", "hooks.example:443")
	if err != nil {
		t.Fatalf("public dial: %v", err)
	}
	_ = connection.Close()
	if _, err := dialer.DialContext(context.Background(), "tcp", "hooks.example:443"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("rebound dial err = %v", err)
	}
	if f.lookups != 2 || len(f.dialed) != 1 || f.dialed[0] != "8.8.8.8:443" {
		t.Fatalf("lookups=%d dialed=%v, want one dial of the checked address", f.lookups, f.dialed)
	}
}

func TestDialerSkipsRefusedCandidates(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("127.0.0.1", "10.0.0.1", "93.184.215.14")}}
	connection, err := newDialer(Policy{}, f.lookup, f.dial).DialContext(context.Background(), "tcp", "mixed.example:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = connection.Close()
	if len(f.dialed) != 1 || f.dialed[0] != "93.184.215.14:443" {
		t.Fatalf("dialed %v, want only the public candidate", f.dialed)
	}
}

func TestDialerPrivateCIDRs(t *testing.T) {
	narrowed := Policy{AllowPrivate: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	for address, want := range map[string]bool{"10.20.3.4": true, "10.30.3.4": false, "fd12::1": false} {
		f := &fakeNet{answers: [][]netip.Addr{addrs(address)}}
		_, err := newDialer(narrowed, f.lookup, f.dial).DialContext(context.Background(), "tcp", "jira.internal:443")
		if (err == nil) != want {
			t.Errorf("%s: err=%v, want allowed=%v", address, err, want)
		}
	}
	f := &fakeNet{answers: [][]netip.Addr{addrs("10.20.3.4")}}
	if _, err := newDialer(Policy{}, f.lookup, f.dial).DialContext(context.Background(), "tcp", "jira.internal:443"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("private address without opt-in: err = %v", err)
	}
}

func TestDialerAppliesHostPredicateBeforeLookup(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("8.8.8.8")}}
	policy := Policy{AllowHost: func(host, _ string) bool { return host == "jira.corp.example" }}
	if _, err := newDialer(policy, f.lookup, f.dial).DialContext(context.Background(), "tcp", "evil.example:443"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("host outside the allowlist: err = %v", err)
	}
	if f.lookups != 0 {
		t.Fatalf("host outside the allowlist was resolved %d times", f.lookups)
	}
}

func TestDialerRefusesNonTCPNetworks(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("8.8.8.8")}}
	for _, network := range []string{"udp", "unix", "ip"} {
		if _, err := newDialer(Policy{}, f.lookup, f.dial).DialContext(context.Background(), network, "x.example:53"); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("network %s: err = %v", network, err)
		}
	}
}

func TestDialerKeepsTheLegacyErrorText(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("127.0.0.1")}}
	_, err := newDialer(Policy{}, f.lookup, f.dial).DialContext(context.Background(), "tcp", "local.example:443")
	if err == nil || err.Error() != "safehttp: destination is not allowed: endpoint resolves to a disallowed address" {
		t.Fatalf("err = %v", err)
	}
}

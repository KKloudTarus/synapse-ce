package safehttp

import (
	"net/netip"
	"testing"
)

func TestPolicyPermits(t *testing.T) {
	public := Policy{}
	private := Policy{AllowPrivate: true}
	narrowed := Policy{AllowPrivate: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	operator := OperatorPolicy()
	cases := []struct {
		address                                string
		public, private, narrowed, operatorWay bool
	}{
		// Globally reachable.
		{"8.8.8.8", true, true, true, true},
		{"2606:4700:4700::1111", true, true, true, true},
		{"::ffff:8.8.8.8", true, true, true, true},
		// Private use: only when opened, and only inside PrivateCIDRs when those are set.
		{"10.0.0.1", false, true, false, true},
		{"10.20.3.4", false, true, true, true},
		{"172.16.0.1", false, true, false, true},
		{"192.168.1.1", false, true, false, true},
		{"fd12:3456::1", false, true, false, true},
		{"::ffff:10.20.3.4", false, true, true, true},
		// Loopback: operator endpoints only.
		{"127.0.0.1", false, false, false, true},
		{"127.8.9.10", false, false, false, true},
		{"::1", false, false, false, true},
		{"::ffff:127.0.0.1", false, false, false, true},
		// Cloud metadata: never.
		{"169.254.169.254", false, false, false, false},
		{"::ffff:169.254.169.254", false, false, false, false},
		{"fd00:ec2::254", false, false, false, false},
		{"100.100.100.200", false, false, false, false},
		// Other special-purpose ranges: never.
		{"0.0.0.0", false, false, false, false},
		{"0.1.2.3", false, false, false, false},
		{"192.0.0.8", false, false, false, false},
		{"192.0.2.1", false, false, false, false},
		{"192.88.99.1", false, false, false, false},
		{"198.18.0.1", false, false, false, false},
		{"198.51.100.1", false, false, false, false},
		{"203.0.113.1", false, false, false, false},
		{"224.0.0.1", false, false, false, false},
		{"240.0.0.1", false, false, false, false},
		{"255.255.255.255", false, false, false, false},
		{"::", false, false, false, false},
		{"::7f00:1", false, false, false, false},
		{"64:ff9b::7f00:1", false, false, false, false},
		{"64:ff9b:1::a00:1", false, false, false, false},
		{"100::1", false, false, false, false},
		{"2001::7f00:1", false, false, false, false},
		{"2001:db8::1", false, false, false, false},
		{"2002:7f00:1::", false, false, false, false},
		{"3fff::1", false, false, false, false},
		{"fe80::1", false, false, false, false},
		{"fec0::1", false, false, false, false},
		{"ff02::1", false, false, false, false},
	}
	for _, tc := range cases {
		address := netip.MustParseAddr(tc.address)
		for name, check := range map[string]struct {
			policy Policy
			want   bool
		}{
			"public": {public, tc.public}, "private": {private, tc.private},
			"narrowed": {narrowed, tc.narrowed}, "operator": {operator, tc.operatorWay},
		} {
			if got := check.policy.permits(address); got != check.want {
				t.Errorf("%s policy permits(%s) = %v, want %v", name, tc.address, got, check.want)
			}
		}
	}
}

func TestPolicyPermitsHost(t *testing.T) {
	if !(Policy{}).permitsHost("any.example", "443") {
		t.Fatal("a policy without a host predicate refused a host")
	}
	allowlist := Policy{AllowHost: func(host, port string) bool { return host == "jira.corp.example" && port == "443" }}
	if !allowlist.permitsHost("jira.corp.example", "443") || allowlist.permitsHost("jira.corp.example", "8443") || allowlist.permitsHost("evil.example", "443") {
		t.Fatal("host predicate not applied")
	}
}

func TestNeverDestinationRangesAreWellFormed(t *testing.T) {
	for _, prefix := range append(append([]netip.Prefix{}, neverDestination...), cloudMetadata...) {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			t.Errorf("prefix %s is not canonical", prefix)
		}
	}
}

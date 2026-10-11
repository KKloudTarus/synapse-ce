package selfhosted

import "testing"

func mustAllowlist(t *testing.T, values ...string) HostAllowlist {
	t.Helper()
	allowlist, err := ParseHostAllowlist(values)
	if err != nil {
		t.Fatalf("ParseHostAllowlist(%q): %v", values, err)
	}
	return allowlist
}

func TestEmptyAllowlistAdmitsEveryHost(t *testing.T) {
	allowlist := mustAllowlist(t)
	if !allowlist.Empty() || !allowlist.Permits("anything.example", "443") {
		t.Fatal("an empty allowlist must admit every host")
	}
}

func TestHostAllowlistPermits(t *testing.T) {
	allowlist := mustAllowlist(t,
		"jenkins.corp.example",
		"JIRA.Corp.Example.:8443",
		"*.ci.example",
		"192.0.2.10",
		"[2001:db8::1]:9443",
		"2001:db8::2",
	)
	cases := []struct {
		host, port string
		want       bool
	}{
		{"jenkins.corp.example", "443", true},
		{"JENKINS.corp.example.", "8080", true},
		{"other.corp.example", "443", false},
		{"evil-jenkins.corp.example", "443", false},
		{"jenkins.corp.example.evil.example", "443", false},
		{"jira.corp.example", "8443", true},
		{"jira.corp.example", "443", false},
		{"build.ci.example", "443", true},
		{"a.b.ci.example", "443", true},
		{"ci.example", "443", false},
		{"evilci.example", "443", false},
		{"192.0.2.10", "443", true},
		{"::ffff:192.0.2.10", "443", true},
		{"192.0.2.11", "443", false},
		{"[2001:db8::1]", "9443", true},
		{"2001:db8:0::1", "9443", true},
		{"2001:db8::1", "443", false},
		{"2001:db8::2", "443", true},
	}
	for _, tc := range cases {
		if got := allowlist.Permits(tc.host, tc.port); got != tc.want {
			t.Errorf("Permits(%q, %q) = %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestParseHostAllowlistRejectsMalformedEntries(t *testing.T) {
	for _, entry := range []string{
		"",
		"https://jenkins.corp.example",
		"jenkins.corp.example/path",
		"user@jenkins.corp.example",
		"jenkins.corp.example:0",
		"jenkins.corp.example:65536",
		"jenkins.corp.example:http",
		"*",
		"*.",
		"jen*kins.corp.example",
		"*.*.corp.example",
		"-bad.corp.example",
		"bad_host.corp.example",
		"double..dot.example",
		"[2001:db8::1",
		"[fe80::1%eth0]",
	} {
		if _, err := ParseHostAllowlist([]string{entry}); err == nil {
			t.Errorf("entry %q was accepted", entry)
		}
	}
}

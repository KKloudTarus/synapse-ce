package ignore

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	src := `# accepted risks for this repo
CVE-2023-1234 exp:2026-12-31 # not exploitable in our config
CVE-2023-5678
GHSA-aaaa-bbbb-cccc  # third-party, tracked upstream

   # a blank + comment line above
badexpiry exp:not-a-date # still a rule, just no expiry
`
	set := Parse([]byte(src))
	if len(set) != 4 {
		t.Fatalf("want 4 rules, got %d: %+v", len(set), set)
	}
	if set[0].ID != "CVE-2023-1234" || set[0].Reason != "not exploitable in our config" || set[0].Expires.IsZero() {
		t.Errorf("rule 0 mis-parsed: %+v", set[0])
	}
	if set[1].ID != "CVE-2023-5678" || set[1].Reason != "" || !set[1].Expires.IsZero() {
		t.Errorf("rule 1 mis-parsed: %+v", set[1])
	}
	if set[2].ID != "GHSA-aaaa-bbbb-cccc" || set[2].Reason != "third-party, tracked upstream" {
		t.Errorf("rule 2 mis-parsed: %+v", set[2])
	}
	if set[3].ID != "badexpiry" || !set[3].Expires.IsZero() || !set[3].Malformed {
		t.Errorf("an unparseable expiry must be flagged Malformed (fail-safe), not silently permanent: %+v", set[3])
	}
}

func TestMalformedExpiryNeverSuppresses(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	set := Parse([]byte("CVE-2023-1 exp:2026-31-12 # month/day typo\nCVE-2023-2\n"))
	// The malformed rule must NOT match (a date typo can't become a permanent silent acceptance)...
	if _, ok := set.Match([]string{"CVE-2023-1"}, now); ok {
		t.Error("a rule with an unparseable expiry must not suppress")
	}
	// ...but a well-formed rule still works.
	if _, ok := set.Match([]string{"CVE-2023-2"}, now); !ok {
		t.Error("a valid rule alongside a malformed one must still match")
	}
	// ...and the malformed rule is surfaced for fixing.
	m := set.Malformed()
	if len(m) != 1 || m[0].ID != "CVE-2023-1" {
		t.Errorf("the malformed rule must be surfaced, got %+v", m)
	}
}

func TestMatchCaseInsensitiveAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	set := Parse([]byte("CVE-2023-1234 exp:2026-12-31\nGHSA-old exp:2026-01-01\nGHSA-never\n"))

	// active, exact + case-insensitive match
	if r, ok := set.Match([]string{"cve-2023-1234"}, now); !ok || r.ID != "CVE-2023-1234" {
		t.Errorf("active rule must match case-insensitively, got ok=%v r=%+v", ok, r)
	}
	// expired rule must NOT match (finding re-surfaces)
	if _, ok := set.Match([]string{"GHSA-old"}, now); ok {
		t.Error("an expired rule must not suppress")
	}
	// no-expiry rule matches
	if _, ok := set.Match([]string{"GHSA-never"}, now); !ok {
		t.Error("a no-expiry rule must match")
	}
	// a non-listed id does not match
	if _, ok := set.Match([]string{"CVE-9999-0000"}, now); ok {
		t.Error("an unlisted id must not match")
	}
	// multiple identifiers: any one matching suppresses (e.g. dedup key OR the CVE)
	if _, ok := set.Match([]string{"some:dedup:key", "CVE-2023-1234"}, now); !ok {
		t.Error("a match on any of the finding's identifiers must suppress")
	}
}

func TestExpiredSurfacing(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	set := Parse([]byte("A exp:2026-01-01\nB\nC exp:2027-01-01\n"))
	exp := set.Expired(now)
	if len(exp) != 1 || exp[0].ID != "A" {
		t.Errorf("want exactly rule A expired, got %+v", exp)
	}
}

func TestParseEmpty(t *testing.T) {
	if s := Parse(nil); len(s) != 0 {
		t.Errorf("empty input must yield an empty set, got %+v", s)
	}
	if s := Parse([]byte("# only comments\n\n   \n")); len(s) != 0 {
		t.Errorf("comment/blank-only input must yield an empty set, got %+v", s)
	}
}

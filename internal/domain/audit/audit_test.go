package audit

import (
	"errors"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

// chain builds an intact chain from content tuples (actor, action, target).
func chain(rows [][3]string, when time.Time) []Record {
	prev := ""
	out := make([]Record, len(rows))
	for i, r := range rows {
		h := ComputeHash(prev, r[0], r[1], r[2], nil, when)
		out[i] = Record{Actor: r[0], Action: r[1], Target: r[2], At: when, Hash: h, PreviousHash: prev}
		prev = h
	}
	return out
}

func TestComputeHashDeterministicAndOrderIndependentMetadata(t *testing.T) {
	when := at("2026-06-21T12:00:00Z")
	a := ComputeHash("prev", "alice", "recon.subfinder", "example.com",
		map[string]string{"tool": "subfinder", "kind": "domain"}, when)
	// Same content, metadata inserted in a different order → same hash (keys sorted).
	b := ComputeHash("prev", "alice", "recon.subfinder", "example.com",
		map[string]string{"kind": "domain", "tool": "subfinder"}, when)
	if a != b {
		t.Fatalf("metadata order must not change the hash:\n a=%s\n b=%s", a, b)
	}
	// A different previous hash → different chain hash (binds to history).
	if c := ComputeHash("other", "alice", "recon.subfinder", "example.com",
		map[string]string{"tool": "subfinder", "kind": "domain"}, when); c == a {
		t.Fatal("hash must depend on previousHash")
	}
}

func TestComputeHashStableAcrossMicrosecondPrecision(t *testing.T) {
	// A nanosecond-precision write time and the same time read back at µs precision
	// (as Postgres stores it) must hash identically, else verification false-fails.
	nanos := at("2026-06-21T12:00:00.123456789Z")
	micros := nanos.Truncate(time.Microsecond)
	if ComputeHash("p", "a", "x", "t", nil, nanos) != ComputeHash("p", "a", "x", "t", nil, micros) {
		t.Fatal("hash must be stable when the timestamp is truncated to microseconds")
	}
}

func TestVerifyChainIntact(t *testing.T) {
	c := chain([][3]string{
		{"operator", "engagement.created", "lab"},
		{"alice", "recon.subfinder", "example.com"},
		{"bob", "finding.updated", "f-1"},
	}, at("2026-06-21T12:00:00Z"))
	if err := VerifyChain(c); err != nil {
		t.Fatalf("intact chain must verify: %v", err)
	}
	rep := Verify(c)
	if !rep.Intact || rep.Verified != 3 || rep.Unchained != 0 || rep.Head != c[2].Hash {
		t.Fatalf("report = %+v, want intact/3/0/head", rep)
	}
}

func TestVerifyChainDetectsTamperedContent(t *testing.T) {
	c := chain([][3]string{{"alice", "x", "t1"}, {"bob", "y", "t2"}}, at("2026-06-21T12:00:00Z"))
	c[0].Action = "z" // edit content without recomputing the stored hash
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("tampered content must break the chain, got %v", err)
	}
	if Verify(c).Intact {
		t.Fatal("Verify must report a tampered chain as not intact")
	}
}

func TestVerifyChainDetectsDeletedLink(t *testing.T) {
	c := chain([][3]string{{"a", "1", "t"}, {"b", "2", "t"}, {"c", "3", "t"}}, at("2026-06-21T12:00:00Z"))
	// Drop the middle entry: entry 2's previous_hash no longer matches entry 0's hash.
	broken := []Record{c[0], c[2]}
	if err := VerifyChain(broken); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a deleted link must break the chain, got %v", err)
	}
}

func TestVerifyTreatsLeadingLegacyRowsAsUnchained(t *testing.T) {
	when := at("2026-06-21T12:00:00Z")
	// Two pre-chain rows (no hash) followed by an intact chain.
	legacy := []Record{
		{Actor: "operator", Action: "old.1", Target: "t"},
		{Actor: "operator", Action: "old.2", Target: "t"},
	}
	c := chain([][3]string{{"alice", "new.1", "t"}, {"bob", "new.2", "t"}}, when)
	rep := Verify(append(legacy, c...))
	if !rep.Intact {
		t.Fatalf("leading legacy rows must not break the chain: %+v", rep)
	}
	if rep.Unchained != 2 || rep.Verified != 2 {
		t.Fatalf("want 2 unchained + 2 verified, got %+v", rep)
	}
	// But an empty hash AFTER the chain begins is a real break, not a legacy row.
	mixed := append(c, Record{Actor: "x", Action: "y", Target: "t"})
	if Verify(mixed).Intact {
		t.Fatal("an unchained row after the chain begins must be a break")
	}
}

func TestVerifyDetectsErasedLeadingPrefix(t *testing.T) {
	when := at("2026-06-21T12:00:00Z")
	// An attacker blanks the hash of leading rows hoping Verify skips them as "legacy".
	// Because the surviving suffix's first record still points at a non-empty previous
	// hash, the erasure is detected – only a FULL reforge (recomputing every subsequent
	// hash), which an unanchored chain cannot defend against, could hide it.
	base := chain([][3]string{{"a", "1", "t"}, {"b", "2", "t"}, {"c", "3", "t"}}, when)

	c1 := append([]Record(nil), base...)
	c1[0].Hash, c1[0].PreviousHash = "", "" // blank the genesis row
	if Verify(c1).Intact {
		t.Fatal("blanking the genesis row must break the chain (suffix prev != \"\")")
	}

	c2 := append([]Record(nil), base...)
	c2[0].Hash, c2[0].PreviousHash = "", ""
	c2[1].Hash, c2[1].PreviousHash = "", "" // blank a two-row leading prefix
	if Verify(c2).Intact {
		t.Fatal("blanking a leading prefix must break the chain")
	}
}

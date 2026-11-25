package audit

import (
	"strings"
	"testing"
	"time"
)

func chainOf(prefix string, n int) []Record {
	at := time.Unix(1700000000, 0).UTC()
	out := make([]Record, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		r := Record{Actor: "operator", Action: prefix + "." + string(rune('a'+i)), Target: "t", At: at.Add(time.Duration(i) * time.Second)}
		r.PreviousHash = prev
		r.Hash = ComputeHash(prev, r.Actor, r.Action, r.Target, r.Metadata, r.At)
		out = append(out, r)
		prev = r.Hash
	}
	return out
}

// The audit log holds one chain per tenant since migration 0085, each starting at an empty
// previous_hash. Verifying them as a single sequence reported a break at the first row of the second
// tenant, so synapse-verify-restore called every healthy multi-tenant restore tampered.
func TestIndependentChainsVerifyIndependently(t *testing.T) {
	t.Parallel()
	chains := map[string][]Record{"tenant ta": chainOf("ta", 3), "tenant tb": chainOf("tb", 2)}
	got := VerifyChains(chains)
	if !got.Intact {
		t.Fatalf("two healthy chains reported broken: %+v", got)
	}
	if got.Verified != 5 {
		t.Fatalf("verified = %d, want every record across both chains", got.Verified)
	}
	// Concatenating them is what used to happen, and it is what must not be mistaken for a chain.
	flat := append(append([]Record{}, chains["tenant ta"]...), chains["tenant tb"]...)
	if Verify(flat).Intact {
		t.Fatal("the test fixture does not reproduce the shape: concatenation should look broken")
	}
}

func TestABreakInOneChainNamesThatChain(t *testing.T) {
	t.Parallel()
	broken := chainOf("tb", 2)
	broken[1].PreviousHash = "deadbeef"
	got := VerifyChains(map[string][]Record{"tenant ta": chainOf("ta", 2), "tenant tb": broken})
	if got.Intact {
		t.Fatal("a broken chain was reported intact")
	}
	// An operator reading this has to know where to look; "the audit chain is broken" does not say.
	if !strings.HasPrefix(got.Error, "tenant tb:") {
		t.Fatalf("error = %q, want it to name the chain that broke", got.Error)
	}
}

func TestOneChainStillReportsItsHead(t *testing.T) {
	t.Parallel()
	only := chainOf("legacy", 3)
	got := VerifyChains(map[string][]Record{"legacy global chain": only})
	if got.Head != only[len(only)-1].Hash {
		t.Fatalf("head = %q, want the last hash of the only chain", got.Head)
	}
	// With several chains there are several heads, and picking one would be arbitrary.
	several := VerifyChains(map[string][]Record{"a": chainOf("a", 2), "b": chainOf("b", 2)})
	if several.Head != "" {
		t.Fatalf("head = %q, want none when the report covers several chains", several.Head)
	}
}

func TestNoChainsIsIntactAndVerifiesNothing(t *testing.T) {
	t.Parallel()
	got := VerifyChains(nil)
	if !got.Intact || got.Verified != 0 {
		t.Fatalf("empty report = %+v, want intact with nothing verified", got)
	}
}

// A report that names only the first broken chain sends an operator round a loop: they repair it,
// re-run, and meet the next one. It also makes any assertion about a particular chain depend on how
// the names happen to sort, which is how this surfaced: the Postgres test asserting its own chain
// was named failed under the full suite, because the legacy chain sorts first and other tests had
// left it broken.
func TestEveryBrokenChainIsNamed(t *testing.T) {
	t.Parallel()
	first, second := chainOf("one", 2), chainOf("two", 2)
	first[1].PreviousHash = "deadbeef"
	second[1].PreviousHash = "deadbeef"
	got := VerifyChains(map[string][]Record{
		"aaa first":   first,
		"zzz second":  second,
		"mmm healthy": chainOf("ok", 2),
	})
	if got.Intact {
		t.Fatal("two broken chains were reported intact")
	}
	for _, name := range []string{"aaa first", "zzz second"} {
		if !strings.Contains(got.Error, name) {
			t.Fatalf("error %q does not name %q", got.Error, name)
		}
	}
	if strings.Contains(got.Error, "mmm healthy") {
		t.Fatalf("error %q names a chain that verified", got.Error)
	}
}

func TestTheNamedChainListIsBounded(t *testing.T) {
	t.Parallel()
	chains := map[string][]Record{}
	for i := 0; i < maxReportedBrokenChains+5; i++ {
		c := chainOf("t"+string(rune('a'+i)), 2)
		c[1].PreviousHash = "deadbeef"
		chains["tenant "+string(rune('a'+i))] = c
	}
	got := VerifyChains(chains)
	if got.Intact {
		t.Fatal("broken chains were reported intact")
	}
	// The message is stored and rendered, so it cannot grow with the tenant count.
	if strings.Count(got.Error, "audit chain broken") > maxReportedBrokenChains {
		t.Fatalf("error names more than %d chains: %q", maxReportedBrokenChains, got.Error)
	}
	if !strings.Contains(got.Error, "further chains are broken") {
		t.Fatalf("error %q does not say it was truncated", got.Error)
	}
}

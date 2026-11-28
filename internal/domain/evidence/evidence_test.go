package evidence

import (
	"errors"
	"testing"
	"time"
)

func chain() []Evidence {
	e1 := Evidence{Kind: "scan", Content: []byte("scan-a")}.Seal()
	e2 := Evidence{Kind: "finding", Content: []byte("finding-b"), PreviousHash: e1.Hash}.Seal()
	e3 := Evidence{Kind: "report", Content: []byte("report-c"), PreviousHash: e2.Hash}.Seal()
	return []Evidence{e1, e2, e3}
}

func TestComputeHashLinksPrevious(t *testing.T) {
	base := Evidence{Kind: "scan", Content: []byte("x")}
	// The same content under a different previous hash yields a different hash.
	a := ComputeHash(base)
	withPrev := base
	withPrev.PreviousHash = "prev"
	if a == ComputeHash(withPrev) {
		t.Error("hash must incorporate the previous hash (chain link)")
	}
	if h1, h2 := ComputeHash(base), ComputeHash(base); h1 != h2 {
		t.Error("hash must be deterministic for identical inputs")
	}
}

// TestVerifyChainTamperedAttribution covers the re-audit fix: rewriting WHO produced an
// evidence link (created_by) or WHEN (created_at) breaks the chain, not just content edits.
func TestVerifyChainTamperedAttribution(t *testing.T) {
	c := chain()
	c[1].CreatedBy = "attacker" // rewrite attribution without re-sealing
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for rewritten created_by, got %v", err)
	}
	c = chain()
	c[1].CreatedAt = c[1].CreatedAt.Add(48 * 3600 * 1e9) // backdate by 48h
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for rewritten created_at, got %v", err)
	}
}

func TestVerifyChainValid(t *testing.T) {
	if err := VerifyChain(chain()); err != nil {
		t.Fatalf("valid chain failed verification: %v", err)
	}
	if err := VerifyChain(nil); err != nil {
		t.Errorf("empty chain should verify, got %v", err)
	}
}

func TestVerifyChainTamperedContent(t *testing.T) {
	c := chain()
	c[1].Content = []byte("tampered") // edit content without re-sealing
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for tampered content, got %v", err)
	}
}

func TestVerifyChainBrokenLink(t *testing.T) {
	c := chain()
	c[2].PreviousHash = "0000" // break the link to the prior item
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for a broken link, got %v", err)
	}
}

func TestVerifyChainReordered(t *testing.T) {
	c := chain()
	c[1], c[2] = c[2], c[1] // reordering breaks the previous_hash continuity
	if err := VerifyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Errorf("want ErrChainBroken for reordered items, got %v", err)
	}
}

// TestSealedFindingIDBindsTheHash (#1722): an imported link hashes over the finding id it was sealed with,
// so its FindingID may point at the importing instance's finding without breaking the chain; a link sealed
// here never carries a sealed id and keeps binding its FindingID.
func TestSealedFindingIDBindsTheHash(t *testing.T) {
	at := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	for _, scheme := range []int{HashSchemeLegacy, HashSchemeFramed} {
		native := Evidence{Kind: "finding", FindingID: "source-f1", CreatedBy: "ada", CreatedAt: at, Content: []byte("x"), HashScheme: scheme}
		native.Hash = ComputeHash(native)
		imported := native
		imported.FindingID, imported.SealedFindingID = "local-f9", "source-f1"
		if ComputeHash(imported) != native.Hash {
			t.Errorf("scheme %d: a remapped link with its sealed id must hash like the original", scheme)
		}
		if err := VerifyChain([]Evidence{imported}); err != nil {
			t.Errorf("scheme %d: remapped link must verify: %v", scheme, err)
		}
		unlinked := imported
		unlinked.FindingID = "" // the finding was absent from the bundle
		if err := VerifyChain([]Evidence{unlinked}); err != nil {
			t.Errorf("scheme %d: a link whose finding is absent must still verify: %v", scheme, err)
		}
		forged := imported
		forged.SealedFindingID = "source-f2"
		if err := VerifyChain([]Evidence{forged}); err == nil {
			t.Errorf("scheme %d: a changed sealed id must break the chain", scheme)
		}
	}
	sealed := Evidence{Kind: "finding", FindingID: "f1", SealedFindingID: "other", CreatedAt: at}.Seal()
	if sealed.SealedFindingID != "" || sealed.Hash != ComputeHash(Evidence{Kind: "finding", FindingID: "f1", CreatedAt: at, HashScheme: CurrentHashScheme}) {
		t.Fatal("Seal must clear a caller-supplied sealed id and bind FindingID")
	}
}

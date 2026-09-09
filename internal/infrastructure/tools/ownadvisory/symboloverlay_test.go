package ownadvisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func writeOverlay(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasSymbol(syms []string, want string) bool {
	for _, s := range syms {
		if s == want {
			return true
		}
	}
	return false
}

// TestSymbolOverlayEnrichesFinding is the D4.1 overlay: a curated overlay supplies affected symbols for an
// advisory whose feed carries none (here an npm advisory), and the matcher merges them onto the finding so a
// non-Go reachability analysis has symbols to prove against. Lookup is by the advisory's id AND its aliases.
func TestSymbolOverlayEnrichesFinding(t *testing.T) {
	// An npm advisory with no ecosystem_specific.imports carries no symbols on its own.
	const j = `{
	  "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2024-9999"],
	  "affected": [{
	    "package": {"ecosystem": "npm", "name": "leftpad"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
	  }]
	}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if len(adv.Affected[0].AffectedSymbols) != 0 {
		t.Fatalf("feed carries no symbols for this npm advisory, got %v", adv.Affected[0].AffectedSymbols)
	}

	// The overlay is keyed by the CVE alias, not the primary GHSA id, to prove alias lookup.
	dir := t.TempDir()
	writeOverlay(t, dir, "overlay.json", `{"cve-2024-9999": ["leftpad.pad", "leftpad.internal"]}`)
	overlay, err := LoadSymbolOverlay(dir)
	if err != nil {
		t.Fatal(err)
	}

	store := memStore{byKey: map[string][]advisory.Advisory{"npm|leftpad": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "leftpad", Version: "1.0.0", PURL: "pkg:npm/leftpad@1.0.0"},
	}}

	// Without the overlay the finding carries no symbols.
	bare, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != 1 || len(bare[0].AffectedSymbols) != 0 {
		t.Fatalf("without overlay the finding must carry no symbols, got %+v", bare)
	}

	// With the overlay the finding is enriched with the curated symbols (matched via the CVE alias).
	raws, err := New(store).WithSymbolOverlay(overlay).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding, got %d", len(raws))
	}
	if !hasSymbol(raws[0].AffectedSymbols, "leftpad.pad") || !hasSymbol(raws[0].AffectedSymbols, "leftpad.internal") {
		t.Errorf("overlay symbols must enrich the finding, got %v", raws[0].AffectedSymbols)
	}
}

func TestLoadSymbolOverlayBlankAndNonDir(t *testing.T) {
	if o, err := LoadSymbolOverlay(""); err != nil || o != nil {
		t.Errorf("blank dir disables the overlay, got %v err=%v", o, err)
	}
	f := filepath.Join(t.TempDir(), "file.json")
	writeOverlay(t, filepath.Dir(f), "file.json", `{}`)
	if _, err := LoadSymbolOverlay(f); err == nil {
		t.Error("a non-directory path must error")
	}
}

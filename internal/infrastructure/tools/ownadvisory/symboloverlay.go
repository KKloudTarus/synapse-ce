package ownadvisory

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A symbol overlay supplies per-advisory affected symbols for advisories whose feed does not carry them (the
// Go vuln DB is the only OSV source that publishes symbols, so everything non-Go, and every NVD/CSAF-only
// advisory, is symbol-starved). It is a CURATED side table keyed by advisory id — an operator maintains
// "<advisory-id> -> [importPath.Symbol, ...]" mappings — consulted by the matcher at emit time and merged
// onto the finding's AffectedSymbols alongside any feed-provided ones. It never changes WHICH advisories
// match (no ranges, no matching); it only enriches a matched finding with symbols so a non-Go Tier-2
// reachability analysis has something to prove against. A symbol for the wrong language is inert: it simply
// never matches that language's call graph, so a mis-curated entry cannot cause a false reachable verdict.

const (
	maxOverlayFiles   = 4096      // *.json overlay files read from the directory
	maxOverlayBytes   = 8 << 20   // per-file read cap (an overlay file is small curated data)
	maxOverlayEntries = 1_000_000 // total advisory-id entries retained
	maxOverlaySymbols = 4096      // symbols retained per advisory id
)

// SymbolOverlay maps a normalized (upper-cased) advisory id to its curated affected symbols.
type SymbolOverlay map[string][]string

// normID normalizes an advisory id for overlay keying (upper-cased, trimmed), so "cve-2024-1" and
// "CVE-2024-1" resolve to the same entry regardless of how the feed or the overlay spelled it.
func normID(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// symbolsFor returns the deduplicated overlay symbols for an advisory id, or nil.
func (o SymbolOverlay) symbolsFor(id string) []string {
	if o == nil {
		return nil
	}
	return o[normID(id)]
}

// LoadSymbolOverlay reads every *.json file under dir as a curated symbol overlay and merges them. Each file
// is a JSON object mapping an advisory id to an array of affected symbols, e.g.
//
//	{ "CVE-2024-1234": ["org.example.Foo#bar", "org.example.Baz#qux"] }
//
// Ids are upper-cased so a lookup meets the matcher's normID form; symbols are trimmed, de-duplicated, and
// bounded. An empty dir yields an empty overlay; an unreadable/oversized/unparseable file is skipped
// best-effort (curated data must never abort a scan). A blank dir returns (nil, nil): overlay disabled.
func LoadSymbolOverlay(dir string) (SymbolOverlay, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	// Resolve a symlinked directory root so WalkDir actually descends it (WalkDir lstat's the root and would
	// otherwise treat a symlink-to-dir as a single non-dir entry, silently yielding an empty overlay).
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("symbol overlay dir %q: %w", dir, err)
	}
	dir = resolved
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("symbol overlay dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("symbol overlay path %q is not a directory", dir)
	}
	overlay := SymbolOverlay{}
	files := 0
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if files++; files > maxOverlayFiles || len(overlay) >= maxOverlayEntries {
			return fs.SkipAll
		}
		fi, lerr := os.Lstat(path)
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > maxOverlayBytes {
			return nil // never follow a symlink out of the dir; skip an oversized file
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- WalkDir entry under dir, re-verified regular via Lstat
		if rerr != nil {
			return nil
		}
		var raw map[string][]string
		if json.Unmarshal(data, &raw) != nil {
			return nil // a malformed overlay file contributes nothing (best-effort curated data)
		}
		mergeOverlayFile(overlay, raw)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk symbol overlay dir %q: %w", dir, walkErr)
	}
	return overlay, nil
}

// mergeOverlayFile folds one parsed overlay file into the accumulator, normalizing ids, trimming and
// de-duplicating symbols, and enforcing the per-id symbol cap.
func mergeOverlayFile(overlay SymbolOverlay, raw map[string][]string) {
	for id, syms := range raw {
		key := normID(id)
		if key == "" || len(overlay) >= maxOverlayEntries {
			continue
		}
		seen := map[string]bool{}
		merged := overlay[key]
		for _, s := range merged {
			seen[s] = true
		}
		for _, s := range syms {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] || len(merged) >= maxOverlaySymbols {
				continue
			}
			seen[s] = true
			merged = append(merged, s)
		}
		sort.Strings(merged)
		overlay[key] = merged
	}
}

// dedupSymbols returns the sorted, de-duplicated non-empty symbols.
func dedupSymbols(symbols []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(symbols))
	for _, s := range symbols {
		s = strings.TrimSpace(s) // trim so a feed-provided symbol with surrounding space is not a distinct entry
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

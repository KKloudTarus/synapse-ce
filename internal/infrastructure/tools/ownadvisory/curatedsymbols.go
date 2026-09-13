package ownadvisory

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
)

// The curated vulnerable-methods corpus is the moat: SME-confirmed root-cause symbols attached to the
// OWNED advisory store, in the affected block they belong to, so MatchDetails seeds them version-scoped and
// only when CONFIRMED. It is the successor to the version-blind SymbolOverlay: an overlay enriches any
// matched finding with all curated symbols for the advisory id regardless of which version block matched,
// which can attach a symbol to a version it does not apply to. A curated corpus attaches each entry to the
// affected block(s) it applies to, so the domain's version guard (advisory.MatchDetails) governs seeding.
//
// A GHSA fix-commit function name is only a CANDIDATE: fix commits touch wrappers, tests, and renames as
// well as the true sink, so a candidate is retained for review but never seeds. Confirm promotes a candidate
// to CONFIRMED (with the curator + timestamp) after SME review; only then does it seed a symbol-level match.
// Every entry carries provenance + confidence, and a wrong-language symbol is inert (ecosystem-scoped by its
// block, and its canonical form never matches another language's call graph).

const (
	maxCuratedFiles      = 4096
	maxCuratedBytes      = 8 << 20   // per-file read cap
	maxCuratedTotalBytes = 256 << 20 // aggregate cap across all corpus files (DoS bound)
	maxCuratedEntries    = 1_000_000 // total entries retained
	// Per-entry string/aux caps come from the domain guard so ingest and the domain never diverge.
	maxCuratedAux       = advisory.MaxCuratedAuxSymbols
	maxCuratedSymbolLen = advisory.MaxCuratedSymbolLen
)

// CuratedEntry is the wire form of one curated vulnerable-method record. It names the advisory and the exact
// (ecosystem, package) it applies to, the canonical symbol plus its overload/alias set, and the status +
// confidence + provenance that make it auditable. Symbols are stored in the same raw source form as
// AffectedSymbols; the reachability engine canonicalizes both sides at comparison (symbolcanon), so the
// corpus must not pre-transform them, only reject a mangled binary symbol that has not been demangled. The
// seeding scope is the affected block's version range (advisory.MatchDetails), so an entry seeds exactly for
// the versions the advisory marks affected; finer per-symbol version scoping is a curation-granularity
// concern handled by scoping the advisory's affected blocks, not by this record.
type CuratedEntry struct {
	AdvisoryID  string    `json:"advisoryId"`
	Ecosystem   string    `json:"ecosystem"`
	Package     string    `json:"package"`
	Symbol      string    `json:"symbol"`
	Signature   string    `json:"signature,omitempty"`
	Overloads   []string  `json:"overloads,omitempty"`
	Aliases     []string  `json:"aliases,omitempty"`
	Status      string    `json:"status"`
	Confidence  int       `json:"confidence"`
	Source      string    `json:"source"`
	Reference   string    `json:"reference,omitempty"`
	Curator     string    `json:"curator,omitempty"`
	ConfirmedAt time.Time `json:"confirmedAt,omitempty"`
}

// CuratedCorpus maps a normalized advisory id to its curated entries.
type CuratedCorpus map[string][]CuratedEntry

// toCuratedSymbol builds and validates the domain CuratedSymbol, rejecting a mangled symbol (an un-demangled
// C++/Rust binary name must never enter the store: it would never match a source-form call graph, and worse
// could be mistaken for a real symbol). Overloads and aliases are trimmed, de-duplicated, bounded, and also
// rejected if mangled.
func (e CuratedEntry) toCuratedSymbol() (advisory.CuratedSymbol, error) {
	sym := strings.TrimSpace(e.Symbol)
	if len(sym) > maxCuratedSymbolLen {
		return advisory.CuratedSymbol{}, fmt.Errorf("%w: curated symbol exceeds %d bytes", shared.ErrValidation, maxCuratedSymbolLen)
	}
	if symbolcanon.LooksMangled(sym) {
		return advisory.CuratedSymbol{}, fmt.Errorf("%w: curated symbol %q is mangled; demangle before curation", shared.ErrValidation, sym)
	}
	overloads, err := cleanCuratedSymbols(e.Overloads)
	if err != nil {
		return advisory.CuratedSymbol{}, fmt.Errorf("overload: %w", err)
	}
	aliases, err := cleanCuratedSymbols(e.Aliases)
	if err != nil {
		return advisory.CuratedSymbol{}, fmt.Errorf("alias: %w", err)
	}
	cs := advisory.CuratedSymbol{
		Symbol:     sym,
		Signature:  strings.TrimSpace(e.Signature),
		Overloads:  overloads,
		Aliases:    aliases,
		Status:     advisory.CuratedStatus(strings.ToLower(strings.TrimSpace(e.Status))),
		Confidence: e.Confidence,
		Provenance: advisory.CuratedProvenance{
			Source:      strings.TrimSpace(e.Source),
			Reference:   strings.TrimSpace(e.Reference),
			Curator:     strings.TrimSpace(e.Curator),
			ConfirmedAt: e.ConfirmedAt,
		},
	}
	if err := cs.Validate(); err != nil {
		return advisory.CuratedSymbol{}, err
	}
	return cs, nil
}

// Confirm promotes a candidate entry to CONFIRMED, recording the curator and the confirmation time. This is
// the candidate->confirmed workflow: a candidate (e.g. a GHSA fix-commit function name) is retained but
// inert until an SME confirms the root cause here. It returns a validated confirmed entry or an error, so an
// unnamed curator or a malformed symbol can never be confirmed.
func (e CuratedEntry) Confirm(curator string, at time.Time) (CuratedEntry, error) {
	if strings.TrimSpace(curator) == "" {
		return CuratedEntry{}, fmt.Errorf("%w: confirming a curated symbol requires a curator", shared.ErrValidation)
	}
	e.Status = string(advisory.CuratedConfirmed)
	e.Curator = curator
	e.ConfirmedAt = at
	if _, err := e.toCuratedSymbol(); err != nil {
		return CuratedEntry{}, err
	}
	return e, nil
}

// cleanCuratedSymbols trims, drops empty, de-duplicates, bounds, and rejects a mangled or oversized entry.
func cleanCuratedSymbols(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if len(s) > maxCuratedSymbolLen {
			return nil, fmt.Errorf("%w: curated symbol exceeds %d bytes", shared.ErrValidation, maxCuratedSymbolLen)
		}
		if symbolcanon.LooksMangled(s) {
			return nil, fmt.Errorf("%w: curated symbol %q is mangled; demangle before curation", shared.ErrValidation, s)
		}
		seen[s] = true
		if out = append(out, s); len(out) >= maxCuratedAux {
			break
		}
	}
	return out, nil
}

// sanitizeEntry bounds the memory a single loaded entry retains before Apply validates it: it truncates the
// overload and alias arrays to maxCuratedAux, so a hostile corpus file with millions of aux strings cannot
// be held in the corpus map. It does not validate (Apply does); it only caps retention.
func sanitizeEntry(e CuratedEntry) CuratedEntry {
	if len(e.Overloads) > maxCuratedAux {
		e.Overloads = e.Overloads[:maxCuratedAux]
	}
	if len(e.Aliases) > maxCuratedAux {
		e.Aliases = e.Aliases[:maxCuratedAux]
	}
	return e
}

// Apply attaches the corpus's curated entries to the matching affected blocks of adv, so a later
// MatchDetails seeds a CONFIRMED entry version-scoped by that block's range. An entry matches a block by
// exact (ecosystem, package) and attaches to every such block, so the advisory's own version ranges (a
// symbol never seeds outside an affected range) are the seeding scope. A malformed entry is skipped (never
// seeds). Entries are found by the advisory's primary id AND its aliases, so a CVE-keyed curation attaches
// to a GHSA-keyed advisory and vice versa.
func (c CuratedCorpus) Apply(adv advisory.Advisory) advisory.Advisory {
	if len(c) == 0 {
		return adv
	}
	entries := append([]CuratedEntry(nil), c[normID(adv.ID)]...)
	for _, alias := range adv.Aliases {
		entries = append(entries, c[normID(alias)]...)
	}
	if len(entries) == 0 {
		return adv
	}
	for i := range adv.Affected {
		blk := &adv.Affected[i]
		for _, e := range entries {
			if strings.TrimSpace(e.Ecosystem) != blk.Ecosystem || strings.TrimSpace(e.Package) != blk.Package {
				continue
			}
			cs, err := e.toCuratedSymbol()
			if err != nil {
				continue // malformed curated data must never seed; skip best-effort
			}
			blk.CuratedSymbols = append(blk.CuratedSymbols, cs)
		}
	}
	return adv
}

// LoadCuratedCorpus reads every *.json file under dir as an array of CuratedEntry and merges them, keyed by
// normalized advisory id. A blank dir returns (nil, nil): the corpus is disabled. An unreadable, oversized,
// or unparseable file is skipped best-effort (curated data must never abort a scan). Entries are NOT
// validated here (Apply validates each at attach time), so a partially-malformed file still contributes its
// good entries.
func LoadCuratedCorpus(dir string) (CuratedCorpus, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("curated corpus dir %q: %w", dir, err)
	}
	dir = resolved
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("curated corpus dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("curated corpus path %q is not a directory", dir)
	}
	corpus := CuratedCorpus{}
	files, total, totalBytes := 0, 0, int64(0)
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if files++; files > maxCuratedFiles || total >= maxCuratedEntries || totalBytes >= maxCuratedTotalBytes {
			return fs.SkipAll // bound files, entries, and aggregate bytes so a hostile corpus dir cannot OOM
		}
		fi, lerr := os.Lstat(path)
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > maxCuratedBytes {
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- WalkDir entry under dir, re-verified regular via Lstat
		if rerr != nil {
			return nil
		}
		totalBytes += int64(len(data))
		var raw []CuratedEntry
		if json.Unmarshal(data, &raw) != nil {
			return nil
		}
		for _, e := range raw {
			key := normID(e.AdvisoryID)
			if key == "" || total >= maxCuratedEntries {
				continue
			}
			corpus[key] = append(corpus[key], sanitizeEntry(e))
			total++
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk curated corpus dir %q: %w", dir, walkErr)
	}
	return corpus, nil
}

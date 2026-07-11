// Package duplication is a deterministic, pure-Go copy-paste (clone) detector: it walks a source tree,
// tokenizes each file (comment- and whitespace-insensitive, language-aware comment stripping), and finds
// runs of duplicated tokens across and within files via a Rabin-Karp rolling hash, then reports the
// standard duplication metrics (blocks, duplicated lines, files, density). It NEVER executes the target
// and reads bounded (skips vendored/binary/oversized files, follows no symlinks). Pure Go with no CGO, so
// it is available in every build (unlike the tree-sitter metrics sidecar). Exact (Type-1) clones:
// identifiers and literals are matched by text, which is the copy-paste signal operators expect.
package duplication

import (
	"context"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// DefaultMinTokens is the smallest duplicated token run reported by default. Tokens here are at
	// lexer granularity (an identifier/number, a whole string literal, or an operator run – see the
	// tokenizer), so 100 matches the long-standing PMD/CPD default and keeps trivial repetition out.
	DefaultMinTokens = 100
	maxFileBytes     = 4 << 20
	maxFiles         = 200_000
	hashBase         = 1099511628211 // FNV prime, reused as the rolling-hash polynomial base
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true,
	".vscode": true, ".tox": true, ".hg": true, ".svn": true,
}

// Detector finds duplicated token runs of at least MinTokens tokens.
type Detector struct{ minTokens int }

// New returns a detector. minTokens <= 0 uses DefaultMinTokens.
func New(minTokens int) *Detector {
	if minTokens <= 0 {
		minTokens = DefaultMinTokens
	}
	return &Detector{minTokens: minTokens}
}

var _ ports.DuplicationScanner = (*Detector)(nil)

type token struct {
	text string
	line int // 1-based
}

type fileTokens struct {
	rel       string
	toks      []token
	codeLines int
}

// Duplication walks root, tokenizes each supported source file, and returns the duplication report.
func (d *Detector) Duplication(ctx context.Context, root string) (measure.DuplicationReport, error) {
	files, truncated, err := d.collect(ctx, root)
	if err != nil {
		return measure.DuplicationReport{}, err
	}
	return d.detect(ctx, files, truncated)
}

// collect walks root and tokenizes each regular, non-vendored, non-binary source file.
func (d *Detector) collect(ctx context.Context, root string) ([]fileTokens, bool, error) {
	if root == "" {
		return nil, false, nil
	}
	var out []fileTokens
	truncated := false
	count := 0
	walkErr := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if de.IsDir() {
			if path != root && skipDirs[de.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !de.Type().IsRegular() {
			return nil
		}
		if count++; count > maxFiles {
			truncated = true
			return fs.SkipAll
		}
		fi, lerr := os.Lstat(path)
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > maxFileBytes {
			return nil
		}
		content, rerr := os.ReadFile(path) // #nosec G304 -- regular file, size-capped via Lstat above, under the walked root
		if rerr != nil {
			return nil
		}
		if enry.IsVendor(path) || enry.IsDotFile(path) || enry.IsGenerated(path, content) || enry.IsBinary(content) {
			return nil
		}
		lang := enry.GetLanguage(filepath.Base(path), content)
		if lang == "" {
			return nil
		}
		switch enry.GetLanguageType(lang) {
		case enry.Programming, enry.Markup:
		default:
			return nil
		}
		toks, codeLines := tokenize(lang, content)
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		out = append(out, fileTokens{rel: rel, toks: toks, codeLines: codeLines})
		return nil
	})
	if walkErr != nil {
		return nil, false, walkErr
	}
	// Deterministic file order (WalkDir is lexical already, but be explicit for stable output).
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, truncated, nil
}

// detect finds maximal duplicated token runs across the collected files. Greedy: each token is assigned
// to at most one clone class (via covered[]), so overlapping clone classes that share tokens can be
// undercounted – false negatives only, never false positives.
func (d *Detector) detect(ctx context.Context, files []fileTokens, truncated bool) (measure.DuplicationReport, error) {
	k := d.minTokens
	rep := measure.DuplicationReport{Truncated: truncated}
	for _, f := range files {
		rep.TotalLines += f.codeLines
	}

	// token hashes per file + the FNV of each token text.
	th := make([][]uint64, len(files))
	for fi, f := range files {
		th[fi] = make([]uint64, len(f.toks))
		for i, t := range f.toks {
			th[fi][i] = fnv64(t.text)
		}
	}

	// bucket every length-k window by its rolling hash: hash -> positions.
	type pos struct{ file, tok int }
	buckets := map[uint64][]pos{}
	pow := uint64(1)
	for i := 1; i < k; i++ {
		pow *= hashBase
	}
	for fi := range files {
		h := th[fi]
		if len(h) < k {
			continue
		}
		var win uint64
		for i := 0; i < k; i++ {
			win = win*hashBase + h[i]
		}
		buckets[win] = append(buckets[win], pos{fi, 0})
		for i := k; i < len(h); i++ {
			win = (win-h[i-k]*pow)*hashBase + h[i]
			buckets[win] = append(buckets[win], pos{fi, i - k + 1})
		}
	}

	// covered[file] = set of token indices already reported, so overlapping sub-clones are not re-emitted.
	covered := make([]map[int]bool, len(files))
	for i := range covered {
		covered[i] = map[int]bool{}
	}
	dupLines := make([]map[int]bool, len(files))
	for i := range dupLines {
		dupLines[i] = map[int]bool{}
	}

	// Process seeds in file/token order for determinism; the leftmost start of a clone is seen first, so
	// right-extension captures it maximally and covered[] suppresses its interior windows.
	for fi := range files {
		if ctx.Err() != nil {
			return measure.DuplicationReport{}, ctx.Err()
		}
		toks := files[fi].toks
		for start := 0; start+k <= len(toks); start++ {
			if covered[fi][start] {
				continue
			}
			var win uint64
			for i := start; i < start+k; i++ {
				win = win*hashBase + th[fi][i]
			}
			cands := buckets[win]
			if len(cands) < 2 {
				continue
			}
			// members = positions whose k-token text matches this window and are not covered.
			members := []pos{{fi, start}}
			for _, c := range cands {
				if c.file == fi && c.tok == start {
					continue
				}
				if covered[c.file][c.tok] {
					continue
				}
				if equalRun(files[fi].toks, start, files[c.file].toks, c.tok, k) {
					members = append(members, c)
				}
			}
			if len(members) < 2 {
				continue
			}
			// Extend right while every member has a matching next token in-bounds.
			length := k
			for {
				base := files[members[0].file].toks
				bi := members[0].tok + length
				if bi >= len(base) {
					break
				}
				ok := true
				for _, m := range members[1:] {
					mt := files[m.file].toks
					mi := m.tok + length
					if mi >= len(mt) || mt[mi].text != base[bi].text {
						ok = false
						break
					}
				}
				if !ok {
					break
				}
				length++
			}
			// Record the block, mark covered + duplicated lines.
			block := measure.DuplicationBlock{Tokens: length}
			for _, m := range members {
				mt := files[m.file].toks
				block.Occurrences = append(block.Occurrences, measure.CodeRange{
					File:      files[m.file].rel,
					StartLine: mt[m.tok].line,
					EndLine:   mt[m.tok+length-1].line,
				})
				for i := m.tok; i < m.tok+length; i++ {
					covered[m.file][i] = true
					dupLines[m.file][mt[i].line] = true
				}
			}
			sort.Slice(block.Occurrences, func(i, j int) bool {
				if block.Occurrences[i].File != block.Occurrences[j].File {
					return block.Occurrences[i].File < block.Occurrences[j].File
				}
				return block.Occurrences[i].StartLine < block.Occurrences[j].StartLine
			})
			rep.Blocks = append(rep.Blocks, block)
		}
	}

	filesWith := 0
	for fi := range files {
		if len(dupLines[fi]) > 0 {
			filesWith++
			rep.DuplicatedLines += len(dupLines[fi])
		}
	}
	rep.Files = filesWith
	return rep, nil
}

// equalRun reports whether a[ai:ai+n] and b[bi:bi+n] have identical token text.
func equalRun(a []token, ai int, b []token, bi, n int) bool {
	if ai+n > len(a) || bi+n > len(b) {
		return false
	}
	for i := 0; i < n; i++ {
		if a[ai+i].text != b[bi+i].text {
			return false
		}
	}
	return true
}

func fnv64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

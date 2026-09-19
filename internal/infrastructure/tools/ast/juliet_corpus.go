package ast

// juliet_corpus.go loads the Juliet Java test suite answer key. Juliet (NIST SARD, public domain; the
// find-sec-bugs/juliet-test-suite Java checkout) is a large synthetic taint corpus whose ground truth is
// METHOD-based, not inline like Securibench: a modeled sink call inside a `bad*` method is a true
// vulnerability (a tainted source reaches it), and the SAME sink inside a `good*` method is safe (the source
// was neutralized or the sink sanitized). So each sink line is classified by its enclosing top-level method.
// Juliet's formatting is rigidly regular (every top-level method is declared at exactly four-space indent), so
// the enclosing method is tracked by that indentation rather than brace counting, which a string- or
// comment-embedded brace could fool. The CWE comes from the test-case directory name (CWE89_... -> CWE-89),
// and only the sink calls the owned Java value-flow engine models are emitted; other calls are ignored, so
// coverage is never overstated. File I/O lives here in infrastructure so the sastbench reducer stays pure,
// mirroring the OWASP and Securibench loaders.

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// julietCWESinks maps a Juliet CWE directory prefix (e.g. "CWE89") to the CWE id the owned engine scores and
// the sink-call substrings that identify a sink line for that class. Only classes the owned Java value-flow
// engine models are listed; a test-case directory not listed here is skipped entirely.
var julietCWESinks = map[string]struct {
	cwe   string
	sinks []string
}{
	"CWE89": {"CWE-89", []string{".executeQuery(", ".executeUpdate(", ".executeBatch(", ".prepareStatement(", ".prepareCall(", ".addBatch(", ".execute("}},
}

// julietMethodDeclRE matches a Juliet top-level method declaration: a modifier at exactly four-space indent,
// then `void <name>(`. Juliet declares bad(), good(), goodG2B*, goodB2G*, and bad/goodSink/Source helpers all
// at this indent, so the capture group is the enclosing method for every deeper-indented line beneath it.
var julietMethodDeclRE = regexp.MustCompile(`^ {4}(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?void\s+([A-Za-z0-9_]+)\s*\(`)

// julietCorpus is the parsed answer key plus the count of sink lines whose sink token the owned engine models
// but whose enclosing method could not be classified (neither bad nor good), so nothing is silently misscored.
type julietCorpus struct {
	Cases        []sastbench.LabeledCase
	Files        int
	Unclassified int
}

// loadJuliet walks a Juliet Java checkout's src/testcases tree and returns the answer key for the modeled
// CWEs. Only SINGLE-FILE test cases (the flow-variant suffix is all digits, e.g. `__X_01.java`) are used; the
// multi-file `..a.java`/`..b.java` split-flow cases need cross-file taint that this line-anchored harness does
// not stage, so they are skipped rather than misscored. Each modeled sink line becomes one case keyed by the
// base filename and its 1-based line, with Real=true when the enclosing method is a bad* method.
func loadJuliet(root string) (julietCorpus, error) {
	testcases := root
	if st, err := os.Stat(filepath.Join(root, "src", "testcases")); err == nil && st.IsDir() {
		testcases = filepath.Join(root, "src", "testcases")
	}
	var out julietCorpus
	err := filepath.WalkDir(testcases, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		base := filepath.Base(path)
		spec, ok := julietSinkSpecForFile(base)
		if !ok || !julietSingleFile(base) {
			return nil
		}
		cases, unclassified, ferr := scanJulietFile(path, base, spec.cwe, spec.sinks)
		if ferr != nil {
			return ferr
		}
		if len(cases) > 0 {
			out.Files++
		}
		out.Cases = append(out.Cases, cases...)
		out.Unclassified += unclassified
		return nil
	})
	if err != nil {
		return julietCorpus{}, fmt.Errorf("load juliet corpus at %s: %w", testcases, err)
	}
	sort.Slice(out.Cases, func(i, j int) bool { return out.Cases[i].Name < out.Cases[j].Name })
	return out, nil
}

// julietSinkSpecForFile returns the modeled sink spec for a test-case file from its CWE prefix, or ok=false.
func julietSinkSpecForFile(base string) (struct {
	cwe   string
	sinks []string
}, bool) {
	prefix := base
	if i := strings.Index(base, "_"); i >= 0 {
		prefix = base[:i]
	}
	spec, ok := julietCWESinks[prefix]
	return spec, ok
}

// julietSingleFile reports whether a Juliet file name is a single-file test case: the trailing flow-variant
// token (after the last '_') is all digits. Multi-file cases end in a digit-plus-letter token (e.g. `_54a`).
func julietSingleFile(base string) bool {
	name := strings.TrimSuffix(base, ".java")
	i := strings.LastIndexByte(name, '_')
	if i < 0 || i == len(name)-1 {
		return false
	}
	variant := name[i+1:]
	for _, r := range variant {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// scanJulietFile line-scans one test case, tracking the enclosing top-level method by four-space-indent
// declarations, and emits a labeled case for each modeled sink line (Real from the enclosing method).
func scanJulietFile(path, base, cwe string, sinks []string) (cases []sastbench.LabeledCase, unclassified int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	method := ""         // enclosing top-level method name, "" before the first declaration
	flawPending := false // a POTENTIAL FLAW / FIX marker has been seen and its sink line not yet consumed
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if m := julietMethodDeclRE.FindStringSubmatch(text); m != nil {
			method = m[1]
			flawPending = false // markers do not cross a method boundary
			continue
		}
		if julietFlawMarker(text) {
			// A source marker precedes a source read (not a sink token), a sink marker precedes the sink call.
			// Either way the NEXT modeled-sink line in this method is Juliet's one intended sink for the flaw,
			// so anchoring on a pending marker yields exactly one case per flaw even when the sink spans several
			// calls (e.g. addBatch then executeBatch).
			flawPending = true
			continue
		}
		if !flawPending || !julietLineHasSink(text, sinks) {
			continue
		}
		flawPending = false
		real, ok := julietMethodIsBad(method)
		if !ok {
			unclassified++ // a marked sink outside any bad*/good* method (a shared helper): never guess
			continue
		}
		cases = append(cases, sastbench.LabeledCase{
			Name: fmt.Sprintf("%s:%d", base, line),
			File: base, Line: line, CWE: cwe, Real: real,
		})
	}
	return cases, unclassified, scanner.Err()
}

// julietFlawMarker reports whether a line is a Juliet ground-truth marker: `/* POTENTIAL FLAW` on a source or
// sink, or `/* FIX` on the sanitized replacement in a goodB2G sink (so the sanitized sink is still scored, to
// catch a false positive when the engine does not model the sanitizer).
func julietFlawMarker(text string) bool {
	return strings.Contains(text, "/* POTENTIAL FLAW") || strings.Contains(text, "/* FIX")
}

// julietLineHasSink reports whether a source line contains one of the modeled sink-call tokens.
func julietLineHasSink(text string, sinks []string) bool {
	for _, s := range sinks {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// julietMethodIsBad classifies the enclosing method: a `bad*` method holds a genuine flaw (Real=true), a
// `good*` method is safe (Real=false). Any other method (or none) is unclassifiable and the caller skips it.
func julietMethodIsBad(method string) (real, ok bool) {
	switch {
	case strings.HasPrefix(method, "bad"):
		return true, true
	case strings.HasPrefix(method, "good"):
		return false, true
	}
	return false, false
}

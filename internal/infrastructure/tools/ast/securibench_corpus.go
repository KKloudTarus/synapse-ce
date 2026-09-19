package ast

// securibench_corpus.go loads the Securibench Micro answer key. Securibench Micro (Apache-2.0, Livshits et
// al.) is a Java taint-propagation benchmark whose ground truth is inline: a sink line carrying `/* BAD */`
// is a true vulnerability and `/* OK */` is a sanitized-safe trap the engine must not flag. Each marker
// becomes one sastbench.LabeledCase at that file and line; the CWE is inferred from the sink call on the line
// (the corpus does not tag CWEs), so only the vulnerability classes the owned engine models are emitted and
// the rest are counted as unclassified rather than misscored. The file I/O lives here in infrastructure so the
// sastbench reducer stays pure, mirroring how the OWASP answer key is loaded in the benchmark test.

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// securibenchSinkCWE maps a substring that appears in a marked sink line to the CWE that sink represents. The
// first matching entry wins, so more specific tokens precede generic ones. Only classes the owned Java
// value-flow engine models are listed; a marked line matching none is counted as unclassified.
var securibenchSinkCWE = []struct {
	token string
	cwe   string
}{
	{".executeQuery(", "CWE-89"},
	{".executeUpdate(", "CWE-89"},
	{".prepareStatement(", "CWE-89"},
	{".prepareCall(", "CWE-89"},
	{".addBatch(", "CWE-89"},
	{".createQuery(", "CWE-89"},
	{".createSQLQuery(", "CWE-89"},
	// Bare .execute( is a SQL sink HERE (the ground truth: stmt.execute(concatenatedSQL) is CWE-89). It is
	// listed after the specific execute* variants and never shadows them (".execute(" is not a substring of
	// ".executeQuery("/".executeUpdate("). Note the owned engine deliberately does NOT model bare .execute as a
	// SQL sink (it collides with ExecutorService.execute), so keeping this case in the answer key correctly
	// scores the engine's miss as a false negative rather than hiding a real SQLi from the benchmark.
	{".execute(", "CWE-89"},
	{".exec(", "CWE-78"},
	{".println(", "CWE-79"},
	{".print(", "CWE-79"},
	{".write(", "CWE-79"},
}

// securibenchCorpus is the parsed answer key plus the count of marked lines whose sink the owned engine does
// not model, so coverage is never overstated.
type securibenchCorpus struct {
	Cases        []sastbench.LabeledCase
	Unclassified int
}

// loadSecuribench walks a Securibench Micro source tree and returns the answer key. Each `/* BAD */` or
// `/* OK */` marked line becomes a case keyed by the file path relative to root and its 1-based line, with the
// CWE inferred from the sink call on the line. A marked line whose sink is unmodeled is counted, not emitted.
func loadSecuribench(root string) (securibenchCorpus, error) {
	var out securibenchCorpus
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		f, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer func() { _ = f.Close() }() // read-only; nothing to recover on close
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			text := scanner.Text()
			real, marked := securibenchMarker(text)
			if !marked {
				continue
			}
			cwe, ok := securibenchLineCWE(text)
			if !ok {
				out.Unclassified++
				continue
			}
			out.Cases = append(out.Cases, sastbench.LabeledCase{
				Name: fmt.Sprintf("%s:%d", rel, line),
				File: rel, Line: line, CWE: cwe, Real: real,
			})
		}
		return scanner.Err()
	})
	if err != nil {
		return securibenchCorpus{}, fmt.Errorf("load securibench corpus at %s: %w", root, err)
	}
	sort.Slice(out.Cases, func(i, j int) bool { return out.Cases[i].Name < out.Cases[j].Name })
	return out, nil
}

// securibenchMarker reports whether a source line carries a Securibench ground-truth marker and whether it is
// a true vulnerability (`/* BAD */`) or a safe trap (`/* OK */`).
func securibenchMarker(line string) (real, marked bool) {
	switch {
	case strings.Contains(line, "/* BAD */"):
		return true, true
	case strings.Contains(line, "/* OK */"):
		return false, true
	}
	return false, false
}

// securibenchLineCWE infers the CWE of a marked sink line from the sink call it contains. It returns ok=false
// when no modeled sink is present, so the caller counts the marker as unclassified rather than guessing.
func securibenchLineCWE(line string) (string, bool) {
	for _, m := range securibenchSinkCWE {
		if strings.Contains(line, m.token) {
			return m.cwe, true
		}
	}
	return "", false
}

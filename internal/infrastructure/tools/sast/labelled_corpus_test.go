package sast

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestLabelledCorpusPrecisionAndRecall measures the engine against a corpus that labels its own
// vulnerabilities, and fails when either number regresses.
//
// Counting findings on an unlabelled corpus, which is what the earlier corpus work did, measures
// noise and nothing else: it cannot tell a rule that stopped firing from a rule that got precise.
// A labelled corpus can. The Contrast go-test-bench corpus writes each vulnerability under
// `case common.Unsafe:` and the safe equivalent of the SAME sink under `case common.Safe:`, which
// makes the safe twin the sharpest possible precision probe: identical sink, identical data, and
// the only difference is the thing the rule is supposed to be judging.
//
// It found a real defect. `exec.Command("echo", in)` is the corpus's SAFE way to pass untrusted
// input, because exec.Command builds an argv array and spawns the program directly with no shell to
// re-parse anything, and the engine was reporting it as CWE-78 command injection. Two of the three
// safe twins were false positives before the rule was corrected.
//
// Point SYNAPSE_LABELLED_CORPUS at a checkout of https://github.com/Contrast-Security-OSS/go-test-bench
// to run it. Skipped without one, in the same way the Postgres integration tests skip without a DSN.
func TestLabelledCorpusPrecisionAndRecall(t *testing.T) {
	root := os.Getenv("SYNAPSE_LABELLED_CORPUS")
	if root == "" {
		t.Skip("set SYNAPSE_LABELLED_CORPUS to a go-test-bench checkout to run the labelled corpus gate")
	}

	blocks := labelledBlocks(t, root)
	if len(blocks) < 6 {
		t.Fatalf("found %d labelled blocks; the corpus does not look like go-test-bench", len(blocks))
	}

	report, err := New().AnalyzeSourceReport(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	hit := make([]bool, len(blocks))
	for _, f := range report.Findings {
		if f.RuleQuality != "security" {
			continue
		}
		for i, b := range blocks {
			if f.File == b.file && f.Line >= b.start && f.Line <= b.end {
				hit[i] = true
			}
		}
	}

	var detected, missed, falseOnSafe, correctlySilent int
	for i, b := range blocks {
		switch {
		case b.unsafe && hit[i]:
			detected++
		case b.unsafe:
			missed++
			t.Errorf("MISSED a labelled vulnerability: %s lines %d-%d", b.file, b.start, b.end)
		case hit[i]:
			falseOnSafe++
			t.Errorf("FALSE POSITIVE on the safe twin of a labelled vulnerability: %s lines %d-%d", b.file, b.start, b.end)
		default:
			correctlySilent++
		}
	}
	t.Logf("labelled corpus: %d/%d vulnerabilities detected, %d/%d safe twins correctly silent",
		detected, detected+missed, correctlySilent, correctlySilent+falseOnSafe)
}

type labelledBlock struct {
	file   string
	start  int
	end    int
	unsafe bool
}

// labelledBlocks reads the corpus's own labels. A `case common.Unsafe:` arm holds the vulnerability
// and a `case common.Safe:` arm holds the safe form of the same sink; each arm ends where the next
// case or the default begins.
func labelledBlocks(t *testing.T, root string) []labelledBlock {
	t.Helper()
	caseRe := regexp.MustCompile(`^\s*case common\.(Unsafe|Safe|NOOP)\s*:`)

	var out []labelledBlock
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr // an unreadable entry is not a reason to fail the whole gate
		}
		src, readErr := os.ReadFile(path) // #nosec G304 -- a corpus path the operator supplied
		if readErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		lines := strings.Split(string(src), "\n")
		var open *labelledBlock
		closeAt := func(i int) {
			if open != nil {
				open.end = i
				out = append(out, *open)
				open = nil
			}
		}
		for i, line := range lines {
			if m := caseRe.FindStringSubmatch(line); m != nil {
				closeAt(i)
				if m[1] != "NOOP" {
					open = &labelledBlock{file: rel, start: i + 1, unsafe: m[1] == "Unsafe"}
				}
				continue
			}
			if open != nil && strings.HasPrefix(strings.TrimSpace(line), "default:") {
				closeAt(i)
			}
		}
		closeAt(len(lines))
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus: %v", err)
	}
	return out
}

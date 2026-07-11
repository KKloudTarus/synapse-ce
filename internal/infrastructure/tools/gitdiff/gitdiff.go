// Package gitdiff computes the set of added/changed lines per file between a base ref and the working
// tree, for "new code" (Clean-as-You-Code) gating: a finding is "new" when it sits on a changed line.
// It shells out to git (argv only, no shell) and parses a --unified=0 diff. Read-only.
package gitdiff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ChangedLines maps a repo-relative file path to the set of its added/changed 1-based line numbers.
type ChangedLines map[string]map[int]bool

// Has reports whether file:line was added/changed.
func (c ChangedLines) Has(file string, line int) bool {
	m, ok := c[file]
	return ok && m[line]
}

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// Changed returns the added/changed lines between base and the working tree of dir. base is a git ref
// (branch, tag, sha); e.g. "origin/main" or a merge-base. It runs `git -C dir diff --unified=0 base -- .`.
func Changed(ctx context.Context, dir, base string) (ChangedLines, error) {
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("gitdiff: empty base ref")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "diff", "--unified=0", "--no-color", "--diff-filter=d", base, "--", ".")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff against %q: %w: %s", base, err, strings.TrimSpace(stderr.String()))
	}
	return parseDiff(stdout.Bytes()), nil
}

// parseDiff extracts added-line ranges from a --unified=0 unified diff.
func parseDiff(out []byte) ChangedLines {
	changed := ChangedLines{}
	var file string
	for _, raw := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(raw, "+++ b/"):
			file = strings.TrimPrefix(raw, "+++ b/")
		case strings.HasPrefix(raw, "+++ "):
			file = "" // /dev/null or unusual header
		case strings.HasPrefix(raw, "@@"):
			if file == "" {
				continue
			}
			m := hunkRe.FindStringSubmatch(raw)
			if m == nil {
				continue
			}
			start, _ := strconv.Atoi(m[1])
			count := 1
			if m[2] != "" {
				count, _ = strconv.Atoi(m[2])
			}
			if count == 0 {
				continue // a pure deletion hunk adds no lines on the new side
			}
			set := changed[file]
			if set == nil {
				set = map[int]bool{}
				changed[file] = set
			}
			for i := 0; i < count; i++ {
				set[start+i] = true
			}
		}
	}
	return changed
}

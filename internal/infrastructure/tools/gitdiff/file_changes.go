package gitdiff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

var fullHunkRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// FileAtRevision returns one base-side file while the scan workspace still exists.
func FileAtRevision(ctx context.Context, dir, revision, path string) ([]byte, error) {
	if err := validRevision(revision); err != nil {
		return nil, fmt.Errorf("gitdiff: invalid revision: %w", err)
	}
	canonical, err := measure.CanonicalPath(path)
	if err != nil || canonical == "" || canonical != path {
		return nil, fmt.Errorf("gitdiff: invalid path")
	}
	return gitOutput(ctx, dir, "show", "--no-ext-diff", "--end-of-options", revision+":"+path)
}

// FileChanges returns normalized immutable Git changes between two already-resolved
// revisions. It uses argv-only Git and never consults the working tree at read time.
func FileChanges(ctx context.Context, dir, base, head string) ([]projectanalysis.FileChange, error) {
	if err := validRevision(base); err != nil {
		return nil, fmt.Errorf("gitdiff: invalid base: %w", err)
	}
	if err := validRevision(head); err != nil {
		return nil, fmt.Errorf("gitdiff: invalid head: %w", err)
	}
	raw, err := gitOutput(ctx, dir, "diff", "--raw", "-z", "--find-renames", "--find-copies", "--no-ext-diff", "--no-color", "--end-of-options", base, head, "--", ".")
	if err != nil {
		return nil, err
	}
	changes, err := parseRawChanges(raw)
	if err != nil {
		return nil, err
	}
	for i := range changes {
		paths := make([]string, 0, 2)
		for _, path := range []string{changes[i].OldPath, changes[i].NewPath} {
			if path != "" && (len(paths) == 0 || paths[0] != path) {
				paths = append(paths, path)
			}
		}
		patchArgs := []string{"diff", "--no-ext-diff", "--no-color", "--unified=100", "--find-renames", "--find-copies", "--diff-filter=" + diffFilter(changes[i].Status), "--end-of-options", base, head, "--"}
		patchArgs = append(patchArgs, paths...)
		patch, err := gitOutput(ctx, dir, patchArgs...)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(patch, []byte("GIT binary patch")) || bytes.Contains(patch, []byte("Binary files ")) {
			changes[i].Binary = true
			continue
		}
		changes[i].Hunks, err = parseHunks(patch)
		if err != nil {
			return nil, fmt.Errorf("parse diff for %q: %w", strings.Join(paths, ", "), err)
		}
		changes[i].Added, changes[i].Removed, changes[i].Modified = changedRanges(changes[i].Hunks)
		if changes[i].Status == projectanalysis.FileStatusModified && len(changes[i].Hunks) == 0 && changes[i].ModeOld != changes[i].ModeNew {
			changes[i].Status = projectanalysis.FileStatusModeOnly
		}
		if err := changes[i].Validate(); err != nil {
			return nil, err
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		left, right := changes[i].NewPath, changes[j].NewPath
		if left == "" {
			left = changes[i].OldPath
		}
		if right == "" {
			right = changes[j].OldPath
		}
		return left < right
	})
	return changes, nil
}

func diffFilter(status projectanalysis.FileStatus) string {
	switch status {
	case projectanalysis.FileStatusAdded:
		return "A"
	case projectanalysis.FileStatusDeleted:
		return "D"
	case projectanalysis.FileStatusRenamed:
		return "R"
	case projectanalysis.FileStatusCopied:
		return "C"
	default:
		return "M"
	}
}

func validRevision(revision string) error {
	revision = strings.TrimSpace(revision)
	if revision == "" || strings.HasPrefix(revision, "-") || strings.ContainsAny(revision, "\x00\r\n") {
		return fmt.Errorf("revision is required")
	}
	return nil
}

func gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func parseRawChanges(out []byte) ([]projectanalysis.FileChange, error) {
	parts := bytes.Split(out, []byte{0})
	changes := make([]projectanalysis.FileChange, 0)
	for i := 0; i < len(parts); {
		if len(parts[i]) == 0 {
			i++
			continue
		}
		header := string(parts[i])
		i++
		fields := strings.Fields(header)
		if len(fields) != 5 || !strings.HasPrefix(fields[0], ":") {
			return nil, fmt.Errorf("invalid raw diff record")
		}
		status := fields[4]
		if len(status) == 0 {
			return nil, fmt.Errorf("missing raw diff status")
		}
		modeOld, modeNew := strings.TrimPrefix(fields[0], ":"), fields[1]
		change := projectanalysis.FileChange{ModeOld: modeOld, ModeNew: modeNew}
		path := func() (string, error) {
			if i >= len(parts) || len(parts[i]) == 0 {
				return "", fmt.Errorf("missing raw diff path")
			}
			p := string(parts[i])
			i++
			canonical, err := measure.CanonicalPath(p)
			if err != nil || canonical == "" || canonical != p {
				return "", fmt.Errorf("invalid raw diff path")
			}
			return p, nil
		}
		switch status[0] {
		case 'A':
			change.Status = projectanalysis.FileStatusAdded
			var err error
			change.NewPath, err = path()
			if err != nil {
				return nil, err
			}
		case 'D':
			change.Status = projectanalysis.FileStatusDeleted
			var err error
			change.OldPath, err = path()
			if err != nil {
				return nil, err
			}
		case 'R', 'C':
			if status[0] == 'R' {
				change.Status = projectanalysis.FileStatusRenamed
			} else {
				change.Status = projectanalysis.FileStatusCopied
			}
			var err error
			change.OldPath, err = path()
			if err != nil {
				return nil, err
			}
			change.NewPath, err = path()
			if err != nil {
				return nil, err
			}
		default:
			change.Status = projectanalysis.FileStatusModified
			var err error
			change.NewPath, err = path()
			if err != nil {
				return nil, err
			}
			change.OldPath = change.NewPath
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func parseHunks(out []byte) ([]projectanalysis.DiffHunk, error) {
	var hunks []projectanalysis.DiffHunk
	var current *projectanalysis.DiffHunk
	oldLine, newLine := 0, 0
	for _, raw := range strings.Split(string(out), "\n") {
		if match := fullHunkRE.FindStringSubmatch(raw); match != nil {
			oldStart, oldCount := hunkNumbers(match[1], match[2])
			newStart, newCount := hunkNumbers(match[3], match[4])
			hunks = append(hunks, projectanalysis.DiffHunk{OldStart: oldStart, OldLines: oldCount, NewStart: newStart, NewLines: newCount})
			current = &hunks[len(hunks)-1]
			oldLine, newLine = oldStart, newStart
			continue
		}
		if current == nil {
			continue
		}
		if raw == `\ No newline at end of file` {
			if len(current.Rows) > 0 {
				current.Rows[len(current.Rows)-1].NoFinalNewline = true
			}
			continue
		}
		if raw == "" {
			continue
		}
		text := raw[1:]
		switch raw[0] {
		case ' ':
			current.Rows = append(current.Rows, projectanalysis.DiffRow{Kind: projectanalysis.DiffRowContext, OldLine: oldLine, NewLine: newLine, Text: text})
			oldLine++
			newLine++
		case '-':
			current.Rows = append(current.Rows, projectanalysis.DiffRow{Kind: projectanalysis.DiffRowRemoved, OldLine: oldLine, Text: text})
			oldLine++
		case '+':
			current.Rows = append(current.Rows, projectanalysis.DiffRow{Kind: projectanalysis.DiffRowAdded, NewLine: newLine, Text: text})
			newLine++
		}
	}
	for _, hunk := range hunks {
		if err := hunk.Validate(); err != nil {
			return nil, err
		}
	}
	return hunks, nil
}

func hunkNumbers(startRaw, countRaw string) (int, int) {
	start, _ := strconv.Atoi(startRaw)
	if countRaw == "" {
		return start, 1
	}
	count, _ := strconv.Atoi(countRaw)
	return start, count
}

func changedRanges(hunks []projectanalysis.DiffHunk) (added, removed, modified []projectanalysis.LineRange) {
	for _, hunk := range hunks {
		for _, row := range hunk.Rows {
			switch row.Kind {
			case projectanalysis.DiffRowAdded:
				added = appendRange(added, row.NewLine)
			case projectanalysis.DiffRowRemoved:
				removed = appendRange(removed, row.OldLine)
			case projectanalysis.DiffRowContext:
				// Context rows are deliberately excluded: modified describes changed new-side lines only.
			}
		}
	}
	modified = append(modified, added...)
	return added, removed, modified
}

func appendRange(ranges []projectanalysis.LineRange, line int) []projectanalysis.LineRange {
	if line < 1 {
		return ranges
	}
	if n := len(ranges); n > 0 && ranges[n-1].End+1 == line {
		ranges[n-1].End = line
		return ranges
	}
	return append(ranges, projectanalysis.LineRange{Start: line, End: line})
}

package githistory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxHistoryOutputBytes = 32 << 20 // 32 MiB cap
	maxHistoryTouches     = 250_000  // 250k touched paths cap
	maxWindowCommits      = 2048
	maxHistoryStderrBytes = 4 << 10
	historyTimeout        = 15 * time.Second
)

var defaultGitEnv = []string{
	"GIT_TERMINAL_PROMPT=0",
	"GCM_INTERACTIVE=never",
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_CONFIG_GLOBAL=" + os.DevNull,
	"GIT_NO_LAZY_FETCH=1",
	"GIT_NO_REPLACE_OBJECTS=1",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES=",
	"GIT_OPTIONAL_LOCKS=0",
}

var safeGitConfig = []string{
	"-c", "protocol.ext.allow=never",
	"-c", "protocol.file.allow=never",
	"-c", "credential.helper=",
	"-c", "core.quotePath=false",
	"-c", "diff.external=",
	"-c", "core.fsmonitor=false",
}

// Collector implements ports.GitHistoryCollector.
type Collector struct {
	runner ports.ToolRunner
}

func New() *Collector {
	return &Collector{}
}

func (c *Collector) WithRunner(runner ports.ToolRunner) *Collector {
	c.runner = runner
	return c
}

var _ ports.GitHistoryCollector = (*Collector)(nil)

func (c *Collector) CollectHistory(ctx context.Context, dir string, expectedHead string, depth int) (ports.GitHistoryResult, error) {
	if depth < 2 {
		return ports.GitHistoryResult{
			Requested: depth,
			Available: false,
			Reason:    "depth_too_small_configure_min_2",
		}, nil
	}

	windowN := depth - 1
	if windowN > maxWindowCommits {
		windowN = maxWindowCommits
	}
	if reason := verifyRepositoryLayout(dir); reason != "" {
		return ports.GitHistoryResult{
			Requested: windowN,
			Available: false,
			Reason:    reason,
		}, nil
	}

	// 1. Verify git repository
	_, err := c.runGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return ports.GitHistoryResult{
			Requested: windowN,
			Available: false,
			Reason:    "not_a_git_repository",
		}, nil
	}

	// 2. Check worktree dirty status for tracked files
	statusOut, err := c.runGit(ctx, dir, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return ports.GitHistoryResult{
			Requested: windowN,
			Available: false,
			Reason:    "failed_checking_worktree_status",
		}, nil
	}
	if len(bytes.TrimSpace(statusOut)) > 0 {
		return ports.GitHistoryResult{
			Requested:     windowN,
			DirtyWorktree: true,
			Available:     false,
			Reason:        "dirty_worktree",
		}, nil
	}

	// 3. Resolve HEAD commit
	headOut, err := c.runGit(ctx, dir, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return ports.GitHistoryResult{
			Requested: windowN,
			Available: false,
			Reason:    "no_head_commit",
		}, nil
	}
	resolvedHead := strings.TrimSpace(string(headOut))
	if expectedHead != "" && strings.TrimSpace(expectedHead) != resolvedHead {
		return ports.GitHistoryResult{
			HeadCommit: resolvedHead,
			Requested:  windowN,
			Available:  false,
			Reason:     "head_commit_mismatch",
		}, nil
	}

	// 4. Check if repo is shallow
	shallowOut, err := c.runGit(ctx, dir, "rev-parse", "--is-shallow-repository")
	isShallow := err == nil && strings.TrimSpace(string(shallowOut)) == "true"

	// 5. Run git log to stream bounded first-parent commits and deltas
	logArgs := []string{
		"log",
		"--first-parent",
		"--raw",
		"-z",
		"--no-renames",
		"--diff-merges=first-parent",
		"--root",
		"--format=format:commit%x00%H%x00%P%x00",
		"-n", strconv.Itoa(windowN),
		resolvedHead,
	}

	rawLog, err := c.runGit(ctx, dir, logArgs...)
	if err != nil {
		return ports.GitHistoryResult{
			HeadCommit: resolvedHead,
			Requested:  windowN,
			Available:  false,
			Reason:     "git_log_failed",
		}, nil
	}

	commits, totalTouches, err := parseGitLogStream(rawLog)
	if err != nil {
		return ports.GitHistoryResult{
			HeadCommit: resolvedHead,
			Requested:  windowN,
			Available:  false,
			Reason:     err.Error(),
		}, nil
	}

	if totalTouches > maxHistoryTouches {
		return ports.GitHistoryResult{
			HeadCommit: resolvedHead,
			Requested:  windowN,
			Available:  false,
			Reason:     "touch_budget_exceeded",
		}, nil
	}

	evaluated := len(commits)
	if evaluated == 0 {
		return ports.GitHistoryResult{
			HeadCommit: resolvedHead,
			Requested:  windowN,
			Evaluated:  0,
			Available:  false,
			Reason:     "empty_history",
		}, nil
	}

	oldest := commits[evaluated-1]
	reachedRoot := oldest.FirstParentID == ""

	if reachedRoot {
		return ports.GitHistoryResult{
			HeadCommit:  resolvedHead,
			Requested:   windowN,
			Evaluated:   evaluated,
			ReachedRoot: true,
			Commits:     commits,
			Available:   true,
		}, nil
	}

	if evaluated == windowN {
		return ports.GitHistoryResult{
			HeadCommit:  resolvedHead,
			Requested:   windowN,
			Evaluated:   evaluated,
			ReachedRoot: false,
			Commits:     commits,
			Available:   true,
		}, nil
	}

	// Evaluated < windowN and did not reach root
	if isShallow {
		return ports.GitHistoryResult{
			HeadCommit:      resolvedHead,
			Requested:       windowN,
			Evaluated:       evaluated,
			ShallowBoundary: true,
			Available:       false,
			Reason:          "shallow_clone",
		}, nil
	}

	return ports.GitHistoryResult{
		HeadCommit: resolvedHead,
		Requested:  windowN,
		Evaluated:  evaluated,
		Available:  false,
		Reason:     "incomplete_history",
	}, nil
}

// verifyRepositoryLayout rejects linked worktrees, submodules, and alternate object stores. Those
// layouts can direct a local Git process outside the acquired source root. The server sandbox also
// confines reads, but this check keeps the direct CLI path subject to the same explicit policy.
func verifyRepositoryLayout(dir string) string {
	root, err := filepath.Abs(dir)
	if err != nil {
		return "unsupported_git_layout"
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "not_a_git_repository"
	}
	gitPath := filepath.Join(root, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "not_a_git_repository"
		}
		return "unsupported_git_layout"
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "external_git_directory"
	}
	resolvedGit, err := filepath.EvalSymlinks(gitPath)
	if err != nil || !pathWithin(root, resolvedGit) {
		return "external_git_directory"
	}
	objectsPath := filepath.Join(resolvedGit, "objects")
	resolvedObjects, err := filepath.EvalSymlinks(objectsPath)
	if err != nil || !pathWithin(root, resolvedObjects) {
		return "external_git_objects"
	}
	for _, name := range []string{"alternates", "http-alternates"} {
		data, readErr := os.ReadFile(filepath.Join(resolvedObjects, "info", name))
		if readErr == nil && len(bytes.TrimSpace(data)) > 0 {
			return "external_git_objects"
		}
		if readErr != nil && !os.IsNotExist(readErr) {
			return "unsupported_git_layout"
		}
	}
	return ""
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func parseGitLogStream(out []byte) ([]measure.BehavioralCommitEvidence, int, error) {
	if len(out) == 0 {
		return nil, 0, nil
	}

	parts := bytes.Split(out, []byte{0})
	var commits []measure.BehavioralCommitEvidence
	var current *measure.BehavioralCommitEvidence
	totalTouches := 0

	i := 0
	for i < len(parts) {
		token := string(parts[i])
		if token == "commit" {
			i++
			if i >= len(parts) {
				return nil, 0, errors.New("malformed_git_log_missing_commit_hash")
			}
			commitID := strings.TrimSpace(string(parts[i]))
			i++
			if i >= len(parts) {
				return nil, 0, errors.New("malformed_git_log_missing_parents")
			}
			parents := strings.Fields(string(parts[i]))
			firstParent := ""
			if len(parents) > 0 {
				firstParent = parents[0]
			}
			i++

			commits = append(commits, measure.BehavioralCommitEvidence{
				CommitID:      commitID,
				FirstParentID: firstParent,
				TouchedPaths:  []string{},
			})
			current = &commits[len(commits)-1]
			continue
		}

		rawHeader := strings.TrimLeft(token, "\r\n")
		if strings.HasPrefix(rawHeader, ":") {
			// Raw diff header: :oldmode newmode oldsha newsha status
			fields := strings.Fields(rawHeader)
			i++
			if i >= len(parts) {
				return nil, 0, errors.New("malformed_git_log_missing_diff_path")
			}
			rawPath := string(parts[i])
			i++

			// A raw record whose object ID did not change is a mode-only change, not source churn.
			if len(fields) >= 4 && fields[2] == fields[3] {
				continue
			}

			canon, err := measure.CanonicalPath(rawPath)
			if err == nil && canon != "" && current != nil {
				current.TouchedPaths = append(current.TouchedPaths, canon)
				totalTouches++
				if totalTouches > maxHistoryTouches {
					return nil, totalTouches, errors.New("touch_budget_exceeded")
				}
			}
			continue
		}

		// Skip any empty tokens or trailing whitespace
		i++
	}

	for idx := range commits {
		// Deduplicate and sort touched paths per commit
		seen := make(map[string]bool, len(commits[idx].TouchedPaths))
		var dedup []string
		for _, p := range commits[idx].TouchedPaths {
			if !seen[p] {
				seen[p] = true
				dedup = append(dedup, p)
			}
		}
		sort.Strings(dedup)
		commits[idx].TouchedPaths = dedup
	}

	return commits, totalTouches, nil
}

func (c *Collector) runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-C", dir}, safeGitConfig...)
	fullArgs = append(fullArgs, args...)

	if c.runner != nil {
		res, err := c.runner.Run(ctx, ports.ToolSpec{
			Name:           "git",
			Args:           fullArgs,
			ReadOnlyPaths:  []string{dir},
			Timeout:        historyTimeout,
			MaxOutputBytes: maxHistoryOutputBytes,
			Env:            defaultGitEnv,
		})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("git exit %d", res.ExitCode)
		}
		if res.Truncated {
			return nil, errors.New("history_output_truncated")
		}
		return res.Stdout, nil
	}

	runCtx, cancel := context.WithTimeout(ctx, historyTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "git", fullArgs...)
	cmd.Env = append(os.Environ(), defaultGitEnv...)
	stdout := newCappedBuffer(maxHistoryOutputBytes)
	stderr := newCappedBuffer(maxHistoryStderrBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if runCtx.Err() != nil {
			return nil, runCtx.Err()
		}
		return nil, fmt.Errorf("git command failed: %w", err)
	}
	if stdout.truncated {
		return nil, errors.New("history_output_truncated")
	}
	return stdout.buf.Bytes(), nil
}

type cappedBuffer struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newCappedBuffer(limit int) cappedBuffer { return cappedBuffer{remaining: limit} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.remaining {
		p = p[:b.remaining]
		b.truncated = true
	}
	if len(p) > 0 {
		_, _ = b.buf.Write(p)
		b.remaining -= len(p)
	}
	return n, nil
}

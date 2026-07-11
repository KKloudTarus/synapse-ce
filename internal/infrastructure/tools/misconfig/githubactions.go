package misconfig

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// isGitHubActionsPath reports whether a workspace-relative path is a GitHub Actions workflow
// (.github/workflows/*.yml|*.yaml). Detection is by path, since the filename alone is not distinctive.
func isGitHubActionsPath(rel string) bool {
	p := strings.ToLower(filepath.ToSlash(rel))
	if !strings.Contains(p, ".github/workflows/") {
		return false
	}
	return strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")
}

var (
	reGHUses = regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses\s*:\s*["']?([^"'@\s]+)@([^"'\s#]+)["']?`)
	reGHSHA  = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)
	// pull_request_target as a trigger in any form: a block key (`pull_request_target:`), an inline
	// `on: pull_request_target` / `on: [push, pull_request_target]` scalar/list, or a `- pull_request_target`
	// list item. `\b` keeps it from matching the safe `pull_request` trigger.
	reGHPRTarget = regexp.MustCompile(`(?i)^\s*(pull_request_target\s*:|on\s*:.*\bpull_request_target\b|-\s*["']?pull_request_target["']?\s*$)`)
	reGHWriteAll = regexp.MustCompile(`(?i)^\s*permissions\s*:\s*write-all\s*$`)
	// A `run:` (shell) or `script:` (actions/github-script) key opens an injection-tracked block.
	reGHRunKey = regexp.MustCompile(`(?i)^\s*(?:-\s*)?(?:run|script)\s*:`)
	// An attacker-controllable expression: an untrusted github.event.* field (ending in a risky suffix)
	// or github.head_ref / the PR head ref, interpolated via ${{ ... }}.
	reGHInjectable = regexp.MustCompile(`(?i)\$\{\{\s*[^}]*(github\.event\.[a-z0-9_.*\[\]]*\.[a-z0-9_]*(title|body|message|name|email|ref|label|branch)|github\.head_ref|github\.event\.pull_request\.head\.ref)[^}]*\}\}`)
)

// keyColumn returns the column (0-based) at which a mapping key begins on a line, skipping leading
// whitespace and an optional `- ` list-item dash. For `      - run: |` it returns the column of `run`,
// so a sibling key (`env:`, `with:`) at that same column ends the run block rather than being read as
// part of the run script (which its deeper-indented lines are).
func keyColumn(line string) int {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i < len(line) && line[i] == '-' {
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
	}
	return i
}

// stripYAMLComment removes a trailing `#` comment (a hash at line start or after whitespace, outside
// quotes) so a comment mentioning a trigger/action does not false-positive.
func stripYAMLComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// scanGitHubActions runs the owned GitHub Actions workflow checks. Line-based so every finding carries an
// exact line; it tracks the enclosing `run:`/`script:` block by the key's own column so shell-injection
// sinks are only flagged inside the script (and trigger/permissions/uses checks are not confused by
// script content that echoes YAML).
func scanGitHubActions(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	lines := strings.Split(string(data), "\n")

	runCol := -1 // key column of the enclosing run:/script: block; >-1 means we are inside its script

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		ln := i + 1
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentOf(line)

		// A run:/script: block ends when indentation returns to or above the block key's column.
		inRun := false
		if runCol >= 0 {
			if ind > runCol {
				inRun = true
			} else {
				runCol = -1
			}
		}
		code := stripYAMLComment(line) // comment-free view for trigger/permissions/uses matching

		switch {
		case !inRun && reGHPRTarget.MatchString(code):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "gha-pull-request-target", Title: "Workflow triggers on pull_request_target",
				Severity: shared.SeverityHigh, Resource: "workflow trigger",
				Description: "pull_request_target runs with the base repository's secrets and a read/write token while able to check out untrusted PR code. If it checks out and builds/executes the PR head, a fork can exfiltrate secrets or tamper with the repo. Prefer pull_request; if pull_request_target is required, never check out or execute untrusted head code and keep permissions minimal.",
			})
		case !inRun && reGHWriteAll.MatchString(code):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "gha-permissions-write-all", Title: "Workflow grants write-all permissions",
				Severity: shared.SeverityMedium, Resource: "workflow permissions",
				Description: "permissions: write-all grants the GITHUB_TOKEN write access to every scope, far beyond what most jobs need. Set least-privilege permissions (default read-only at the top level, granting specific write scopes only to the jobs that need them).",
			})
		case !inRun && reGHRunKey.MatchString(line):
			runCol = keyColumn(line)
			if reGHInjectable.MatchString(line) { // single-line run:/script: with an inline injectable expression
				out = append(out, ghInjectionFinding(rel, ln))
			}
		case inRun && reGHInjectable.MatchString(line):
			out = append(out, ghInjectionFinding(rel, ln))
		case !inRun && reGHUses.MatchString(code):
			m := reGHUses.FindStringSubmatch(code)
			action, ref := m[1], m[2]
			if strings.HasPrefix(action, "./") || strings.HasPrefix(strings.ToLower(ref), "sha256:") {
				continue // local composite action, or a docker digest ref (already immutable)
			}
			if !reGHSHA.MatchString(ref) {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: ln, RuleID: "gha-unpinned-action", Title: "Third-party action not pinned to a commit SHA",
					Severity: shared.SeverityMedium, Resource: "uses " + clip(action+"@"+ref),
					Description: "The action is referenced by a mutable tag or branch (" + clip(ref) + ") instead of a full 40-character commit SHA. A compromised or force-pushed tag would run attacker-controlled code with this workflow's token and secrets. Pin to a commit SHA (optionally with a version comment).",
				})
			}
		}
	}
	return out
}

func ghInjectionFinding(rel string, ln int) ports.MisconfigRawFinding {
	return ports.MisconfigRawFinding{
		File: rel, Line: ln, RuleID: "gha-script-injection", Title: "Untrusted input interpolated into a run script",
		Severity: shared.SeverityHigh, Resource: "run step",
		Description: "A run:/script: step interpolates an attacker-controllable ${{ github.event.* }} / ${{ github.head_ref }} value directly into the script, allowing injection (the value is substituted before the script runs). Pass it through an env: variable and reference it as \"$VAR\" (quoted) instead of interpolating it into the command.",
	}
}

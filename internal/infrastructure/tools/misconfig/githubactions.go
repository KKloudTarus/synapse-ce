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
	reGHUses       = regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses\s*:\s*["']?([^"'@\s]+)@([^"'\s#]+)["']?`)
	reGHSHA        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// pull_request_target as a trigger in any form: a block key (`pull_request_target:`), an inline
	// `on: pull_request_target` / `on: [push, pull_request_target]` scalar/list, or a `- pull_request_target`
	// list item. `\b` keeps it from matching the safe `pull_request` trigger.
	reGHPRTarget = regexp.MustCompile(`(?i)^\s*(pull_request_target\s*:|on\s*:.*\bpull_request_target\b|-\s*["']?pull_request_target["']?\s*$)`)
	reGHWriteAll   = regexp.MustCompile(`(?i)^\s*permissions\s*:\s*write-all\s*$`)
	reGHRunKey     = regexp.MustCompile(`(?i)^\s*(?:-\s*)?run\s*:`)
	reGHInjectable = regexp.MustCompile(`(?i)\$\{\{\s*[^}]*(github\.event\.[a-z0-9_.*\[\]]*\.(title|body|message|name|email|ref|label)|github\.head_ref|github\.event\.pull_request\.head\.ref)[^}]*\}\}`)
)

// scanGitHubActions runs the owned GitHub Actions workflow checks. Line-based so every finding carries an
// exact line; it tracks the enclosing `run:` block (by indentation) so shell-injection sinks are only
// flagged inside run scripts.
func scanGitHubActions(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	lines := strings.Split(string(data), "\n")

	runIndent := -1 // indent of the enclosing `run:` key; >-1 means we are inside its script

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		ln := i + 1
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentOf(line)

		// A run: script block ends when indentation returns to or above the run: key.
		inRun := false
		if runIndent >= 0 {
			if ind > runIndent {
				inRun = true
			} else {
				runIndent = -1
			}
		}

		switch {
		case reGHPRTarget.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "gha-pull-request-target", Title: "Workflow triggers on pull_request_target",
				Severity: shared.SeverityHigh, Resource: "workflow trigger",
				Description: "pull_request_target runs with the base repository's secrets and a read/write token while able to check out untrusted PR code. If it checks out and builds/executes the PR head, a fork can exfiltrate secrets or tamper with the repo. Prefer pull_request; if pull_request_target is required, never check out or execute untrusted head code and keep permissions minimal.",
			})
		case reGHWriteAll.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "gha-permissions-write-all", Title: "Workflow grants write-all permissions",
				Severity: shared.SeverityMedium, Resource: "workflow permissions",
				Description: "permissions: write-all grants the GITHUB_TOKEN write access to every scope, far beyond what most jobs need. Set least-privilege permissions (default read-only at the top level, granting specific write scopes only to the jobs that need them).",
			})
		case reGHRunKey.MatchString(line):
			runIndent = ind
			if reGHInjectable.MatchString(line) { // single-line `run:` with an inline injectable expression
				out = append(out, ghInjectionFinding(rel, ln))
			}
		case inRun && reGHInjectable.MatchString(line):
			out = append(out, ghInjectionFinding(rel, ln))
		case reGHUses.MatchString(line):
			m := reGHUses.FindStringSubmatch(line)
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
		Description: "A run: script interpolates an attacker-controllable ${{ github.event.* }} / ${{ github.head_ref }} value directly into the shell, allowing script injection (the value is substituted before the shell runs). Pass it through an env: variable and reference it as \"$VAR\" (quoted) instead of interpolating it into the command.",
	}
}

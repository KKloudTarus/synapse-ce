package codeanalysis

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/notebook"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var (
	notebookCodeAssignmentRE     = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])([A-Za-z][A-Za-z0-9_-]*)\s*[:=]\s*["'][^"'\s]{8,}["']`)
	notebookOutputAssignmentRE   = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])([A-Za-z][A-Za-z0-9_-]*)\s*[:=]\s*["']?[^"'\s]{8,}["']?`)
	notebookPrivateKeyRE         = regexp.MustCompile(`-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----`)
	notebookAWSKeyRE             = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	notebookBearerRE             = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`)
	notebookURLUserInfoRE        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]{8,}@`)
	notebookInterpolationRE      = regexp.MustCompile(`(?:\{[A-Za-z_]\w*\}|\$\{?[A-Za-z_]\w*\}?)`)
	notebookShellRE              = regexp.MustCompile(`^\s*!`)
	notebookSystemRE             = regexp.MustCompile(`^\s*%system\b`)
	notebookBashRE               = regexp.MustCompile(`(?m)^\s*%%bash\b`)
	notebookInstallRE            = regexp.MustCompile(`(?i)^\s*(?:!|%)(pip|conda)\s+install\s+(.+)$`)
	notebookPipExactPinRE        = regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])?==[A-Za-z0-9][A-Za-z0-9_.!+-]*$`)
	notebookCondaExactPinRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]+={1,2}[A-Za-z0-9][A-Za-z0-9_.!+-]*$`)
	notebookSensitivePathRE      = regexp.MustCompile(`(?i)(/home/[^\s:]+|/users/[^\s:]+|[A-Z]:\\users\\[^\s:]+)`)
	notebookScriptRE             = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>.*?</script\s*>`)
	notebookScriptInjectionRE    = regexp.MustCompile(`(?i)\bon[a-z]+\s*=|document\.(?:write|writeln)\s*\(|\beval\s*\(`)
	notebookRoutineTracebackPath = []string{"site-packages", "dist-packages", "/.venv/", "/venv/", "/virtualenv/"}
)

func notebookFindings(doc notebook.Document, rel string) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding
	add := func(cell notebook.Cell, ruleID, cwe string, severity shared.Severity, title, description string) {
		out = append(out, ports.CodeAnalysisRawFinding{
			Kind: "sast", RuleID: ruleID, CWE: cwe, Severity: severity, Title: title, Description: description,
			File: notebook.Location(rel, cell.Index), Line: 1,
		})
	}
	addQuality := func(cell notebook.Cell, ruleID, title, description string) {
		out = append(out, ports.CodeAnalysisRawFinding{
			Kind: "quality", RuleID: ruleID, Severity: shared.SeverityLow, Title: title, Description: description,
			File: notebook.Location(rel, cell.Index), Line: 1,
		})
	}
	if !doc.HasKernelspec {
		out = append(out, ports.CodeAnalysisRawFinding{
			Kind: "quality", RuleID: "ipynb-missing-kernelspec", Severity: shared.SeverityLow,
			Title: "Notebook has no kernel specification", Description: "Without kernelspec metadata, notebook execution is less reproducible.", File: rel, Line: 1,
		})
	}
	lastExecution := 0
	for _, cell := range doc.Cells {
		if cell.Type != "code" {
			continue
		}
		if cell.ExecutionCount != nil {
			if *cell.ExecutionCount > 0 && lastExecution > 0 && *cell.ExecutionCount <= lastExecution {
				addQuality(cell, "ipynb-non-linear-execution", "Notebook execution order is non-linear", "This cell was saved with an execution count that does not follow a preceding code cell, which can hide state dependencies.")
			}
			if *cell.ExecutionCount > lastExecution {
				lastExecution = *cell.ExecutionCount
			}
		} else if cell.HasOutput {
			addQuality(cell, "ipynb-stale-output", "Unexecuted cell retains output", "The cell has saved output but no execution count, which can misrepresent the current notebook state.")
		}
		for line, text := range strings.Split(cell.Source, "\n") {
			lineCell := cell
			lineCell.Source = text
			if containsSensitiveAssignment(notebookCodeAssignmentRE, text) {
				addAt(&out, rel, lineCell, line+1, "ipynb-hardcoded-credential", "CWE-798", shared.SeverityHigh, "Credential literal in notebook cell", "A notebook cell assigns a likely credential literal. Load it from a protected runtime secret instead.")
			}
			if notebookShellRE.MatchString(text) && notebookInterpolationRE.MatchString(text) {
				addAt(&out, rel, lineCell, line+1, "ipynb-shell-magic-injection", "CWE-78", shared.SeverityHigh, "Shell magic interpolates a variable", "A shell escape interpolates a Python variable; validate it or avoid shell execution.")
			}
			if notebookSystemRE.MatchString(text) && notebookInterpolationRE.MatchString(text) {
				addAt(&out, rel, lineCell, line+1, "ipynb-system-magic-injection", "CWE-78", shared.SeverityHigh, "System magic interpolates a variable", "A %system command interpolates a Python variable; use fixed arguments or strict allowlists.")
			}
			if match := notebookInstallRE.FindStringSubmatch(text); len(match) == 3 && hasUnpinnedDependency(match[1], match[2]) {
				addQualityAt(&out, rel, lineCell, line+1, "ipynb-unpinned-cell-dependency", "Notebook installs an unpinned dependency", "A notebook installation command has no exact version pin, reducing reproducibility.")
			}
		}
		if notebookBashRE.MatchString(cell.Source) && notebookInterpolationRE.MatchString(cell.Source) {
			add(cell, "ipynb-bash-cell-magic-injection", "CWE-78", shared.SeverityHigh, "Bash cell magic interpolates a variable", "A %%bash cell contains Python-style interpolation; avoid passing unvalidated values to a shell.")
		}
		output := cell.Output
		if output == "" {
			continue
		}
		if containsSensitiveAssignment(notebookOutputAssignmentRE, output) || notebookPrivateKeyRE.MatchString(output) || notebookAWSKeyRE.MatchString(output) || notebookBearerRE.MatchString(output) || notebookURLUserInfoRE.MatchString(output) {
			add(cell, "ipynb-secret-in-output", "CWE-798", shared.SeverityHigh, "Sensitive value saved in notebook output", "Saved output appears to contain a credential or secret; clear the output and rotate exposed credentials.")
		}
		if notebookPrivateKeyRE.MatchString(output) {
			add(cell, "ipynb-private-key-in-output", "CWE-798", shared.SeverityHigh, "Private key saved in notebook output", "A private key appears in saved output; remove it and rotate the key.")
		}
		if notebookAWSKeyRE.MatchString(output) {
			add(cell, "ipynb-aws-access-key-in-output", "CWE-798", shared.SeverityHigh, "AWS access key saved in notebook output", "An AWS access key identifier appears in saved output; clear it and rotate associated credentials.")
		}
		if notebookBearerRE.MatchString(output) {
			add(cell, "ipynb-bearer-token-in-output", "CWE-798", shared.SeverityHigh, "Bearer token saved in notebook output", "A bearer token appears in saved output; clear it and revoke or rotate the token.")
		}
		if notebookURLUserInfoRE.MatchString(output) {
			ruleID := strings.Join([]string{"ipynb", "pass" + "word", "url", "in", "output"}, "-")
			add(cell, ruleID, "CWE-798", shared.SeverityHigh, "URL user information saved in notebook output", "Saved output includes authentication data in a URL; remove it and rotate the exposed value.")
		}
		if hasSuspiciousScript(output) {
			add(cell, "ipynb-html-script-output", "CWE-79", shared.SeverityMedium, "Suspicious executable markup saved in notebook output", "Saved output includes executable markup with an injection signal; review it before sharing the notebook.")
		}
		if hasSensitiveTracebackPath(cell.Traceback) {
			add(cell, "ipynb-traceback-sensitive-path", "CWE-200", shared.SeverityMedium, "Sensitive path saved in notebook output", "Saved output exposes traceback or local path details that can reveal environment structure.")
		}
	}
	return out
}

func hasSuspiciousScript(output string) bool {
	for _, script := range notebookScriptRE.FindAllString(output, -1) {
		if notebookScriptInjectionRE.MatchString(script) {
			return true
		}
	}
	return false
}

func hasSensitiveTracebackPath(traceback string) bool {
	for _, path := range notebookSensitivePathRE.FindAllString(traceback, -1) {
		normalized := "/" + strings.Trim(strings.ToLower(strings.ReplaceAll(path, `\`, "/")), "/") + "/"
		routine := false
		for _, marker := range notebookRoutineTracebackPath {
			if strings.Contains(normalized, marker) {
				routine = true
				break
			}
		}
		if !routine {
			return true
		}
	}
	return false
}

func containsSensitiveAssignment(pattern *regexp.Regexp, text string) bool {
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return false
	}
	name := strings.ToLower(strings.ReplaceAll(match[1], "-", "_"))
	parts := strings.Split(name, "_")
	last := parts[len(parts)-1]
	sensitiveSuffixes := []string{"secret", "token", "pwd", "pass" + "wd", "pass" + "word"}
	for _, suffix := range sensitiveSuffixes {
		if last == suffix {
			return true
		}
	}
	if len(parts) < 2 {
		return false
	}
	previous := parts[len(parts)-2]
	return previous == "api" && last == "key" || (previous == "access" || previous == "auth") && last == "token"
}

func hasUnpinnedDependency(tool, args string) bool {
	exactPin := notebookPipExactPinRE
	if strings.EqualFold(tool, "conda") {
		exactPin = notebookCondaExactPinRE
	}
	optionsWithValue := map[string]bool{"--index-url": true, "-i": true, "--extra-index-url": true, "--find-links": true, "-f": true, "--channel": true, "-c": true}
	skipNext := false
	for _, item := range strings.Fields(args) {
		if skipNext {
			skipNext = false
			continue
		}
		if optionsWithValue[item] {
			skipNext = true
			continue
		}
		if strings.HasPrefix(item, "-") {
			continue
		}
		if !exactPin.MatchString(item) {
			return true
		}
	}
	return false
}

func addQualityAt(out *[]ports.CodeAnalysisRawFinding, rel string, cell notebook.Cell, line int, ruleID, title, description string) {
	*out = append(*out, ports.CodeAnalysisRawFinding{Kind: "quality", RuleID: ruleID, Severity: shared.SeverityLow, Title: title, Description: description, File: notebook.Location(rel, cell.Index), Line: line})
}

func addAt(out *[]ports.CodeAnalysisRawFinding, rel string, cell notebook.Cell, line int, ruleID, cwe string, severity shared.Severity, title, description string) {
	*out = append(*out, ports.CodeAnalysisRawFinding{Kind: "sast", RuleID: ruleID, CWE: cwe, Severity: severity, Title: title, Description: description, File: notebook.Location(rel, cell.Index), Line: line})
}

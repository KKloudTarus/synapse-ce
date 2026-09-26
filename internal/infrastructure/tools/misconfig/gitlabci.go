package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A .gitlab-ci.yml is the deployment path: it holds the credentials that reach production and it decides what
// code runs with them. These checks read the decisions the file alone settles.
//
// Line-based, like the GitHub Actions scanner, so every finding carries an exact line and a GitLab-specific
// tag (`!reference`) or a YAML anchor cannot stop the file being read.

var (
	reGLIncludeKey = regexp.MustCompile(`(?i)^include\s*:`)
	reGLItemKey    = regexp.MustCompile(`(?i)^\s*(?:-\s*)?([a-z_][\w-]*)\s*:`)
	reGLScriptKey  = regexp.MustCompile(`(?i)^\s*(?:-\s*)?(before_script|after_script|script)\s*:`)
	reGLImageKey   = regexp.MustCompile(`(?i)^\s*(?:-\s*)?image\s*:\s*(\S.*)?$`)
	reGLNameKey    = regexp.MustCompile(`(?i)^\s*(?:-\s*)?name\s*:\s*(\S.*)$`)
	reGLServices   = regexp.MustCompile(`(?i)^\s*services\s*:`)
	reGLSeqString  = regexp.MustCompile(`^\s*-\s*(["']?)([^"'\s#][^"'#]*)(["']?)\s*$`)
	reGLDebugTrace = regexp.MustCompile(`(?i)^\s*CI_DEBUG_TRACE\s*:\s*["']?(true|1|yes)["']?\s*$`)

	// A registry credential on the command line is readable in the node's process table and is echoed by any
	// shell trace. Docker itself says so and offers --password-stdin.
	reGLLoginPassword = regexp.MustCompile(`(?i)\b(docker|podman|nerdctl|buildah|crane|skopeo)\b[^\n]*\blogin\b[^\n]*(\s-p\s|\s-p"|\s-p'|--password[ =])`)

	// A remote script executed straight from the network: whatever the URL serves at pipeline time runs with
	// the job's credentials, and nothing in the repository records what that was.
	reGLCurlPipeShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|d|a)?sh\b`)

	// GitLab expands a variable as an environment variable, and shell parameter expansion does NOT re-parse
	// the value as code, so an untrusted value is only executable where something parses it a second time.
	// `eval` and a `-c` string are the two constructs that do. A command substitution is deliberately absent:
	// `$(echo $CI_COMMIT_REF_NAME | tr / -)` expands the variable as a parameter inside the substitution, which
	// is parsed once, so the value is data there and flagging it would be a false positive on the ordinary way
	// a branch name is turned into a tag.
	reGLReevaluates = regexp.MustCompile(`(?i)(\beval\b|\b(ba|z|k|d|a)?sh\s+(-[a-z]*\s+)*-[a-z]*c\b)`)

	// The variables a person outside the project controls. A *_SLUG variant is sanitised by GitLab to lower
	// case alphanumerics and hyphens, so it carries nothing executable and is deliberately absent.
	reGLUntrusted = regexp.MustCompile(`\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_DESCRIPTION|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|CI_COMMIT_TAG|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b`)
)

// isGitLabCIName reports whether a basename is GitLab pipeline configuration. A template repository keeps its
// pipelines as `<name>.gitlab-ci.yml`, and those are included verbatim into other projects' pipelines, so they
// are the same surface as the root file.
func isGitLabCIName(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	return strings.Contains(lower, "gitlab-ci")
}

// scanGitLabCI runs the owned GitLab pipeline checks.
func scanGitLabCI(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	lines := strings.Split(string(data), "\n")

	inInclude := false // inside the top-level include: section
	includeItem := -1  // indentation of the current include entry; -1 means none is open
	itemKinds := map[string]int{}
	itemLine := 0
	scriptCol := -1   // key column of the enclosing script block
	servicesCol := -1 // key column of the enclosing services block
	imageBlock := -1  // key column of an `image:` block whose name: is still to come

	// flushIncludeItem judges one finished include entry. A project include without a ref takes whatever that
	// project's default branch holds when the pipeline runs.
	flushIncludeItem := func() {
		if includeItem < 0 {
			return
		}
		switch {
		case itemKinds["remote"] > 0:
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: itemLine, RuleID: "gitlab-ci-include-remote", Title: "Pipeline includes remote configuration",
				Severity: shared.SeverityHigh, Resource: "include remote",
				Description: "The pipeline includes configuration fetched from a URL at run time, so whatever that URL serves becomes pipeline code with this project's credentials, and the repository records neither what it was nor that it changed. Vendor the file into this repository, or include it from a project on this GitLab instance with a pinned ref.",
			})
		case itemKinds["project"] > 0 && itemKinds["ref"] == 0:
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: itemLine, RuleID: "gitlab-ci-include-project-unpinned", Title: "Pipeline includes another project with no ref",
				Severity: shared.SeverityHigh, Resource: "include project",
				Description: "The include names another project but no ref, so it resolves to that project's default branch every time the pipeline runs. Whoever can push there runs commands in this pipeline, with this project's deploy credentials, and no change lands in this repository to review. Pin ref to a tag or a commit SHA.",
			})
		}
		includeItem = -1
		itemKinds = map[string]int{}
	}

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		ln := i + 1
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		code := stripYAMLComment(line)
		ind := indentOf(line)

		// Close any block the indentation has left.
		if scriptCol >= 0 && ind <= scriptCol {
			scriptCol = -1
		}
		if servicesCol >= 0 && ind <= servicesCol {
			servicesCol = -1
		}
		if imageBlock >= 0 && ind <= imageBlock {
			imageBlock = -1
		}
		if inInclude && ind == 0 && !reGLIncludeKey.MatchString(code) {
			flushIncludeItem()
			inInclude = false
		}
		if inInclude {
			// A new list item at the entry's own indentation ends the previous entry.
			if includeItem >= 0 && (ind <= includeItem) && strings.HasPrefix(trimmed, "- ") {
				flushIncludeItem()
			}
			if m := reGLItemKey.FindStringSubmatch(code); m != nil {
				key := strings.ToLower(m[1])
				if includeItem < 0 {
					includeItem = ind
					itemLine = ln
				}
				itemKinds[key]++
			}
		}

		inScript := scriptCol >= 0

		switch {
		case ind == 0 && reGLIncludeKey.MatchString(code):
			flushIncludeItem()
			inInclude = true
		case !inScript && reGLDebugTrace.MatchString(code):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "gitlab-ci-debug-trace-enabled", Title: "Pipeline enables debug tracing",
				Severity: shared.SeverityHigh, Resource: "CI_DEBUG_TRACE",
				Description: "CI_DEBUG_TRACE makes the runner trace every command, which writes the value of every variable into the job log, masked project and group variables included. Anyone who can read a job log then reads the deploy credentials. Remove it, and rotate any credential a job has already logged.",
			})
		case reGLScriptKey.MatchString(code):
			scriptCol = keyColumn(code)
			out = append(out, glScriptFindings(rel, ln, code)...)
		case inScript:
			out = append(out, glScriptFindings(rel, ln, code)...)
		case reGLServices.MatchString(code):
			servicesCol = keyColumn(code)
		case reGLImageKey.MatchString(code):
			m := reGLImageKey.FindStringSubmatch(code)
			if strings.TrimSpace(m[1]) == "" {
				imageBlock = keyColumn(code) // `image:` block; the reference arrives on a following name:
				break
			}
			if f, ok := glImageFinding(rel, ln, m[1]); ok {
				out = append(out, f)
			}
		case imageBlock >= 0 && reGLNameKey.MatchString(code):
			m := reGLNameKey.FindStringSubmatch(code)
			if f, ok := glImageFinding(rel, ln, m[1]); ok {
				out = append(out, f)
			}
		case servicesCol >= 0 && reGLNameKey.MatchString(code):
			m := reGLNameKey.FindStringSubmatch(code)
			if f, ok := glImageFinding(rel, ln, m[1]); ok {
				out = append(out, f)
			}
		case servicesCol >= 0 && reGLSeqString.MatchString(code):
			m := reGLSeqString.FindStringSubmatch(code)
			if f, ok := glImageFinding(rel, ln, m[2]); ok {
				out = append(out, f)
			}
		}
	}
	flushIncludeItem()
	return out
}

// glScriptFindings reads one shell line of a job.
func glScriptFindings(rel string, ln int, line string) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	if reGLLoginPassword.MatchString(line) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: ln, RuleID: "gitlab-ci-registry-password-on-command-line",
			Title:    "Registry credential passed on the command line",
			Severity: shared.SeverityMedium, Resource: "registry login",
			Description: "The registry password is an argument, so it is readable in the node's process table by anything else running on that runner and is echoed verbatim by any shell trace. Pipe it instead: echo \"$CI_REGISTRY_PASSWORD\" | docker login --password-stdin.",
		})
	}
	if reGLCurlPipeShell.MatchString(line) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: ln, RuleID: "gitlab-ci-curl-pipe-shell",
			Title:    "Pipeline executes a downloaded script",
			Severity: shared.SeverityMedium, Resource: "job script",
			Description: "The job downloads a script and runs it in one step, so whatever the URL serves at pipeline time executes with the job's credentials, with no checksum and no record of what ran. Download to a file, verify a pinned checksum, then execute it.",
		})
	}
	// GitLab expands a variable as an environment variable, and shell parameter expansion does not re-parse
	// the value as code, so an untrusted value is only executable where something evaluates it a second time.
	// That second evaluation is what this looks for, and it is why an ordinary "$CI_COMMIT_MESSAGE" is not
	// reported here.
	// The variable has to sit AFTER the construct that re-parses it; `eval "$SAFE"` followed by a comment
	// naming an untrusted variable is not the same line of code.
	if where := reGLReevaluates.FindStringIndex(line); where != nil && reGLUntrusted.MatchString(line[where[1]:]) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: ln, RuleID: "gitlab-ci-script-injection",
			Title:    "Untrusted pipeline variable is evaluated as code",
			Severity: shared.SeverityHigh, Resource: "job script",
			Description: "The line evaluates a variable whose value comes from outside the project (a commit message, a branch name, a merge-request title). Anyone who can open a merge request chooses that text, and this line runs it as a command with the job's credentials. Read the value into a quoted variable and pass it as data, never through eval, a command substitution or a backtick.",
		})
	}
	return out
}

// glImageFinding reports an image reference nothing pins. A reference built from a variable is not judged:
// what it expands to is not in this file.
func glImageFinding(rel string, ln int, reference string) (ports.MisconfigRawFinding, bool) {
	ref := strings.Trim(strings.TrimSpace(reference), `"'`)
	if ref == "" || strings.Contains(ref, "$") {
		return ports.MisconfigRawFinding{}, false
	}
	if strings.Contains(ref, "@sha256:") {
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: ln, RuleID: "gitlab-ci-image-no-digest", Title: "Job image is not pinned to a digest",
		Severity: shared.SeverityLow, Resource: clip(ref),
		Description: "The job runs image " + clip(ref) + ", which names a tag rather than a digest, so the runner executes whatever that tag points at when the pipeline runs. A moved or republished tag silently changes the build and the credentials it holds. Pin the image by digest (name@sha256:...).",
	}, true
}

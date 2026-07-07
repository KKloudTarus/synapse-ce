package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// pipeToShell matches a download piped straight into a shell (curl ... | sh, wget ... | bash) — a common
// remote-code-execution pattern in image builds.
var pipeToShell = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b`)

// instruction is one logical Dockerfile instruction with its starting line (backslash continuations joined).
type instruction struct {
	cmd  string // upper-cased, e.g. "FROM"
	args string // the remainder of the logical line
	line int    // 1-indexed line of the instruction start
}

// scanDockerfile runs the owned Dockerfile checks and returns located findings.
func scanDockerfile(rel string, data []byte) []ports.MisconfigRawFinding {
	instrs := parseDockerfile(string(data))
	var out []ports.MisconfigRawFinding

	// Track build stages so multi-stage builds are judged by their FINAL stage (an early builder stage
	// running as root is fine). A new FROM opens a stage; USER within it sets that stage's user.
	stageNames := map[string]bool{}
	var lastUserLine, lastFromLine int
	lastUserRoot := true // no USER yet ⇒ root
	haveStage := false

	for _, in := range instrs {
		switch in.cmd {
		case "FROM":
			// New stage: reset the per-stage user state.
			haveStage = true
			lastFromLine = in.line
			lastUserLine = 0
			lastUserRoot = true
			img, alias := parseFrom(in.args)
			if alias != "" {
				stageNames[strings.ToLower(alias)] = true
			}
			if r, ok := checkBaseImageTag(img, stageNames, rel, in.line); ok {
				out = append(out, r)
			}
		case "USER":
			lastUserLine = in.line
			lastUserRoot = isRootUser(in.args)
		case "ADD":
			if r, ok := checkAddRemote(in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "RUN":
			if pipeToShell.MatchString(in.args) {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: in.line, RuleID: "dockerfile-run-pipe-shell",
					Title: "Remote script piped to a shell", Severity: shared.SeverityHigh,
					Resource:    "Dockerfile RUN",
					Description: "A RUN step downloads a script and pipes it directly into a shell (e.g. curl ... | sh), executing unverified remote code at build time. Download to a file, verify a checksum or signature, then run it.",
				})
			}
		}
	}

	// Final-stage user check: if the last stage runs as root (explicit root USER, or no USER at all),
	// flag it. Point at the offending USER line, or the final FROM when none was set.
	if haveStage && lastUserRoot {
		line := lastUserLine
		desc := "The final build stage sets USER root (or 0), so the container runs as root. Add a non-root USER as the last USER instruction."
		if lastUserLine == 0 {
			line = lastFromLine
			desc = "No USER instruction, so the container runs as root by default. Add a non-root USER (e.g. a dedicated app user) before the entrypoint."
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-run-as-root",
			Title: "Container runs as root", Severity: shared.SeverityHigh,
			Resource: "Dockerfile USER", Description: desc,
		})
	}
	return out
}

// checkBaseImageTag flags a FROM that pins no immutable version: no tag, an explicit :latest, and no
// @sha256 digest. It skips `scratch`, ARG-templated refs, and references to a previous local stage.
func checkBaseImageTag(img string, stageNames map[string]bool, rel string, line int) (ports.MisconfigRawFinding, bool) {
	if img == "" || img == "scratch" || strings.Contains(img, "$") {
		return ports.MisconfigRawFinding{}, false
	}
	if stageNames[strings.ToLower(img)] {
		return ports.MisconfigRawFinding{}, false // FROM a prior build stage, not a registry image
	}
	if strings.Contains(img, "@sha256:") {
		return ports.MisconfigRawFinding{}, false // digest-pinned
	}
	tag := imageTag(img)
	if tag != "" && tag != "latest" {
		return ports.MisconfigRawFinding{}, false // an explicit non-latest tag
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-image-no-tag",
		Title: "Base image is not version-pinned", Severity: shared.SeverityMedium,
		Resource:    "Dockerfile FROM " + clip(img),
		Description: "The base image uses no tag or :latest, so builds are not reproducible and can silently pull a changed or vulnerable image. Pin an explicit version tag, ideally with an @sha256 digest.",
	}, true
}

// checkAddRemote flags ADD with a remote (http/https) source; COPY, or a verified download in a RUN
// step, is preferred.
func checkAddRemote(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	for _, f := range fields(args) {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return ports.MisconfigRawFinding{
				File: rel, Line: line, RuleID: "dockerfile-add-remote-url",
				Title: "ADD fetches a remote URL", Severity: shared.SeverityMedium,
				Resource:    "Dockerfile ADD",
				Description: "ADD with a remote URL downloads over the network with no integrity check and does not cache well. Use a RUN step that downloads and verifies a checksum, or COPY a vendored file.",
			}, true
		}
	}
	return ports.MisconfigRawFinding{}, false
}

// parseDockerfile splits source into logical instructions, joining backslash line-continuations and
// skipping comments and blank lines. The reported line is where the instruction starts.
func parseDockerfile(src string) []instruction {
	lines := strings.Split(src, "\n")
	var out []instruction
	i := 0
	for i < len(lines) {
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)
		startLine := i + 1
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			i++
			continue
		}
		// Join continuations: a trailing backslash continues onto the next line.
		full := trimmed
		for strings.HasSuffix(strings.TrimRight(full, " \t"), `\`) && i+1 < len(lines) {
			full = strings.TrimSuffix(strings.TrimRight(full, " \t"), `\`)
			i++
			full += " " + strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		}
		i++
		cmd, args := splitInstruction(full)
		if cmd == "" {
			continue
		}
		out = append(out, instruction{cmd: strings.ToUpper(cmd), args: strings.TrimSpace(args), line: startLine})
	}
	return out
}

func splitInstruction(line string) (cmd, args string) {
	line = strings.TrimSpace(line)
	sp := strings.IndexAny(line, " \t")
	if sp < 0 {
		return line, ""
	}
	return line[:sp], line[sp+1:]
}

// parseFrom returns the image reference and the optional stage alias ("... AS name").
func parseFrom(args string) (img, alias string) {
	f := fields(args)
	// Drop --platform=... and similar flags.
	rest := make([]string, 0, len(f))
	for _, tok := range f {
		if strings.HasPrefix(tok, "--") {
			continue
		}
		rest = append(rest, tok)
	}
	if len(rest) == 0 {
		return "", ""
	}
	img = rest[0]
	for j := 1; j+1 < len(rest); j++ {
		if strings.EqualFold(rest[j], "AS") {
			alias = rest[j+1]
			break
		}
	}
	return img, alias
}

// imageTag returns the tag portion of an image ref (after the last ':' that is not part of a registry
// host:port), or "" when untagged. A '/' after the last ':' means the colon was a port, not a tag.
func imageTag(img string) string {
	if strings.Contains(img, "@") {
		img = img[:strings.Index(img, "@")]
	}
	c := strings.LastIndex(img, ":")
	if c < 0 {
		return ""
	}
	if strings.Contains(img[c:], "/") {
		return "" // the colon belonged to a registry host:port
	}
	return img[c+1:]
}

func isRootUser(args string) bool {
	u := strings.TrimSpace(args)
	if i := strings.IndexAny(u, " \t"); i >= 0 {
		u = u[:i]
	}
	if c := strings.IndexByte(u, ':'); c >= 0 { // strip :group
		u = u[:c]
	}
	return u == "" || u == "root" || u == "0"
}

func fields(s string) []string { return strings.Fields(s) }

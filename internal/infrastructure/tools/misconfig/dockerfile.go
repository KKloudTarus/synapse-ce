package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// pipeToShell matches a download piped straight into a shell (curl ... | sh, wget ... | bash) – a common
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
	haveHealthcheck := false

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
		case "HEALTHCHECK":
			if !strings.EqualFold(strings.TrimSpace(in.args), "NONE") {
				haveHealthcheck = true
			}
		case "ENV", "ARG":
			if r, ok := checkSecretEnv(in.cmd, in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "ADD":
			if r, ok := checkAddRemote(in.args, rel, in.line); ok {
				out = append(out, r)
			} else if r, ok := checkAddLocal(in.args, rel, in.line); ok {
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
			out = append(out, checkRunStep(in.args, rel, in.line)...)
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

	// No HEALTHCHECK: an orchestrator can't tell whether the container is actually serving.
	if haveStage && !haveHealthcheck {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: lastFromLine, RuleID: "dockerfile-no-healthcheck",
			Title: "No container HEALTHCHECK", Severity: shared.SeverityLow,
			Resource:    "Dockerfile",
			Description: "The image declares no HEALTHCHECK instruction, so an orchestrator cannot detect an unhealthy-but-running container. Add a HEALTHCHECK that probes the application's readiness.",
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
			next := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			if strings.HasPrefix(next, "#") {
				// A full-line comment inside a continuation. Docker strips comments before joining
				// continuations, so skip it and keep the continuation open instead of ending the
				// instruction early (which would drop the real commands that follow the comment).
				full += ` \`
				continue
			}
			full += " " + next
		}
		full = strings.TrimSuffix(strings.TrimRight(full, " \t"), `\`) // drop a dangling trailing backslash
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

// secretKeyRe matches an ENV/ARG key that names a credential; a literal value on such a key bakes a
// secret into an image layer (recoverable by anyone who can pull the image).
var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|\bauth\b)`)

// checkSecretEnv flags an ENV/ARG that assigns a literal value to a secret-named key. A value that
// references another variable ($X / ${X}) or is empty is not a baked-in secret.
func checkSecretEnv(cmd, args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	for _, kv := range envAssignments(args) {
		key, val := kv[0], kv[1]
		if !secretKeyRe.MatchString(key) {
			continue
		}
		v := strings.TrimSpace(val)
		if v == "" || strings.HasPrefix(v, "$") {
			continue // references another var or unset – not a baked literal
		}
		return ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-secret-in-" + strings.ToLower(cmd),
			Title: "Secret baked into image (" + cmd + ")", Severity: shared.SeverityHigh,
			Resource:    "Dockerfile " + cmd + " " + clip(key),
			Description: "A secret-looking " + cmd + " key is assigned a literal value, so the credential is persisted in an image layer and recoverable by anyone who can pull the image. Inject secrets at runtime (env or secret mount) or use BuildKit --secret; never bake them in.",
		}, true
	}
	return ports.MisconfigRawFinding{}, false
}

// checkAddLocal flags ADD of a plain local path (not a URL, not an archive ADD auto-extracts): COPY is
// clearer and lacks ADD's implicit URL/extraction behavior.
func checkAddLocal(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	var src []string
	for _, tok := range fields(args) {
		if !strings.HasPrefix(tok, "--") {
			src = append(src, tok)
		}
	}
	if len(src) < 2 {
		return ports.MisconfigRawFinding{}, false
	}
	for _, s := range src[:len(src)-1] { // all but the destination
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			return ports.MisconfigRawFinding{}, false // remote: handled by checkAddRemote
		}
		low := strings.ToLower(s)
		for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".xz", ".bz2"} {
			if strings.HasSuffix(low, ext) {
				return ports.MisconfigRawFinding{}, false // ADD auto-extracts archives – a legitimate use
			}
		}
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-add-instead-of-copy",
		Title: "ADD used for a local file (prefer COPY)", Severity: shared.SeverityLow,
		Resource:    "Dockerfile ADD",
		Description: "ADD copies a local file here, but ADD also fetches URLs and auto-extracts archives, which is surprising and error-prone. Use COPY for local files so the intent is explicit.",
	}, true
}

var (
	insecureDownloadRe = regexp.MustCompile(`(?i)(?:curl\b[^|&;]*\s(?:-k|--insecure)|wget\b[^|&;]*\s--no-check-certificate)`)
	aptInstallRe       = regexp.MustCompile(`(?i)\bapt(?:-get)?\s+(?:-[a-z]+\s+)*install\b`)
	aptCleanRe         = regexp.MustCompile(`(?i)rm\s+-rf?\s+[^\n]*/var/lib/apt/lists`)
	sudoRe             = regexp.MustCompile(`(?i)(?:^|[|&;]\s*|\s)sudo\s`)
)

// checkRunStep runs the RUN-instruction checks other than pipe-to-shell: sudo use, TLS-disabling
// downloads, and apt installs that never prune the package cache.
func checkRunStep(args, rel string, line int) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	if sudoRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-run-sudo",
			Title: "sudo used in a RUN step", Severity: shared.SeverityMedium,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step uses sudo. Image builds already run as root, so sudo is unnecessary and can pull in a setuid binary or mask the intended user. Run the command directly, or switch USER explicitly.",
		})
	}
	if insecureDownloadRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-insecure-download",
			Title: "TLS verification disabled in a download", Severity: shared.SeverityMedium,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step downloads with TLS verification disabled (curl -k / --insecure or wget --no-check-certificate), so the content can be tampered with in transit. Remove the flag and trust the system CA store.",
		})
	}
	if aptInstallRe.MatchString(args) && !aptCleanRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-apt-no-clean",
			Title: "apt install without cache cleanup", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "An apt/apt-get install in this RUN step does not remove /var/lib/apt/lists afterward, leaving the package index in the image layer (larger image, stale metadata). Append: rm -rf /var/lib/apt/lists/*.",
		})
	}
	return out
}

// envAssignments parses an ENV/ARG argument into (key, value) pairs, handling the modern "K=V K2=V2"
// form and the legacy "ENV KEY the value" single-pair form.
func envAssignments(args string) [][2]string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var out [][2]string
	if strings.Contains(args, "=") {
		for _, tok := range splitEnvTokens(args) {
			if eq := strings.IndexByte(tok, '='); eq > 0 {
				out = append(out, [2]string{tok[:eq], strings.Trim(tok[eq+1:], `"'`)})
			}
		}
		return out
	}
	if f := strings.Fields(args); len(f) >= 2 { // legacy: ENV KEY rest-is-value
		out = append(out, [2]string{f[0], strings.Trim(strings.TrimSpace(args[len(f[0]):]), `"'`)})
	} else if len(f) == 1 {
		out = append(out, [2]string{f[0], ""})
	}
	return out
}

// splitEnvTokens splits `K=V K2="a b"` on spaces that are outside quotes.
func splitEnvTokens(s string) []string {
	var toks []string
	var cur strings.Builder
	inQ := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ != 0:
			if c == inQ {
				inQ = 0
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			inQ = c
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

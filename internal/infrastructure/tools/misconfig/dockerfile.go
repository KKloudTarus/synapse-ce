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
	cmdCount := 0        // CMD instructions in the current stage (only the last one takes effect)
	entrypointCount := 0 // ENTRYPOINT instructions in the current stage (only the last one takes effect)

	for _, in := range instrs {
		switch in.cmd {
		case "FROM":
			// New stage: reset the per-stage user + CMD state.
			haveStage = true
			lastFromLine = in.line
			lastUserLine = 0
			lastUserRoot = true
			cmdCount = 0
			entrypointCount = 0
			img, alias := parseFrom(in.args)
			if alias != "" {
				stageNames[strings.ToLower(alias)] = true
			}
			if r, ok := checkBaseImageTag(img, stageNames, rel, in.line); ok {
				out = append(out, r)
			}
			if r, ok := checkFromPlatform(in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "USER":
			lastUserLine = in.line
			lastUserRoot = isRootUser(in.args)
		case "HEALTHCHECK":
			if !strings.EqualFold(strings.TrimSpace(in.args), "NONE") {
				haveHealthcheck = true
			}
		case "MAINTAINER":
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: in.line, RuleID: "dockerfile-maintainer-deprecated",
				Title: "Deprecated MAINTAINER instruction", Severity: shared.SeverityLow,
				Resource:    "Dockerfile MAINTAINER",
				Description: "MAINTAINER is deprecated. Record authorship with a LABEL (for example org.opencontainers.image.authors) so image metadata stays standard and machine-readable.",
			})
		case "WORKDIR":
			if r, ok := checkWorkdirRelative(in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "EXPOSE":
			if r, ok := checkExposeSSH(in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "CMD":
			cmdCount++
			if cmdCount > 1 {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: in.line, RuleID: "dockerfile-multiple-cmd",
					Title: "Multiple CMD instructions", Severity: shared.SeverityLow,
					Resource:    "Dockerfile CMD",
					Description: "This build stage has more than one CMD; only the last CMD takes effect, so the earlier ones are dead configuration and usually signal a mistake. Keep a single CMD per stage.",
				})
			}
		case "ENTRYPOINT":
			entrypointCount++
			if entrypointCount > 1 {
				out = append(out, ports.MisconfigRawFinding{
					File: rel, Line: in.line, RuleID: "dockerfile-multiple-entrypoint",
					Title: "Multiple ENTRYPOINT instructions", Severity: shared.SeverityLow,
					Resource:    "Dockerfile ENTRYPOINT",
					Description: "This build stage has more than one ENTRYPOINT; only the last one takes effect, so the earlier ones are dead configuration and usually signal a mistake. Keep a single ENTRYPOINT per stage.",
				})
			}
			if r, ok := checkShellFormEntrypoint(in.args, rel, in.line); ok {
				out = append(out, r)
			}
		case "COPY":
			if r, ok := checkCopyToRoot("COPY", in.args, rel, in.line); ok {
				out = append(out, r)
			}
			if r, ok := checkKeyMaterialCopy("COPY", in.args, rel, in.line); ok {
				out = append(out, r)
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
			if r, ok := checkCopyToRoot("ADD", in.args, rel, in.line); ok {
				out = append(out, r)
			}
			if r, ok := checkKeyMaterialCopy("ADD", in.args, rel, in.line); ok {
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
	aptUpgradeRe       = regexp.MustCompile(`(?i)\bapt(?:-get)?\s+(?:-[a-z]+\s+)*(?:dist-upgrade|upgrade)\b`)
	aptYesRe           = regexp.MustCompile(`(?i)(?:--yes|--assume-yes|(?:^|\s)-[a-z]*y[a-z]*(?:\s|$))`)
	apkAddRe           = regexp.MustCompile(`(?i)\bapk\s+(?:-[a-z]+\s+)*add\b`)
	yumInstallRe       = regexp.MustCompile(`(?i)\b(?:yum|dnf|microdnf)\s+(?:-[a-z]+\s+)*install\b`)
	yumCleanRe         = regexp.MustCompile(`(?i)\b(?:yum|dnf|microdnf)\s+clean\b`)
	pipInstallRe       = regexp.MustCompile(`(?i)\bpip[0-9]*\s+install\b`)
	cdInRunRe          = regexp.MustCompile(`(?i)(?:^|&&|;|\|)\s*cd\s+\S`)
	worldWritableRe    = regexp.MustCompile(`(?i)\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:0?777|a\+rwx|o\+w)\b`)
	setuidRe           = regexp.MustCompile(`(?i)\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:[2467][0-7]{3}|[ugo]*\+s)\b`)
	secretInRunRe      = regexp.MustCompile(`(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*=\s*["']?[A-Za-z0-9/+_.-]{4,}`)
	fromPlatformRe     = regexp.MustCompile(`(?i)--platform=(\S+)`)
	keyMaterialRe      = regexp.MustCompile(`(?i)(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)\b|\.(?:pem|key|pfx|p12|ppk)\b`)
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
	if aptInstallRe.MatchString(args) && !strings.Contains(strings.ToLower(args), "--no-install-recommends") {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-apt-no-norecommends",
			Title: "apt install without --no-install-recommends", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "An apt/apt-get install in this RUN step omits --no-install-recommends, so recommended-but-unneeded packages are pulled in, enlarging the image and its attack surface. Add --no-install-recommends (or set APT::Install-Recommends \"false\").",
		})
	}
	if aptUpgradeRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-apt-upgrade",
			Title: "apt upgrade in a RUN step", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step runs apt-get upgrade or dist-upgrade, which upgrades base-image packages non-deterministically and defeats reproducible, pinned builds. Update the base image tag instead and pin the packages you install.",
		})
	}
	if aptInstallRe.MatchString(args) && !aptYesRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-apt-no-yes",
			Title: "apt install without -y", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "An apt/apt-get install runs without -y/--yes, so a non-interactive image build hangs waiting for a confirmation prompt. Add -y (or --assume-yes).",
		})
	}
	if apkAddRe.MatchString(args) && !strings.Contains(strings.ToLower(args), "--no-cache") {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-apk-no-cache",
			Title: "apk add without --no-cache", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "An apk add omits --no-cache, so the Alpine package index is written into the image layer (larger image, stale metadata). Add --no-cache.",
		})
	}
	if yumInstallRe.MatchString(args) && !yumCleanRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-yum-no-clean",
			Title: "yum/dnf install without clean", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "A yum/dnf install in this RUN step does not run `clean all` afterward, leaving package caches in the image layer. Append `&& yum clean all` (or `dnf clean all`).",
		})
	}
	if pipInstallRe.MatchString(args) && !strings.Contains(strings.ToLower(args), "--no-cache-dir") {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-pip-no-cache-dir",
			Title: "pip install without --no-cache-dir", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "A pip install omits --no-cache-dir, so the wheel/download cache is baked into the image layer, enlarging it. Add --no-cache-dir.",
		})
	}
	if cdInRunRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-cd-in-run",
			Title: "cd used in a RUN step", Severity: shared.SeverityLow,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step changes directory with `cd`. Each RUN is a fresh shell, so the cd does not persist to later instructions and makes the build fragile. Set the directory with WORKDIR instead.",
		})
	}
	if worldWritableRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-world-writable",
			Title: "World-writable permissions set", Severity: shared.SeverityMedium,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step grants world-writable permissions (chmod 777 / a+rwx), so any user in the container can modify the file, enabling tampering or privilege abuse. Grant only the permissions the process needs.",
		})
	}
	if setuidRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-setuid-chmod",
			Title: "setuid/setgid bit set", Severity: shared.SeverityMedium,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step sets a setuid/setgid bit (chmod u+s / 4xxx), so the binary runs with the file owner's privileges regardless of the caller, a classic privilege-escalation primitive. Avoid setuid binaries in images; prefer capabilities or a non-root design.",
		})
	}
	if secretInRunRe.MatchString(args) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: "dockerfile-secret-in-run",
			Title: "Secret literal in a RUN step", Severity: shared.SeverityHigh,
			Resource:    "Dockerfile RUN",
			Description: "A RUN step assigns a credential as a literal value (a password/token/key), so the secret is persisted in an image layer and the build cache. Use BuildKit `--mount=type=secret` or inject the value at runtime instead of baking it in.",
		})
	}
	return out
}

// checkWorkdirRelative flags a WORKDIR set to a relative path. A relative WORKDIR resolves against the
// previous WORKDIR (or /), so the effective directory is order-dependent and easy to get wrong; an
// absolute path is unambiguous. A variable-templated ($X) or Windows path is left alone.
func checkWorkdirRelative(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	p := strings.Trim(strings.TrimSpace(args), `"'`)
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "$") || strings.HasPrefix(p, `\`) {
		return ports.MisconfigRawFinding{}, false
	}
	if len(p) >= 2 && p[1] == ':' { // Windows drive, e.g. C:\app
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-workdir-relative",
		Title: "WORKDIR uses a relative path", Severity: shared.SeverityLow,
		Resource:    "Dockerfile WORKDIR " + clip(p),
		Description: "WORKDIR is a relative path, so the effective working directory depends on the previous WORKDIR and is easy to get wrong across stages or edits. Use an absolute path (for example /app).",
	}, true
}

// checkExposeSSH flags EXPOSE 22 (the SSH port). Running an SSH daemon inside an application container
// is an anti-pattern that adds a remote-login attack surface and credential-management burden.
func checkExposeSSH(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	for _, f := range fields(args) {
		port := f
		if i := strings.IndexByte(port, '/'); i >= 0 { // drop /tcp, /udp
			port = port[:i]
		}
		if port == "22" {
			return ports.MisconfigRawFinding{
				File: rel, Line: line, RuleID: "dockerfile-expose-ssh",
				Title: "SSH port (22) exposed", Severity: shared.SeverityMedium,
				Resource:    "Dockerfile EXPOSE",
				Description: "The image EXPOSEs port 22, implying an in-container SSH daemon. SSH inside an application container is an anti-pattern that widens the attack surface and adds credential management; use `docker exec` or your orchestrator's tooling for shell access instead.",
			}, true
		}
	}
	return ports.MisconfigRawFinding{}, false
}

// checkFromPlatform flags a FROM that hardcodes --platform to a concrete value; a build-arg-templated
// platform ($TARGETPLATFORM / $BUILDPLATFORM) is fine and left alone.
func checkFromPlatform(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	m := fromPlatformRe.FindStringSubmatch(args)
	if m == nil || strings.HasPrefix(m[1], "$") {
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-from-platform-pinned",
		Title: "Hardcoded --platform in FROM", Severity: shared.SeverityLow,
		Resource:    "Dockerfile FROM",
		Description: "FROM pins a hardcoded --platform (for example linux/amd64), forcing a single architecture and breaking multi-arch builds. Drop the flag and let the builder choose, or use the $TARGETPLATFORM build arg.",
	}, true
}

// checkShellFormEntrypoint flags an ENTRYPOINT written in shell form (not a JSON array). Shell form runs
// the process under `/bin/sh -c` as a child of PID 1, so it never receives SIGTERM/SIGINT and cannot
// shut down gracefully.
func checkShellFormEntrypoint(args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	a := strings.TrimSpace(args)
	if a == "" || strings.HasPrefix(a, "[") {
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-shell-form-entrypoint",
		Title: "ENTRYPOINT in shell form", Severity: shared.SeverityLow,
		Resource:    "Dockerfile ENTRYPOINT",
		Description: "ENTRYPOINT uses shell form, so the process runs under `/bin/sh -c` as a child of PID 1 and does not receive SIGTERM/SIGINT, preventing graceful shutdown. Use the JSON exec form, e.g. ENTRYPOINT [\"app\"].",
	}, true
}

// checkCopyToRoot flags a COPY/ADD whose destination is the container root (/); files belong in a
// dedicated application directory, not scattered across system paths.
func checkCopyToRoot(cmd, args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	var toks []string
	for _, t := range fields(args) {
		if !strings.HasPrefix(t, "--") {
			toks = append(toks, t)
		}
	}
	if len(toks) < 2 {
		return ports.MisconfigRawFinding{}, false
	}
	if strings.Trim(toks[len(toks)-1], `"'`) != "/" {
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "dockerfile-copy-to-root",
		Title: "Files copied into the container root", Severity: shared.SeverityLow,
		Resource:    "Dockerfile " + cmd,
		Description: "A " + cmd + " writes into the container root (/), scattering files across system directories and risking overwrites of base-image paths. Copy into a dedicated application directory (for example /app) instead.",
	}, true
}

// checkKeyMaterialCopy flags a COPY/ADD that brings a private key or certificate file into the image
// (a baked-in secret recoverable from the layer). A public key (.pub) is skipped.
func checkKeyMaterialCopy(cmd, args, rel string, line int) (ports.MisconfigRawFinding, bool) {
	var toks []string
	for _, t := range fields(args) {
		if !strings.HasPrefix(t, "--") {
			toks = append(toks, t)
		}
	}
	if len(toks) < 2 {
		return ports.MisconfigRawFinding{}, false
	}
	for _, s := range toks[:len(toks)-1] { // sources (all but the destination)
		if strings.Contains(strings.ToLower(s), ".pub") {
			continue // a public key is not a secret
		}
		if keyMaterialRe.MatchString(s) {
			return ports.MisconfigRawFinding{
				File: rel, Line: line, RuleID: "dockerfile-private-key-copy",
				Title: "Private key or certificate copied into image", Severity: shared.SeverityHigh,
				Resource:    "Dockerfile " + cmd,
				Description: "A " + cmd + " brings a private key or certificate file (for example id_rsa, *.pem, *.key) into the image, persisting the secret in a layer that anyone who can pull the image can extract. Use a runtime secret or BuildKit `--mount=type=secret` instead.",
			}, true
		}
	}
	return ports.MisconfigRawFinding{}, false
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

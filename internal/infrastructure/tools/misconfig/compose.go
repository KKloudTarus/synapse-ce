package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// isComposeName recognises the conventional Docker Compose file names.
func isComposeName(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return true
	}
	// docker-compose.<env>.yml / compose.override.yaml, etc.
	return (strings.HasPrefix(n, "docker-compose.") || strings.HasPrefix(n, "compose.")) &&
		(strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml"))
}

var reComposeServices = regexp.MustCompile(`(?m)^services:\s*$`)

// looksCompose sniffs a non-conventionally-named YAML file that is a Compose file: a top-level
// `services:` mapping plus at least one service-shaped key. It intentionally does not fire on a
// Kubernetes manifest (which the caller has already ruled out) since those never have top-level services.
func looksCompose(data []byte) bool {
	s := string(data)
	if !reComposeServices.MatchString(s) {
		return false
	}
	return strings.Contains(s, "image:") || strings.Contains(s, "build:") || strings.Contains(s, "container_name:")
}

var (
	reComposePrivileged  = regexp.MustCompile(`(?i)^\s*privileged\s*:\s*(?:"true"|'true'|true)\s*$`)
	reComposeNetHost     = regexp.MustCompile(`(?i)^\s*network_mode\s*:\s*["']?host["']?\s*$`)
	reComposePIDHost     = regexp.MustCompile(`(?i)^\s*pid\s*:\s*["']?host["']?\s*$`)
	reComposeIPCHost     = regexp.MustCompile(`(?i)^\s*ipc\s*:\s*["']?host["']?\s*$`)
	reComposeUsernsHost  = regexp.MustCompile(`(?i)^\s*userns_mode\s*:\s*["']?host["']?\s*$`)
	reComposeUnconfined  = regexp.MustCompile(`(?i)(seccomp|apparmor)[:=]unconfined|\blabel[:=]disable\b`)
	reComposeImage       = regexp.MustCompile(`(?i)^\s*image\s*:\s*(.+?)\s*$`)
	reComposeCapAdd      = regexp.MustCompile(`(?i)^\s*cap_add\s*:\s*(.*)$`)
	reComposeEnvKey      = regexp.MustCompile(`(?i)^\s*-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*(.+?)\s*$`)
	reComposeServiceHead = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*:\s*(?:&\S+)?\s*$`)
	reListItem           = regexp.MustCompile(`^\s*-\s*(.+?)\s*$`)
)

// indentOf returns the number of leading spaces (tabs count as one) of a line.
func indentOf(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}

// scanCompose runs the owned Docker Compose checks. It is line-based (so every finding carries an exact
// line), tracking the current service name for the Resource label and the enclosing `cap_add:` /
// `environment:` block by indentation. Environment entries are handled before the single-line rules so an
// env var whose key happens to look like a directive (e.g. `PRIVILEGED: true`) is not misclassified.
func scanCompose(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	lines := strings.Split(string(data), "\n")

	service := ""
	serviceIndent := -1
	inServices := false
	capIndent := -1 // indent of the `cap_add:` key; >-1 means following list items are capabilities
	envIndent := -1 // indent of the `environment:` key
	res := func() string {
		if service == "" {
			return "compose service"
		}
		return "compose service " + service
	}

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ln := i + 1
		ind := indentOf(line)

		// Leaving a tracked block once indentation returns to or above the block key's level.
		if capIndent >= 0 && ind <= capIndent {
			capIndent = -1
		}
		if envIndent >= 0 && ind <= envIndent {
			envIndent = -1
		}

		if trimmed == "services:" && ind == 0 {
			inServices = true
			continue
		}
		// A new top-level section (networks:, volumes:, ...) ends the services block.
		if ind == 0 && trimmed != "services:" {
			inServices = false
		}
		// A service header: `  name:` (optionally with a YAML anchor) directly under services:.
		if inServices && reComposeServiceHead.MatchString(trimmed) {
			if serviceIndent == -1 {
				serviceIndent = ind
			}
			if ind == serviceIndent {
				service = reComposeServiceHead.FindStringSubmatch(trimmed)[1]
				capIndent, envIndent = -1, -1
				continue
			}
		}

		// Environment entries first: an env KEY must not be matched by the directive regexes below.
		if envIndent >= 0 {
			if f, ok := composeSecretEnv(line, rel, ln, res()); ok {
				out = append(out, f)
			}
			continue
		}
		// Capability list items under a cap_add: block.
		if capIndent >= 0 && reListItem.MatchString(line) {
			cap := reListItem.FindStringSubmatch(line)[1]
			if f, ok := dangerousCapFinding(strings.Trim(strings.TrimSpace(cap), `"'`), rel, ln, res()); ok {
				out = append(out, f)
			}
			continue
		}
		// Block openers.
		if trimmed == "environment:" {
			envIndent = ind
			continue
		}
		if m := reComposeCapAdd.FindStringSubmatch(line); m != nil {
			capIndent = ind
			if inline := strings.Trim(strings.TrimSpace(m[1]), "[]"); inline != "" { // inline `cap_add: [SYS_ADMIN]`
				for _, c := range strings.Split(inline, ",") {
					if f, ok := dangerousCapFinding(strings.Trim(strings.TrimSpace(c), `"'`), rel, ln, res()); ok {
						out = append(out, f)
					}
				}
			}
			continue
		}

		switch {
		case reComposePrivileged.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-privileged", "Privileged container", shared.SeverityHigh, res(),
				"A Compose service runs with privileged: true, which disables almost all container isolation (full device access, capabilities, and host kernel interfaces). Remove privileged and grant only the specific capabilities/devices the workload needs."))
		case reComposeNetHost.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-host-network", "Host network mode", shared.SeverityMedium, res(),
				"network_mode: host shares the host network namespace, so the container can bind host ports and reach loopback-only services, bypassing network isolation. Use a bridge/user-defined network and publish only the needed ports."))
		case reComposePIDHost.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-host-pid", "Host PID namespace", shared.SeverityMedium, res(),
				"pid: host shares the host process namespace, letting the container see and signal host processes. Remove it unless a debugging/monitoring workload genuinely requires host process visibility."))
		case reComposeIPCHost.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-host-ipc", "Host IPC namespace", shared.SeverityLow, res(),
				"ipc: host shares the host IPC namespace (shared memory, semaphores), weakening isolation between the container and the host. Remove it unless explicitly required."))
		case reComposeUsernsHost.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-userns-host", "User namespace isolation disabled", shared.SeverityMedium, res(),
				"userns_mode: host disables user-namespace remapping, so the container's root maps to host root. Remove it and rely on userns remapping (or run as a non-root user)."))
		case reComposeUnconfined.MatchString(line):
			out = append(out, mkCompose(rel, ln, "compose-unconfined-security-opt", "Container security profile disabled", shared.SeverityHigh, res(),
				"A security_opt disables a kernel confinement profile (seccomp/AppArmor unconfined, or SELinux label:disable), removing a major layer of syscall/host isolation. Keep the default profiles or supply a tailored one; do not disable them."))
		case strings.Contains(line, "/var/run/docker.sock"), strings.Contains(line, "/run/docker.sock"):
			out = append(out, mkCompose(rel, ln, "compose-docker-socket-mount", "Docker socket mounted into a container", shared.SeverityHigh, res(),
				"Mounting the Docker socket grants the container full control of the Docker daemon, which is equivalent to root on the host (it can start privileged containers or mount host paths). Avoid it; if unavoidable, use a locked-down socket proxy with a minimal allowlist."))
		case reComposeImage.MatchString(line):
			img := strings.Trim(reComposeImage.FindStringSubmatch(line)[1], `"'`)
			if img != "" && !strings.Contains(img, "$") && !strings.Contains(img, "@sha256:") {
				if tag := imageTag(img); tag == "" || tag == "latest" {
					out = append(out, mkCompose(rel, ln, "compose-image-unpinned", "Image is not version-pinned", shared.SeverityLow, res(),
						"The service image uses no tag or :latest, so a redeploy can silently pull a changed or vulnerable image. Pin an explicit version tag, ideally with an @sha256 digest."))
				}
			}
		}
	}
	return out
}

func mkCompose(rel string, line int, id, title string, sev shared.Severity, resource, desc string) ports.MisconfigRawFinding {
	return ports.MisconfigRawFinding{File: rel, Line: line, RuleID: id, Title: title, Severity: sev, Resource: resource, Description: desc}
}

func dangerousCapFinding(cap, rel string, line int, resource string) (ports.MisconfigRawFinding, bool) {
	if cap == "" || !dangerousCaps[strings.ToUpper(cap)] {
		return ports.MisconfigRawFinding{}, false
	}
	return mkCompose(rel, line, "compose-dangerous-capability", "Dangerous Linux capability added", shared.SeverityHigh, resource,
		"cap_add grants "+clip(strings.ToUpper(cap))+", a capability broad enough to escape or compromise the host (e.g. SYS_ADMIN, NET_ADMIN, or ALL). Drop it and add only narrowly-scoped capabilities the workload actually needs."), true
}

// composeSecretEnv flags a literal secret assigned in an environment: entry (list `- KEY=v` or map
// `KEY: v` form). A value that interpolates a variable ($X / ${X}) or is empty is not a baked secret.
func composeSecretEnv(line, rel string, ln int, resource string) (ports.MisconfigRawFinding, bool) {
	m := reComposeEnvKey.FindStringSubmatch(line)
	if m == nil {
		return ports.MisconfigRawFinding{}, false
	}
	key, val := m[1], strings.Trim(strings.TrimSpace(m[2]), `"'`)
	if !secretKeyRe.MatchString(key) {
		return ports.MisconfigRawFinding{}, false
	}
	if val == "" || strings.Contains(val, "$") {
		return ports.MisconfigRawFinding{}, false
	}
	return mkCompose(rel, ln, "compose-secret-in-env", "Secret hardcoded in environment", shared.SeverityMedium, resource,
		"A secret-looking environment key ("+clip(key)+") is assigned a literal value in the Compose file, so the credential lives in source control. Inject it at runtime via an env_file kept out of VCS, a secrets manager, or Docker/Compose secrets."), true
}

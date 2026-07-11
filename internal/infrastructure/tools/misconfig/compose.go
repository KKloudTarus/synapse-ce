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
	reComposePrivileged = regexp.MustCompile(`(?i)^\s*privileged\s*:\s*(?:"true"|'true'|true)\s*$`)
	reComposeNetHost    = regexp.MustCompile(`(?i)^\s*network_mode\s*:\s*["']?host["']?\s*$`)
	reComposePIDHost    = regexp.MustCompile(`(?i)^\s*pid\s*:\s*["']?host["']?\s*$`)
	reComposeIPCHost    = regexp.MustCompile(`(?i)^\s*ipc\s*:\s*["']?host["']?\s*$`)
	reComposeImage      = regexp.MustCompile(`(?i)^\s*image\s*:\s*(.+?)\s*$`)
	reComposeCapAdd     = regexp.MustCompile(`(?i)^\s*cap_add\s*:\s*(.*)$`)
	reComposeEnvKey     = regexp.MustCompile(`(?i)^\s*-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*(.+?)\s*$`)
	reListItem          = regexp.MustCompile(`^\s*-\s*(.+?)\s*$`)
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
// `environment:` block by indentation.
func scanCompose(rel string, data []byte) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	lines := strings.Split(string(data), "\n")

	service := ""     // current top-level service name (2-space indent under services:)
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

		if strings.HasPrefix(trimmed, "services:") && ind == 0 {
			inServices = true
			continue
		}
		// A new top-level section (networks:, volumes:, ...) ends the services block.
		if ind == 0 && !strings.HasPrefix(trimmed, "services:") {
			inServices = false
		}
		// A service header: `  name:` directly under services:.
		if inServices && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			if serviceIndent == -1 {
				serviceIndent = ind
			}
			if ind == serviceIndent {
				service = strings.TrimSuffix(trimmed, ":")
				capIndent, envIndent = -1, -1
				continue
			}
		}

		switch {
		case reComposePrivileged.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "compose-privileged", Title: "Privileged container",
				Severity: shared.SeverityHigh, Resource: res(),
				Description: "A Compose service runs with privileged: true, which disables almost all container isolation (full device access, capabilities, and host kernel interfaces). Remove privileged and grant only the specific capabilities/devices the workload needs.",
			})
		case reComposeNetHost.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "compose-host-network", Title: "Host network mode",
				Severity: shared.SeverityMedium, Resource: res(),
				Description: "network_mode: host shares the host network namespace, so the container can bind host ports and reach loopback-only services, bypassing network isolation. Use a bridge/user-defined network and publish only the needed ports.",
			})
		case reComposePIDHost.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "compose-host-pid", Title: "Host PID namespace",
				Severity: shared.SeverityMedium, Resource: res(),
				Description: "pid: host shares the host process namespace, letting the container see and signal host processes. Remove it unless a debugging/monitoring workload genuinely requires host process visibility.",
			})
		case reComposeIPCHost.MatchString(line):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "compose-host-ipc", Title: "Host IPC namespace",
				Severity: shared.SeverityLow, Resource: res(),
				Description: "ipc: host shares the host IPC namespace (shared memory, semaphores), weakening isolation between the container and the host. Remove it unless explicitly required.",
			})
		case strings.Contains(line, "/var/run/docker.sock"), strings.Contains(line, "/run/docker.sock"):
			out = append(out, ports.MisconfigRawFinding{
				File: rel, Line: ln, RuleID: "compose-docker-socket-mount", Title: "Docker socket mounted into a container",
				Severity: shared.SeverityHigh, Resource: res(),
				Description: "Mounting the Docker socket grants the container full control of the Docker daemon, which is equivalent to root on the host (it can start privileged containers or mount host paths). Avoid it; if unavoidable, use a locked-down socket proxy with a minimal allowlist.",
			})
		case reComposeCapAdd.MatchString(line):
			// Inline form `cap_add: [SYS_ADMIN]` or the start of a list block.
			m := reComposeCapAdd.FindStringSubmatch(line)
			capIndent = ind
			if inline := strings.Trim(strings.TrimSpace(m[1]), "[]"); inline != "" {
				for _, c := range strings.Split(inline, ",") {
					if f, ok := dangerousCapFinding(strings.TrimSpace(c), rel, ln, res()); ok {
						out = append(out, f)
					}
				}
			}
		case capIndent >= 0 && reListItem.MatchString(line):
			cap := reListItem.FindStringSubmatch(line)[1]
			if f, ok := dangerousCapFinding(strings.Trim(cap, `"'`), rel, ln, res()); ok {
				out = append(out, f)
			}
		case reComposeImage.MatchString(line):
			img := strings.Trim(reComposeImage.FindStringSubmatch(line)[1], `"'`)
			if img != "" && !strings.Contains(img, "$") && !strings.Contains(img, "@sha256:") {
				if tag := imageTag(img); tag == "" || tag == "latest" {
					out = append(out, ports.MisconfigRawFinding{
						File: rel, Line: ln, RuleID: "compose-image-unpinned", Title: "Image is not version-pinned",
						Severity: shared.SeverityLow, Resource: res(),
						Description: "The service image uses no tag or :latest, so a redeploy can silently pull a changed or vulnerable image. Pin an explicit version tag, ideally with an @sha256 digest.",
					})
				}
			}
		case strings.HasSuffix(trimmed, "environment:"):
			envIndent = ind
		case envIndent >= 0:
			if f, ok := composeSecretEnv(line, rel, ln, res()); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func dangerousCapFinding(cap, rel string, line int, resource string) (ports.MisconfigRawFinding, bool) {
	if cap == "" || !dangerousCaps[strings.ToUpper(cap)] {
		return ports.MisconfigRawFinding{}, false
	}
	return ports.MisconfigRawFinding{
		File: rel, Line: line, RuleID: "compose-dangerous-capability", Title: "Dangerous Linux capability added",
		Severity: shared.SeverityHigh, Resource: resource,
		Description: "cap_add grants " + clip(strings.ToUpper(cap)) + ", a capability broad enough to escape or compromise the host (e.g. SYS_ADMIN, NET_ADMIN, or ALL). Drop it and add only narrowly-scoped capabilities the workload actually needs.",
	}, true
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
	return ports.MisconfigRawFinding{
		File: rel, Line: ln, RuleID: "compose-secret-in-env", Title: "Secret hardcoded in environment",
		Severity: shared.SeverityMedium, Resource: resource,
		Description: "A secret-looking environment key (" + clip(key) + ") is assigned a literal value in the Compose file, so the credential lives in source control. Inject it at runtime via an env_file kept out of VCS, a secrets manager, or Docker/Compose secrets.",
	}, true
}

// Package imageconfig runs owned hardening checks over a scanned container image's configuration and build
// history (EPIC #860 D7.10): a container that runs as root, a credential baked into an environment variable,
// and a sensitive build command (a remote script piped to a shell, or an ADD of a remote URL). It needs no
// filesystem walk: it reads only sbom.ImageInfo, which the acquirer already recovered from the OCI image
// config. Findings are deterministic and, like the misconfig scanner's, are ungated presence facts.
//
// This package also owns the credential redaction the acquirer applies BEFORE persisting the config, so a
// baked-in secret never reaches stored scan data: env values and build-command strings are scrubbed of
// recognized credentials (RedactEnv / RedactCommand), and the check keys off that redaction rather than a
// key-name heuristic, so a config knob like PASSWORD_MIN_LENGTH is never a false "secret in ENV".
package imageconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// secretValuePatterns are distinctive, high-confidence credential shapes. Detection is VALUE-based (never on a
// variable NAME), so it is precise: it flags an actual token/key/URL-credential, not a config knob whose name
// merely contains "password" or "token". A generic high-entropy string without a recognizable shape is NOT
// matched, keeping false positives at zero at the cost of some recall (the secret scanner covers the workspace).
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                               // AWS access key id
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),                               // AWS temporary access key id
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                     // GitHub PAT / OAuth / app tokens
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),                   // GitHub fine-grained PAT
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                   // Slack tokens
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{16,}`),                       // GitLab PAT
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),                          // Google API key
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.`), // JWT (header.payload.)
	// The WHOLE PEM block, so a build-command redaction scrubs the key body/footer too, not just the header.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
}

// urlUserinfo matches the "user:password@" credential after a URL's "//", capturing the leading "//" so a
// build-command redaction keeps the scheme+authority structure (a downstream check like remote-ADD still
// matches) while scrubbing only the credential.
var urlUserinfo = regexp.MustCompile(`(//)[^/\s:@]+:[^/\s:@]+@`)

// secretRedacted is the sentinel an env value is replaced with when it holds a recognized credential. The
// check flags an env entry whose value is exactly this sentinel, so detection and the finding stay in lockstep.
const secretRedacted = "<redacted>"

// pipeToShell matches a build command that pipes a downloaded script straight into a shell (curl … | sh),
// the classic unverified-remote-code install step.
var pipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b`)

// remoteAdd matches a Dockerfile ADD of a remote URL (bypasses checksum verification and can smuggle content).
var remoteAdd = regexp.MustCompile(`(?i)\bADD\s+https?://`)

// RedactEnv returns a copy of the image config env with the VALUE of any entry holding a recognized credential
// replaced by the redaction sentinel, so a baked-in secret never reaches persisted scan data while the key is
// preserved for the hardening finding. A non-credential value (a path, a flag, a DSN with no inline password)
// is kept verbatim.
func RedactEnv(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		key, value, ok := strings.Cut(e, "=")
		if ok && looksLikeSecretValue(value) {
			out = append(out, key+"="+secretRedacted)
			continue
		}
		out = append(out, e)
	}
	return out
}

// RedactCommand scrubs recognized credentials out of a build-command string (e.g. a token in a URL, an
// Authorization header, a PEM block) while leaving the command structure intact, so a build step can still be
// pattern-matched and shown without persisting a secret.
func RedactCommand(cmd string) string {
	for _, re := range tokenPatterns {
		cmd = re.ReplaceAllString(cmd, "***")
	}
	cmd = urlUserinfo.ReplaceAllString(cmd, "//***@") // keep the "//" (and thus the scheme) so structure survives
	return cmd
}

func looksLikeSecretValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, re := range tokenPatterns {
		if re.MatchString(v) {
			return true
		}
	}
	return urlUserinfo.MatchString(v)
}

// isRootUser reports whether a config.User value leaves the container running as the superuser: unset, or a
// user component (the part before an optional ":group") of "root" or uid "0".
func isRootUser(user string) bool {
	u := strings.TrimSpace(user)
	if u == "" {
		return true
	}
	if i := strings.IndexByte(u, ':'); i >= 0 { // "user:group" — only the user component decides root
		u = u[:i]
	}
	u = strings.ToLower(strings.TrimSpace(u))
	return u == "root" || u == "0"
}

// Checker is the owned image-config hardening checker. It holds no state.
type Checker struct{}

var _ ports.ImageConfigChecker = (*Checker)(nil)

// New returns a Checker.
func New() *Checker { return &Checker{} }

// Check implements ports.ImageConfigChecker.
func (Checker) Check(info *sbom.ImageInfo) []ports.MisconfigRawFinding { return Check(info) }

// Check returns the hardening findings for an image's config and history, or nil for a non-image / empty
// info. It is pure and deterministic. Each finding is a first-party presence fact (like the misconfig scanner's).
func Check(info *sbom.ImageInfo) []ports.MisconfigRawFinding {
	if info == nil {
		return nil
	}
	var out []ports.MisconfigRawFinding

	// Runs as root: no USER, or an explicit root/uid-0 (with or without a group).
	if isRootUser(info.User) {
		out = append(out, ports.MisconfigRawFinding{
			RuleID: "image-runs-as-root", Title: "Container image runs as root", Severity: shared.SeverityMedium,
			Resource:    "image config USER",
			Description: "The image sets no non-root USER, so its default runtime user is root. A compromise of the process then has full container privileges. Add a USER directive that drops to a dedicated non-root, non-zero uid.",
		})
	}

	// Credential baked into an environment variable: the value was replaced with the redaction sentinel at read
	// time (a recognized credential was detected), so the finding names the key without ever seeing the secret.
	for _, e := range info.Env {
		key, value, ok := strings.Cut(e, "=")
		if ok && value == secretRedacted {
			out = append(out, ports.MisconfigRawFinding{
				RuleID: "image-secret-in-env", Title: "Credential baked into an image environment variable", Severity: shared.SeverityHigh,
				Resource:    "image config ENV " + strings.TrimSpace(key),
				Description: "The environment variable " + strings.TrimSpace(key) + " holds a credential baked into the image, readable by anyone who can pull it and visible in `docker inspect`. Inject secrets at runtime (a mounted secret or an orchestrator secret), never in the image ENV.",
			})
		}
	}

	// Sensitive build commands in the image history (already credential-scrubbed by the acquirer).
	for _, layer := range info.Layers {
		cmd := layer.CreatedBy
		if cmd == "" {
			continue
		}
		switch {
		case pipeToShell.MatchString(cmd):
			out = append(out, ports.MisconfigRawFinding{
				RuleID: "image-pipe-to-shell", Title: "Build step pipes a remote script into a shell", Severity: shared.SeverityMedium,
				Resource:    truncateCmd(cmd),
				Description: "A build step downloads a script and executes it directly (curl … | sh), running unverified remote code at build time. Download to a file, verify a checksum or signature, then execute.",
			})
		case remoteAdd.MatchString(cmd):
			out = append(out, ports.MisconfigRawFinding{
				RuleID: "image-add-remote-url", Title: "Build step ADDs a remote URL", Severity: shared.SeverityMedium,
				Resource:    truncateCmd(cmd),
				Description: "A build step ADDs content from a remote URL, which is fetched with no checksum verification and can change under the image. Fetch with a pinned checksum (RUN curl + sha256 check), or COPY a vendored copy.",
			})
		}
	}
	return out
}

// truncateCmd bounds a build-command string for a finding's Resource label.
func truncateCmd(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if len(cmd) > 160 {
		return cmd[:160] + "…"
	}
	return cmd
}

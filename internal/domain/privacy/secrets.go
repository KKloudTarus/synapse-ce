package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// secretPattern is a compiled redaction rule: match sensitive text and replace it with `repl`, where `repl`
// may reference capture groups (e.g. ${1}) so a key/prefix is kept while only its value is scrubbed. All
// patterns are RE2 (Go regexp): no backreferences or lookaround, so match time is linear and safe on
// attacker-influenced argv.
type secretPattern struct {
	re   *regexp.Regexp
	repl string
}

// secretPatterns is the curated, low-false-positive set applied to allowed string values. It targets the
// structured ways secrets appear on a command line — keyed assignments (incl. underscore/dash-joined
// env-style keys like DB_PASSWORD / aws_secret_access_key), CLI credential flags (incl. mysql-style -p),
// connection strings, bearer tokens, cloud access-key ids, and PEM private-key blocks — keeping the
// surrounding forensic context (a captured leading delimiter, the key/flag name, the connection host)
// while removing the secret itself.
var secretPatterns = []secretPattern{
	// key=value / key: value. The keyword may be joined to a prefix by '_' or '-' (DB_PASSWORD=,
	// aws_secret_access_key:), so the lead delimiter is a captured class (start | space | quote | separator |
	// _ | -) that is preserved in the replacement rather than a \b (which does not break between '_' and a
	// letter and would miss the canonical env-var-as-argv form).
	{regexp.MustCompile(`(?i)(^|[\s"'=:,;/\\_-])((?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token|client[-_]?secret|credential)\s*[=:]\s*)([^\s"']+)`), `${1}${2}` + RedactionPlaceholder},
	// CLI credential flags with an INLINE value: --password=X, --token:X, and the single-token
	// "--password X" form. The space-separated form where the value is a SEPARATE argv element is handled
	// cross-element by scrubArgv (per-element scanning cannot see the next element). A bare "-p" short flag
	// is deliberately NOT matched here: it is too ambiguous (-progress, -port, tar -pxf, cp -pr) and would
	// destroy forensic context; glued `-pSECRET` is a documented residual covered by --password/env/=forms.
	{regexp.MustCompile(`(?i)(^|\s)(--?(?:password|passwd|pwd|token|secret|api[-_]?key|auth)[=: ]\s*)([^\s"']+)`), `${1}${2}` + RedactionPlaceholder},
	// connection string credentials: scheme://user:PASSWORD@host  → redact only the password
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)([^\s:/@]+)(@)`), `${1}` + RedactionPlaceholder + `${3}`},
	// bearer tokens
	{regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._~+/=\-]{8,})`), `${1}` + RedactionPlaceholder},
	// AWS access key id
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), RedactionPlaceholder},
	// PEM private key block (single or multi-line)
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), RedactionPlaceholder},
}

// credentialFlag matches an argv element that is EXACTLY a credential-passing flag with no inline value, so
// the FOLLOWING argv element (its value) must be redacted — this catches the very common space-separated
// `--password secret` form that a per-element scan cannot see (each element scanned in isolation).
var credentialFlag = regexp.MustCompile(`(?i)^--?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token|client[-_]?secret|credential)$`)

// IsCredentialFlag reports whether an argv element is a lone credential flag whose next element is a value
// to redact.
func IsCredentialFlag(arg string) bool { return credentialFlag.MatchString(arg) }

// scrubSecrets applies every secret pattern to value, returning the scrubbed string and whether anything
// changed. It is idempotent: re-scrubbing already-redacted text is a no-op (the placeholder matches no
// pattern), so a re-normalized/replayed event redacts to byte-identical output.
func scrubSecrets(value string) (string, bool) {
	if value == "" {
		return value, false
	}
	out := value
	for _, p := range secretPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out, out != value
}

// hashValue is the DispositionHash transform: a salted digest that preserves correlation (same salt+value
// → same output) without revealing the cleartext. The salt is domain-separated from the value with 0x1e.
func hashValue(salt, value string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte{0x1e})
	h.Write([]byte(value))
	return "h:" + hex.EncodeToString(h.Sum(nil))[:32]
}

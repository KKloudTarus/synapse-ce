package sast

import (
	"regexp"
	"strings"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// rule is one deterministic pattern check: a regex over a source line plus the finding metadata it
// yields. skipFn is an optional false-positive filter (e.g. drop env-ref "secrets"). exts, when non-nil,
// restricts the rule to those file extensions (lower-case, dot-prefixed) so a language-specific idiom
// (e.g. a C string function) can't false-positive on a same-named safe function in another language.
//
// rtype/rquality classify the finding. They are optional: the zero value means a security vulnerability
// (Vulnerability + Security), which is what the security-focused tier-1 rules are. Correctness/style
// rules set them explicitly (e.g. Bug+Reliability, CodeSmell+Maintainability).
type rule struct {
	id       string
	cwe      string
	severity shared.Severity
	title    string
	desc     string
	re       *regexp.Regexp
	skipFn   func(line string) bool
	exts     map[string]bool
	rtype    domainrule.Type
	rquality domainrule.Quality
}

// ruleType returns the finding type, defaulting to a security vulnerability.
func (r *rule) ruleType() domainrule.Type {
	if r.rtype == "" {
		return domainrule.TypeVulnerability
	}
	return r.rtype
}

// ruleQuality returns the finding quality, defaulting to the security dimension.
func (r *rule) ruleQuality() domainrule.Quality {
	if r.rquality == "" {
		return domainrule.QualitySecurity
	}
	return r.rquality
}

func (r *rule) skip(line string) bool { return r.skipFn != nil && r.skipFn(line) }

// appliesTo reports whether the rule runs on a file with the given (lower-case) extension. A nil exts
// means language-agnostic (every file).
func (r *rule) appliesTo(ext string) bool { return r.exts == nil || r.exts[ext] }

// cSourceExts are the C/C++/Objective-C source and header extensions that the C-specific rules gate on.
var cSourceExts = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true, ".hh": true,
	".hxx": true, ".m": true, ".mm": true,
}

// pyExts / jsExts gate rules whose sink or idiom belongs to a single language ecosystem, so a
// Python- or JS/TS-specific pattern (SQLAlchemy, Prisma, React/DOM, node-serialize, ...) can never
// false-positive on a same-named construct in another language (e.g. the "Python SQLAlchemy" rule
// firing on a .java file, or a Prisma rule on Go). nil exts stays language-agnostic.
var pyExts = map[string]bool{".py": true, ".pyi": true, ".pyw": true, ".pyx": true}
var javaExts = map[string]bool{".java": true}
var jsExts = map[string]bool{
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true, // .mts/.cts are first-class TS ESM/CJS extensions
	".vue": true, ".svelte": true, ".astro": true, // single-file components embed JS/TS
}

// placeholderSecret drops obvious non-secrets (env refs, templating, placeholders) so the
// hardcoded-credential rule stays high-signal – deterministic findings are publishable directly
// (no AI gate), so precision matters more than recall here.
func placeholderSecret(line string) bool {
	l := strings.ToLower(line)
	for _, marker := range []string{
		"os.environ", "os.getenv", "getenv", "process.env", "secretmanager", "vault",
		"${", "{{", "%(", "<%", "example", "changeme", "change_me", "changeit", "placeholder",
		"redacted", "your_", "xxxx", "dummy", "notreal", "fake", "sample", "localhost",
		"127.0.0.1", "password123", "secret123", "abc123", "test123",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

// commentOnlyLine suppresses rules where a plain comment mention is a noisy false positive.
func commentOnlyLine(line string) bool {
	l := strings.TrimSpace(line)
	return strings.HasPrefix(l, "//") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "*") ||
		strings.HasPrefix(l, "/*") || strings.HasPrefix(l, "--")
}

func commentOrTestPlaceholder(line string) bool {
	l := strings.ToLower(line)
	if commentOnlyLine(line) {
		return true
	}
	for _, marker := range []string{"test", "spec", "fixture", "mock", "dummy", "example", "sample"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func safePathAccess(line string) bool {
	l := strings.ToLower(line)
	return commentOnlyLine(line) || strings.Contains(l, "path.join(") || strings.Contains(l, "filepath.join(") || strings.Contains(l, "safejoin")
}

func safeLDAPFilter(line string) bool {
	l := strings.ToLower(line)
	return commentOnlyLine(line) || strings.Contains(l, "escape_filter_chars(") ||
		strings.Contains(l, "escapefilter(") || strings.Contains(l, "ldapencoder.filterencode(")
}

// builtinRules is the tier-1 (cheap, deterministic) rule set: high-signal weaknesses across common
// languages. Intentionally precision-biased – taint/dataflow + broader coverage is the AI/E39 tier.
// redosContextRe marks a line that constructs or uses a regular expression, so the ReDoS rule only fires
// on actual regex text and never on ordinary parenthesised arithmetic like (a + b) * c.
var redosContextRe = regexp.MustCompile(`(?i)(regexp\.|RegExp|re\.(compile|match|search|fullmatch)|Pattern\.compile|MustCompile|preg_match|\.match\(|\.test\(|=~)`)

// skipUnlessRegexContext skips a line that is a comment or does not look like regex construction.
func skipUnlessRegexContext(line string) bool {
	return commentOnlyLine(line) || !redosContextRe.MatchString(line)
}

func builtinRules() []rule {
	core := []rule{
		{
			id: "weak-hash-md5", cwe: "CWE-327", severity: shared.SeverityMedium, title: "Weak hash: MD5",
			desc: "MD5 is cryptographically broken; use SHA-256+ for integrity/signatures and a salted KDF (bcrypt/scrypt/argon2) for passwords.",
			re:   regexp.MustCompile(`(?i)(crypto/md5|hashlib\.md5\(|md5\.new\(|MessageDigest\.getInstance\(\s*"MD5"|CryptoJS\.MD5)`),
		},
		{
			id: "weak-hash-sha1", cwe: "CWE-327", severity: shared.SeverityMedium, title: "Weak hash: SHA-1",
			desc: "SHA-1 is collision-vulnerable; use SHA-256 or stronger.",
			re:   regexp.MustCompile(`(?i)(crypto/sha1|hashlib\.sha1\(|sha1\.new\(|MessageDigest\.getInstance\(\s*"SHA-?1")`),
		},
		{
			id: "weak-cipher", cwe: "CWE-327", severity: shared.SeverityHigh, title: "Weak cipher: DES/3DES/RC4",
			desc: "DES/3DES/RC4 are insecure; use AES-GCM or ChaCha20-Poly1305.",
			re:   regexp.MustCompile(`(?i)(crypto/des|crypto/rc4|getInstance\(\s*"DES|getInstance\(\s*"RC4|\bDESede\b)`),
		},
		{
			id: "insecure-tls-verify-disabled", cwe: "CWE-295", severity: shared.SeverityHigh, title: "TLS certificate verification disabled",
			desc: "Disabling certificate verification enables machine-in-the-middle attacks; verify certificates in production.",
			re:   regexp.MustCompile(`(?i)(InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))`),
		},
		{
			id: "debug-mode-enabled", cwe: "CWE-489", severity: shared.SeverityMedium, title: "Active debug mode enabled",
			desc: "Debug mode is enabled in source (verbose errors, interactive debuggers, stack traces leak internals). Disable it in production builds.",
			// High-signal forms only: a literal debug=true assignment (Django/Flask/generic), Flask app.run(debug=True),
			// and Gin's debug mode. \b avoids is_debug/app_debug; env-derived RHS (debug=os.getenv(...)) never matches "true".
			re: regexp.MustCompile(`(?i)(\bdebug\s*=\s*true\b|app\.run\([^)]*debug\s*=\s*true|gin\.SetMode\(\s*gin\.DebugMode\s*\))`),
		},
		{
			id: "permissive-cors-wildcard", cwe: "CWE-942", severity: shared.SeverityMedium, title: "Permissive CORS: wildcard origin",
			desc: "CORS allows any origin (\"*\"); restrict it to trusted domains. Combined with credentialed requests this enables cross-site data theft.",
			// Matches the ACAO header/Set form (Access-Control-Allow-Origin: * or Set(\"...\", \"*\")) and a Go
			// AllowedOrigins config carrying a literal \"*\" on the same line. A specific origin never matches.
			re: regexp.MustCompile(`(?i)(Access-Control-Allow-Origin["']?\s*[:,]?\s*["']?\*|AllowedOrigins\b[^\n]*["']\*["'])`),
		},
		{
			id: "hardcoded-aws-access-key", cwe: "CWE-798", severity: shared.SeverityCritical, title: "Hardcoded AWS access key id",
			desc: "An AWS access key id is embedded in source. Rotate it immediately and load credentials from the environment or a secrets manager.",
			re:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		},
		{
			id: "private-key-material", cwe: "CWE-798", severity: shared.SeverityCritical, title: "Private key material in source",
			desc: "A PEM private-key block is embedded in source. Remove it from the repository and rotate the key.",
			re:   regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		},
		{
			id: "hardcoded-credential", cwe: "CWE-798", severity: shared.SeverityHigh, title: "Possible hardcoded credential",
			desc:   "A credential appears to be assigned a literal value. Load secrets from the environment or a vault instead of embedding them.",
			re:     regexp.MustCompile(`(?i)\b(password|passwd|pwd|api[_-]?key|secret|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']`),
			skipFn: placeholderSecret,
		},
		{
			id: "password-md5-hash", cwe: "CWE-916", severity: shared.SeverityMedium, title: "Password hashed with unsalted MD5",
			desc:   "MD5 is not a password hashing function and is fast to brute force. Store passwords with a salted adaptive KDF such as Argon2id, bcrypt, or scrypt.",
			re:     regexp.MustCompile(`(?i)(\b(password|passwd|pwd|newPassword|currentPassword)\b[^\n]{0,80}\bmd5\s*\(|\bmd5\s*\(\s*(password|passwd|pwd|newPassword|currentPassword|req\.body\.password))`),
			skipFn: commentOnlyLine,
		},
		{
			id: "prisma-raw-sql-unsafe", cwe: "CWE-89", severity: shared.SeverityCritical, title: "Raw SQL query uses unsafe Prisma API",
			desc:   "Prisma $queryRawUnsafe executes string-built SQL. If request-controlled values reach the query string this is SQL injection; use parameterized $queryRaw or Prisma query builders.",
			re:     regexp.MustCompile(`(?i)\$queryRawUnsafe\s*(<[^>]+>)?\s*[\(\x60]`),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "template-sql-interpolation", cwe: "CWE-89", severity: shared.SeverityCritical, title: "SQL string interpolates dynamic data",
			desc:   "A SQL-like string contains template interpolation. Verify the interpolated value is not attacker-controlled; prefer parameterized queries.",
			re:     regexp.MustCompile(`(?i)\b(SELECT\s+.+\s+FROM|UPDATE\s+\w+\s+SET|DELETE\s+FROM|INSERT\s+INTO)\b[^\n]*\$\{[^}]+}`),
			skipFn: commentOnlyLine,
		},
		{
			id: "generic-sql-dynamic-execute", cwe: "CWE-89", severity: shared.SeverityHigh, title: "SQL execution uses dynamic string construction",
			desc: "A SQL execution sink appears to receive a string built from request/user-controlled data. Use parameterized queries or ORM query builders.",
			// The evidence must be a request/interpolation marker, an f-string, OR a string literal that is
			// then combined dynamically: `"..." +` (concat), `"..." . $var` (PHP concat), or
			// `"...".format(` (Python). A bare `.` used to count as evidence, which flagged any
			// `x.execute(y.z(...))` – notably java.util.concurrent Executor.execute(Runnable) – as SQL
			// injection; anchoring the concat markers to a preceding quote keeps the JDBC/DBAPI/PHP/Python
			// true positives while dropping the executor/worker false positives. (Bare `%` is deliberately
			// excluded: it false-positives on constant `LIKE '%x%'` queries.)
			re:     regexp.MustCompile(`(?i)(cursor\.execute|execute(Query|Update)?|mysqli_query|pg_query|sequelize\.query|ActiveRecord::Base\.connection\.execute)\s*\([^;\n]*(request\.|req\.|params\[|\$_(GET|POST|REQUEST)|\$\{|#\{|\bf["'` + "`" + `]|["'` + "`" + `][^;\n]*(\+|\.\s*\$|\.format\s*\())`),
			skipFn: commentOnlyLine,
		},
		{
			id: "go-sql-dynamic-query", cwe: "CWE-89", severity: shared.SeverityHigh, title: "Go SQL query uses dynamic string construction",
			desc:   "A Go database/sql query appears to use string concatenation, fmt.Sprintf, or request-derived data. Use placeholders and parameter binding.",
			re:     regexp.MustCompile(`(?i)\.(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)\s*\([^;\n]*(\+|fmt\.Sprintf|FormValue|PostFormValue|URL\.Query|c\.(Query|Param))`),
			skipFn: commentOnlyLine,
		},
		{
			id: "sqlalchemy-raw-sql-dynamic", cwe: "CWE-89", severity: shared.SeverityHigh, title: "Python SQLAlchemy/raw SQL uses dynamic string construction",
			desc:   "SQLAlchemy/session execution appears to receive dynamically formatted SQL. Use bound parameters instead of f-strings, concatenation, or request-derived interpolation.",
			re:     regexp.MustCompile(`(?i)(session\.execute|connection\.execute|db\.session\.execute|text)\s*\([^;\n]*(f["']|%|\+|\.format\s*\(|request\.|params\[)`),
			skipFn: commentOnlyLine,
			exts:   pyExts,
		},
		{
			id: "child-process-exec-template", cwe: "CWE-78", severity: shared.SeverityCritical, title: "Shell command uses template interpolation",
			desc:   "child_process.exec runs through a shell. Interpolating paths, filenames, request fields, or other variables can enable command injection; use execFile/spawn with argv and strict validation.",
			re:     regexp.MustCompile("(?i)\\bexec\\s*\\(\\s*`[^`]*\\$\\{[^}]+}[^`]*`"),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "generic-command-injection-sink", cwe: "CWE-78", severity: shared.SeverityHigh, title: "Command execution sink receives dynamic input",
			desc:   "A command execution API appears to receive request/user-controlled or dynamically concatenated input. Avoid shell execution; use argv arrays and strict allowlists.",
			re:     regexp.MustCompile(`(?i)(os\.system|subprocess\.(run|Popen|call|check_output)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|system|shell_exec|passthru)\s*\([^;\n]*(\+|%|\$\{|f["']|request\.|req\.|params\[|\$_(GET|POST|REQUEST)|shell\s*=\s*True)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "go-command-dynamic", cwe: "CWE-78", severity: shared.SeverityHigh, title: "Go command execution receives dynamic input",
			desc:   "exec.Command/CommandContext appears to receive request-derived or dynamically built arguments. Use fixed argv templates and strict allowlists.",
			re:     regexp.MustCompile(`(?i)exec\.Command(Context)?\s*\([^;\n]*(FormValue|PostFormValue|URL\.Query|c\.(Query|Param)|\+|fmt\.Sprintf|[A-Za-z_$][\w$]*)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "unsafe-deserialization-node-serialize", cwe: "CWE-502", severity: shared.SeverityHigh, title: "Unsafe node-serialize deserialization",
			desc:   "node-serialize unserialize() can execute attacker-controlled JavaScript payloads. Never deserialize untrusted request data with this package.",
			re:     regexp.MustCompile(`(?i)\bunserialize\s*\(`),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "unsafe-deserialization-generic", cwe: "CWE-502", severity: shared.SeverityHigh, title: "Unsafe deserialization of potentially untrusted data",
			desc:   "Unsafe deserialization APIs can execute code or instantiate attacker-controlled objects. Use safe parsers and schema validation for untrusted input.",
			re:     regexp.MustCompile(`(?i)(pickle\.loads?\s*\(|yaml\.load\s*\([^,\n]*(Loader\s*=\s*yaml\.Loader|Loader\s*=\s*Loader)?|ObjectInputStream\s*\(|BinaryFormatter\s*\(|Marshal\.load\s*\(|unserialize\s*\(\s*\$_(GET|POST|REQUEST))`),
			skipFn: commentOnlyLine,
		},
		{
			id: "ssrf-fetch-user-url", cwe: "CWE-918", severity: shared.SeverityHigh, title: "Server-side fetch of user-controlled URL",
			desc:   "A server-side fetch appears to use a generic url variable or request field. Validate scheme/host, block private networks/metadata IPs, and proxy through an allowlist.",
			re:     regexp.MustCompile(`(?i)\b(fetch|axios\.(get|post|put|request))\s*\(\s*([A-Za-z_$][\w$]*|url\b|req\.(body|query|params)|.*\burl\b)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "generic-ssrf-request-url", cwe: "CWE-918", severity: shared.SeverityHigh, title: "Server-side request uses request-controlled URL",
			desc:   "An outbound HTTP/file fetch appears to use request-controlled URL data. Apply URL allowlists, private-network blocking, and redirect controls.",
			re:     regexp.MustCompile(`(?i)(requests\.(get|post|put|request)|http\.Get|http\.Post|RestTemplate\.(getFor|exchange|postFor)|file_get_contents|curl_exec|URI\.open)\s*\([^;\n]*(request\.|req\.|params\[|r\.URL\.Query|c\.Query|\$_(GET|POST|REQUEST)|url)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "go-ssrf-dynamic-url", cwe: "CWE-918", severity: shared.SeverityHigh, title: "Go server-side request uses dynamic URL",
			desc:   "A Go outbound HTTP request appears to use a dynamic URL. Validate scheme/host, block private networks/metadata IPs, and apply allowlists.",
			re:     regexp.MustCompile(`(?i)http\.(Get|Post|Head)\s*\(\s*[A-Za-z_$][\w$]*`),
			skipFn: commentOnlyLine,
		},
		{
			id: "react-dangerous-html", cwe: "CWE-79", severity: shared.SeverityHigh, title: "React renders unsanitized HTML",
			desc:   "dangerouslySetInnerHTML bypasses React escaping. Ensure the value is sanitized server-side and client-side before rendering untrusted content.",
			re:     regexp.MustCompile(`\bdangerouslySetInnerHTML\b`),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "reflected-response-write", cwe: "CWE-79", severity: shared.SeverityHigh, title: "Response writes potentially unescaped request data",
			desc:   "A response sink appears to write request-controlled data. Ensure framework auto-escaping applies or explicitly HTML-escape before writing.",
			re:     regexp.MustCompile(`(?i)(res\.(send|end|write)|response\.write|HttpResponse|w\.Write)\s*\([^;\n]*(req\.|request\.|params\[|\$_(GET|POST|REQUEST)|FormValue|URL\.Query|c\.(Query|Param)|[A-Za-z_$][\w$]*)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "server-template-injection", cwe: "CWE-1336", severity: shared.SeverityHigh, title: "Template rendering uses dynamic template text",
			desc:   "Rendering attacker-controlled template text can lead to server-side template injection. Render fixed templates and pass user data as escaped variables.",
			re:     regexp.MustCompile(`(?i)(render_template_string|jinja2\.Template|engines\[['"][^'"]+['"]\]\.from_string|ERB\.new)\s*\([^;\n]*(request\.|req\.|params\[|\$_(GET|POST|REQUEST)|\+|%|\$\{)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "password-reset-token-disclosure", cwe: "CWE-640", severity: shared.SeverityCritical, title: "Password reset token may be disclosed",
			desc:   "A reset/debug token appears to be returned or logged. Password reset tokens must never be exposed through API responses, logs, or debug output.",
			re:     regexp.MustCompile(`(?i)(debug[_-]?token|debugToken|\b(logger|console)\.(info|log|warn|error|debug)\s*\([^)]*(resetUrl|token))`),
			skipFn: commentOnlyLine,
		},
		{
			id: "sensitive-data-logging", cwe: "CWE-532", severity: shared.SeverityMedium, title: "Sensitive data written to logs",
			desc:   "Logging passwords, tokens, secrets, or reset URLs can leak credentials through log pipelines. Redact or omit sensitive fields.",
			re:     regexp.MustCompile(`(?i)\b(logger|console)\.(info|log|warn|error|debug)\s*\([^)]*(password|token|secret|resetUrl)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "insecure-cookie-flags", cwe: "CWE-614", severity: shared.SeverityMedium, title: "Session cookie uses insecure flags",
			desc:   "Session cookies should generally be HttpOnly, Secure on HTTPS, and SameSite=Lax/Strict unless a reviewed cross-site flow requires otherwise.",
			re:     regexp.MustCompile(`(?i)(httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['"]none['"])`),
			skipFn: commentOnlyLine,
		},
		{
			id: "jwt-hardcoded-secret-or-none", cwe: "CWE-347", severity: shared.SeverityHigh, title: "JWT uses hardcoded secret or insecure algorithm",
			desc:   "JWT signing/verifying with a hardcoded weak secret or accepting the none algorithm can allow token forgery. Use managed secrets and enforce strong algorithms.",
			re:     regexp.MustCompile(`(?i)(jwt\.(sign|verify)\s*\([^,\n]+,\s*["'](secret|changeme|password|jwt[_-]?secret|test)["']|algorithm\s*[:=]\s*["']none["']|algorithms\s*[:=]\s*\[[^\]]*["']none["'])`),
			skipFn: commentOrTestPlaceholder,
		},
		{
			id: "path-traversal-file-access", cwe: "CWE-22", severity: shared.SeverityHigh, title: "File path access uses request-controlled input",
			desc:   "A filesystem read/write/send operation appears to use request-controlled path data. Normalize, constrain to an allowlisted base directory, and reject traversal.",
			re:     regexp.MustCompile(`(?i)(readFile|writeFile|createReadStream|sendFile|send_file|File\.open|open\s*\(|os\.Open|ioutil\.ReadFile|Files\.(read|write)|new File)\s*\([^;\n]*(req\.|request\.|params\[|r\.URL\.Query|c\.Query|\$_(GET|POST|REQUEST)|filename|filepath|\bfile\b|\bpath\b)`),
			skipFn: safePathAccess,
		},
		{
			id: "possible-idor-prisma-id-only", cwe: "CWE-639", severity: shared.SeverityHigh, title: "Possible object-level authorization gap",
			desc:   "A Prisma find/update/delete operation appears to select an object by id only. For user-owned resources, include an owner/tenant/role predicate or perform an explicit authorization check.",
			re:     regexp.MustCompile(`(?i)prisma\.\w+\.(findUnique|update|delete)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*[:}]`),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "mass-assignment-request-body", cwe: "CWE-915", severity: shared.SeverityMedium, title: "Mass assignment from request body",
			desc:   "Passing an entire request body into create/update/model constructors can allow privilege or ownership field overwrite. Whitelist assignable fields explicitly.",
			re:     regexp.MustCompile(`(?i)(\.(create|update)\s*\([^;\n]*(data\s*:\s*req\.body|req\.body)|new\s+\w+\s*\(\s*req\.body|\b[A-Z]\w*\.create\s*\(\s*params|update_attributes\s*\(\s*params)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "xxe-insecure-xml-parsing", cwe: "CWE-611", severity: shared.SeverityHigh, title: "XML parser resolves external entities (XXE)",
			desc:   "An XML parser is explicitly configured to resolve external entities or expand DTDs, enabling XXE (file read, SSRF, DoS). Disable DOCTYPE/external-entity processing on the parser.",
			re:     regexp.MustCompile(`(?i)(resolve_entities\s*=\s*True|libxml_disable_entity_loader\s*\(\s*false|setExpandEntityReferences\s*\(\s*true|\bLIBXML_NOENT\b|setFeature\s*\(\s*["'][^"']*(external-general-entities|load-external-dtd)["']\s*,\s*true)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "dynamic-code-eval", cwe: "CWE-95", severity: shared.SeverityCritical, title: "Dynamic code evaluation of untrusted input",
			desc:   "eval() runs its argument as code. When request-controlled or externally-read data reaches it this is remote code execution; parse the value explicitly instead of evaluating it.",
			re:     regexp.MustCompile(`(?i)\beval\s*\(\s*[^)\n]*(req\.|request\.|params\[|\$_(GET|POST|REQUEST)|\binput\s*\()`),
			skipFn: commentOnlyLine,
		},
		{
			id: "dom-xss-inner-html", cwe: "CWE-79", severity: shared.SeverityHigh, title: "DOM sink assigns untrusted data to innerHTML",
			desc: "Assigning request-, location-, or template-derived data to innerHTML/outerHTML (or document.write) executes markup in the page (DOM XSS). Use textContent or sanitize before insertion.",
			// A bare ${...} is NOT a marker (benign ${count} is not XSS); a template interpolation only counts
			// when it carries a taint source. \+?= also catches the innerHTML += append form.
			re:     regexp.MustCompile(`(?i)(\.(inner|outer)HTML\s*\+?=\s*[^;\n]*(req\.|request\.|params\[|location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|\$\{[^}]*(req\.|location\.|document\.|params\[))|document\.write\s*\(\s*[^)\n]*(location\.|document\.(URL|referrer)|req\.|params\[|\$\{[^}]*(req\.|location\.|document\.)))`),
			skipFn: commentOnlyLine,
			exts:   jsExts,
		},
		{
			id: "nosql-injection-request", cwe: "CWE-943", severity: shared.SeverityHigh, title: "NoSQL query built from request data",
			desc:   "A MongoDB query passes request data (or a $where JavaScript predicate) straight into the filter, allowing NoSQL operator injection. Cast/validate fields and never pass req.body as a filter.",
			re:     regexp.MustCompile(`(?i)(\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|count|aggregate)\s*\(\s*(req\.(body|query|params)|\{[^}\n]*(\$where|req\.(body|query|params)))|\$where\s*:\s*["'` + "`" + `])`),
			skipFn: commentOnlyLine,
		},
		{
			id: "ldap-injection", cwe: "CWE-90", severity: shared.SeverityHigh, title: "LDAP search filter built from untrusted input",
			desc: "An LDAP search filter is built from request/user-controlled data without LDAP filter escaping. Escape values per RFC 4515 or use a parameterized LDAP search API.",
			re: regexp.MustCompile(`(?i)\b((ldap\w*|conn|ctx|dir(ectory)?(context)?|ldaptemplate)\.)?(search|search_s|search_ext)\s*\([^\n]{0,160}(` +
				`["'][^"'\n]{0,120}\([a-z][\w.-]*\s*(=|~=|>=|<=)[^"'\n]{0,120}["']\s*\+\s*(req\.(body|query|params)|request\.(args|form|values|json)|params\[|\$_(GET|POST|REQUEST)|user(name)?\b|uid\b|input\b|param\b)|` +
				`f["'][^"'\n]{0,120}\([a-z][\w.-]*\s*(=|~=|>=|<=)[^"'\n]{0,120}\{\s*(req\.|request\.|params\[|user(name)?\b|uid\b|input\b|param\b)|` +
				"`[^`\\n]{0,120}\\([a-z][\\w.-]*\\s*(=|~=|>=|<=)[^`\\n]{0,120}\\$\\{\\s*(req\\.|request\\.|params\\[|user(name)?\\b|uid\\b|input\\b|param\\b))"),
			skipFn: safeLDAPFilter,
		},
		{
			id: "open-redirect-user-url", cwe: "CWE-601", severity: shared.SeverityMedium, title: "Redirect target is request-controlled",
			desc: "A redirect appears to use a request-controlled destination, enabling open redirect (phishing, token leakage). Redirect to a fixed allowlist or validate against a same-origin allowlist.",
			// The request markers are the USER-controlled subset only (query/params/body/url/headers/cookies),
			// so a canonical-host redirect built from server-derived req.protocol/req.hostname is not flagged.
			re:     regexp.MustCompile(`(?i)(res\.redirect|response\.redirect|sendRedirect|http\.Redirect|c\.Redirect)\s*\(\s*[^;\n]*(req\.(query|params|body|originalUrl|url|headers|cookies)|params\[|r\.URL|\$_(GET|POST|REQUEST)|c\.Query|getParameter)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "insecure-randomness-security-context", cwe: "CWE-338", severity: shared.SeverityMedium, title: "Weak PRNG used in a security context",
			desc:   "A non-cryptographic PRNG (Math.random, random.*, mt_rand, math/rand) appears to generate a token, OTP, salt, or session value. Use a CSPRNG (crypto.randomBytes, secrets, crypto/rand).",
			re:     regexp.MustCompile(`(?i)((token|otp|nonce|salt|secret|session|csrf|password|passwd|apikey|api_key|verification|reset)\b[^\n]{0,50}(Math\.random\s*\(|random\.(random|randint|choice|getrandbits)\s*\(|mt_rand\s*\(|\bmath/rand\b)|(Math\.random\s*\(|random\.(random|randint|choice|getrandbits)\s*\(|mt_rand\s*\(|\bmath/rand\b)[^\n]{0,50}(token|otp|nonce|salt|secret|session|csrf|password|passwd|apikey|api_key|verification|reset)\b)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "weak-rsa-key-size", cwe: "CWE-326", severity: shared.SeverityMedium, title: "RSA key size below 2048 bits",
			desc: "An RSA key is generated with 512 or 1024 bits, which is factorable. Generate at least 2048-bit RSA (3072+ preferred) or use an elliptic-curve key.",
			// RSA-specific constructors only (Go rsa.GenerateKey, Java RSAKeyGenParameterSpec, Python/Ruby
			// RSA.generate, openssl genrsa). A bare `.initialize(1024)` is deliberately excluded – it false-
			// positives on buffer/pool sizing.
			re:     regexp.MustCompile(`(?i)(rsa\.GenerateKey\s*\([^,\n]+,\s*(512|1024)\b|RSAKeyGenParameterSpec\s*\(\s*(512|1024)\b|RSA\.generate\s*\(\s*(512|1024)\b|genrsa\b[^\n]*\b(512|1024)\b)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "world-writable-permissions", cwe: "CWE-732", severity: shared.SeverityMedium, title: "World-writable file or directory permissions",
			desc: "A file or directory is created world-writable (0777), letting any local user tamper with it. Use least-privilege modes (0600/0640 for files, 0700/0750 for directories).",
			// The gap is bounded and stops at ')' so it can't reach a 0777 mentioned in a trailing comment.
			re:     regexp.MustCompile(`(?i)((os\.(Chmod|Mkdir|MkdirAll)|os\.WriteFile|ioutil\.WriteFile|os\.chmod)\s*\([^;)\n]{0,40}0o?777\b|\bchmod\s*\(\s*["']?0?777|\bchmod\s+(-R\s+)?0?777\b)`),
			skipFn: commentOnlyLine,
		},
		{
			id: "unsafe-c-string-function", cwe: "CWE-676", severity: shared.SeverityMedium, title: "Unsafe C string function (buffer overflow risk)",
			desc: "gets/strcpy/strcat/vsprintf write without a bound and are classic buffer-overflow sources. Use the size-bounded variants (fgets, strncpy/strlcpy, strncat/strlcat, vsnprintf).",
			// Gated to C/C++/ObjC files (exts) AND anchored with (^|[^.\w]) so the same names as safe functions
			// in other languages (Ruby gets, PHP vsprintf) can never produce a finding.
			re:     regexp.MustCompile(`(^|[^.\w])(gets|strcpy|strcat|vsprintf)\s*\(`),
			skipFn: commentOnlyLine,
			exts:   cSourceExts,
		},
		{
			id: "xpath-injection", cwe: "CWE-643", severity: shared.SeverityHigh, title: "XPath query built from untrusted input",
			desc: "An XPath expression is concatenated or interpolated from untrusted input, allowing XPath injection (authentication bypass, data disclosure). Use a precompiled expression with variable bindings and validate any dynamic value.",
			// Anchored so the XPath (the //... string) must be the sink's first argument: an opening quote
			// right after "(" pins // inside a string literal, not a // line comment or Python floor division.
			// A concat marker must sit adjacent to a quote (real string concatenation) or be an ${...}/{name}/%s
			// interpolation, so a fully constant query like "//user[name='admin']" never fires. \b stops
			// preEvaluate/deselectNodes substring matches.
			re:     regexp.MustCompile(`(?i)\b(evaluate|selectNodes|selectSingleNode|xpath)\s*\(\s*f?["'` + "`" + `][^"'` + "`" + `\n]*//[^\n]*(["'` + "`" + `]\s*\+|\+\s*["'` + "`" + `]|\$\{|%[sv]|\{[a-zA-Z_])`),
			skipFn: commentOnlyLine,
		},
		{
			id: "redos-vulnerable-regex", cwe: "CWE-1333", severity: shared.SeverityMedium, title: "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
			desc:   "A regex nests a quantifier inside a quantified group (e.g. (a+)+, (.*)*), which backtracks exponentially on crafted input and can hang the process. Rewrite without nested quantifiers, anchor the pattern, or use a linear-time engine.",
			re:     regexp.MustCompile(`\([^()\n]{0,80}[+*][^()\n]{0,80}\)\s*[+*]`),
			skipFn: skipUnlessRegexContext,
		},
		{
			id: "insecure-temp-file", cwe: "CWE-377", severity: shared.SeverityMedium, title: "Insecure temporary file",
			desc:   "A predictable temporary path (a hardcoded /tmp/<name>) or an unsafe API (tmpnam/mktemp) invites a symlink or race attack. Use a library that creates the file atomically with a random name (os.CreateTemp, tempfile.NamedTemporaryFile, mkstemp).",
			re:     regexp.MustCompile(`(?i)(["'` + "`" + `]/tmp/[\w.$+-]+|\btmpnam\s*\(|\btempnam\s*\(|\bmktemp\s*\()`),
			skipFn: commentOnlyLine,
		},
	}
	return append(core, langPackRules()...)
}

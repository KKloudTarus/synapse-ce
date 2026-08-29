package rulecatalog

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type cRuleSpec struct {
	family                                               string
	key, name, cwe, compliant, noncompliant, remediation string
	type_                                                rule.Type
	quality                                              rule.Quality
	severity                                             shared.Severity
	detection                                            rule.Detection
}

func cRule(key, name, cwe, compliant, noncompliant, remediation string, typ rule.Type, quality rule.Quality, severity shared.Severity) cRuleSpec {
	return cRuleSpec{key: key, name: name, cwe: cwe, compliant: compliant, noncompliant: noncompliant, remediation: remediation, type_: typ, quality: quality, severity: severity, detection: rule.DetectionAST}
}

func cExtendedRules() []rule.Rule {
	memory := []cRuleSpec{
		cRule("stack-buffer-overflow-loop", "Loop index exceeds stack buffer bounds", "CWE-121", "for (size_t i = 0; i < sizeof(buf); i++) { buf[i] = 0; }", "for (size_t i = 0; i <= sizeof(buf); i++) { buf[i] = 0; }", "Use strictly less than (<) for loop bounds over array sizes.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("vla-stack-allocation", "Variable Length Array stack allocation", "CWE-770", "char *buf = malloc(len);\nif (buf) { /* use */ free(buf); }", "char buf[len];", "Use heap allocation or fixed-size buffers instead of VLAs.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityMedium),
		cRule("alloca-in-loop", "alloca() called inside loop body", "CWE-770", "char *buf = malloc(sz);\nfor (int i = 0; i < count; i++) { process(buf); }\nfree(buf);", "for (int i = 0; i < count; i++) { void *p = alloca(sz); process(p); }", "Allocate memory once outside the loop or use standard heap allocation.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("unbounded-memcpy-size", "memcpy with unvalidated length", "CWE-120", "if (user_count <= sizeof(dst)) { memcpy(dst, src, user_count); }", "memcpy(dst, src, user_count);", "Validate copying lengths against target buffer capacities.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("off-by-one-null-terminator", "Buffer missing space for null terminator", "CWE-193", "char *buf = malloc(strlen(str) + 1);", "char *buf = malloc(strlen(str));", "Allocate strlen(s) + 1 bytes to accommodate the null terminator.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("unaligned-pointer-cast", "Pointer cast with stricter alignment", "CWE-125", "uint32_t val;\nmemcpy(&val, byte_ptr, sizeof(val));", "uint32_t *p = (uint32_t *)byte_ptr;\nuint32_t val = *p;", "Use memcpy or char pointers to access unaligned data safely.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("flexible-array-member-misuse", "Flexible array allocated without element size", "CWE-131", "struct Packet *p = malloc(sizeof(struct Packet) + n * sizeof(int));", "struct Packet *p = malloc(sizeof(struct Packet));", "Add the flexible array payload size when allocating struct memory.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("stack-array-large-allocation", "Large buffer allocated on stack", "CWE-770", "char *buf = malloc(1024 * 1024);", "char buf[1024 * 1024];", "Allocate large buffers on the heap to avoid stack overflow.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("strncpy-missing-null-termination", "strncpy without explicit null termination", "CWE-170", "strncpy(dst, src, sizeof(dst) - 1);\ndst[sizeof(dst) - 1] = '\\0';", "strncpy(dst, src, sizeof(dst));", "Explicitly set the last byte to '\\0' when using strncpy.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("dangling-stack-pointer-return", "Function returns pointer to local stack variable", "CWE-562", "static char buf[256];\nreturn buf;", "char local[256];\nreturn local;", "Do not return addresses of local automatic stack variables.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("memset-cleared-by-compiler", "Sensitive buffer memset before exit", "CWE-14", "explicit_bzero(secret, sizeof(secret));", "memset(secret, 0, sizeof(secret));", "Use explicit_bzero or SecureZeroMemory to clear sensitive data.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityMedium),
	}

	format := []cRuleSpec{
		cRule("printf-non-literal-format", "printf format string passed as variable", "CWE-134", "printf(\"%s\", user_str);", "printf(user_str);", "Always pass string literals as format strings to printf.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("percent-n-specifier-used", "%n format specifier used in format string", "CWE-134", "int written = snprintf(buf, sizeof(buf), \"value: %d\", v);", "printf(\"value: %d%n\", v, &count);", "Avoid %n format specifiers that write to target memory.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("syslog-variable-format", "syslog format string from untrusted variable", "CWE-134", "syslog(LOG_INFO, \"%s\", msg);", "syslog(LOG_INFO, msg);", "Pass a constant format string literal to syslog.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("custom-varargs-missing-format-attr", "Variadic logging function missing format attribute", "CWE-134", "__attribute__((format(printf, 1, 2)))\nvoid log_msg(const char *fmt, ...);", "void log_msg(const char *fmt, ...);", "Add format attributes to custom variadic printf wrappers.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
	}

	types := []cRuleSpec{
		cRule("signed-integer-overflow", "Signed integer arithmetic overflow hazard", "CWE-190", "if (a <= INT_MAX - b) { int sum = a + b; }", "int sum = a + b;", "Check for potential integer overflow before arithmetic operations.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("signed-unsigned-comparison", "Comparison between signed and unsigned integers", "CWE-681", "if (signed_len >= 0 && (size_t)signed_len < buf_size) {}", "if (signed_len < buf_size) {}", "Cast signed integers to matching unsigned types after non-negativity checks.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("integer-truncation-cast", "Integer conversion truncates wider type", "CWE-197", "if (wide_val <= SHRT_MAX && wide_val >= SHRT_MIN) { short s = (short)wide_val; }", "short s = (short)wide_val;", "Validate numeric ranges before downcasting integer types.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("shift-count-overflow", "Bit shift count exceeds type bit width", "CWE-190", "if (shift < 32) { uint32_t x = 1U << shift; }", "uint32_t x = 1U << shift;", "Ensure shift count is strictly less than the bit width of the operand.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("multiplication-overflow-malloc", "Multiplication in malloc argument without check", "CWE-190", "if (num <= SIZE_MAX / size) { void *p = malloc(num * size); }", "void *p = malloc(num * size);", "Check for multiplication overflow or use calloc for array allocations.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("lossy-pointer-to-int-cast", "Pointer cast to narrower integer type", "CWE-704", "uintptr_t addr = (uintptr_t)ptr;", "uint32_t addr = (uint32_t)ptr;", "Cast pointers to uintptr_t or intptr_t to preserve 64-bit addresses.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("divide-by-zero-hazard", "Division without zero divisor check", "CWE-369", "if (divisor != 0) { int q = num / divisor; }", "int q = num / divisor;", "Check that divisors are non-zero before division operations.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
	}

	nullchecks := []cRuleSpec{
		cRule("unchecked-malloc-return", "malloc return value used without NULL check", "CWE-476", "char *p = malloc(sz);\nif (!p) return -1;\np[0] = 'a';", "char *p = malloc(sz);\np[0] = 'a';", "Always verify malloc return values are not NULL before dereferencing.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("null-pointer-dereference", "Dereference of known NULL pointer", "CWE-476", "char *ptr = get_buffer();\nif (ptr) *ptr = 10;", "char *ptr = NULL;\n*ptr = 10;", "Do not dereference pointers assigned to NULL.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("unchecked-fopen-return", "fopen return value passed without NULL check", "CWE-476", "FILE *f = fopen(path, \"r\");\nif (f) { fread(buf, 1, 10, f); fclose(f); }", "FILE *f = fopen(path, \"r\");\nfread(buf, 1, 10, f);", "Check that file handles returned by fopen are non-NULL.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("unchecked-getenv-return", "getenv return value used without NULL check", "CWE-476", "char *home = getenv(\"HOME\");\nif (home) strcpy(dst, home);", "char *home = getenv(\"HOME\");\nstrcpy(dst, home);", "Check getenv return values for NULL before passing to string functions.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
	}

	async := []cRuleSpec{
		cRule("signal-handler-async-unsafe", "Async-signal-unsafe function in signal handler", "CWE-479", "void handler(int sig) { flag = 1; }", "void handler(int sig) { printf(\"caught signal\\n\"); }", "Call only async-signal-safe functions inside signal handlers.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		cRule("volatile-used-for-synchronization", "volatile used for thread synchronization", "CWE-362", "atomic_int flag = ATOMIC_VAR_INIT(0);", "volatile int flag = 0;", "Use C11 stdatomic.h or pthread mutexes for thread synchronization.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("pthread-join-missing", "pthread_create without join or detach", "CWE-404", "pthread_create(&tid, NULL, worker, NULL);\npthread_join(tid, NULL);", "pthread_create(&tid, NULL, worker, NULL);", "Join or detach spawned pthread threads to prevent resource leaks.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	crypto := []cRuleSpec{
		cRule("insecure-rand-function", "rand() used in security context", "CWE-338", "getrandom(&token, sizeof(token), 0);", "int token = rand();", "Use getrandom() or OpenSSL RAND_bytes for cryptographic tokens.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		cRule("deprecated-des-cipher", "DES or 3DES encryption API used", "CWE-327", "EVP_CIPHER_CTX_new();\nEVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);", "DES_ecb_encrypt(&input, &output, &ks, DES_ENCRYPT);", "Use AES-GCM or modern authenticated ciphers.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("hardcoded-cryptographic-key", "Hardcoded cryptographic key material in C", "CWE-321", "const char *key = getenv(\"SECRET_KEY\");", "const char *key = \"secret_key_1234567890abcdef\";", "Load cryptographic keys dynamically from secure key stores.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		cRule("static-iv-initialization", "Static initialization vector used with cipher", "CWE-329", "RAND_bytes(iv, sizeof(iv));", "unsigned char iv[16] = {0};", "Generate unique random initialization vectors for each encryption.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		cRule("insecure-md5-hashing", "MD5 hash function used in security verification", "CWE-327", "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);", "MD5_Init(&ctx);", "Use SHA-256 or SHA-3 for cryptographic hashing.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
		cRule("insecure-ssl-version", "Deprecated SSLv2, SSLv3, or TLS 1.0/1.1 protocol", "CWE-326", "SSL_CTX_new(TLS_method());", "SSL_CTX_new(SSLv23_method());", "Configure TLS 1.2 or TLS 1.3 as the minimum acceptable protocol version.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
	}

	maint := []cRuleSpec{
		cRule("long-function-body", "Function body exceeds statement count", "CWE-1120", "void build(void) { step_a(); step_b(); }", "void build(void) {\n\tint a = 1;\n\tint b = 2;\n\tint c = 3;\n\tint d = 4;\n\tint e = 5;\n\tint f = 6;\n\tint g = 7;\n\tint h = 8;\n\tint i = 9;\n\tint j = 10;\n\tint k = 11;\n\tint l = 12;\n\tint m = 13;\n\tint n = 14;\n\tint o = 15;\n\tint p = 16;\n\tint q = 17;\n\tint r = 18;\n\tint s = 19;\n\tint t = 20;\n\tint u = 21;\n\tint v = 22;\n\tint w = 23;\n\tint x = 24;\n\tint y = 25;\n\tint z = 26;\n\ta += 1;\n\tb += 1;\n\tc += 1;\n\td += 1;\n\te += 1;\n\tf += 1;\n\tg += 1;\n\th += 1;\n\ti += 1;\n\tj += 1;\n\tk += 1;\n\tl += 1;\n\tm += 1;\n\tn += 1;\n\to += 1;\n\tp += 1;\n\tq += 1;\n\tr += 1;\n\ts += 1;\n\tt += 1;\n\tu += 1;\n\tv += 1;\n\tw += 1;\n\tx += 1;\n\ty += 1;\n\tz += 1;\n}", "Refactor large functions into focused helper functions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("deeply-nested-control-flow", "Deeply nested control structures", "CWE-1120", "if (!ready) return;\nprocess();", "if (a) { if (b) { if (c) { if (d) { if (e) { run(); } } } } }", "Flatten deeply nested logic using early returns and guard clauses.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium),
		cRule("excessive-parameters", "Function declared with too many parameters", "CWE-1120", "void configure(const struct Config *cfg);", "void configure(int a, int b, int c, int d, int e, int f, int g, int h);", "Encapsulate multiple function parameters into a configuration struct.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("goto-backward-jump", "Backward goto jump used for looping", "CWE-1120", "while (attempts < 3) { if (try_op()) break; attempts++; }", "retry: if (!try_op()) goto retry;", "Use standard structured loop constructs (while, for) instead of backward goto jumps.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("macro-missing-parentheses", "Macro parameter missing safety parentheses", "CWE-783", "#define SQUARE(x) ((x) * (x))", "#define SQUARE(x) x * x", "Wrap macro parameters and entire macro expressions in parentheses.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("magic-numbers-in-logic", "Unnamed numeric literal in conditional logic", "CWE-1120", "#define MAX_ATTEMPTS 3\nif (attempts > MAX_ATTEMPTS) abort();", "if (attempts > 3) abort();", "Define named constants for magic numeric values.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("todo-comment-left", "TODO or FIXME marker in source code", "CWE-546", "/* Tracked in PROJ-456 */", "/* TODO: fix memory leak */", "Resolve pending TODO items or link to an active issue tracker.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
		cRule("commented-out-c-code", "Block of commented-out C code", "CWE-561", "void active_code(void) {}", "/* void old_function(void) { int x = 1; } */", "Delete obsolete commented-out code and rely on git history.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
		cRule("single-letter-identifier", "Single-letter variable name in wide scope", "CWE-1120", "void process_data(void) {\n\tint buffer_index = 0;\n}", "void process_data(void) {\n\tint i = 0;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n\ti++;\n}", "Use meaningful variable names for identifiers used across wide scopes.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		cRule("duplicate-switch-cases", "Duplicate case label in switch statement", "CWE-561", "switch (val) { case 1: handle_one(); break; case 2: handle_two(); break; }", "switch (val) { case 1: handle_one(); break; case 1: handle_duplicate(); break; }", "Ensure each case label in a switch statement is unique.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		cRule("unreachable-code-after-return", "Statement immediately follows return", "CWE-561", "return total;", "return total;\nprintf(\"done\\n\");", "Remove dead statements following unconditional returns.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	families := map[string][]cRuleSpec{
		"memory": memory, "format": format, "types": types, "nullchecks": nullchecks,
		"async": async, "crypto": crypto, "maintainability": maint,
	}
	var allSpecs []cRuleSpec
	for _, family := range []string{"memory", "format", "types", "nullchecks", "async", "crypto", "maintainability"} {
		for i := range families[family] {
			families[family][i].family = family
		}
		allSpecs = append(allSpecs, families[family]...)
	}

	rules := make([]rule.Rule, 0, len(allSpecs))
	for _, s := range allSpecs {
		cweSlice := []string{}
		if s.cwe != "" {
			cweSlice = []string{s.cwe}
		}
		owaspSlice := []string{}
		if s.family == "crypto" {
			owaspSlice = []string{"A02:2021"}
		} else if s.family == "format" {
			owaspSlice = []string{"A03:2021"}
		}
		rules = append(rules, rule.Rule{
			Key: rule.Key("c:" + s.key), Name: s.name, Language: "C", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"c", "c-" + s.family}, CWE: cweSlice, OWASP: owaspSlice,
			Description: cDescription(s), Rationale: cRationale(s),
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: cEffort(s), Detection: s.detection,
		})
	}
	return rules
}

func cDescription(s cRuleSpec) string {
	shape := map[string]string{
		"stack-buffer-overflow-loop":       "a loop condition reaching or exceeding sizeof(buffer)",
		"vla-stack-allocation":             "a variable length array (VLA) stack allocation",
		"alloca-in-loop":                   "alloca() invoked inside a loop body",
		"unbounded-memcpy-size":            "memcpy() called with an unvalidated user length",
		"off-by-one-null-terminator":       "allocating string memory with strlen() without + 1",
		"unaligned-pointer-cast":           "casting a byte pointer to a type with stricter alignment requirements",
		"flexible-array-member-misuse":     "allocating a struct with flexible array member without element size",
		"stack-array-large-allocation":     "allocating an excessively large buffer on the stack",
		"strncpy-missing-null-termination": "strncpy called with full buffer size without explicit null termination",
		"dangling-stack-pointer-return":    "a function returning the address of a local stack variable",
		"memset-cleared-by-compiler":       "clearing sensitive memory with memset before function exit",

		"printf-non-literal-format":          "passing a dynamic variable directly as a format string to printf",
		"percent-n-specifier-used":           "using the %n format specifier in a format string",
		"syslog-variable-format":             "passing dynamic message variables directly as format strings to syslog",
		"custom-varargs-missing-format-attr": "a custom variadic logging function missing format attributes",

		"signed-integer-overflow":        "unvalidated signed arithmetic addition or multiplication",
		"signed-unsigned-comparison":     "direct relational comparison between signed and unsigned integers",
		"integer-truncation-cast":        "downcasting integer types without bounds validation",
		"shift-count-overflow":           "bit shifting by an amount equal to or greater than the operand width",
		"multiplication-overflow-malloc": "multiplication inside a malloc argument without overflow check",
		"lossy-pointer-to-int-cast":      "casting a pointer to a narrower integer type",
		"divide-by-zero-hazard":          "division operation without verifying the divisor is non-zero",

		"unchecked-malloc-return":  "dereferencing a malloc return pointer without checking for NULL",
		"null-pointer-dereference": "dereferencing a pointer that was assigned to NULL",
		"unchecked-fopen-return":   "passing fopen result to file operations without NULL check",
		"unchecked-getenv-return":  "passing getenv result to string functions without NULL check",

		"signal-handler-async-unsafe":       "calling async-signal-unsafe functions inside a signal handler",
		"volatile-used-for-synchronization": "using volatile variables for thread synchronization",
		"pthread-join-missing":              "calling pthread_create without pthread_join or pthread_detach",

		"insecure-rand-function":      "using rand() or random() in a security or token generation context",
		"deprecated-des-cipher":       "using legacy DES or 3DES encryption routines",
		"hardcoded-cryptographic-key": "hardcoded cryptographic secret string literal in C code",
		"static-iv-initialization":    "using an all-zero or constant initialization vector with a block cipher",
		"insecure-md5-hashing":        "using MD5 hash functions for security verification",
		"insecure-ssl-version":        "enabling deprecated SSLv2/SSLv3/TLS 1.0 protocols",

		"long-function-body":            "a function containing more than 50 statements",
		"deeply-nested-control-flow":    "control flow nested beyond four levels",
		"excessive-parameters":          "a function declared with more than seven parameters",
		"goto-backward-jump":            "a backward goto jump used for looping",
		"macro-missing-parentheses":     "a preprocessor macro missing parameter parentheses",
		"magic-numbers-in-logic":        "an unnamed numeric literal in a conditional comparison",
		"todo-comment-left":             "a TODO or FIXME marker left in source code",
		"commented-out-c-code":          "a block of commented-out C code",
		"single-letter-identifier":      "a single-letter variable name used across a wide scope",
		"duplicate-switch-cases":        "duplicate case labels in a switch statement",
		"unreachable-code-after-return": "unreachable statements following an unconditional return",
	}[s.key]
	return fmt.Sprintf("Reports %s. It inspects only that local syntax or structure and does not prove the surrounding runtime path, memory management, or input trust.", shape)
}

func cRationale(s cRuleSpec) string {
	reason := map[string]string{
		"stack-buffer-overflow-loop":       "Writing past stack buffer boundaries corrupts return addresses and causes remote code execution.",
		"vla-stack-allocation":             "Variable length arrays can exhaust the stack and trigger kernel stack faults with large inputs.",
		"alloca-in-loop":                   "Calling alloca inside a loop continuously grows the stack frame until stack exhaustion.",
		"unbounded-memcpy-size":            "Unbounded memcpy lengths lead to buffer overflow and arbitrary memory corruption.",
		"off-by-one-null-terminator":       "Failing to allocate space for the null terminator causes string reads to overflow buffer boundaries.",
		"unaligned-pointer-cast":           "Accessing unaligned pointers triggers CPU alignment traps and undefined behavior.",
		"flexible-array-member-misuse":     "Omitting element size when allocating flexible arrays results in heap buffer overflow.",
		"stack-array-large-allocation":     "Large stack allocations risk exceeding thread stack limits and causing immediate stack overflows.",
		"strncpy-missing-null-termination": "strncpy does not null-terminate if the source length equals or exceeds the buffer size.",
		"dangling-stack-pointer-return":    "Returning pointers to stack memory results in use-after-free when the frame is popped.",
		"memset-cleared-by-compiler":       "Compilers optimize away trailing memset calls on dead stack buffers, leaving keys in RAM.",

		"printf-non-literal-format":          "Dynamic format strings allow format string attacks for arbitrary memory reading and writing.",
		"percent-n-specifier-used":           "The %n specifier allows attackers to overwrite memory locations via format string injection.",
		"syslog-variable-format":             "Dynamic syslog format arguments lead to format string vulnerabilities in daemon processes.",
		"custom-varargs-missing-format-attr": "Missing format attributes prevents the compiler from validating argument types.",

		"signed-integer-overflow":        "Signed integer overflow is undefined behavior in C and leads to security vulnerabilities.",
		"signed-unsigned-comparison":     "Comparing signed and unsigned values promotes signed values to unsigned, turning negative numbers huge.",
		"integer-truncation-cast":        "Narrowing casts silently discard significant bits and cause incorrect calculation logic.",
		"shift-count-overflow":           "Bit shifts with counts equal to or exceeding type width trigger undefined hardware behavior.",
		"multiplication-overflow-malloc": "Multiplication overflow wraps allocation sizes, creating small buffers that overflow.",
		"lossy-pointer-to-int-cast":      "Casting 64-bit pointers to 32-bit integers truncates address bits and causes memory access faults.",
		"divide-by-zero-hazard":          "Division by zero raises hardware arithmetic exceptions that terminate the program.",

		"unchecked-malloc-return":  "Dereferencing NULL pointers on memory exhaustion crashes processes or causes kernel panics.",
		"null-pointer-dereference": "Dereferencing NULL pointers leads to segmentation faults and denial of service.",
		"unchecked-fopen-return":   "Passing NULL file pointers to file operations causes segmentation faults.",
		"unchecked-getenv-return":  "Passing NULL environment variables to string functions triggers NULL pointer dereferences.",

		"signal-handler-async-unsafe":       "Calling async-signal-unsafe functions in signal handlers causes deadlocks and heap corruption.",
		"volatile-used-for-synchronization": "volatile does not emit CPU memory fences; it cannot guarantee cross-thread memory visibility.",
		"pthread-join-missing":              "Unjoined and undetached threads leak their thread control blocks and stack allocations.",

		"insecure-rand-function":      "rand() uses linear congruential algorithms easily predictable by attackers.",
		"deprecated-des-cipher":       "DES uses a 56-bit key size easily broken by brute-force cracking.",
		"hardcoded-cryptographic-key": "Hardcoded keys in binaries are easily extracted with strings or disassemblers.",
		"static-iv-initialization":    "Constant IVs reveal patterns across ciphertexts and compromise confidentiality.",
		"insecure-md5-hashing":        "MD5 collisions allow forging digital certificates and data signatures.",
		"insecure-ssl-version":        "Legacy SSL/TLS protocols are vulnerable to POODLE, BEAST, and downgrade attacks.",

		"long-function-body":            "Long monolithic functions are difficult to comprehend, verify, and maintain.",
		"deeply-nested-control-flow":    "Deep nesting significantly increases cognitive complexity and testing burden.",
		"excessive-parameters":          "Excessive parameters indicate high coupling and increase invocation error rates.",
		"goto-backward-jump":            "Backward gotos produce spaghetti code that complicates control flow reasoning.",
		"macro-missing-parentheses":     "Missing macro parentheses alters operator precedence and introduces calculation bugs.",
		"magic-numbers-in-logic":        "Magic numbers obscure calculation intent and complicate codebase refactoring.",
		"todo-comment-left":             "Untracked TODO comments accumulate technical debt and represent incomplete features.",
		"commented-out-c-code":          "Commented-out code litters source files and confuses subsequent maintainers.",
		"single-letter-identifier":      "Single-letter variable names reduce readability when used across large scopes.",
		"duplicate-switch-cases":        "Duplicate switch case labels create dead code and signal developer logic errors.",
		"unreachable-code-after-return": "Statements placed after unconditional returns can never execute.",
	}[s.key]

	source := "https://en.cppreference.com/w/c"
	if s.cwe != "" {
		source = "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(s.cwe, "CWE-") + ".html"
	}
	switch s.family {
	case "memory":
		source = "https://wiki.sei.cmu.edu/confluence/display/c/MEM+Memory+Management"
	case "format":
		source = "https://wiki.sei.cmu.edu/confluence/display/c/FIO+Input+Output"
	case "crypto":
		source = "https://wiki.sei.cmu.edu/confluence/display/c/MSC+Miscellaneous"
	}
	return fmt.Sprintf("%s\n\nSource: %s", reason, source)
}

func cEffort(s cRuleSpec) int {
	switch s.family {
	case "memory", "format", "crypto":
		return 30
	case "maintainability":
		return 5
	default:
		return 15
	}
}

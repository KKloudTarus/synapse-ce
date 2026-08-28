package rulecatalog

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type rustRuleSpec struct {
	family                                               string
	key, name, cwe, compliant, noncompliant, remediation string
	type_                                                rule.Type
	quality                                              rule.Quality
	severity                                             shared.Severity
	detection                                            rule.Detection
}

func rustRule(key, name, cwe, compliant, noncompliant, remediation string, typ rule.Type, quality rule.Quality, severity shared.Severity) rustRuleSpec {
	return rustRuleSpec{key: key, name: name, cwe: cwe, compliant: compliant, noncompliant: noncompliant, remediation: remediation, type_: typ, quality: quality, severity: severity, detection: rule.DetectionAST}
}

func rustRules() []rule.Rule {
	unsafe_ := []rustRuleSpec{
		rustRule("transmute-ptr-to-ref", "Transmute raw pointer to reference", "CWE-843", "let r = unsafe { ptr.as_ref() };", "let r: &T = unsafe { std::mem::transmute(ptr) };", "Use pointer as_ref() or as_mut() to validate lifetime and nullability.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("unsafe-block-scope", "Excessive unsafe block scope", "CWE-658", "let raw = prepare();\nlet val = unsafe { *raw };\nprocess(val);", "unsafe {\n    let raw = prepare();\n    let val = *raw;\n    process(val);\n}", "Narrow unsafe blocks to contain only the specific unsafe operations.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium),
		rustRule("raw-ptr-deref-no-null-check", "Raw pointer dereference without null check", "CWE-476", "if !ptr.is_null() { unsafe { *ptr = 42; } }", "unsafe { *ptr = 42; }", "Check that raw pointers are non-null and aligned before dereferencing.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("unaligned-raw-ptr-read", "Unaligned raw pointer read", "CWE-125", "let val = unsafe { std::ptr::read_unaligned(ptr) };", "let val = unsafe { *ptr };", "Use std::ptr::read_unaligned when pointer memory alignment cannot be guaranteed.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("slice-from-raw-parts-null", "Slice constructed from raw parts without null check", "CWE-476", "let s = if ptr.is_null() { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len) } };", "let s = unsafe { std::slice::from_raw_parts(ptr, len) };", "Ensure the pointer is non-null and properly aligned before constructing slices.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("non-repr-c-transmute", "Transmute between structs without repr(C)", "CWE-843", "#[repr(C)]\nstruct A(u32);\n#[repr(C)]\nstruct B(u32);", "struct A(u32);\nstruct B(u32);\nlet b: B = unsafe { std::mem::transmute(a) };", "Add #[repr(C)] to struct declarations before relying on memory layout equivalence.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("unsafe-static-mut-ref", "Shared reference to mutable static variable", "CWE-362", "static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\nCOUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);", "static mut COUNTER: usize = 0;\nlet r = unsafe { &COUNTER };", "Use atomic types or Mutex instead of creating references to mutable statics.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("unsafe-impl-send-sync", "Unchecked manual Send/Sync implementation", "CWE-667", "struct SafeWrapper<T>(T);\n// Let compiler auto-derive Send and Sync when safe", "unsafe impl<T> Send for Custom<T> {}", "Ensure inner types and synchronization primitives guarantee thread safety before implementing Send or Sync.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("ptr-copy-overlap-hazard", "Pointer copy non-overlapping with overlapping memory", "CWE-119", "unsafe { std::ptr::copy(src, dst, count); }", "unsafe { std::ptr::copy_nonoverlapping(src, dst, count); }", "Use std::ptr::copy when source and destination buffers may overlap.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("uninit-buffer-exposure", "MaybeUninit assume_init before full initialization", "CWE-908", "let mut buf = std::mem::MaybeUninit::<[u8; 32]>::uninit();\nunsafe { init(buf.as_mut_ptr()); }\nlet res = unsafe { buf.assume_init() };", "let mut buf = std::mem::MaybeUninit::<u32>::uninit();\nlet res = unsafe { buf.assume_init() };", "Ensure memory is completely initialized before invoking assume_init().", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("transmute-mut-ref-aliasing", "Transmute creating aliased mutable references", "CWE-416", "let r1 = &mut data.a;\nlet r2 = &mut data.b;", "let r1 = &mut data;\nlet r2: &mut Data = unsafe { std::mem::transmute(&mut *r1) };", "Do not bypass the borrow checker to create multiple simultaneous mutable references.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("raw-pointer-arithmetic-oob", "Raw pointer arithmetic without bounds validation", "CWE-125", "let target = if offset < len { unsafe { base.add(offset) } } else { base };", "let target = unsafe { base.add(user_offset) };", "Validate offset calculations against allocation bounds before pointer arithmetic.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("unsafe-fn-without-doc", "Unsafe function missing Safety documentation", "CWE-398", "/// # Safety\n/// Caller must ensure `ptr` is non-null and aligned.\npub unsafe fn process(ptr: *const u8) {}", "pub unsafe fn process(ptr: *const u8) {}", "Document safety prerequisites and caller obligations in a # Safety section.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
	}

	ownership := []rustRuleSpec{
		rustRule("refcell-borrow-across-await", "RefCell borrow held across await point", "CWE-667", "let data = cell.borrow().clone();\nasync_op().await;", "let guard = cell.borrow();\nasync_op().await;\nuse_guard(&guard);", "Drop RefCell borrows before asynchronous suspension points.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("drop-reference-noop", "Explicit drop called on a reference", "CWE-672", "let x = 42;\nstd::mem::drop(x);", "let mut x = 42;\nstd::mem::drop(&mut x);", "Pass the owned value to std::mem::drop instead of dropping a reference.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("unneeded-box-sized", "Unneeded Box on small sized value", "CWE-401", "fn compute() -> u64 { 42 }", "fn compute() -> Box<u64> { Box::new(42) }", "Pass small sized types directly on the stack instead of heap allocating.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("clone-in-hot-loop", "Redundant clone inside loop body", "CWE-400", "let template = make_template();\nfor item in items { process(&template, item); }", "for item in items { process(template.clone(), item); }", "Borrow shared structures inside loops instead of cloning on every iteration.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("interior-mutability-shared", "Non-thread-safe interior mutability shared across threads", "CWE-362", "use std::sync::Mutex;\nlet counter = Mutex::new(0);", "use std::cell::Cell;\nlet counter = Cell::new(0);", "Use Mutex, RwLock, or Atomic types for interior mutability shared across threads.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("leaked-raw-box", "Box into_raw without paired from_raw", "CWE-401", "let b = Box::new(42);\nlet ptr = Box::into_raw(b);\nlet _ = unsafe { Box::from_raw(ptr) };", "let b = Box::new(42);\nlet _ = Box::into_raw(b);", "Reconstruct Box with Box::from_raw when finished with raw ownership.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	err := []rustRuleSpec{
		rustRule("expect-empty-message", "expect() with empty message", "CWE-248", "let val = config.get(key).expect(\"config key required\");", "let val = config.get(key).expect(\"\");", "Provide detailed diagnostic context in expect messages.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("panic-in-ffi-boundary", "Panic called across FFI boundary", "CWE-248", "extern \"C\" fn api_call() -> i32 {\n    let _ = std::panic::catch_unwind(|| { work() });\n    0\n}", "extern \"C\" fn api_call() {\n    panic!(\"error\");\n}", "Catch panics at FFI boundaries and translate them to C error codes.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("swallowed-error-let-underscore", "Result discarded with let _", "CWE-391", "store.save(item)?;", "let _ = store.save(item);", "Handle or propagate errors instead of discarding with let _.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("custom-error-no-std-trait", "Custom error type missing std::error::Error", "CWE-398", "#[derive(Debug, thiserror::Error)]\npub enum AppError { #[error(\"io error\")] Io(#[from] std::io::Error) }", "pub enum AppError { Failed }", "Implement std::error::Error for custom error types.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("panic-in-drop", "Panic inside Drop implementation", "CWE-248", "impl Drop for Resource { fn drop(&mut self) { if let Err(e) = self.flush() { log::warn!(\"flush: {}\", e); } } }", "impl Drop for Resource { fn drop(&mut self) { self.flush().unwrap(); } }", "Avoid panics in drop to prevent double-panic aborts during stack unwinding.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
	}

	ffi := []rustRuleSpec{
		rustRule("ffi-null-ptr-unchecked", "Raw pointer from FFI used without null check", "CWE-476", "let res = if !ptr.is_null() { Some(unsafe { *ptr }) } else { None };", "let res = unsafe { *ptr };", "Verify pointers returned from external FFI calls before dereferencing.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("ffi-missing-repr-c", "Struct passed to FFI missing repr(C)", "CWE-704", "#[repr(C)]\npub struct CHeader { pub magic: u32, pub version: u16 }", "pub struct CHeader { pub magic: u32, pub version: u16 }", "Annotate structs shared across FFI boundaries with #[repr(C)].", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("ffi-c-string-missing-nul", "C string constructed without null terminator", "CWE-170", "let c_str = std::ffi::CString::new(\"hello\").unwrap();", "let ptr = \"hello\".as_ptr() as *const std::ffi::c_char;", "Use std::ffi::CString or null-terminated byte literals for C strings.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("ffi-opaque-struct-by-value", "Opaque C struct passed by value", "CWE-704", "extern \"C\" fn process(handle: *mut OpaqueHandle);", "extern \"C\" fn process(handle: OpaqueHandle);", "Pass pointers to opaque C structures rather than value types.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("ffi-freed-c-pointer", "Deallocating Rust pointer with libc free", "CWE-762", "unsafe { drop(Box::from_raw(rust_ptr)); }", "unsafe { libc::free(rust_ptr as *mut libc::c_void); }", "Use the matching deallocator for memory allocated by Rust or external libraries.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("ffi-wide-string-unterminated", "Wide string slice missing null termination", "CWE-170", "let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();", "let wide: Vec<u16> = text.encode_utf16().collect();", "Append a null u16 (0) terminator when passing wide strings to platform APIs.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	concurrency := []rustRuleSpec{
		rustRule("lock-held-across-await", "Mutex lock held across await suspension point", "CWE-667", "let data = { let g = lock.lock().unwrap(); *g };\nasync_op().await;", "let g = lock.lock().unwrap();\nasync_op().await;", "Release synchronous locks before awaiting asynchronous futures.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("unbounded-channel-send", "Unbounded channel growth in loop", "CWE-400", "let (tx, rx) = tokio::sync::mpsc::channel(100);", "let (tx, rx) = tokio::sync::mpsc::unbounded_channel();", "Use bounded channels to apply backpressure and bound memory usage.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("thread-spawn-in-loop", "Unbounded thread spawning in loop", "CWE-400", "let pool = rayon::ThreadPoolBuilder::new().build().unwrap();\npool.install(|| { for i in items { process(i); } });", "for item in items { std::thread::spawn(move || process(item)); }", "Use a scoped thread pool or worker queue instead of spawning raw threads.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("atomic-relaxed-ordering-sync", "Relaxed atomic ordering in synchronization flag", "CWE-362", "flag.store(true, std::sync::atomic::Ordering::Release);\nflag.load(std::sync::atomic::Ordering::Acquire);", "flag.store(true, std::sync::atomic::Ordering::Relaxed);", "Use Acquire/Release or SeqCst ordering for synchronization flags.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("condvar-wait-no-predicate", "Condvar wait without predicate check", "CWE-835", "let mut g = lock.lock().unwrap();\nwhile !ready(&g) { g = cvar.wait(g).unwrap(); }", "let mut g = lock.lock().unwrap();\ng = cvar.wait(g).unwrap();", "Check the condition in a loop around Condvar::wait to guard against spurious wakeups.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
	}

	crypto := []rustRuleSpec{
		rustRule("insecure-cipher-ecb", "Electronic codebook cipher mode", "CWE-327", "let cipher = Aes256Gcm::new(key);", "let cipher = Aes128Ecb::new(key);", "Use authenticated encryption modes like AES-GCM or ChaCha20-Poly1305.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("insecure-prng-security", "Predictable PRNG used in security context", "CWE-338", "use rand::RngCore;\nlet mut key = [0u8; 32];\nrand::rngs::OsRng.fill_bytes(&mut key);", "let token: u64 = rand::random();", "Use OsRng or ring/aws-lc-rs for generating security tokens and key material.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("hardcoded-secret-bytes", "Hardcoded cryptographic secret literal", "CWE-321", "let key = std::env::var(\"API_KEY\")?;", "let key = b\"super_secret_master_key_12345678\";", "Load cryptographic keys and secrets from environment variables or key vaults.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("static-nonce-reuse", "Static nonce used with AEAD cipher", "CWE-329", "let nonce = Aes256Gcm::generate_nonce(&mut OsRng);", "let nonce = Nonce::from_slice(b\"unique nonce 123\");", "Generate a fresh unique nonce for each encryption operation.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("timing-attack-memcmp", "Non-constant-time secret comparison", "CWE-208", "use subtle::ConstantTimeEq;\nlet valid = user_token.ct_eq(&expected_token).into();", "let valid = user_token == expected_token;", "Use subtle::ConstantTimeEq to compare tokens and hashes without timing leaks.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
		rustRule("deprecated-hash-md5", "Deprecated MD5 or SHA-1 hash function", "CWE-327", "use sha2::Sha256;\nlet hash = Sha256::digest(data);", "use md5::Md5;\nlet hash = Md5::digest(data);", "Use SHA-256 or BLAKE3 for cryptographic hashing.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
		rustRule("weak-rsa-key-size", "RSA key size less than 2048 bits", "CWE-326", "let priv_key = RsaPrivateKey::new(&mut rng, 2048)?;", "let priv_key = RsaPrivateKey::new(&mut rng, 1024)?;", "Use RSA keys of at least 2048 bits (3072 or 4096 recommended).", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("jwt-insecure-none-algo", "JWT verification allows none algorithm", "CWE-347", "let val = Validation::new(Algorithm::HS256);", "let mut val = Validation::default();\nval.algorithms = vec![Algorithm::None];", "Require strong signature algorithms and reject Algorithm::None.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
	}

	injection := []rustRuleSpec{
		rustRule("sql-string-formatting", "SQL query constructed with string formatting", "CWE-89", "sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id);", "let query = format!(\"SELECT * FROM users WHERE id = '{}'\", id);", "Use parameterized SQL queries instead of string formatting.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("command-injection-sh", "Command executed via shell interpreter with user string", "CWE-78", "std::process::Command::new(\"/usr/bin/git\").args([\"status\"]);", "std::process::Command::new(\"sh\").args([\"-c\", &format!(\"git {}\", user_arg)]);", "Execute fixed binaries directly with structured arguments rather than invoking shell interpreters.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("path-traversal-join", "Path traversal in Path join operation", "CWE-22", "let path = base_dir.join(std::path::Path::new(input).file_name().unwrap());", "let path = base_dir.join(user_input);", "Validate or sanitize dynamic path segments to prevent directory traversal outside base.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("regex-dynamic-compilation", "Regular expression compiled from untrusted string", "CWE-1333", "static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(\"^[a-z]+$\").unwrap());", "let re = regex::Regex::new(&user_pattern).unwrap();", "Use static precompiled regex patterns or configure size and nesting limits.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
		rustRule("server-side-template-injection", "Raw string rendered in template engine", "CWE-94", "tera.render(\"index.html\", &context);", "tera.render_str(&user_template, &context);", "Render fixed template files instead of evaluating user-supplied template strings.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("ldap-injection-filter", "LDAP filter built with string concatenation", "CWE-90", "let filter = format!(\"(uid={})\", escape_ldap(username));", "let filter = format!(\"(uid={})\", username);", "Escape special filter characters before constructing LDAP queries.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("xpath-injection-query", "XPath query built with string formatting", "CWE-643", "let xpath = format!(\"//user[@name=$name]\");", "let xpath = format!(\"//user[@name='{}']\", user_name);", "Use XPath variables or escape untrusted parameters.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("unrestricted-zip-extract", "Zip extraction without path sanitization", "CWE-22", "if file.enclosed_name().is_some() { zip.extract(target)?; }", "zip.extract(target)?;", "Validate file enclosed names to guard against Zip Slip directory traversal.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
		rustRule("eval-dynamic-expression", "Dynamic script evaluation with untrusted code", "CWE-94", "engine.eval::<i64>(\"1 + 2\");", "engine.eval::<i64>(&user_script);", "Avoid executing untrusted scripts or sandbox engine capabilities strictly.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh),
	}

	types := []rustRuleSpec{
		rustRule("lossy-integer-cast", "Lossy integer truncation via as keyword", "CWE-197", "let narrow: u16 = u16::try_from(wide_val)?;", "let narrow = wide_val as u16;", "Use TryFrom to detect integer truncation and overflow explicitly.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("signed-unsigned-cast-hazard", "Signed to unsigned cast with as keyword", "CWE-681", "let u: usize = usize::try_from(signed_val)?;", "let u = signed_val as usize;", "Check for negative values before converting signed integers to unsigned.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("float-nan-comparison", "Direct equality comparison with float NaN", "CWE-697", "if val.is_nan() { handle_nan(); }", "if val == f64::NAN { handle_nan(); }", "Use is_nan() because NaN comparisons always return false.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("pointer-to-integer-cast", "Pointer cast to narrower integer type", "CWE-704", "let addr: usize = ptr as usize;", "let addr: u32 = ptr as u32;", "Cast pointers to usize to match target architecture address widths.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("char-from-u32-unchecked", "char from u32 unchecked conversion", "CWE-843", "let ch = char::from_u32(code_point).ok_or(Error::InvalidChar)?;", "let ch = unsafe { char::from_u32_unchecked(code_point) };", "Use char::from_u32 to validate Unicode scalar value boundaries.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
		rustRule("bitshift-oversized", "Bit shift count exceeds type bit width", "CWE-190", "let res = if shift < 32 { val << shift } else { 0 };", "let res = val << shift;", "Check shift operands to ensure shift amount is less than value bit width.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh),
	}

	resource := []rustRuleSpec{
		rustRule("tempfile-insecure-path", "Predictable temporary file path creation", "CWE-377", "let temp = tempfile::NamedTempFile::new()?;", "let file = std::fs::File::create(\"/tmp/app_temp.dat\")?;", "Use tempfile::NamedTempFile or tempfile::tempdir for secure atomic temporary storage.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium),
		rustRule("socket-missing-timeout", "TcpStream connected without read or write timeout", "CWE-400", "let stream = std::net::TcpStream::connect(addr)?;\nstream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;", "let stream = std::net::TcpStream::connect(addr)?;", "Set read and write timeouts on network sockets to prevent hung connections.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("file-unbuffered-io", "Unbuffered file operations in loop", "CWE-400", "let mut reader = std::io::BufReader::new(file);", "let mut file = std::fs::File::open(path)?;\nfor _ in 0..1000 { file.read(&mut buf)?; }", "Wrap File in BufReader or BufWriter for sequential I/O.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("child-process-not-waited", "Child process spawned without wait or kill handling", "CWE-404", "let mut child = std::process::Command::new(\"ls\").spawn()?;\nchild.wait()?;", "let _ = std::process::Command::new(\"ls\").spawn()?;", "Wait on spawned child processes to avoid zombie processes and resource leaks.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium),
		rustRule("unbounded-vec-reserve", "Vec reserve with untrusted size", "CWE-400", "if requested_len < MAX_SAFE_CAPACITY { vec.reserve(requested_len); }", "vec.reserve(user_requested_len);", "Cap allocation requests to prevent denial of service through memory exhaustion.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh),
	}

	maint := []rustRuleSpec{
		rustRule("long-function-statements", "Function exceeds statement length threshold", "CWE-1120", "fn build() -> Model { let a = step_a(); let b = step_b(); Model { a, b } }", "fn build() { /* >50 statements */ }", "Split long functions into modular and testable units.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("deep-control-nesting", "Deeply nested control structures", "CWE-1120", "fn handle() { if !ready { return; } process(); }", "fn handle() { if a { if b { if c { if d { if e { run(); } } } } } }", "Use guard clauses and early returns to flatten nested branches.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium),
		rustRule("excessive-parameters", "Function declared with too many parameters", "CWE-1120", "fn configure(opts: ServerOptions) {}", "fn configure(a: u32, b: String, c: bool, d: u16, e: i64, f: u8, g: usize, h: &str) {}", "Group related parameters into a configuration struct.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("magic-number-condition", "Magic numeric literal in condition", "CWE-1120", "const MAX_RETRIES: u32 = 5;\nif retries > MAX_RETRIES { abort(); }", "if retries > 5 { abort(); }", "Extract numeric literals into named constants.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("todo-comment-untracked", "TODO or FIXME comment left in code", "CWE-546", "// Follow-up in ticket PROJ-123\nfn process() {}", "// TODO: fix this bug later\nfn process() {}", "Resolve pending items or reference an issue tracker ID.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
		rustRule("commented-out-code", "Commented out Rust code block", "CWE-561", "fn active_code() {}", "// fn old_code() {\n//     deprecated_step();\n// }", "Remove dead code and rely on version control history.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
		rustRule("single-letter-variable-name", "Single-letter variable name in wide scope", "CWE-1120", "let user_account = fetch();", "let u = fetch(); /* used across 40 lines */", "Use descriptive variable names for items with extensive scope.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("large-enum-variant-size", "Large enum variant size disparity", "CWE-400", "enum Message { Small(u32), Large(Box<[u8; 1024]>) }", "enum Message { Small(u32), Large([u8; 1024]) }", "Box large variant fields to avoid inflating overall enum size.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("redundant-closure-call", "Redundant closure wrapping named function", "CWE-398", "items.into_iter().map(process);", "items.into_iter().map(|x| process(x));", "Pass the function name directly instead of creating a redundant closure.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo),
		rustRule("collapsible-if-statements", "Nested if statements collapsible with logical AND", "CWE-398", "if condition_a && condition_b { run(); }", "if condition_a { if condition_b { run(); } }", "Combine nested if blocks into a single condition with &&.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("match-single-binding", "Match expression with single arm better written as if let", "CWE-398", "if let Some(val) = opt { process(val); }", "match opt { Some(val) => process(val), _ => {} }", "Use `if let` or `let else` for single-pattern matches.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
	}

	api := []rustRuleSpec{
		rustRule("missing-must-use", "Result or pure query function missing #[must_use]", "CWE-398", "#[must_use]\npub fn is_empty(&self) -> bool { self.len == 0 }", "pub fn is_empty(&self) -> bool { self.len == 0 }", "Add #[must_use] attribute to functions whose return values should not be ignored.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("public-api-undocumented", "Public declaration missing doc comments", "CWE-546", "/// Processes incoming request payloads.\npub fn process() {}", "pub fn process() {}", "Add documentation comments to all public API functions and types.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
		rustRule("display-missing-debug", "Type implements Display without Debug derive", "CWE-398", "#[derive(Debug)]\npub struct Item;\nimpl std::fmt::Display for Item { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, \"item\") } }", "pub struct Item;\nimpl std::fmt::Display for Item { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, \"item\") } }", "Derive std::fmt::Debug for all types that implement std::fmt::Display.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow),
	}

	families := map[string][]rustRuleSpec{
		"unsafe": unsafe_, "ownership": ownership, "error": err, "ffi": ffi, "concurrency": concurrency,
		"crypto": crypto, "injection": injection, "types": types, "resource": resource, "maintainability": maint, "api": api,
	}
	var allSpecs []rustRuleSpec
	for _, family := range []string{"unsafe", "ownership", "error", "ffi", "concurrency", "crypto", "injection", "types", "resource", "maintainability", "api"} {
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
		} else if s.family == "injection" {
			owaspSlice = []string{"A03:2021"}
		}
		rules = append(rules, rule.Rule{
			Key: rule.Key("rust:" + s.key), Name: s.name, Language: "Rust", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"rust", "rust-" + s.family}, CWE: cweSlice, OWASP: owaspSlice,
			Description: rustDescription(s), Rationale: rustRationale(s),
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: rustEffort(s), Detection: s.detection,
		})
	}
	return rules
}

func rustDescription(s rustRuleSpec) string {
	shape := map[string]string{
		"transmute-ptr-to-ref": "std::mem::transmute converting a raw pointer directly to a reference",
		"unsafe-block-scope": "an overly broad unsafe block containing safe expressions",
		"raw-ptr-deref-no-null-check": "a raw pointer dereference without checking is_null()",
		"unaligned-raw-ptr-read": "a direct dereference of a potentially unaligned raw pointer",
		"slice-from-raw-parts-null": "slice::from_raw_parts called without a null pointer check",
		"non-repr-c-transmute": "transmuting between struct types that lack #[repr(C)]",
		"unsafe-static-mut-ref": "creating a shared or mutable reference to a static mut variable",
		"unsafe-impl-send-sync": "a manual unsafe impl of Send or Sync for a generic type",
		"ptr-copy-overlap-hazard": "std::ptr::copy_nonoverlapping on potentially overlapping slices",
		"uninit-buffer-exposure": "MaybeUninit::assume_init invoked before memory is populated",
		"transmute-mut-ref-aliasing": "transmute used to alias multiple mutable references to one location",
		"raw-pointer-arithmetic-oob": "raw pointer offset calculation without bounds validation",
		"unsafe-fn-without-doc": "an unsafe function declaration without a # Safety documentation section",

		"refcell-borrow-across-await": "a RefCell borrow guard held across an async await point",
		"drop-reference-noop": "std::mem::drop invoked on a reference which has no effect",
		"unneeded-box-sized": "a small sized value unnecessarily allocated in a Box on the heap",
		"clone-in-hot-loop": "a deep clone called redundantly inside a loop body",
		"interior-mutability-shared": "a thread-shared struct containing Cell or RefCell interior mutability",
		"leaked-raw-box": "Box::into_raw invoked without paired Box::from_raw cleanup",

		"expect-empty-message": "expect() invoked with an empty or trivial message string",
		"panic-in-ffi-boundary": "panic! invoked inside an extern C ABI function",
		"swallowed-error-let-underscore": "a Result return value discarded using let _ =",
		"custom-error-no-std-trait": "a custom error type that does not implement std::error::Error",
		"panic-in-drop": "panic! or unwrap invoked inside a Drop::drop implementation",

		"ffi-null-ptr-unchecked": "a pointer received from external FFI used without checking is_null()",
		"ffi-missing-repr-c": "a struct passed across an FFI boundary lacking #[repr(C)]",
		"ffi-c-string-missing-nul": "a C string pointer passed to external code without null termination",
		"ffi-opaque-struct-by-value": "an opaque external C struct passed by value instead of by pointer",
		"ffi-freed-c-pointer": "libc::free invoked on a Rust memory allocation",
		"ffi-wide-string-unterminated": "a Windows UTF-16 wide string slice lacking a null terminator",

		"lock-held-across-await": "a synchronous Mutex lock held across an async await point",
		"unbounded-channel-send": "an unbounded channel used without backpressure control",
		"thread-spawn-in-loop": "unbounded std::thread::spawn calls inside a loop",
		"atomic-relaxed-ordering-sync": "Atomic Ordering::Relaxed used for a thread synchronization flag",
		"condvar-wait-no-predicate": "Condvar::wait called without a surrounding predicate loop",

		"insecure-cipher-ecb": "AES encryption configured with electronic codebook (ECB) mode",
		"insecure-prng-security": "non-cryptographic randomness used for security tokens",
		"hardcoded-secret-bytes": "hardcoded cryptographic key or secret byte literal",
		"static-nonce-reuse": "a static or hardcoded nonce used with an AEAD cipher",
		"timing-attack-memcmp": "non-constant-time equality comparison on secret tokens",
		"deprecated-hash-md5": "MD5 or SHA-1 hash function used in security context",
		"weak-rsa-key-size": "an RSA key generated with fewer than 2048 bits",
		"jwt-insecure-none-algo": "JWT validation configured to accept the None algorithm",

		"sql-string-formatting": "a SQL query built using string formatting macros",
		"command-injection-sh": "a shell command string formatted with dynamic user input",
		"path-traversal-join": "Path::join called with untrusted dynamic path components",
		"regex-dynamic-compilation": "Regex::new compiled from dynamic user input",
		"server-side-template-injection": "rendering raw user input as a template string",
		"ldap-injection-filter": "an LDAP query filter constructed with unescaped string formatting",
		"xpath-injection-query": "an XPath expression assembled with string concatenation",
		"unrestricted-zip-extract": "extracting zip archive entries without path normalization",
		"eval-dynamic-expression": "evaluating dynamic script expressions from untrusted input",

		"lossy-integer-cast": "a numeric cast with `as` that may truncate higher-order bits",
		"signed-unsigned-cast-hazard": "a signed integer cast to unsigned with `as` without sign check",
		"float-nan-comparison": "a floating-point value compared directly against NaN",
		"pointer-to-integer-cast": "casting pointer to a narrower integer type",
		"char-from-u32-unchecked": "char::from_u32_unchecked called without validation",
		"bitshift-oversized": "a bit shift operation with operand exceeding bit width",

		"tempfile-insecure-path": "creating a temporary file with a predictable static path",
		"socket-missing-timeout": "a TcpStream created without read or write timeouts",
		"file-unbuffered-io": "unbuffered file I/O operations inside a loop",
		"child-process-not-waited": "spawning a child process without calling wait() or handling exit",
		"unbounded-vec-reserve": "Vec::reserve called with unvalidated user capacity",

		"long-function-statements": "a function body containing an excessive number of statements",
		"deep-control-nesting": "control flow nested beyond four levels",
		"excessive-parameters": "a function declared with more than seven parameters",
		"magic-number-condition": "an unnamed numeric literal in a conditional comparison",
		"todo-comment-untracked": "a TODO or FIXME comment left in production source",
		"commented-out-code": "a block of commented-out Rust code statements",
		"single-letter-variable-name": "a single-letter variable name in a wide scope",
		"large-enum-variant-size": "an enum variant significantly larger than others requiring Box",
		"redundant-closure-call": "a closure that simply forwards arguments to a named function",
		"collapsible-if-statements": "nested if statements that can be merged with &&",
		"match-single-binding": "a match expression with a single active arm",

		"missing-must-use": "a pure or Result-returning public function missing #[must_use]",
		"public-api-undocumented": "a public API function or type missing doc comments",
		"display-missing-debug": "a type implementing Display but missing a Debug derive",
	}[s.key]
	return fmt.Sprintf("Reports %s. It inspects only that local syntax or structure and does not prove the surrounding runtime path, ownership, input trust, or intent.", shape)
}

func rustRationale(s rustRuleSpec) string {
	reason := map[string]string{
		"transmute-ptr-to-ref": "Transmuting raw pointers directly to references bypasses lifetime, nullability, and alignment invariants.",
		"unsafe-block-scope": "Overly broad unsafe blocks obscure the exact operations requiring invariant maintenance.",
		"raw-ptr-deref-no-null-check": "Dereferencing null or unaligned raw pointers causes segmentation faults and undefined behavior.",
		"unaligned-raw-ptr-read": "Reading unaligned memory on architectures requiring alignment leads to crashes and CPU traps.",
		"slice-from-raw-parts-null": "Passing a null pointer to slice::from_raw_parts violates the non-null slice invariant.",
		"non-repr-c-transmute": "Structs without #[repr(C)] have unspecified layout that may change between compiler releases.",
		"unsafe-static-mut-ref": "References to mutable static variables introduce data races when accessed concurrently.",
		"unsafe-impl-send-sync": "Incorrect Send/Sync implementations permit non-thread-safe data to cross thread boundaries.",
		"ptr-copy-overlap-hazard": "Calling copy_nonoverlapping on overlapping memory regions corrupts memory contents.",
		"uninit-buffer-exposure": "Assuming initialization of uninitialized memory reads arbitrary memory contents.",
		"transmute-mut-ref-aliasing": "Aliasing mutable references violates Rust's fundamental aliasing XOR mutability model.",
		"raw-pointer-arithmetic-oob": "Unchecked pointer arithmetic can compute out-of-bounds addresses leading to memory corruption.",
		"unsafe-fn-without-doc": "Unsafe functions require clear documentation of caller invariants to prevent misuse.",

		"refcell-borrow-across-await": "Holding RefCell borrow guards across await points causes runtime panic on re-entrant calls.",
		"drop-reference-noop": "Calling std::mem::drop on a reference does not drop the underlying owned value.",
		"unneeded-box-sized": "Heap allocating small sized values adds unnecessary allocation overhead and indirection.",
		"clone-in-hot-loop": "Deep cloning large structures on each loop iteration multiplies memory and CPU overhead.",
		"interior-mutability-shared": "Cell and RefCell are not thread-safe; sharing them across threads causes data corruption.",
		"leaked-raw-box": "Forgetting to reclaim Box::into_raw allocations leads to progressive heap memory leaks.",

		"expect-empty-message": "Empty expect messages make crash diagnostics difficult during production triage.",
		"panic-in-ffi-boundary": "Panicking inside an FFI function violates the C ABI and aborts the host process.",
		"swallowed-error-let-underscore": "Discarding Result errors with let _ ignores failure notifications and causes silent corruption.",
		"custom-error-no-std-trait": "Error types not implementing std::error::Error cannot integrate with standard error machinery.",
		"panic-in-drop": "Panicking during stack unwinding inside Drop causes the Rust runtime to immediately abort.",

		"ffi-null-ptr-unchecked": "Dereferencing unchecked null pointers from FFI boundaries crashes the host process.",
		"ffi-missing-repr-c": "Rust struct layout is undefined without #[repr(C)], causing field misalignment with C code.",
		"ffi-c-string-missing-nul": "Passing non-null-terminated byte buffers to C string APIs causes buffer over-reads.",
		"ffi-opaque-struct-by-value": "Passing opaque structs by value causes size and alignment mismatches across ABIs.",
		"ffi-freed-c-pointer": "Deallocating Rust heap memory with libc free causes heap corruption and crashes.",
		"ffi-wide-string-unterminated": "Unterminated wide strings cause Windows APIs to read beyond buffer boundaries.",

		"lock-held-across-await": "Holding standard mutex guards across await points starves other tasks and causes deadlocks.",
		"unbounded-channel-send": "Unbounded channels can exhaust available RAM when producers outpace consumers.",
		"thread-spawn-in-loop": "Spawning unbounded OS threads exhausts system thread limits and causes OS failure.",
		"atomic-relaxed-ordering-sync": "Relaxed ordering allows CPU instruction reordering that breaks synchronization barriers.",
		"condvar-wait-no-predicate": "Spurious wakeups cause threads to proceed before conditions are actually met.",

		"insecure-cipher-ecb": "ECB mode preserves plaintext patterns in ciphertext, leaking confidential data.",
		"insecure-prng-security": "Non-cryptographic RNGs produce predictable sequences vulnerable to token forgery.",
		"hardcoded-secret-bytes": "Embedded secrets in binaries are easily extracted by reverse engineering.",
		"static-nonce-reuse": "Reusing nonces in AEAD encryption completely compromises confidentiality and integrity.",
		"timing-attack-memcmp": "Standard equality comparisons leak secret byte values through variable execution time.",
		"deprecated-hash-md5": "MD5 and SHA-1 have practical collision attacks and are broken for digital signatures.",
		"weak-rsa-key-size": "RSA keys smaller than 2048 bits are vulnerable to factorization attacks.",
		"jwt-insecure-none-algo": "Accepting Algorithm::None allows attackers to forge tokens with empty signatures.",

		"sql-string-formatting": "Formatting user input directly into SQL strings allows SQL injection attacks.",
		"command-injection-sh": "Passing unescaped user data to shell interpreters allows arbitrary OS command execution.",
		"path-traversal-join": "Unsanitized path joins allow directory traversal attacks outside the target folder.",
		"regex-dynamic-compilation": "Compiling untrusted regexes permits Regular Expression Denial of Service (ReDoS).",
		"server-side-template-injection": "Evaluating untrusted template strings allows remote code execution in template engines.",
		"ldap-injection-filter": "Unescaped LDAP queries allow attackers to bypass authentication and extract directory data.",
		"xpath-injection-query": "Unsanitized XPath concatenation allows attackers to extract unauthorized XML nodes.",
		"unrestricted-zip-extract": "Extracting archive entries with ../ components allows arbitrary file overwrite (Zip Slip).",
		"eval-dynamic-expression": "Evaluating untrusted expressions allows arbitrary script execution within the application.",

		"lossy-integer-cast": "Casting with `as` silently truncates higher bits when values exceed target range.",
		"signed-unsigned-cast-hazard": "Casting negative signed numbers to unsigned integers produces massive values.",
		"float-nan-comparison": "Comparing NaN with == always returns false, causing logic branches to be skipped.",
		"pointer-to-integer-cast": "Casting pointers to narrower integer types truncates address bits and causes crashes.",
		"char-from-u32-unchecked": "Unchecked character conversion creates invalid Unicode scalar values.",
		"bitshift-oversized": "Shifting by an amount equal to or greater than bit width produces undefined results.",

		"tempfile-insecure-path": "Predictable temporary paths invite symlink attacks and race condition exploits.",
		"socket-missing-timeout": "Connecting sockets without timeouts can block worker threads indefinitely on hung networks.",
		"file-unbuffered-io": "Performing unbuffered I/O in loops causes massive system call overhead.",
		"child-process-not-waited": "Uncollected child processes remain as zombies and consume OS process table slots.",
		"unbounded-vec-reserve": "Unvalidated reservation sizes allow attackers to trigger out-of-memory panics.",

		"long-function-statements": "Excessively long functions mix responsibilities and resist unit testing.",
		"deep-control-nesting": "Deeply nested control structures increase cognitive load and defect density.",
		"excessive-parameters": "Long parameter lists invite argument ordering errors and indicate high coupling.",
		"magic-number-condition": "Magic numbers obscure domain meaning and complicate future maintenance.",
		"todo-comment-untracked": "Untracked TODO comments accumulate technical debt and represent forgotten work.",
		"commented-out-code": "Dead code in comments creates visual clutter and confuses maintainers.",
		"single-letter-variable-name": "Short variable names outside small loops reduce readability and clarity.",
		"large-enum-variant-size": "Large enum variants increase the memory footprint of every instance of the enum.",
		"redundant-closure-call": "Redundant closure wrappers add unnecessary syntax without functional benefit.",
		"collapsible-if-statements": "Nested single if statements add unnecessary nesting levels.",
		"match-single-binding": "Matching a single pattern with match is more verbose than if let.",

		"missing-must-use": "Ignoring return values from pure functions or constructors usually indicates a caller bug.",
		"public-api-undocumented": "Undocumented public APIs increase onboarding friction and misuse risks.",
		"display-missing-debug": "Types implementing Display without Debug cannot be printed using debug formatting.",
	}[s.key]

	source := "https://doc.rust-lang.org/book/"
	if s.cwe != "" {
		source = "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(s.cwe, "CWE-") + ".html"
	}
	switch s.family {
	case "unsafe":
		source = "https://doc.rust-lang.org/nomicon/"
	case "concurrency":
		source = "https://doc.rust-lang.org/book/ch16-00-concurrency.html"
	case "crypto":
		source = "https://docs.rs/ring/latest/ring/"
	case "injection":
		source = "https://owasp.org/www-project-top-ten/"
	case "api":
		source = "https://rust-lang.github.io/api-guidelines/"
	}
	return fmt.Sprintf("%s\n\nSource: %s", reason, source)
}

func rustEffort(s rustRuleSpec) int {
	switch s.family {
	case "injection", "crypto":
		return 60
	case "concurrency", "resource", "unsafe":
		return 30
	case "maintainability", "api":
		return 5
	default:
		return 15
	}
}

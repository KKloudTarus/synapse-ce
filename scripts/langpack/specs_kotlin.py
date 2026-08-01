# Clean-room Kotlin language-pack rules for issue #202. Each rule is deliberately bounded to a
# high-signal single-line syntax shape; scope-sensitive checks remain conservative rather than pretending
# to have compiler type information.
CC = "commentOnlyLine"

SOURCES = {
    "bugs": "https://kotlinlang.org/docs/exceptions.html",
    "err": "https://kotlinlang.org/docs/exceptions.html",
    "res": "https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.io/use.html",
    "conc": "https://kotlinlang.org/docs/coroutines-basics.html",
    "inj": "https://cwe.mitre.org/data/definitions/74.html",
    "crypto": "https://cwe.mitre.org/data/definitions/327.html",
    "authz": "https://cwe.mitre.org/data/definitions/862.html",
    "hotspot": "https://cwe.mitre.org/data/definitions/489.html",
    "api": "https://kotlinlang.org/docs/coding-conventions.html",
    "types": "https://kotlinlang.org/docs/null-safety.html",
    "perf": "https://kotlinlang.org/docs/sequences.html",
    "maint": "https://kotlinlang.org/docs/coding-conventions.html",
}

DEFAULTS = {
    "bugs": ("bug", "rel", "medium", "CWE-682"),
    "err": ("smell", "maint", "medium", ""),
    "res": ("smell", "maint", "medium", "CWE-404"),
    "conc": ("smell", "maint", "medium", ""),
    "inj": ("vuln", "sec", "high", "CWE-74"),
    "crypto": ("hotspot", "sec", "high", "CWE-327"),
    "authz": ("hotspot", "sec", "high", "CWE-862"),
    "hotspot": ("hotspot", "sec", "medium", "CWE-489"),
    "api": ("smell", "maint", "low", ""),
    "types": ("smell", "maint", "medium", ""),
    "perf": ("smell", "maint", "low", ""),
    "maint": ("smell", "maint", "low", ""),
}

RATIONALES = {
    "bugs": "The {title} form has a direct failure mode or produces a result that contradicts the apparent intent.",
    "err": "The {title} form hides failure context or makes recovery behavior difficult to reason about.",
    "res": "The {title} form leaves resource ownership implicit, making deterministic cleanup easy to miss.",
    "conc": "The {title} form weakens structured concurrency or can block, leak, or outlive its owning scope.",
    "inj": "The {title} form places dynamic data at a sensitive interpreter or I/O boundary without a safe structured API.",
    "crypto": "The {title} form is security-sensitive and needs review to confirm that modern primitives and parameters protect the intended data.",
    "authz": "The {title} form is an authorization boundary that needs review for least-privilege enforcement.",
    "hotspot": "The {title} form changes a security-sensitive runtime behavior and needs explicit review.",
    "api": "The {title} form uses an API with a safer, clearer Kotlin or modern JVM alternative.",
    "types": "The {title} form weakens Kotlin's type or null-safety guarantees and shifts failures to runtime.",
    "perf": "The {title} form performs avoidable work or allocation that a direct collection operation avoids.",
    "maint": "The {title} form adds unnecessary syntax or control-flow burden for future readers and maintainers.",
}

REMEDIATIONS = {
    "bugs": "Replace the faulty expression with the checked operation shown in the compliant example.",
    "err": "Preserve the failure or handle it explicitly as shown in the compliant example.",
    "res": "Give the resource a bounded lifetime with use or an explicit managed owner.",
    "conc": "Use a lifecycle-owned scope and non-blocking coroutine primitive.",
    "inj": "Use a structured, parameterized API and validate untrusted values before the sink.",
    "crypto": "Use the modern primitive or configuration shown in the compliant example and document its security purpose.",
    "authz": "Enforce an explicit authenticated role or ownership predicate at this boundary.",
    "hotspot": "Review the call site and replace it with the restricted alternative shown in the compliant example.",
    "api": "Use the modern Kotlin or JVM API shown in the compliant example.",
    "types": "Keep nullability and type conversion explicit with the safe Kotlin form shown in the compliant example.",
    "perf": "Use the direct collection or sequence operation shown in the compliant example.",
    "maint": "Use the simpler Kotlin form shown in the compliant example.",
}


def r(fam, ident, title, regex, nc, c, *, remediation=None, source=None, cwe=None, type=None, qual=None, sev=None, detection="pattern"):
    dt, dq, ds, dc = DEFAULTS[fam]
    return {
        "id": "kotlin-" + ident, "lang": "kt", "type": type or dt, "qual": qual or dq,
        "sev": sev or ds, "cwe": dc if cwe is None else cwe, "owasp": "", "tags": ["sast", "kotlin", fam],
        "effort": 15, "title": title,
        "desc": "Detects " + title.lower() + " in Kotlin source.",
        "cat_desc": "Detects " + title.lower() + " in Kotlin source.",
        "rationale": RATIONALES[fam].format(title=title.lower()),
        "remediation": remediation or REMEDIATIONS[fam],
        "source": source or SOURCES[fam], "re": regex, "nc": nc, "c": c, "skip": CC,
        "detection": detection,
    }


RULES = [
    # bugs (22)
    r("bugs", "constant-if-true", "Constant true if condition", r'\bif\s*\(\s*true\s*\)', 'if (true) work()', 'if (ready) work()'),
    r("bugs", "constant-if-false", "Constant false if condition", r'\bif\s*\(\s*false\s*\)', 'if (false) work()', 'if (ready) work()'),
    r("bugs", "self-assignment", "Self assignment", r'^\s*(count\s*=\s*count|value\s*=\s*value|result\s*=\s*result)\s*$', 'count = count', 'this.count = count'),
    r("bugs", "self-equality", "Self equality comparison", r'\b(value\s*==\s*value|count\s*==\s*count|result\s*==\s*result)\b', 'if (value == value) work()', 'if (value == expected) work()'),
    r("bugs", "self-inequality", "Self inequality comparison", r'\b(value\s*!=\s*value|count\s*!=\s*count|result\s*!=\s*result)\b', 'if (value != value) work()', 'if (value != expected) work()'),
    r("bugs", "nan-equality", "NaN equality comparison", r'(==|!=)\s*(Double|Float)\.NaN|\b(Double|Float)\.NaN\s*(==|!=)', 'if (value == Double.NaN) work()', 'if (value.isNaN()) work()'),
    r("bugs", "integer-division-before-conversion", "Integer division before floating conversion", r'\b\w+\s*/\s*\w+\s*\.to(Double|Float)\(\)', 'val ratio = total / count.toDouble()', 'val ratio = total.toDouble() / count'),
    r("bugs", "random-empty-bound", "Random call with zero bound", r'\b(nextInt|nextLong)\s*\(\s*0\s*\)', 'val n = random.nextInt(0)', 'val n = random.nextInt(10)'),
    r("bugs", "division-by-zero", "Literal division by zero", r'/\s*0(?:[LFDf])?\b', 'val result = total / 0', 'val result = total / divisor'),
    r("bugs", "modulo-by-zero", "Literal modulo by zero", r'%\s*0(?:[LFDf])?\b', 'val bucket = id % 0', 'val bucket = id % bucketCount'),
    r("bugs", "negative-repeat", "Negative repeat count", r'\brepeat\s*\(\s*-\s*\d+', 'repeat(-1) { work() }', 'repeat(items.size) { work() }'),
    r("bugs", "negative-substring-index", "Negative substring index", r'\.substring\s*\(\s*-\s*\d+', 'val tail = text.substring(-1)', 'val tail = text.substring(1)'),
    r("bugs", "negative-take-count", "Negative take count", r'\.take(Last)?\s*\(\s*-\s*\d+', 'val part = items.take(-2)', 'val part = items.take(2)'),
    r("bugs", "negative-drop-count", "Negative drop count", r'\.drop(Last)?\s*\(\s*-\s*\d+', 'val part = items.drop(-2)', 'val part = items.drop(2)'),
    r("bugs", "empty-random-range", "Empty random range", r'\(\s*(5\s+until\s+5|0\s+until\s+0)\s*\)\.random\(', 'val n = (5 until 5).random()', 'val n = (0 until 5).random()'),
    r("bugs", "assert-false", "Assertion with constant false", r'\bassert\s*\(\s*false\s*\)', 'assert(false)', 'assert(isValid)'),
    r("bugs", "require-false", "Requirement with constant false", r'\brequire\s*\(\s*false\s*\)', 'require(false)', 'require(value > 0)'),
    r("bugs", "check-false", "State check with constant false", r'\bcheck\s*\(\s*false\s*\)', 'check(false)', 'check(isReady)'),
    r("bugs", "int-shift-width", "Integer shift exceeds width", r'\b(shl|shr|ushr)\s+(3[2-9]|[4-9][0-9])\b', 'val mask = 1 shl 32', 'val mask = 1 shl 16'),
    r("bugs", "long-shift-width", "Long shift exceeds width", r'\b(shl|shr|ushr)\s+(6[4-9]|[7-9][0-9])\b', 'val mask = 1L shl 64', 'val mask = 1L shl 32'),
    r("bugs", "iterator-next-direct", "Iterator next without availability check", r'\biterator\(\)\.next\(\)', 'val first = items.iterator().next()', 'val first = items.firstOrNull()'),
    r("bugs", "single-null-list", "List initialized with unintended single null", r'\b(listOf|mutableListOf)\s*\(\s*null\s*\)', 'val values = listOf(null)', 'val values = emptyList<String?>()'),

    # err (8)
    r("err", "empty-catch", "Empty catch block", r'\bcatch\s*\([^)]*\)\s*\{\s*\}', 'try { work() } catch (e: Exception) {}', 'try { work() } catch (e: Exception) { logger.warn("failed", e) }', detection="ast"),
    r("err", "catch-throwable", "Catch of Throwable", r'\bcatch\s*\([^:]+:\s*Throwable\b', 'catch (failure: Throwable) { recover() }', 'catch (failure: IOException) { recover() }'),
    r("err", "catch-error", "Catch of JVM Error", r'\bcatch\s*\([^:]+:\s*(Error|VirtualMachineError)\b', 'catch (failure: Error) { recover() }', 'catch (failure: IOException) { recover() }'),
    r("err", "print-stack-trace", "Direct stack trace printing", r'\.printStackTrace\s*\(', 'failure.printStackTrace()', 'logger.error("request failed", failure)'),
    r("err", "throw-message-only", "Exception wrapping loses cause", r'throw\s+\w*Exception\s*\(\s*\w+\.message\s*\)', 'throw IllegalStateException(error.message)', 'throw IllegalStateException("operation failed", error)'),
    r("err", "run-catching-get-or-null", "runCatching failure discarded by getOrNull", r'runCatching\s*\{.*\}\s*\.getOrNull\s*\(', 'val value = runCatching { load() }.getOrNull()', 'val value = runCatching { load() }.getOrElse { recover(it) }'),
    r("err", "empty-on-failure", "Empty onFailure handler", r'\.onFailure\s*\{\s*\}', 'runCatching { load() }.onFailure {}', 'runCatching { load() }.onFailure { logger.warn("failed", it) }'),
    r("err", "return-in-finally", "Return from finally block", r'\bfinally\s*\{[^}]*\breturn\b', 'try { load() } finally { return fallback }', 'try { load() } finally { cleanup() }', detection="ast"),

    # res (6)
    r("res", "file-input-stream-without-use", "FileInputStream created without use", r'FileInputStream\s*\([^)]*\)\s*$', 'val input = FileInputStream(path)', 'FileInputStream(path).use { input -> read(input) }'),
    r("res", "file-output-stream-without-use", "FileOutputStream created without use", r'FileOutputStream\s*\([^)]*\)\s*$', 'val output = FileOutputStream(path)', 'FileOutputStream(path).use { output -> write(output) }'),
    r("res", "files-lines-without-use", "Files lines stream created without use", r'Files\.lines\s*\([^)]*\)\s*$', 'val lines = Files.lines(path)', 'Files.lines(path).use { lines -> consume(lines) }'),
    r("res", "cursor-without-use", "Database cursor created without use", r'\b(rawQuery|query)\s*\([^;]*\)\s*$', 'val cursor = db.rawQuery(sql, args)', 'db.rawQuery(sql, args).use { cursor -> read(cursor) }'),
    r("res", "response-body-without-use", "HTTP response body created without use", r'\.body\(\)\s*$', 'val body = response.body()', 'response.body().use { body -> consume(body) }'),
    r("res", "executor-without-close", "Executor created without managed shutdown", r'Executors\.new\w*Thread\w*\s*\([^)]*\)\s*$', 'val pool = Executors.newFixedThreadPool(4)', 'Executors.newFixedThreadPool(4).use { pool -> submit(pool) }'),

    # conc (12)
    r("conc", "global-scope", "GlobalScope coroutine", r'\bGlobalScope\.(launch|async)\s*(\(|\{)', 'GlobalScope.launch { refresh() }', 'scope.launch { refresh() }'),
    r("conc", "blocking-in-coroutine", "Blocking sleep in coroutine", r'\b(suspend\s+fun|launch\s*\{|async\s*\{).*Thread\.sleep\s*\(', 'suspend fun refresh() { Thread.sleep(100) }', 'suspend fun refresh() { delay(100) }', detection="ast"),
    r("conc", "future-get-in-coroutine", "Blocking Future get in coroutine", r'\b(suspend\s+fun|launch\s*\{|async\s*\{).*\.get\s*\(\s*\)', 'suspend fun load() { future.get() }', 'suspend fun load() { future.await() }', detection="ast"),
    r("conc", "latch-await-in-coroutine", "Blocking latch await in coroutine", r'\b(suspend\s+fun|launch\s*\{|async\s*\{).*\b(latch|barrier)\.await\s*\(\s*\)', 'suspend fun load() { latch.await() }', 'suspend fun load() { deferred.await() }', detection="ast"),
    r("conc", "run-blocking-in-suspend", "runBlocking inside suspend function", r'\bsuspend\s+fun\b.*\brunBlocking\s*\{', 'suspend fun load() { runBlocking { fetch() } }', 'suspend fun load() { coroutineScope { fetch() } }', detection="ast"),
    r("conc", "synchronized-in-suspend", "Synchronized block in suspend function", r'\bsuspend\s+fun\b.*\bsynchronized\s*\(', 'suspend fun load() { synchronized(lock) { fetch() } }', 'suspend fun load() { mutex.withLock { fetch() } }', detection="ast"),
    r("conc", "unconfined-dispatcher", "Unconfined coroutine dispatcher", r'\bDispatchers\.Unconfined\b', 'scope.launch(Dispatchers.Unconfined) { work() }', 'scope.launch(Dispatchers.Default) { work() }'),
    r("conc", "new-single-thread-context", "Unmanaged single thread coroutine context", r'\bnewSingleThreadContext\s*\(', 'val dispatcher = newSingleThreadContext("worker")', 'val dispatcher = Dispatchers.IO.limitedParallelism(1)'),
    r("conc", "detached-main-scope", "Unmanaged MainScope creation", r'\bMainScope\s*\(\s*\)', 'val scope = MainScope()', 'val scope = CoroutineScope(job + Dispatchers.Main)'),
    r("conc", "async-result-ignored", "Async result ignored", r'^\s*async\s*\{', 'async { load() }', 'val result = async { load() }'),
    r("conc", "bare-launch", "Coroutine launch without explicit scope", r'^\s*launch\s*\{', 'launch { load() }', 'scope.launch { load() }'),
    r("conc", "cancellation-swallowed", "Cancellation exception swallowed", r'catch\s*\([^:]+:\s*CancellationException\b[^}]*\b(logger|recover|return)\b[^}]*\}', 'catch (cancelled: CancellationException) { logger.info("cancelled") }', 'catch (cancelled: CancellationException) { throw cancelled }', detection="ast"),

    # inj (8)
    r("inj", "sql-concat", "SQL statement built by concatenation", r'(?i)(execute|query|rawQuery)\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*\+', 'statement.execute("SELECT * FROM users WHERE id=" + id)', 'statement.execute("SELECT * FROM users WHERE id=?", arrayOf(id))', cwe="CWE-89"),
    r("inj", "sql-template", "SQL statement uses string interpolation", r'(?i)(execute|query|rawQuery)\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*\$', 'statement.execute("SELECT * FROM users WHERE id=$id")', 'statement.execute("SELECT * FROM users WHERE id=?", arrayOf(id))', cwe="CWE-89"),
    r("inj", "runtime-exec", "Dynamic Runtime command execution", r'Runtime\.getRuntime\(\)\.exec\s*\([^"].*\)', 'Runtime.getRuntime().exec(command)', 'ProcessBuilder(listOf("convert", safePath)).start()', cwe="CWE-78"),
    r("inj", "process-builder-string", "ProcessBuilder receives dynamic command string", r'ProcessBuilder\s*\(\s*[^"\[]', 'ProcessBuilder(command).start()', 'ProcessBuilder("convert", safePath).start()', cwe="CWE-78"),
    r("inj", "path-from-request", "File path built directly from request input", r'\b(File|Path\.of|Paths\.get)\s*\([^)]*(request|parameter|query|input)', 'val file = File(request.getParameter("path"))', 'val file = safeRoot.resolve(name).normalize().toFile()', cwe="CWE-22"),
    r("inj", "url-from-request", "Network URL built directly from request input", r'\b(URL|URI)\s*\([^)]*(request|parameter|query|input)', 'val url = URL(request.getParameter("url"))', 'val url = URL("https://api.example.test/status")', cwe="CWE-918"),
    r("inj", "object-input-stream", "Native object deserialization", r'\bObjectInputStream\s*\(', 'val stream = ObjectInputStream(request.inputStream)', 'val value = json.decodeFromStream<Message>(request.inputStream)', cwe="CWE-502"),
    r("inj", "xpath-concat", "XPath expression built by concatenation", r'\.evaluate\s*\([^)]*\+', 'xpath.evaluate("//user[name=" + name + "]", doc)', 'xpath.evaluate("//user", doc)', cwe="CWE-643"),

    # crypto (6)
    r("crypto", "weak-hash", "Weak MD5 or SHA-1 digest", r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"', 'val digest = MessageDigest.getInstance("MD5")', 'val digest = MessageDigest.getInstance("SHA-256")'),
    r("crypto", "weak-cipher", "Weak DES or RC4 cipher", r'Cipher\.getInstance\s*\(\s*"(DES|DESede|RC4)', 'val cipher = Cipher.getInstance("DES")', 'val cipher = Cipher.getInstance("AES/GCM/NoPadding")'),
    r("crypto", "ecb-mode", "Cipher uses ECB mode", r'Cipher\.getInstance\s*\(\s*"[^"]*/ECB/', 'val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")', 'val cipher = Cipher.getInstance("AES/GCM/NoPadding")'),
    r("crypto", "insecure-random", "Predictable random generator in security context", r'\b(Random|java\.util\.Random)\s*\(\s*\)', 'val token = Random().nextBytes(buffer)', 'val token = SecureRandom().nextBytes(buffer)'),
    r("crypto", "static-iv", "Static initialization vector", r'IvParameterSpec\s*\(\s*(byteArrayOf|"[^"]*"\.toByteArray)', 'val iv = IvParameterSpec(byteArrayOf(0, 0, 0, 0))', 'val iv = IvParameterSpec(SecureRandom().generateSeed(12))'),
    r("crypto", "trust-all-hostnames", "Trust-all hostname verifier", r'HostnameVerifier\s*\{[^}]*true\s*\}', 'val verifier = HostnameVerifier { _, _ -> true }', 'val verifier = HttpsURLConnection.getDefaultHostnameVerifier()'),

    # authz (3)
    r("authz", "permit-all-requests", "All HTTP requests permitted", r'\banyRequest\(\)\.permitAll\(\)', 'http.authorizeHttpRequests { it.anyRequest().permitAll() }', 'http.authorizeHttpRequests { it.anyRequest().authenticated() }'),
    r("authz", "wildcard-role", "Wildcard authorization role", r'\b(hasRole|hasAuthority)\s*\(\s*"\*"', 'authorize.hasRole("*")', 'authorize.hasRole("ADMIN")'),
    r("authz", "hardcoded-admin-name", "Authorization by hardcoded user name", r'\b(user(name)?|principal\.name)\s*==\s*"admin"', 'if (principal.name == "admin") allow()', 'if (principal.hasRole(Role.ADMIN)) allow()'),

    # hotspot (8)
    r("hotspot", "reflection-accessible", "Reflective access override", r'\.isAccessible\s*=\s*true\b|\.setAccessible\s*\(\s*true\s*\)', 'field.isAccessible = true', 'val value = publicMethod.invoke(target)'),
    r("hotspot", "webview-javascript", "WebView JavaScript enabled", r'\.javaScriptEnabled\s*=\s*true\b', 'webView.settings.javaScriptEnabled = true', 'webView.settings.javaScriptEnabled = false'),
    r("hotspot", "webview-javascript-interface", "WebView JavaScript interface exposed", r'\.addJavascriptInterface\s*\(', 'webView.addJavascriptInterface(bridge, "native")', 'webView.loadUrl(safePage)'),
    r("hotspot", "sensitive-logging", "Sensitive value written to log", r'(?i)\b(log|logger)\.(trace|debug|info|warn|error)\s*\([^)]*(password|token|secret|credential)', 'logger.info("token=$token")', 'logger.info("authentication completed")', cwe="CWE-532"),
    r("hotspot", "cleartext-http", "Cleartext HTTP endpoint", r'"http://[A-Za-z][^"]+"', 'val endpoint = "http://api.example.test"', 'val endpoint = "https://api.example.test"', cwe="CWE-319"),
    r("hotspot", "legacy-tls", "Legacy TLS protocol requested", r'SSLContext\.getInstance\s*\(\s*"(SSL|TLSv1|TLSv1\.1)"', 'val context = SSLContext.getInstance("TLSv1")', 'val context = SSLContext.getInstance("TLSv1.3")', cwe="CWE-326"),
    r("hotspot", "dynamic-class-loading", "Dynamic class loading", r'\bClass\.forName\s*\([^"].*\)', 'val type = Class.forName(className)', 'val type = KnownHandler::class.java'),
    r("hotspot", "reflection-invoke", "Reflective method invocation", r'\.getDeclaredMethod\s*\([^)]*\).*\.invoke\s*\(', 'service.javaClass.getDeclaredMethod(name).invoke(service)', 'service.handle(request)'),

    # api (15)
    r("api", "println-logging", "Console printing used for logging", r'\b(System\.(out|err)\.)?(print|println)\s*\(', 'println("request failed")', 'logger.warn("request failed")'),
    r("api", "java-date", "Legacy java.util.Date API", r'\b(Date\s*\(|java\.util\.Date\b)', 'val now = Date()', 'val now = Instant.now()'),
    r("api", "calendar", "Legacy Calendar API", r'\bCalendar\.getInstance\s*\(', 'val calendar = Calendar.getInstance()', 'val today = LocalDate.now()'),
    r("api", "simple-date-format", "Non-thread-safe SimpleDateFormat", r'\bSimpleDateFormat\s*\(', 'val format = SimpleDateFormat("yyyy-MM-dd")', 'val format = DateTimeFormatter.ISO_LOCAL_DATE'),
    r("api", "string-buffer", "Legacy StringBuffer API", r'\bStringBuffer\s*\(', 'val text = StringBuffer()', 'val text = StringBuilder()'),
    r("api", "vector", "Legacy Vector collection", r'\bVector\s*<|\bVector\s*\(', 'val values = Vector<String>()', 'val values = mutableListOf<String>()'),
    r("api", "hashtable", "Legacy Hashtable collection", r'\bHashtable\s*<|\bHashtable\s*\(', 'val values = Hashtable<String, String>()', 'val values = mutableMapOf<String, String>()'),
    r("api", "thread-stop", "Unsafe Thread stop", r'\.stop\s*\(\s*\)', 'worker.stop()', 'worker.interrupt()'),
    r("api", "thread-suspend", "Unsafe Thread suspend", r'\.suspend\s*\(\s*\)', 'worker.suspend()', 'pauseSignal.await()'),
    r("api", "thread-resume", "Unsafe Thread resume", r'\.resume\s*\(\s*\)', 'worker.resume()', 'pauseSignal.countDown()'),
    r("api", "system-gc", "Explicit garbage collection request", r'\b(System\.gc|Runtime\.getRuntime\(\)\.gc)\s*\(', 'System.gc()', 'releaseReferences()'),
    r("api", "finalize", "Finalizer override", r'\boverride\s+fun\s+finalize\s*\(', 'override fun finalize() { close() }', 'override fun close() { release() }'),
    r("api", "locale-lowercase", "Locale-sensitive lowercase conversion", r'\.(toLowerCase|lowercase)\s*\(\s*\)', 'val key = name.lowercase()', 'val key = name.lowercase(Locale.ROOT)'),
    r("api", "locale-uppercase", "Locale-sensitive uppercase conversion", r'\.(toUpperCase|uppercase)\s*\(\s*\)', 'val key = name.uppercase()', 'val key = name.uppercase(Locale.ROOT)'),
    r("api", "big-decimal-double", "BigDecimal constructed from Double", r'\bBigDecimal\s*\(\s*\d+\.\d+', 'val amount = BigDecimal(0.1)', 'val amount = BigDecimal("0.1")'),

    # types (12)
    r("types", "not-null-assertion", "Not-null assertion", r'!!', 'val name = user.name!!', 'val name = user.name ?: return', detection="ast"),
    # ponytail: syntax-only Java-boundary proxy; upgrade to classpath-aware Kotlin Analysis API for full platform-type resolution.
    r("types", "platform-type-npe", "Unsafe Java-boundary nullability use", r'\b(java|javax|android)\.[A-Za-z0-9_.]+\([^)]*\)\.[A-Za-z_]\w*\s*\(', 'val value = java.lang.System.getenv("NAME").trim()', 'val value = java.lang.System.getenv("NAME")?.trim().orEmpty()'),
    r("types", "unsafe-cast", "Unchecked cast with as", r'\bas\s+[A-Z][A-Za-z0-9_<>?, .]*\b', 'val user = value as User', 'val user = value as? User ?: return'),
    r("types", "lateinit-property", "Late-initialized property", r'\blateinit\s+var\b', 'lateinit var service: Service', 'val service: Service by lazy { createService() }'),
    r("types", "any-type", "Overly broad Any type", r':\s*Any\??\b', 'fun handle(value: Any) = consume(value)', 'fun handle(value: Request) = consume(value)'),
    r("types", "star-projection", "Unbounded star projection", r'<\s*\*\s*>', 'fun consume(items: List<*>) = work(items)', 'fun consume(items: List<Item>) = work(items)'),
    r("types", "unchecked-cast-suppression", "Unchecked cast warning suppressed", r'@Suppress\s*\(\s*"UNCHECKED_CAST"', '@Suppress("UNCHECKED_CAST")', '@Suppress("DEPRECATION")'),
    r("types", "nullable-collection", "Nullable collection reference", r':\s*(List|Set|Map|Collection)<[^>]+>\?', 'val users: List<User>? = load()', 'val users: List<User> = load().orEmpty()'),
    r("types", "nullable-elements", "Collection with nullable elements", r':\s*(List|Set|Collection)<[^>]+\?>', 'val users: List<User?> = load()', 'val users: List<User> = loadNotNull()'),
    r("types", "java-optional", "Java Optional used in Kotlin API", r'\bOptional<|\bOptional\.(of|empty|ofNullable)\s*\(', 'fun find(): Optional<User> = Optional.empty()', 'fun find(): User? = null'),
    r("types", "nullable-boolean", "Nullable Boolean state", r':\s*Boolean\?', 'val enabled: Boolean? = loadFlag()', 'val enabled: Boolean = loadFlag() ?: false'),
    r("types", "nullable-nothing", "Nullable Nothing declaration", r':\s*Nothing\?', 'val absent: Nothing? = null', 'val absent: String? = null'),

    # perf (8)
    r("perf", "filter-first", "filter followed by first", r'\.filter\s*(\([^)]*\)|\{[^}]*\})\.first(OrNull)?\s*\(', 'val user = users.filter { it.active }.first()', 'val user = users.first { it.active }'),
    r("perf", "filter-last", "filter followed by last", r'\.filter\s*(\([^)]*\)|\{[^}]*\})\.last(OrNull)?\s*\(', 'val user = users.filter { it.active }.last()', 'val user = users.last { it.active }'),
    r("perf", "map-filter", "map before filter allocation", r'\.map\s*(\([^)]*\)|\{[^}]*\})\.filter\s*(\(|\{)', 'val names = users.map { it.name }.filter { it.isNotEmpty() }', 'val names = users.filter { it.name.isNotEmpty() }.map { it.name }'),
    r("perf", "sorted-first", "Full sort used to find minimum", r'\.sorted(By|With)?\s*(\([^)]*\)|\{[^}]*\})\.first(OrNull)?\s*\(', 'val first = users.sortedBy { it.age }.first()', 'val first = users.minByOrNull { it.age }'),
    r("perf", "sorted-last", "Full sort used to find maximum", r'\.sorted(By|With)?\s*(\([^)]*\)|\{[^}]*\})\.last(OrNull)?\s*\(', 'val last = users.sortedBy { it.age }.last()', 'val last = users.maxByOrNull { it.age }'),
    r("perf", "to-list-count", "Collection allocation only to count", r'\.toList\s*\(\s*\)\.(size|count\(\))', 'val count = sequence.toList().size', 'val count = sequence.count()'),
    r("perf", "to-set-distinct", "Set allocation only for distinct list", r'\.toSet\s*\(\s*\)\.toList\s*\(', 'val unique = values.toSet().toList()', 'val unique = values.distinct()'),
    r("perf", "regex-in-loop", "Regular expression compiled in loop", r'\b(for|while)\b.*\bRegex\s*\(', 'for (line in lines) { val match = Regex(pattern).find(line) }', 'val regex = Regex(pattern); for (line in lines) { regex.find(line) }'),

    # maint (21 patterns + cognitive metric catalog rule = 22)
    r("maint", "wildcard-import", "Wildcard import", r'^\s*import\s+[A-Za-z0-9_.]+\.\*\s*$', 'import java.util.*', 'import java.util.Locale'),
    r("maint", "semicolon", "Unnecessary semicolon", r';\s*$', 'val value = load();', 'val value = load()'),
    r("maint", "explicit-public", "Redundant public visibility", r'^\s*public\s+(class|object|interface|fun|val|var)\b', 'public fun load() = repository.load()', 'fun load() = repository.load()'),
    r("maint", "redundant-unit-return", "Redundant Unit return type", r'\bfun\s+\w+\s*\([^)]*\)\s*:\s*Unit\b', 'fun save(): Unit { repository.save() }', 'fun save() { repository.save() }'),
    r("maint", "empty-primary-constructor", "Empty primary constructor parentheses", r'\b(class|object)\s+\w+\s*\(\s*\)', 'class Service()', 'class Service'),
    r("maint", "redundant-string-template-braces", "Redundant string template braces", r'\$\{[A-Za-z_]\w*\}', 'val text = "Hello ${name}"', 'val text = "Hello $name"'),
    r("maint", "redundant-to-string-template", "Redundant toString in template", r'\$\{[^}]+\.toString\(\)\}', 'val text = "Value ${value.toString()}"', 'val text = "Value $value"'),
    r("maint", "boolean-literal-comparison", "Boolean compared to literal", r'(==|!=)\s*(true|false)\b', 'if (enabled == true) start()', 'if (enabled) start()'),
    r("maint", "when-boolean", "when expression used for Boolean", r'\bwhen\s*\([^)]*\)\s*\{\s*(true|false)\s*->', 'val label = when (enabled) { true -> "on"; false -> "off" }', 'val label = if (enabled) "on" else "off"'),
    r("maint", "nested-let", "Nested let scope functions", r'\.let\s*\{[^}]*\.let\s*\{', 'user.let { it.address.let { address -> save(address) } }', 'user?.address?.let(::save)'),
    r("maint", "also-transform", "also used for value transformation", r'\.also\s*\{\s*it\s*=', 'val result = value.also { it = transform(it) }', 'val result = value.let(::transform)'),
    r("maint", "apply-result-ignored", "apply result immediately discarded", r'^\s*[A-Z]\w*\([^)]*\)\.apply\s*\{[^}]*\}\s*;?\s*$', 'Builder().apply { configure() }', 'val builder = Builder().apply { configure() }'),
    r("maint", "run-single-call", "run block wrapping one call", r'\brun\s*\{\s*[A-Za-z_]\w*\([^}]*\)\s*\}', 'val value = run { load() }', 'val value = load()'),
    r("maint", "magic-number", "Unexplained large numeric literal", r'\b([2-9][0-9]{2,}|1[0-9]{3,})\b', 'if (elapsed > 86400) expire()', 'if (elapsed > SECONDS_PER_DAY) expire()'),
    r("maint", "too-many-parameters", "Function has too many parameters", r'\bfun\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,', 'fun connect(host: String, port: Int, tls: Boolean, user: String, pass: String, timeout: Int, retries: Int, backoff: Long) = Unit', 'fun connect(options: ConnectionOptions) = Unit'),
    r("maint", "short-variable-name", "Non-descriptive single-letter variable", r'^\s*(val|var)\s+[a-z]\s*=', 'val x = loadUser()', 'val user = loadUser()'),
    r("maint", "backtick-identifier", "Escaped identifier", r'`[^`]+`', 'fun `load user`() = repository.load()', 'fun loadUser() = repository.load()'),
    r("maint", "suppress-all", "Broad warning suppression", r'@Suppress\s*\(\s*"(ALL|warnings)"', '@Suppress("ALL")', '@Suppress("DEPRECATION")'),
    r("maint", "empty-function", "Empty function body", r'\bfun\s+\w+\s*\([^)]*\)\s*\{\s*\}', 'fun refresh() {}', 'fun refresh() { repository.refresh() }'),
    r("maint", "empty-class", "Empty class body", r'\bclass\s+\w+[^\{]*\{\s*\}', 'class Empty {}', 'class User(val name: String)'),
    r("maint", "redundant-this", "Redundant this qualifier", r'\bthis\.[A-Za-z_]\w*\s*\(', 'fun refresh() { this.load() }', 'fun refresh() { load() }'),
]

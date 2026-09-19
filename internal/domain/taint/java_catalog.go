package taint

// java_catalog.go is the reviewable Java framework/library taint model. Two Java realities shape it and are
// worth stating up front, because they set what CAN and CANNOT be import-anchored source-only:
//
//   - `java.lang` types (Runtime, ProcessBuilder, ...) are AUTO-IMPORTED: there is no import statement to
//     anchor to, so a Runtime.exec / new ProcessBuilder sink can only be matched by the type/method-name
//     floor (RawSuffixes), never by an import anchor.
//   - Instance methods on a RUNTIME receiver (stmt.executeQuery, request.getParameter, ois.readObject) have
//     a receiver whose type the source-only facts cannot resolve, so they too use the method-name floor.
//
// The floor is looser and more FP-prone than an import anchor; every taint finding is PROPOSE-ONLY and
// separately verified, exactly the posture the Python/JS engines take for their receiver-typed sinks. Where
// a type is normally single-imported or fully qualified (java.io.File, java.nio.file.Paths, java.net.URL,
// java.beans.XMLDecoder) the sink IS import-anchored; an on-demand `import java.io.*` then falls back to the
// name floor or is missed (a documented precision gap, never a false suppression, since taint only proposes).
//
// This models the classes whose floor is specific enough to defend (Command, PathTraversal, SQL, SSRF,
// Deserialization, Code), plus LDAP (CWE-90) and XPath (CWE-643), whose receiver-name floors (search/
// evaluate/compile) are too generic alone and so are IMPORT-GATED via JavaCallablePattern.RequiresImport:
// they fire only in a file that imports the anchoring API (javax.naming, javax.xml.xpath). Broader,
// FP-sensitive classes (XSS via response writers, XXE, SSTI, log injection) remain deferred rather than
// shipped as over-broad floors.

// javaMod builds an import-anchored pattern: a callee whose base resolves (via import or FQ path) to one of
// modules and whose accessed member is one of names.
func javaMod(modules []string, names ...string) JavaCallablePattern {
	return JavaCallablePattern{Modules: modules, Names: names}
}

// javaCtor builds a pattern matching only a `new X(...)` of one of the (import-anchored / fully-qualified)
// types in modules.
func javaCtor(modules ...string) JavaCallablePattern {
	return JavaCallablePattern{Modules: modules, Constructor: true}
}

// javaRecv builds a receiver/name floor: the callee's syntactic dotted path ends with one of the method-name
// suffixes (e.g. "executeQuery"). This is the tier for runtime-receiver instance methods whose receiver type
// is unknown source-only. It matches whether or not the call is a constructor.
func javaRecv(suffixes ...string) JavaCallablePattern {
	return JavaCallablePattern{RawSuffixes: suffixes}
}

// javaRawCtor builds a constructor-only floor for an AUTO-IMPORTED type (java.lang.ProcessBuilder) that has
// no import to anchor: it matches only a `new X(...)` whose type name ends with one of the suffixes, so a
// same-named ordinary method never matches.
func javaRawCtor(typeNames ...string) JavaCallablePattern {
	return JavaCallablePattern{RawConstructor: typeNames}
}

func javaSink(pattern JavaCallablePattern, class TaintClass, cwe, rule string, args ...int) JavaSinkModel {
	return JavaSinkModel{Pattern: pattern, Class: class, CWE: cwe, Rule: rule, ArgumentIndexes: args}
}

func javaSinkAll(pattern JavaCallablePattern, class TaintClass, cwe, rule string) JavaSinkModel {
	return JavaSinkModel{Pattern: pattern, Class: class, CWE: cwe, Rule: rule, AllArguments: true}
}

// DefaultJavaCatalog returns the built-in Java taint model.
func DefaultJavaCatalog() JavaCatalog {
	return JavaCatalog{
		// Spring web-input annotations on a controller parameter make it fully untrusted (matched by the
		// annotation's SIMPLE name, so a fully-qualified @org.springframework...RequestParam still matches).
		SourceAnnotations: []string{
			"RequestParam", "RequestBody", "PathVariable", "RequestHeader", "CookieValue",
			"ModelAttribute", "MatrixVariable", "RequestPart",
		},
		Sources: []JavaSourceModel{
			// Servlet request accessors return attacker-controlled data. Receiver-typed
			// (HttpServletRequest is a runtime value), so matched by the method-name floor.
			{Pattern: javaRecv(
				"getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders",
				"getQueryString", "getInputStream", "getReader", "getRequestURI", "getRequestURL",
			), Classes: allJavaTaintClasses},
		},
		Sinks: []JavaSinkModel{
			// Command injection (CWE-78). java.lang auto-imported -> name floor. Runtime.getRuntime().exec(cmd)
			// (".exec" is specific); new ProcessBuilder(cmd...) is constructor-only so a method named
			// ProcessBuilder cannot match. Every argument is the command / its parts.
			javaSinkAll(javaRecv("exec"), TaintCommand, "CWE-78", "java-taint-command-exec"),
			javaSinkAll(javaRawCtor("ProcessBuilder"), TaintCommand, "CWE-78", "java-taint-command-processbuilder"),

			// Path traversal (CWE-22). Import-anchored constructors + Paths.get + Files; on-demand import is a
			// documented gap. Every argument is checked because a path can be assembled from parts
			// (new File(base, userChild), Paths.get(base, userSegments...)); a constant like a File mode never
			// receives taint, so over-checking is harmless for this propose-only floor.
			javaSinkAll(javaCtor("java.io.File", "java.io.FileInputStream", "java.io.FileOutputStream",
				"java.io.FileReader", "java.io.FileWriter", "java.io.RandomAccessFile"),
				TaintPathTraversal, "CWE-22", "java-taint-path-file"),
			javaSinkAll(javaMod([]string{"java.nio.file.Paths"}, "get"),
				TaintPathTraversal, "CWE-22", "java-taint-path-paths-get"),
			javaSinkAll(javaMod([]string{"java.nio.file.Files"},
				"newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter", "readAllBytes", "readString"),
				TaintPathTraversal, "CWE-22", "java-taint-path-files"),

			// SQL injection (CWE-89). THE receiver-typed floor case: a Statement/Connection is a runtime value.
			// Matched by SQL-specific method names (bare "execute" is NOT modeled: it collides with
			// ExecutorService.execute). prepareStatement/prepareCall catch dynamic SQL that is later run by a
			// no-arg ps.execute(). A PreparedStatement built from a CONSTANT is a false positive here, which is
			// why findings are propose-only and verified. See the DECLINED note.
			javaSink(javaRecv("executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch",
				"prepareStatement", "prepareCall"), TaintSQL, "CWE-89", "java-taint-sql-statement", 0),

			// SSRF (CWE-918). new URL/URI(spec) is import-anchored; RestTemplate request methods are
			// receiver-typed (SSRF-specific names; bare "execute" excluded to avoid the SQL/exec collision).
			javaSink(javaCtor("java.net.URL", "java.net.URI"), TaintSSRF, "CWE-918", "java-taint-ssrf-url", 0),
			javaSink(javaRecv("getForObject", "getForEntity", "postForObject", "postForEntity", "exchange"),
				TaintSSRF, "CWE-918", "java-taint-ssrf-resttemplate", 0),

			// Deserialization (CWE-502). The vulnerability is deserializing UNTRUSTED DATA, and that data
			// enters through the STREAM constructor argument, not the no-arg readObject(). So the sink is the
			// ObjectInputStream / XMLDecoder constructor's stream argument.
			javaSink(javaCtor("java.io.ObjectInputStream"), TaintDeserialization, "CWE-502", "java-taint-deser-ois", 0),
			javaSink(javaCtor("java.beans.XMLDecoder"), TaintDeserialization, "CWE-502", "java-taint-deser-xmldecoder", 0),

			// Code / script execution (CWE-94). ScriptEngine.eval is receiver-typed; ".eval" is specific.
			javaSink(javaRecv("eval"), TaintCode, "CWE-94", "java-taint-code-scripteval", 0),

			// LDAP injection (CWE-90). DirContext.search(name, filter, controls) is receiver-typed, and bare
			// ".search" is far too generic to floor alone (List/String/Stack/... all have search-like names), so
			// it is IMPORT-GATED: it fires only in a file that imports javax.naming, where a .search(...) is an
			// LDAP directory search. Only the search FILTER (arg 1) is modeled, the canonical injection point,
			// because it is paired with its EXACT escaper Encode.forLdap below. The base DN (arg 0) is not
			// modeled: its correct escaper (Encode.forDn) cannot be told apart from forLdap at a value-based
			// sanitizer wall, so modeling the DN sink would let a forLdap-escaped value used as a DN be wrongly
			// cleared (a false negative). DN-context injection is deferred to argument-role-scoped modeling.
			javaSink(JavaCallablePattern{RawSuffixes: []string{"search"}, RequiresImport: []string{"javax.naming"}},
				TaintLDAP, "CWE-90", "java-taint-ldap-search", 1),

			// XPath injection (CWE-643). XPath.compile(expr) / XPath.evaluate(expr, item) are receiver-typed and
			// ".evaluate"/".compile" are generic, so they are IMPORT-GATED on javax.xml.xpath. The injectable
			// XPATH EXPRESSION is arg 0 of both (XPath.evaluate(String expression, ...) and XPath.compile(String
			// expression)); XPathExpression.evaluate(item) takes a document at arg 0 (a propose-only false match,
			// separately verified), so the real injection is still caught at compile/evaluate of the expression.
			javaSink(JavaCallablePattern{RawSuffixes: []string{"evaluate", "compile"}, RequiresImport: []string{"javax.xml.xpath"}},
				TaintXPath, "CWE-643", "java-taint-xpath-expression", 0),
		},
		// A sanitizer is only modeled when it has SOUND, class-specific, single-call semantics AND an import
		// anchor: an over-matching sanitizer SUPPRESSES a real flow (a false negative, worse than a propose-only
		// false positive), so unlike a sink floor a sanitizer is never modeled on a bare receiver-name floor.
		Sanitizers: []JavaSanitizerModel{
			// LDAP search-filter escaping (OWASP Java Encoder). Encode.forLdap escapes the LDAP filter
			// metacharacters (* ( ) \ NUL), so its result is safe in the filter argument the LDAP sink models.
			// It clears ONLY CWE-90 (a command/SQL/SSRF flow through the same value is untouched) and is
			// import-anchored on org.owasp.encoder.Encode, so a same-named local method never counts as the
			// escaper. forDn is deliberately NOT modeled here: it escapes DN, not filter, metacharacters, and
			// the DN argument is not a modeled sink; treating forDn as clearing the filter would hide a real
			// filter injection.
			{Pattern: javaMod([]string{"org.owasp.encoder.Encode"}, "forLdap"), Classes: []TaintClass{TaintLDAP}},
		},
		// Still deliberately NOT modeled: a path canonicalizer (getCanonicalPath/normalize does not CONTAIN a
		// path to a base directory, so it cannot sanitize traversal); SQL parameter binding (structural, not a
		// call result); command/SSRF allowlisting (a check, not a transform); and XPath escaping (XPath
		// injection is soundly fixed by parameterization via XPathVariableResolver, not by XML/attribute
		// encoding, so no single-call XPath sanitizer is defensible). Modeling any of these would hide a real
		// flow.
	}
}

// DECLINED (intentionally NOT modeled in this cut, to avoid false suppressions of the true positive or a
// flood of false positives):
//   - Bare `.execute()` is NOT a SQL/SSRF sink: it collides with ExecutorService.execute(Runnable),
//     CompletableFuture, etc. and would flood. SQL is caught at the SQL-specific method names
//     (executeQuery/executeUpdate/...) and at prepareStatement/prepareCall (which catch dynamic SQL later run
//     by a no-arg ps.execute()). A PreparedStatement built from a CONSTANT string still matches
//     executeQuery/prepareStatement here (source-only cannot tell a parameterized query from a concatenated
//     one), so downstream verification separates the true positive; findings are propose-only.
//   - XSS through a response writer (println/print/write) is deferred: the method-name floor would collide
//     with System.out logging and produce a flood of false positives without receiver typing.
//   - LDAP (DirContext.search) and XPath (XPath.evaluate/compile) are now MODELED, but only under the
//     RequiresImport gate (javax.naming, javax.xml.xpath): the bare method-name floor is too generic, so the
//     file's import of the anchoring API is required as a defensible type proxy. Findings stay propose-only.
//   - XXE (DocumentBuilder.parse), SSTI, and log injection remain deferred: parse/format floors are too
//     generic even import-gated (the same packages parse trusted input), pending real receiver typing.

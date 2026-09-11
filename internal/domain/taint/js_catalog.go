package taint

// DefaultJsCatalog returns the reviewed initial JavaScript/TypeScript framework pack. Every sink is anchored
// either to a resolved IMPORT (child_process, fs, vm, axios, http), to an unshadowed language GLOBAL (eval,
// Function, fetch), or to the receiver-NAME convention used by the request/response objects (res.send,
// document.write) as the Python catalog anchors cursor.execute / session.execute. The JS receiver-name match
// is tightened beyond Python's: it fires only on the EXACT dotted path and only when the receiver base is a
// parameter or free/global name, never a locally constructed `const res = {...}` object or an import (res and
// response are far more reused than cursor). A shape that would require value-type or object-field resolution
// the PR1 facts do not provide is DECLINED below, with the reason, because emitting a false injection is the
// one forbidden outcome; a missed flow is a coverage gap, which is the safe direction. A parameter named
// res/req that is not the real Express object remains an accepted name-collision limit (the same floor the
// Python cursor.execute convention accepts); findings are propose-only and separately verified, and a future
// tightening to route-handler anchoring is a conscious change.
func DefaultJsCatalog() JsCatalog {
	all := append([]TaintClass(nil), allJsTaintClasses...)
	return JsCatalog{
		// The request object is a positional parameter, so its untrusted members are anchored at the HEAD of
		// the reference path. Prefix matching taints req.query and, through the extractor's container-granular
		// attribute flows, req.query.id as well.
		ReferenceSourcePrefixes: [][]string{
			{"req", "query"}, {"req", "body"}, {"req", "params"}, {"req", "headers"}, {"req", "cookies"}, {"req", "url"},
			{"request", "query"}, {"request", "body"}, {"request", "params"}, {"request", "headers"}, {"request", "cookies"}, {"request", "url"},
			{"ctx", "query"}, {"ctx", "params"}, {"ctx", "headers"}, {"ctx", "request"},
			{"process", "argv"}, {"process", "env"},
		},
		Sources: []JsSourceModel{
			// Express/Fastify accessor methods return an untrusted header/param value. req.get / req.header are
			// matched by the receiver-name convention because req is a parameter, not an import.
			{Pattern: jsRaw("req.get", "req.header", "req.param", "request.get", "request.header", "request.param"), Classes: all},
		},
		Sinks: []JsSinkModel{
			// CWE-78: OS command execution. child_process resolves through the import; the command string is
			// argument zero for every entry (spawn/execFile take args as a separate array that is not the shell
			// program, so only the program/command argument is modeled).
			jsSink(jsMod([]string{"child_process"}, "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"),
				TaintCommand, "CWE-78", "js-taint-command", 0),

			// CWE-94: dynamic code execution. eval / Function are globals (matched only when unshadowed); vm
			// resolves through its import. Function is modeled over ALL arguments because `new Function(a, b,
			// body)` compiles the last argument as a body and the earlier ones as parameter names, any of which
			// being attacker-controlled is code construction.
			jsSinkGlobal(TaintCode, "CWE-94", "js-taint-code", []int{0}, "eval"),
			jsSinkGlobalAll(TaintCode, "CWE-94", "js-taint-code", "Function"),
			jsSink(jsMod([]string{"vm"}, "runInNewContext", "runInThisContext", "runInContext", "compileFunction"),
				TaintCode, "CWE-94", "js-taint-code", 0),

			// CWE-22: filesystem path traversal. fs (and fs/promises) resolve through the import; only the PATH
			// argument (argument zero) is modeled. writeFile/appendFile carry their DATA in argument one, which
			// is deliberately NOT a path sink.
			jsSink(jsMod([]string{"fs", "fs/promises"},
				"readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
				"createReadStream", "createWriteStream", "open", "openSync", "unlink", "unlinkSync", "readdir",
				"readdirSync", "mkdir", "mkdirSync", "rmdir", "rm", "stat", "statSync", "lstat", "lstatSync",
				"access", "accessSync", "copyFile", "copyFileSync", "realpath", "truncate", "truncateSync"),
				TaintPathTraversal, "CWE-22", "js-taint-path", 0),

			// CWE-918: server-side request forgery. axios/http/https resolve through the import and take the URL
			// as a positional string (argument zero); fetch is a global. axios.request / the object-config forms
			// are DECLINED below because the URL sits in an object field the facts cannot resolve.
			jsSink(jsMod([]string{"axios"}, "get", "post", "put", "patch", "delete", "head", "options"),
				TaintSSRF, "CWE-918", "js-taint-ssrf", 0),
			jsSink(jsMod([]string{"http", "https"}, "get", "request"), TaintSSRF, "CWE-918", "js-taint-ssrf", 0),
			jsSink(jsMod([]string{"got"}, "get", "post", "put", "patch", "delete", "head"), TaintSSRF, "CWE-918", "js-taint-ssrf", 0),
			// got(url) and node-fetch's default export are called directly, so the URL is the first positional
			// argument of a module/default call.
			{Pattern: JsCallablePattern{Modules: []string{"got", "node-fetch"}, CallModule: true}, Class: TaintSSRF, CWE: "CWE-918", Rule: "js-taint-ssrf", ArgumentIndexes: []int{0}},
			jsSinkGlobal(TaintSSRF, "CWE-918", "js-taint-ssrf", []int{0}, "fetch"),

			// CWE-79: reflected cross-site scripting. The Express/Fastify response writers and the DOM document
			// writer are matched by the receiver-name convention (res/response/reply/document are parameters or
			// globals, not imports), the same convention the Python catalog uses for cursor.execute. Only the
			// first argument, the written body, is modeled. The generic stream methods .write / .end are
			// DELIBERATELY excluded (see below): they are the Writable API, so `res` bound to a file stream or a
			// socket would flag a non-HTML write. Only the Express-specific .send is matched.
			jsSink(jsRaw("res.send", "response.send", "reply.send", "document.write", "document.writeln"),
				TaintXSS, "CWE-79", "js-taint-xss", 0),

			// CWE-601: open redirect. The redirect target is the first argument of the response redirect method
			// (res.redirect(url); res.redirect(302, url) is DECLINED, argument one, because a status-first form
			// is rare and modeling argument one would flag the safe status-only usage).
			jsSink(jsRaw("res.redirect", "response.redirect"), TaintRedirect, "CWE-601", "js-taint-open-redirect", 0),

			// CWE-1333: an untrusted value compiled as a regular expression (regex injection / ReDoS). RegExp is
			// a global constructor (matched only when unshadowed), invoked as `new RegExp(pattern)` or
			// `RegExp(pattern)`; the PATTERN is argument zero. A second-argument flags string is not injectable.
			// This fires only when the pattern is TAINTED (a literal `/abc/` or a constant string never is), so
			// it flags an attacker-controlled regex, not every dynamic RegExp.
			jsSinkGlobal(TaintReDoS, "CWE-1333", "js-taint-redos", []int{0}, "RegExp"),

			// CWE-502: unsafe deserialization. node-serialize's unserialize and funcster's deepDeserialize
			// reconstruct FUNCTIONS from the serialized payload (an immediately-invoked function expression), so
			// deserializing attacker-controlled data is remote code execution (CVE-2017-5941). Both resolve
			// through their import; the payload is argument zero. The safe alternative is JSON.parse, a distinct
			// function, so no sanitizer makes these calls safe on untrusted input.
			jsSink(jsMod([]string{"node-serialize"}, "unserialize"), TaintDeserialization, "CWE-502", "js-taint-deserialization", 0),
			jsSink(jsMod([]string{"funcster"}, "deepDeserialize"), TaintDeserialization, "CWE-502", "js-taint-deserialization", 0),

			// CWE-1336: server-side template injection. The template-engine compile/render APIs take the
			// TEMPLATE SOURCE at argument zero, so a tainted template can execute engine expressions on the
			// server. Only the source-string APIs are modeled; Express's res.render is DECLINED (its argument
			// zero is a view NAME, a file lookup, not a template source, so modeling it would be a false SSTI on
			// the safe `res.render('view', userData)` form).
			jsSink(jsMod([]string{"handlebars"}, "compile"), TaintSSTI, "CWE-1336", "js-taint-ssti", 0),
			jsSink(jsMod([]string{"pug", "jade"}, "compile", "render"), TaintSSTI, "CWE-1336", "js-taint-ssti", 0),
			jsSink(jsMod([]string{"ejs"}, "compile", "render"), TaintSSTI, "CWE-1336", "js-taint-ssti", 0),
			jsSink(jsMod([]string{"lodash", "underscore"}, "template"), TaintSSTI, "CWE-1336", "js-taint-ssti", 0),
		},
		Sanitizers: []JsSanitizerModel{
			// CWE-79: contextual HTML/URL encoders. encodeURIComponent / encodeURI are globals; the library
			// escapers resolve through their import. Each neutralizes ONLY the XSS class.
			{Pattern: JsCallablePattern{Globals: []string{"encodeURIComponent", "encodeURI"}}, Classes: []TaintClass{TaintXSS}},
			{Pattern: jsMod([]string{"he"}, "encode", "escape"), Classes: []TaintClass{TaintXSS}},
			{Pattern: jsMod([]string{"lodash", "lodash.escape", "validator"}, "escape"), Classes: []TaintClass{TaintXSS}},
			// escape-html's default export IS the escape function, called directly (`escapeHtml(x)`); it must be
			// recognized so an escaped value is not reported as still-tainted.
			{Pattern: JsCallablePattern{Modules: []string{"escape-html", "lodash.escape"}, CallModule: true}, Classes: []TaintClass{TaintXSS}},

			// CWE-22: a basename strips every directory component, neutralizing path traversal only.
			{Pattern: jsMod([]string{"path"}, "basename"), Classes: []TaintClass{TaintPathTraversal}},

			// CWE-78: shell-argument quoting neutralizes command injection only.
			{Pattern: jsMod([]string{"shell-quote"}, "quote"), Classes: []TaintClass{TaintCommand}},
			{Pattern: jsMod([]string{"shescape"}, "quote", "quoteAll", "escape", "escapeAll"), Classes: []TaintClass{TaintCommand}},

			// CWE-1333: escape-string-regexp's default export escapes a string so it matches literally inside a
			// regex, so the value carries no injectable metacharacters; it neutralizes the ReDoS class only.
			{Pattern: JsCallablePattern{Modules: []string{"escape-string-regexp"}, CallModule: true}, Classes: []TaintClass{TaintReDoS}},

			// Numeric coercion produces a Number with no injectable structure, so it neutralizes every class.
			{Pattern: JsCallablePattern{Globals: []string{"Number", "parseInt", "parseFloat"}}, Classes: all},
		},

		// DECLINED, each because sound detection would need resolution the PR1 facts do not carry and the
		// syntactic shape alone would produce a false positive:
		//
		//   - SQL injection (knex.raw / sequelize.query / pg|mysql|mysql2 .query): the receiver is a runtime
		//     CONNECTION INSTANCE (mysql.createPool(), new Client()), not a direct import, so a bare .query /
		//     .raw / .execute match would flag array.query(fn) and obj.execute(). Needs receiver-value type
		//     resolution. Deferred rather than shipped unsound.
		//   - axios(config) / fetch(req, options) / http.get({host}): the URL lives in an object FIELD the
		//     facts do not resolve, so only the positional-string form is modeled here.
		//   - el.innerHTML = x / el.outerHTML = x and dangerouslySetInnerHTML: an ASSIGNMENT-target sink the
		//     call-based engine does not model, and a plain object with an innerHTML property is not a DOM
		//     write. Deferred to a follow-up that adds assignment-target sinks.
		//   - el[computed] = x: a dynamic attribute write whose property is not statically known.
		//   - setTimeout / setInterval string form: the first argument is normally a FUNCTION, so modeling it
		//     as code would flag the safe callback usage.
		//   - res.render(view, locals): the template name is normally a constant and the locals are auto-
		//     escaped, so this is not SSTI in the way Python's Template(source) is.
		//   - res.write / res.end / response.write / response.end: .write and .end are the Node Writable stream
		//     API, so a value written to a file stream or socket bound to a variable named res/response would be
		//     flagged as XSS. Excluded from the XSS set to keep the receiver-name convention anchored to the
		//     Express-specific .send; the raw-http res.end('<html>'+x) pattern is a coverage gap, the safe
		//     direction. A follow-up can anchor these to an Express request-handler receiver via the entrypoint
		//     hints the facts carry.
	}
}

// jsMod builds an import-anchored pattern: the callee's base resolves to one of modules and the member
// matches one of names.
func jsMod(modules []string, names ...string) JsCallablePattern {
	return JsCallablePattern{Modules: modules, Names: names}
}

// jsRaw builds a receiver-name pattern matched against the callee's syntactic dotted path.
func jsRaw(suffixes ...string) JsCallablePattern {
	return JsCallablePattern{RawSuffixes: suffixes}
}

func jsSink(pattern JsCallablePattern, class TaintClass, cwe, rule string, argument int) JsSinkModel {
	return JsSinkModel{Pattern: pattern, Class: class, CWE: cwe, Rule: rule, ArgumentIndexes: []int{argument}}
}

func jsSinkGlobal(class TaintClass, cwe, rule string, arguments []int, globals ...string) JsSinkModel {
	return JsSinkModel{Pattern: JsCallablePattern{Globals: globals}, Class: class, CWE: cwe, Rule: rule, ArgumentIndexes: arguments}
}

func jsSinkGlobalAll(class TaintClass, cwe, rule string, globals ...string) JsSinkModel {
	return JsSinkModel{Pattern: JsCallablePattern{Globals: globals}, Class: class, CWE: cwe, Rule: rule, AllArguments: true}
}

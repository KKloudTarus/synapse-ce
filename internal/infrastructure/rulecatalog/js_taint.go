package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// jsTaintRules documents the semantic rules emitted by the JavaScript/TypeScript value-flow coordinator.
// Detection is classified as AST because the rule catalog's closed vocabulary predates semantic/value-flow
// analysis; the taint and interprocedural tags preserve the more precise producer identity for clients.
func jsTaintRules() []rule.Rule {
	return []rule.Rule{
		jsTaintRule(
			"js-taint-command", "Interprocedural JavaScript command injection", "CWE-78", "A03:2021", shared.SeverityCritical,
			"Tracks untrusted request, argv, and environment values into Node child_process command execution across calls.",
			"When an attacker controls a command or its program path, the server can run unintended operating-system actions.\n\nSource: https://cwe.mitre.org/data/definitions/78.html",
			"Use execFile with a fixed program and an argument array, avoid a shell, and choose the program from an allowlist.",
			"execFile('/usr/bin/convert', [safeInput], (err, out) => done(err, out));",
			"child_process.exec(req.query.cmd);",
		),
		jsTaintRule(
			"js-taint-code", "Interprocedural JavaScript code injection", "CWE-94", "A03:2021", shared.SeverityCritical,
			"Tracks untrusted values into eval, the Function constructor, and the vm module's code-execution APIs.",
			"Evaluating attacker-controlled text as program code runs arbitrary logic in the server process.\n\nSource: https://cwe.mitre.org/data/definitions/94.html",
			"Never evaluate request input; parse it as data (JSON.parse) or dispatch through a fixed allowlist of operations.",
			"const op = OPERATIONS[req.query.op]; if (op) op();",
			"eval(req.query.expr);",
		),
		jsTaintRule(
			"js-taint-path", "Interprocedural JavaScript path traversal", "CWE-22", "A01:2021", shared.SeverityHigh,
			"Tracks request-controlled paths into Node fs read, write, open, remove, and directory operations.",
			"An unchecked path can escape the intended storage root and disclose or overwrite server files.\n\nSource: https://cwe.mitre.org/data/definitions/22.html",
			"Resolve the path beneath a fixed root, reject absolute or escaping paths, and use path.basename on the user portion.",
			"fs.readFile(path.join(ROOT, path.basename(req.query.name)), cb);",
			"fs.readFile(req.query.name, cb);",
		),
		jsTaintRule(
			"js-taint-ssrf", "Interprocedural JavaScript server-side request forgery", "CWE-918", "A10:2021", shared.SeverityHigh,
			"Tracks untrusted URLs into axios, node-fetch, got, and the Node http/https clients.",
			"A user-selected destination can reach internal services, cloud metadata, or protocols unavailable to the caller.\n\nSource: https://cwe.mitre.org/data/definitions/918.html",
			"Parse and normalize the URL, allowlist schemes and destination hosts, and block private or link-local addresses.",
			"if (allowedHosts.has(new URL(req.query.url).host)) await axios.get(req.query.url);",
			"await axios.get(req.query.url);",
		),
		jsTaintRule(
			"js-taint-xss", "Interprocedural JavaScript cross-site scripting", "CWE-79", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted request values into Express/Fastify response writers and the DOM document writer.",
			"Reflecting attacker-controlled markup into the response executes script in the victim's browser and can steal session data.\n\nSource: https://cwe.mitre.org/data/definitions/79.html",
			"Set a non-HTML content type or escape the value with an HTML encoder before writing it to the response.",
			"res.send(escapeHtml(req.query.message));",
			"res.send(req.query.message);",
		),
		jsTaintRule(
			"js-taint-open-redirect", "Interprocedural JavaScript open redirect", "CWE-601", "A01:2021", shared.SeverityMedium,
			"Tracks untrusted redirect destinations into the Express/Fastify response redirect method.",
			"An attacker-controlled redirect makes a trusted application send users to a phishing or malware destination.\n\nSource: https://cwe.mitre.org/data/definitions/601.html",
			"Redirect only to a fixed set of local paths, or allowlist the normalized host and scheme before redirecting.",
			"res.redirect(SAFE_PATHS[req.query.to] || '/');",
			"res.redirect(req.query.to);",
		),
		jsTaintRule(
			"js-taint-redos", "Interprocedural JavaScript regular-expression injection", "CWE-1333", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted request values into the RegExp constructor, where they are compiled as a pattern.",
			"An attacker-controlled regular expression can trigger catastrophic backtracking that stalls the event loop (denial of service), or alter matching to bypass a security check.\n\nSource: https://cwe.mitre.org/data/definitions/1333.html",
			"Match against a fixed regex, or escape the user portion with escape-string-regexp so it is treated as a literal.",
			"const re = new RegExp('^' + escapeStringRegexp(req.query.q));",
			"const re = new RegExp(req.query.q);",
		),
		jsTaintRule(
			"js-taint-deserialization", "Interprocedural JavaScript unsafe deserialization", "CWE-502", "A08:2021", shared.SeverityCritical,
			"Tracks untrusted values into node-serialize unserialize and funcster deepDeserialize, which reconstruct functions.",
			"These deserializers rebuild functions from the payload and invoke them, so deserializing attacker-controlled data runs arbitrary code in the server process.\n\nSource: https://cwe.mitre.org/data/definitions/502.html",
			"Never deserialize request data with a function-reviving library; parse it as data with JSON.parse and validate the shape.",
			"const data = JSON.parse(req.body.payload);",
			"const data = nodeSerialize.unserialize(req.body.payload);",
		),
		jsTaintRule(
			"js-taint-ssti", "Interprocedural JavaScript server-side template injection", "CWE-1336", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into the template source of handlebars, pug, ejs, and lodash template engines.",
			"When an attacker controls the template source, the engine evaluates their expressions on the server, which can read data or run code.\n\nSource: https://cwe.mitre.org/data/definitions/1336.html",
			"Compile a fixed template and pass user input only as data, never as the template source.",
			"const html = template({ name: req.query.name });",
			"const html = handlebars.compile(req.query.tpl)();",
		),
		jsTaintRule(
			"js-taint-xpath", "Interprocedural JavaScript XPath injection", "CWE-643", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into the xpath package's expression compiler.",
			"Attacker-controlled text in an XPath expression can change the selection to read nodes outside the intended scope.\n\nSource: https://cwe.mitre.org/data/definitions/643.html",
			"Use a fixed XPath expression and pass user input only through variable binding or a parameterized evaluator, never string-concatenated into the expression.",
			"xpath.select('//user[@id=$id]', doc, false, { id: req.query.id });",
			"xpath.select(\"//user[@id='\" + req.query.id + \"']\", doc);",
		),
		jsTaintRule(
			"js-taint-log", "Interprocedural JavaScript log injection", "CWE-117", "A03:2021", shared.SeverityMedium,
			"Tracks untrusted request values into the console logging methods.",
			"Unneutralized input written to a log can inject newlines to forge or split log entries, misleading an investigation or poisoning a log-analysis pipeline.\n\nSource: https://cwe.mitre.org/data/definitions/117.html",
			"Log user input as a bounded field (never concatenated into the message), and strip or encode newline and control characters before logging.",
			"console.log('login for user=%s', encodeURIComponent(req.query.user));",
			"console.log('login for user=' + req.query.user);",
		),
	}
}

func jsTaintRule(key, name, cwe, owasp string, severity shared.Severity, description, rationale, remediation, compliant, noncompliant string) rule.Rule {
	return rule.Rule{
		Key: rule.Key(key), Name: name, Language: "JavaScript/TypeScript", Type: rule.TypeVulnerability,
		Qualities: []rule.Quality{rule.QualitySecurity}, DefaultSeverity: severity,
		Tags: []string{"javascript", "taint", "interprocedural"}, CWE: []string{cwe}, OWASP: []string{owasp},
		Description: description, Rationale: rationale, Remediation: remediation,
		CompliantExample: compliant, NoncompliantExample: noncompliant, RemediationEffort: 60,
		Detection: rule.DetectionAST,
	}
}

package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// pythonTaintRules documents the semantic rules emitted by the Python value-flow coordinator. Detection is
// classified as AST because the rule catalog's closed vocabulary predates semantic/value-flow analysis;
// the taint and interprocedural tags preserve the more precise producer identity for clients.
func pythonTaintRules() []rule.Rule {
	return []rule.Rule{
		pythonTaintRule(
			"python-taint-sqli", "Interprocedural Python SQL injection", "CWE-89", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted Flask, Django, FastAPI, environment, and console values into raw SQL query text across Python calls.",
			"Untrusted query text changes the database command rather than remaining data, which can expose or modify records.\n\nSource: https://cwe.mitre.org/data/definitions/89.html",
			"Use bound parameters and keep the SQL statement itself constant; never concatenate request-controlled text into a query.",
			"cursor.execute('SELECT * FROM users WHERE id = ?', (request.args['id'],))",
			"cursor.execute('SELECT * FROM users WHERE id = ' + request.args['id'])",
		),
		pythonTaintRule(
			"python-taint-code", "Interprocedural Python code injection", "CWE-94", "A03:2021", shared.SeverityCritical,
			"Tracks untrusted request values into the eval, exec, and compile builtins, which evaluate their argument as Python source.",
			"Evaluating attacker-controlled text as Python code runs arbitrary logic in the server process.\n\nSource: https://cwe.mitre.org/data/definitions/94.html",
			"Never eval request input; parse it as data (json.loads) or use ast.literal_eval, which evaluates only literals, and dispatch through a fixed allowlist of operations.",
			"op = OPERATIONS.get(request.args['op']); op and op()",
			"eval(request.args['expr'])",
		),
		pythonTaintRule(
			"python-taint-command", "Interprocedural Python command injection", "CWE-78", "A03:2021", shared.SeverityCritical,
			"Tracks untrusted Python values into os and subprocess command execution APIs through local helpers and return values.",
			"When an attacker controls a command or executable path, the server can run unintended operating-system actions.\n\nSource: https://cwe.mitre.org/data/definitions/78.html",
			"Choose commands from an allowlist, pass fixed executable paths and argument arrays, and avoid shell interpretation.",
			"subprocess.run(['/usr/bin/id', '--user', validated_user], check=True, shell=False)",
			"os.system(request.args.get('command'))",
		),
		pythonTaintRule(
			"python-taint-path", "Interprocedural Python path traversal", "CWE-22", "A01:2021", shared.SeverityHigh,
			"Tracks request-controlled paths into filesystem constructors and read, write, move, remove, or archive operations.",
			"An unchecked path can escape the intended storage root and disclose or overwrite server files.\n\nSource: https://cwe.mitre.org/data/definitions/22.html",
			"Resolve the path beneath a fixed root, reject absolute or escaping paths, and use an opaque server-side identifier where possible.",
			"candidate = (UPLOAD_ROOT / secure_filename(name)).resolve()",
			"open('/srv/uploads/' + request.args.get('name')).read()",
		),
		pythonTaintRule(
			"python-taint-ssrf", "Interprocedural Python server-side request forgery", "CWE-918", "A10:2021", shared.SeverityHigh,
			"Tracks untrusted URLs into requests, httpx, aiohttp, and urllib server-side network clients.",
			"A user-selected destination can reach internal services, cloud metadata, or protocols unavailable to the caller.\n\nSource: https://cwe.mitre.org/data/definitions/918.html",
			"Parse and normalize the URL, allowlist schemes and destination hosts, resolve DNS safely, and block private or link-local addresses.",
			"requests.get('https://api.example.com/v1/status', timeout=3)",
			"requests.get(request.args.get('url'), timeout=3)",
		),
		pythonTaintRule(
			"python-taint-xss", "Interprocedural Python cross-site scripting", "CWE-79", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted web values into Python APIs that bypass or weaken contextual HTML escaping.",
			"Marking attacker-controlled markup as safe can execute script in another user's browser and steal session data.\n\nSource: https://cwe.mitre.org/data/definitions/79.html",
			"Use templates with auto-escaping and apply context-appropriate encoding; do not mark request values as safe HTML.",
			"return render_template('message.html', message=request.args.get('message'))",
			"return render_template_string(request.args.get('template'))",
		),
		pythonTaintRule(
			"python-taint-deserialization", "Interprocedural Python unsafe deserialization", "CWE-502", "A08:2021", shared.SeverityCritical,
			"Tracks untrusted bytes or text into pickle, marshal, unsafe YAML, dill, and cloudpickle loading APIs.",
			"Object deserializers may construct attacker-selected objects or invoke dangerous reconstruction behavior.\n\nSource: https://cwe.mitre.org/data/definitions/502.html",
			"Use JSON or a schema-validated format; for YAML use safe_load and validate the resulting primitive data structure.",
			"record = json.loads(request.get_data(as_text=True))",
			"record = pickle.loads(request.get_data())",
		),
		pythonTaintRule(
			"python-taint-open-redirect", "Interprocedural Python open redirect", "CWE-601", "A01:2021", shared.SeverityMedium,
			"Tracks untrusted redirect destinations into Flask, Werkzeug, Django, Starlette, and FastAPI response APIs.",
			"An attacker-controlled redirect can make a trusted application send users to a phishing or malware destination.\n\nSource: https://cwe.mitre.org/data/definitions/601.html",
			"Resolve relative destinations locally or allowlist normalized hosts and schemes before constructing the redirect response.",
			"return redirect(url_for('account.dashboard'))",
			"return redirect(request.args.get('next'))",
		),
		pythonTaintRule(
			"python-taint-ssti", "Interprocedural Python server-side template injection", "CWE-1336", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into Jinja2, Mako, Django, and Tornado template constructors and string-render APIs.",
			"A template engine evaluates attacker-controlled markup as code, which on engines like Jinja2 can reach remote code execution.\n\nSource: https://cwe.mitre.org/data/definitions/1336.html",
			"Render fixed template files and pass untrusted values only as escaped data; never build a template from request input.",
			"return render_template('greeting.html', name=request.args.get('name'))",
			"return Template(request.args.get('tpl')).render()",
		),
		pythonTaintRule(
			"python-taint-xxe", "Interprocedural Python XML external entity injection", "CWE-611", "A05:2021", shared.SeverityHigh,
			"Tracks untrusted XML into lxml and the standard-library xml.dom / xml.sax parsers that resolve external entities.",
			"A parser that resolves external entities on attacker-controlled XML can disclose local files or reach internal network services.\n\nSource: https://cwe.mitre.org/data/definitions/611.html",
			"Disable DTD loading and entity resolution (defusedxml, or an lxml parser with load_dtd=False, resolve_entities=False, no_network=True) before parsing untrusted XML.",
			"tree = lxml.etree.parse(data, lxml.etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True))",
			"tree = lxml.etree.fromstring(request.get_data())",
		),
		pythonTaintRule(
			"python-taint-ldap", "Interprocedural Python LDAP injection", "CWE-90", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into python-ldap and ldap3 search filters.",
			"Unescaped input in an LDAP filter can alter the query to bypass authentication or read directory entries beyond the intended scope.\n\nSource: https://cwe.mitre.org/data/definitions/90.html",
			"Escape filter assertion values with ldap.filter.escape_filter_chars and build the filter from a fixed template.",
			"flt = '(uid=%s)' % ldap.filter.escape_filter_chars(request.args['uid'])",
			"conn.search_s(base, scope, '(uid=' + request.args['uid'] + ')')",
		),
		pythonTaintRule(
			"python-taint-xpath", "Interprocedural Python XPath injection", "CWE-643", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into lxml and standard-library ElementTree XPath expressions.",
			"Attacker-controlled text in an XPath expression can change the selection to read nodes outside the intended scope.\n\nSource: https://cwe.mitre.org/data/definitions/643.html",
			"Use a fixed XPath expression with variables (lxml XPath variable binding), never string-concatenated request input.",
			"tree.xpath('//user[@id=$id]', id=request.args['id'])",
			"tree.xpath(\"//user[@id='\" + request.args['id'] + \"']\")",
		),
		pythonTaintRule(
			"python-taint-log", "Interprocedural Python log injection", "CWE-117", "A03:2021", shared.SeverityMedium,
			"Tracks untrusted values into the standard-library logging module functions.",
			"Unneutralized input written to a log can inject newlines to forge or split log entries, misleading an investigation or poisoning a log-analysis pipeline.\n\nSource: https://cwe.mitre.org/data/definitions/117.html",
			"Log user input as a bounded parameter (never as part of the format string), and strip or encode newline and control characters before logging.",
			"logging.info('login for user=%s', user_id)",
			"logging.info('login for user=' + request.args['user'])",
		),
		pythonTaintRule(
			"python-taint-redos", "Interprocedural Python regular-expression injection", "CWE-1333", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted request values into the re module, where they are compiled as a regular-expression pattern.",
			"An attacker-controlled regular expression can trigger catastrophic backtracking that stalls the worker (denial of service), or alter matching to bypass a security check.\n\nSource: https://cwe.mitre.org/data/definitions/1333.html",
			"Match against a fixed pattern, or escape the user portion with re.escape so it is treated as a literal.",
			"re.match('^' + re.escape(request.args['q']), text)",
			"re.match(request.args['q'], text)",
		),
	}
}

func pythonTaintRule(key, name, cwe, owasp string, severity shared.Severity, description, rationale, remediation, compliant, noncompliant string) rule.Rule {
	return rule.Rule{
		Key: rule.Key(key), Name: name, Language: "Python", Type: rule.TypeVulnerability,
		Qualities: []rule.Quality{rule.QualitySecurity}, DefaultSeverity: severity,
		Tags: []string{"python", "taint", "interprocedural"}, CWE: []string{cwe}, OWASP: []string{owasp},
		Description: description, Rationale: rationale, Remediation: remediation,
		CompliantExample: compliant, NoncompliantExample: noncompliant, RemediationEffort: 60,
		Detection: rule.DetectionAST,
	}
}

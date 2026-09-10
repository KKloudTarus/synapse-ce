package taint

// DefaultPythonCatalog returns the reviewed initial Python framework pack. Models intentionally describe
// value roles (which result or argument carries taint), not merely that two functions call each other.
func DefaultPythonCatalog() PythonCatalog {
	all := append([]TaintClass(nil), allPythonTaintClasses...)
	return PythonCatalog{
		EntrypointParameters: true,
		ReferenceSources: []string{
			"sys.argv", "request.args", "request.form", "request.values", "request.cookies",
			"request.headers", "request.query_params", "request.path_params", "request.GET",
			"request.POST", "request.FILES", "request.COOKIES", "request.META", "request.files",
			"request.environ", "request.body", "request.data",
		},
		Sources: []PythonSourceModel{
			{Pattern: pyCall([]string{"builtins"}, []string{"input"}), Classes: all},
			{Pattern: pyCall([]string{"os"}, []string{"getenv"}), Classes: all},
			{Pattern: PythonCallablePattern{RawSuffixes: []string{"os.environ.get", "environ.get"}}, Classes: all},
			{Pattern: PythonCallablePattern{RawSuffixes: []string{
				"request.args.get", "request.form.get", "request.values.get", "request.cookies.get",
				"request.headers.get", "request.headers.getlist", "request.query_params.get", "request.path_params.get",
				"request.GET.get", "request.POST.get", "request.FILES.get", "request.COOKIES.get", "request.META.get",
				"request.files.get", "request.environ.get", "request.get_json", "request.json.get",
				"request.json", "request.body", "request.form",
			}}, Classes: all},
			{Pattern: PythonCallablePattern{
				Modules: []string{"sys"}, Names: []string{"stdin.read", "stdin.readline", "stdin.readlines"},
				RawSuffixes: []string{"sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines"},
			}, Classes: all},
		},
		Sinks: []PythonSinkModel{
			// CWE-89: raw SQL execution. Parameterized values passed after argument zero do not taint the SQL
			// program text, so only the query argument is modeled.
			pySinkWithRaw(
				[]string{"sqlite3", "_sqlite3", "sqlalchemy", "django.db"},
				[]string{"execute", "executemany", "executescript", "raw", "extra"},
				[]string{"cursor.execute", "cursor.executemany", "cursor.executescript", "connection.execute", "session.execute", "objects.raw", "objects.extra"},
				TaintSQL, "CWE-89", "python-taint-sqli", 0, "sql", "statement", "query", "raw_query", "where", "select",
			),
			pySink([]string{"sqlalchemy"}, []string{"text"}, TaintSQL, "CWE-89", "python-taint-sqli", 0, "text"),

			// CWE-78: command and shell execution.
			pySink([]string{"os"}, []string{"system", "popen"}, TaintCommand, "CWE-78", "python-taint-command", 0, "command", "cmd"),
			pySink([]string{"os"}, []string{"execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"}, TaintCommand, "CWE-78", "python-taint-command", 0, "path"),
			pySink([]string{"os"}, []string{"spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"}, TaintCommand, "CWE-78", "python-taint-command", 1, "path"),
			pySink([]string{"subprocess"}, []string{"Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}, TaintCommand, "CWE-78", "python-taint-command", 0, "args", "command", "cmd"),
			pySink([]string{"asyncio"}, []string{"create_subprocess_shell", "create_subprocess_exec"}, TaintCommand, "CWE-78", "python-taint-command", 0, "cmd", "program"),

			// CWE-22: host filesystem paths.
			pySink([]string{"builtins"}, []string{"open"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0, "file"),
			pySink([]string{"os"}, []string{"open", "remove", "unlink", "mkdir", "makedirs", "listdir", "scandir"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0, "path", "file"),
			pySinkIndexes([]string{"os"}, []string{"rename", "replace"}, TaintPathTraversal, "CWE-22", "python-taint-path", []int{0, 1}, "src", "dst"),
			pyReceiverSink([]string{"pathlib"}, []string{"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "mkdir", "rmdir", "touch", "chmod", "stat", "iterdir", "glob", "rglob"}, TaintPathTraversal, "CWE-22", "python-taint-path", nil),
			pyReceiverSink([]string{"pathlib"}, []string{"rename", "replace"}, TaintPathTraversal, "CWE-22", "python-taint-path", []int{0}, "target"),
			pySinkIndexes([]string{"shutil"}, []string{"copy", "copy2", "copyfile", "move", "unpack_archive"}, TaintPathTraversal, "CWE-22", "python-taint-path", []int{0, 1}, "src", "dst", "filename", "extract_dir"),
			pySink([]string{"shutil"}, []string{"rmtree"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0, "path"),

			// CWE-918: server-side requests. requests.request(method, url) uses argument one.
			pySink([]string{"requests", "httpx", "aiohttp"}, []string{"get", "post", "put", "patch", "delete", "head", "options"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 0, "url"),
			pySink([]string{"requests", "httpx", "aiohttp"}, []string{"request"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 1, "url"),
			pySink([]string{"urllib.request"}, []string{"urlopen", "Request"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 0, "url", "fullurl"),

			// CWE-79: APIs that deliberately bypass contextual auto-escaping.
			pySink([]string{"flask"}, []string{"render_template_string", "Markup"}, TaintXSS, "CWE-79", "python-taint-xss", 0, "source", "object"),
			pySink([]string{"django.utils.safestring"}, []string{"mark_safe"}, TaintXSS, "CWE-79", "python-taint-xss", 0, "s"),
			pySink([]string{"django.http"}, []string{"HttpResponse"}, TaintXSS, "CWE-79", "python-taint-xss", 0, "content"),
			pySink([]string{"fastapi.responses", "starlette.responses"}, []string{"HTMLResponse"}, TaintXSS, "CWE-79", "python-taint-xss", 0, "content"),

			// CWE-502: unsafe object/data loaders.
			pySink([]string{"pickle", "_pickle", "dill", "cloudpickle", "marshal"}, []string{"load", "loads"}, TaintDeserialization, "CWE-502", "python-taint-deserialization", 0, "file", "data", "bytes_object"),
			pySink([]string{"jsonpickle"}, []string{"decode", "loads"}, TaintDeserialization, "CWE-502", "python-taint-deserialization", 0, "string", "data"),
			pySink([]string{"yaml"}, []string{"load", "unsafe_load", "full_load"}, TaintDeserialization, "CWE-502", "python-taint-deserialization", 0, "stream"),

			// CWE-601: untrusted redirect targets.
			pySink([]string{"flask", "werkzeug.utils", "django.shortcuts", "starlette.responses", "fastapi.responses"}, []string{"redirect", "RedirectResponse"}, TaintRedirect, "CWE-601", "python-taint-open-redirect", 0, "location", "to", "url"),

			// CWE-1336: server-side template injection. The DANGEROUS argument is the template TEXT itself
			// (compiling attacker-controlled markup is code execution), not a render VARIABLE, which the
			// engine auto-escapes. Only the template-source argument is modeled, so passing user input as a
			// render keyword is not flagged.
			pySink([]string{"jinja2", "mako.template", "django.template", "tornado.template"}, []string{"Template"}, TaintSSTI, "CWE-1336", "python-taint-ssti", 0, "source", "template_string", "template", "text"),
			// from_string is a bound method whose FIRST argument is the template text; the Environment
			// receiver is not the taint, so only the argument is modeled.
			pySinkIndexes([]string{"jinja2"}, []string{"from_string"}, TaintSSTI, "CWE-1336", "python-taint-ssti", []int{0}, "source"),

			// CWE-611: XML external entity. lxml (with entity resolution) and the SAX/DOM parsers can expand
			// external entities on untrusted input; the safe shape is the drop-in defusedxml module, which is
			// deliberately NOT a sink, so swapping to it removes the finding (there is no in-place sanitizer to
			// model). xml.etree.ElementTree is intentionally excluded: it does not resolve external entities,
			// so flagging it as XXE would be a false positive (its risk is entity-expansion DoS, not modeled
			// here).
			pySink([]string{"lxml.etree"}, []string{"parse", "fromstring", "XML", "fromstringlist"}, TaintXXE, "CWE-611", "python-taint-xxe", 0, "source", "text"),
			pySink([]string{"xml.dom.minidom", "xml.dom.pulldom", "xml.sax"}, []string{"parse", "parseString"}, TaintXXE, "CWE-611", "python-taint-xxe", 0, "source", "string", "data", "text"),

			// CWE-90: LDAP injection. python-ldap keeps the filter in a positional argument; ldap3 exposes
			// search as a bound method whose search_filter is argument one.
			pySink([]string{"ldap"}, []string{"search", "search_s", "search_st", "search_ext", "search_ext_s"}, TaintLDAP, "CWE-90", "python-taint-ldap", 2, "filterstr"),
			// ldap3 Connection.search(search_base, search_filter, ...): the second positional argument is the
			// filter (the receiver connection is not the taint), so only that argument is modeled.
			pySinkIndexes([]string{"ldap3"}, []string{"search"}, TaintLDAP, "CWE-90", "python-taint-ldap", []int{1}, "search_filter"),

			// CWE-643: XPath injection. lxml exposes xpath as a bound method on a parsed tree; the dangerous
			// argument is the expression text. Passing user input through the parameterized `var=value` form
			// keeps it out of the expression, which is why only the expression argument is modeled.
			// xpath is a bound method whose FIRST POSITIONAL argument is the expression text. No keyword is
			// modeled: lxml's `xpath(expr, name=value)` keywords are safe XPath VARIABLE bindings (the
			// parameterized form), so tainting a keyword argument would flag exactly the safe shape.
			pySinkIndexes([]string{"lxml.etree"}, []string{"xpath"}, TaintXPath, "CWE-643", "python-taint-xpath", []int{0}),
			// ElementTree.find/findall take the path as the first positional argument or the `match` keyword.
			pySink([]string{"xml.etree.ElementTree"}, []string{"find", "findall", "findtext", "iterfind"}, TaintXPath, "CWE-643", "python-taint-xpath", 0, "match"),
		},
		Sanitizers: []PythonSanitizerModel{
			{Pattern: pyCall([]string{"html", "markupsafe", "bleach"}, []string{"escape", "clean"}), Classes: []TaintClass{TaintXSS}},
			{Pattern: pyCall([]string{"shlex"}, []string{"quote"}), Classes: []TaintClass{TaintCommand}},
			{Pattern: pyCall([]string{"werkzeug.utils"}, []string{"secure_filename"}), Classes: []TaintClass{TaintPathTraversal}},
			{Pattern: pyCall([]string{"yaml"}, []string{"safe_load"}), Classes: []TaintClass{TaintDeserialization}},
			// LDAP FILTER escaping neutralizes only the LDAP class; it does nothing for SQL or a URL. DN
			// escaping (escape_dn_chars) is deliberately excluded: it escapes distinguished-name components,
			// not filter metacharacters, so it must not neutralize a search-filter injection finding.
			{Pattern: pyCall([]string{"ldap.filter", "ldap3.utils.conv"}, []string{"escape_filter_chars"}), Classes: []TaintClass{TaintLDAP}},
			{Pattern: pyCall([]string{"builtins"}, []string{"int", "float", "bool", "len"}), Classes: all},
		},
	}
}

func pyCall(modules, names []string) PythonCallablePattern {
	return PythonCallablePattern{Modules: modules, Names: names}
}

func pySink(modules, names []string, class TaintClass, cwe, rule string, argument int, keywords ...string) PythonSinkModel {
	return PythonSinkModel{
		Pattern: PythonCallablePattern{Modules: modules, Names: names}, Class: class, CWE: cwe, Rule: rule,
		ArgumentIndexes: []int{argument}, ArgumentKeywords: keywords,
	}
}

func pySinkIndexes(modules, names []string, class TaintClass, cwe, rule string, arguments []int, keywords ...string) PythonSinkModel {
	return PythonSinkModel{
		Pattern: PythonCallablePattern{Modules: modules, Names: names}, Class: class, CWE: cwe, Rule: rule,
		ArgumentIndexes: arguments, ArgumentKeywords: keywords,
	}
}

func pyReceiverSink(modules, names []string, class TaintClass, cwe, rule string, arguments []int, keywords ...string) PythonSinkModel {
	return PythonSinkModel{
		Pattern: PythonCallablePattern{Modules: modules, Names: names}, Class: class, CWE: cwe, Rule: rule,
		ArgumentIndexes: arguments, ArgumentKeywords: keywords, Receiver: true,
	}
}

func pySinkWithRaw(modules, names, raw []string, class TaintClass, cwe, rule string, argument int, keywords ...string) PythonSinkModel {
	model := pySink(modules, names, class, cwe, rule, argument, keywords...)
	model.Pattern.RawSuffixes = raw
	return model
}

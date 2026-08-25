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
			"request.POST", "request.body", "request.data",
		},
		Sources: []PythonSourceModel{
			{Pattern: pyCall([]string{"builtins"}, []string{"input"}), Classes: all},
			{Pattern: pyCall([]string{"os"}, []string{"getenv"}), Classes: all},
			{Pattern: PythonCallablePattern{RawSuffixes: []string{"os.environ.get", "environ.get"}}, Classes: all},
			{Pattern: PythonCallablePattern{RawSuffixes: []string{
				"request.args.get", "request.form.get", "request.values.get", "request.cookies.get",
				"request.headers.get", "request.query_params.get", "request.path_params.get",
				"request.GET.get", "request.POST.get", "request.get_json", "request.json.get",
			}}, Classes: all},
		},
		Sinks: []PythonSinkModel{
			// CWE-89: raw SQL execution. Parameterized values passed after argument zero do not taint the SQL
			// program text, so only the query argument is modeled.
			pySinkWithRaw(
				[]string{"sqlite3", "_sqlite3", "sqlalchemy", "django.db"},
				[]string{"execute", "executemany", "executescript", "raw", "extra"},
				[]string{"cursor.execute", "cursor.executemany", "cursor.executescript", "connection.execute", "session.execute", "objects.raw", "objects.extra"},
				TaintSQL, "CWE-89", "python-taint-sqli", 0,
			),
			pySink([]string{"sqlalchemy"}, []string{"text"}, TaintSQL, "CWE-89", "python-taint-sqli", 0),

			// CWE-78: command and shell execution.
			pySink([]string{"os"}, []string{"system", "popen"}, TaintCommand, "CWE-78", "python-taint-command", 0),
			pySink([]string{"subprocess"}, []string{"Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}, TaintCommand, "CWE-78", "python-taint-command", 0),

			// CWE-22: host filesystem paths.
			pySink([]string{"builtins"}, []string{"open"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0),
			pySink([]string{"os"}, []string{"open", "remove", "unlink", "rename", "replace", "mkdir", "makedirs", "listdir", "scandir"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0),
			pySink([]string{"pathlib"}, []string{"Path", "open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rename", "replace"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0),
			pySink([]string{"shutil"}, []string{"copy", "copy2", "copyfile", "move", "rmtree", "unpack_archive"}, TaintPathTraversal, "CWE-22", "python-taint-path", 0),

			// CWE-918: server-side requests. requests.request(method, url) uses argument one.
			pySink([]string{"requests", "httpx", "aiohttp"}, []string{"get", "post", "put", "patch", "delete", "head", "options"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 0),
			pySink([]string{"requests", "httpx", "aiohttp"}, []string{"request"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 1),
			pySink([]string{"urllib.request"}, []string{"urlopen", "Request"}, TaintSSRF, "CWE-918", "python-taint-ssrf", 0),

			// CWE-79: APIs that deliberately bypass contextual auto-escaping.
			pySink([]string{"flask"}, []string{"render_template_string", "Markup"}, TaintXSS, "CWE-79", "python-taint-xss", 0),
			pySink([]string{"django.utils.safestring"}, []string{"mark_safe"}, TaintXSS, "CWE-79", "python-taint-xss", 0),
			pySink([]string{"django.http"}, []string{"HttpResponse"}, TaintXSS, "CWE-79", "python-taint-xss", 0),

			// CWE-502: unsafe object/data loaders.
			pySink([]string{"pickle", "_pickle", "dill", "cloudpickle", "marshal"}, []string{"load", "loads"}, TaintDeserialization, "CWE-502", "python-taint-deserialization", 0),
			pySink([]string{"yaml"}, []string{"load", "unsafe_load", "full_load"}, TaintDeserialization, "CWE-502", "python-taint-deserialization", 0),

			// CWE-601: untrusted redirect targets.
			pySink([]string{"flask", "werkzeug.utils", "django.shortcuts", "starlette.responses"}, []string{"redirect", "RedirectResponse"}, TaintRedirect, "CWE-601", "python-taint-open-redirect", 0),
		},
		Sanitizers: []PythonSanitizerModel{
			{Pattern: pyCall([]string{"html", "markupsafe", "bleach"}, []string{"escape", "clean"}), Classes: []TaintClass{TaintXSS}},
			{Pattern: pyCall([]string{"shlex"}, []string{"quote"}), Classes: []TaintClass{TaintCommand}},
			{Pattern: pyCall([]string{"werkzeug.utils"}, []string{"secure_filename"}), Classes: []TaintClass{TaintPathTraversal}},
		},
	}
}

func pyCall(modules, names []string) PythonCallablePattern {
	return PythonCallablePattern{Modules: modules, Names: names}
}

func pySink(modules, names []string, class TaintClass, cwe, rule string, argument int) PythonSinkModel {
	return PythonSinkModel{
		Pattern: PythonCallablePattern{Modules: modules, Names: names}, Class: class, CWE: cwe, Rule: rule,
		ArgumentIndexes: []int{argument},
	}
}

func pySinkWithRaw(modules, names, raw []string, class TaintClass, cwe, rule string, argument int) PythonSinkModel {
	model := pySink(modules, names, class, cwe, rule, argument)
	model.Pattern.RawSuffixes = raw
	return model
}

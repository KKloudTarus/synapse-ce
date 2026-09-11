package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
)

func TestPythonCatalogCoversInitialFrameworkMatrix(t *testing.T) {
	catalog := DefaultPythonCatalog()
	if !catalog.EntrypointParameters {
		t.Fatal("FastAPI/Flask/Django route parameters must be modeled as request sources")
	}
	for _, raw := range []string{
		"flask.request.args.get", "request.GET.get", "request.FILES.get", "request.headers.getlist",
		"request.query_params.get", "request.json", "sys.stdin.readline",
	} {
		matched := false
		for _, source := range catalog.Sources {
			matched = matched || callMatches(source.Pattern, nil, raw)
		}
		if !matched {
			t.Errorf("framework source %q is not modeled", raw)
		}
	}

	wantSinks := []struct {
		call  string
		class TaintClass
	}{
		{"python:sqlalchemy.orm:Session.execute", TaintSQL},
		{"python:django.db.models.query:RawQuerySet.raw", TaintSQL},
		{"python:subprocess:run", TaintCommand},
		{"python:asyncio:create_subprocess_shell", TaintCommand},
		{"python:pathlib:Path.read_text", TaintPathTraversal},
		{"python:httpx:get", TaintSSRF},
		{"python:flask:render_template_string", TaintXSS},
		{"python:fastapi.responses:HTMLResponse", TaintXSS},
		{"python:pickle:loads", TaintDeserialization},
		{"python:jsonpickle:decode", TaintDeserialization},
		{"python:starlette.responses:RedirectResponse", TaintRedirect},
		{"python:fastapi.responses:RedirectResponse", TaintRedirect},
	}
	for _, want := range wantSinks {
		matched := false
		for _, sink := range catalog.Sinks {
			matched = matched || sink.Class == want.class && callMatches(sink.Pattern, []string{want.call}, "")
		}
		if !matched {
			t.Errorf("sink %q (%s) is not modeled", want.call, want.class)
		}
	}
	for _, sink := range catalog.Sinks {
		if sink.Class == TaintPathTraversal && callMatches(sink.Pattern, []string{"python:pathlib:Path"}, "") {
			t.Fatal("pathlib.Path constructs a value and must not be treated as filesystem I/O")
		}
		if sink.Class == TaintPathTraversal && callMatches(sink.Pattern, []string{"python:pathlib:Path.read_text"}, "") && !sink.Receiver {
			t.Fatal("pathlib instance I/O must inspect the path receiver")
		}
	}
}

func TestPythonCatalogSafeLoadIsClassSpecificSafeShape(t *testing.T) {
	catalog := DefaultPythonCatalog()
	call := []string{"python:yaml:safe_load"}
	for _, sink := range catalog.Sinks {
		if sink.Class == TaintDeserialization && callMatches(sink.Pattern, call, "") {
			t.Fatal("yaml.safe_load must not be an unsafe deserialization sink")
		}
	}
	matchedSanitizer := false
	for _, sanitizer := range catalog.Sanitizers {
		if callMatches(sanitizer.Pattern, call, "") && containsTaintClass(sanitizer.Classes, TaintDeserialization) {
			matchedSanitizer = true
		}
	}
	if !matchedSanitizer {
		t.Fatal("yaml.safe_load must stop only the deserialization class")
	}
}

func TestPythonCatalogPrimitiveConversionsNeutralizeStringTaint(t *testing.T) {
	catalog := DefaultPythonCatalog()
	for _, callable := range []string{"python:builtins:int", "python:builtins:float", "python:builtins:bool", "python:builtins:len"} {
		matched := false
		for _, sanitizer := range catalog.Sanitizers {
			matched = matched || callMatches(sanitizer.Pattern, []string{callable}, "") && len(sanitizer.Classes) == len(allPythonTaintClasses)
		}
		if !matched {
			t.Errorf("primitive conversion %q must neutralize string-based taint classes", callable)
		}
	}
}

func containsTaintClass(values []TaintClass, want TaintClass) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestPythonCatalogModelsInjectionClasses covers the D5.6 additions: SSTI, XXE, LDAP, and XPath. For each
// class it asserts a POSITIVE (the dangerous callable is a sink of that class) and a SANITIZED-TWIN (the
// safe shape is not a sink, or is neutralized), which is the direction that keeps a new class from either
// missing a real flow or firing on a safe one.
func TestPythonCatalogModelsInjectionClasses(t *testing.T) {
	catalog := DefaultPythonCatalog()

	isSink := func(callee string, class TaintClass) bool {
		for _, sink := range catalog.Sinks {
			if sink.Class == class && callMatches(sink.Pattern, []string{callee}, "") {
				return true
			}
		}
		return false
	}
	neutralizes := func(callee string, class TaintClass) bool {
		for _, s := range catalog.Sanitizers {
			if callMatches(s.Pattern, []string{callee}, "") && containsTaintClass(s.Classes, class) {
				return true
			}
		}
		return false
	}

	// Positives: the dangerous callable is modeled as a sink of the expected class.
	positives := []struct {
		callee string
		class  TaintClass
	}{
		{"python:jinja2:Template", TaintSSTI},
		{"python:jinja2:Environment.from_string", TaintSSTI},
		{"python:mako.template:Template", TaintSSTI},
		{"python:lxml.etree:parse", TaintXXE},
		{"python:lxml.etree:fromstring", TaintXXE},
		{"python:xml.dom.minidom:parse", TaintXXE},
		{"python:xml.sax:parse", TaintXXE},
		{"python:ldap:search_s", TaintLDAP},
		{"python:ldap:LDAPObject.search_s", TaintLDAP}, // realistic bound-method form
		{"python:ldap3:Connection.search", TaintLDAP},
		{"python:lxml.etree:_Element.xpath", TaintXPath},
		{"python:xml.etree.ElementTree:ElementTree.find", TaintXPath},
		{"python:logging:info", TaintLog},
		{"python:logging:error", TaintLog},
		{"python:logging:log", TaintLog},
		{"python:re:compile", TaintReDoS},
		{"python:re:match", TaintReDoS},
		{"python:re:sub", TaintReDoS},
		{"python:builtins:eval", TaintCode},
		{"python:builtins:exec", TaintCode},
		{"python:builtins:compile", TaintCode},
	}
	for _, p := range positives {
		if !isSink(p.callee, p.class) {
			t.Errorf("positive: %q must be a %s sink", p.callee, p.class)
		}
	}

	// Sanitized twins: the safe shape is not a sink, or is neutralized for that class only.
	if isSink("python:defusedxml.ElementTree:parse", TaintXXE) {
		t.Error("twin: the hardened defusedxml parser must NOT be an XXE sink")
	}
	// xml.etree.ElementTree does not resolve external entities, so it must not be an XXE sink (its risk is
	// entity-expansion DoS, out of scope for CWE-611); flagging it would be a false positive.
	if isSink("python:xml.etree.ElementTree:fromstring", TaintXXE) {
		t.Error("twin: xml.etree.ElementTree must NOT be an XXE sink (it does not resolve external entities)")
	}
	// escape_dn_chars escapes DN components, not filter metacharacters, so it must NOT neutralize a
	// search-filter injection finding.
	if neutralizes("python:ldap.dn:escape_dn_chars", TaintLDAP) {
		t.Error("twin: escape_dn_chars must NOT neutralize an LDAP search-filter finding")
	}
	if isSink("python:jinja2:Environment.get_template", TaintSSTI) {
		t.Error("twin: loading a static named template (not compiling user input) must NOT be an SSTI sink")
	}
	if !neutralizes("python:ldap.filter:escape_filter_chars", TaintLDAP) {
		t.Error("twin: escape_filter_chars must neutralize the LDAP class")
	}
	// re.escape turns the value into a literal pattern, so it neutralizes ReDoS, and only ReDoS.
	if !neutralizes("python:re:escape", TaintReDoS) {
		t.Error("twin: re.escape must neutralize the ReDoS class")
	}
	if neutralizes("python:re:escape", TaintCommand) {
		t.Error("twin: re.escape must not neutralize command injection")
	}
	// The LDAP escaper is class-specific: it must NOT be treated as a SQL or command sanitizer.
	if neutralizes("python:ldap.filter:escape_filter_chars", TaintSQL) {
		t.Error("twin: an LDAP escaper must not neutralize SQL")
	}
	// A primitive conversion neutralizes every string class, XPath included, so int(user) is a safe twin.
	if !neutralizes("python:builtins:int", TaintXPath) {
		t.Error("twin: int() must neutralize the XPath class")
	}
	// Log injection twin: a value coerced to int cannot forge a log line, so int(user) neutralizes the log
	// class (there is no stdlib newline-escaper to model). A bare logger.info receiver is not a sink.
	if !neutralizes("python:builtins:int", TaintLog) {
		t.Error("twin: int() must neutralize the log-injection class")
	}
	// A bare `logger.info` receiver on an arbitrary object must NOT be a log sink (only resolvable
	// module-level logging.* is modeled), so an unrelated `.info()` call is not flagged.
	if isSink("python:mypkg:Thing.info", TaintLog) {
		t.Error("twin: a bare .info receiver on an arbitrary object must NOT be a log sink")
	}
}

// TestPythonValueFlowLDAPInjection is the end-to-end positive + sanitized-twin for the new LDAP class:
// a request that reaches ldap.search_s's filter argument is a finding, and the same request escaped
// through escape_filter_chars first is not.
func TestPythonValueFlowLDAPInjection(t *testing.T) {
	for _, sanitized := range []bool{false, true} {
		doc := ldapPythonDocument(sanitized)
		resolution, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		graph, err := BuildPythonValueGraph(doc, resolution, DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		_, found := pythonFindingFor(graph.Vulnerabilities(), TaintLDAP, "python-taint-ldap")
		if sanitized && found {
			t.Error("an escape_filter_chars-sanitized filter must NOT be an LDAP finding")
		}
		if !sanitized && !found {
			t.Error("a raw request reaching the LDAP filter argument must be a finding")
		}
	}
}

// ldapPythonDocument builds a Flask route whose parameter reaches ldap.search_s(base, scope, filter). When
// sanitized, the filter is escape_filter_chars(request); otherwise it is the raw request.
func ldapPythonDocument(sanitized bool) pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "request", Pos: pyPos(2, 10)}}
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "ldap", Pos: pyPos(1, 0)}}

	values := []pythonprogram.Value{
		pyValue("request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("base-lit", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 5, 20),
		pyValue("scope-lit", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 5, 26),
		pyValue("search-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("ldap", "search_s"), 5, 4),
	}
	var filterArg pythonprogram.Argument
	var calls []pythonprogram.Call
	if sanitized {
		document.Imports = append(document.Imports, pythonprogram.Import{ScopeID: moduleID, Module: "ldap.filter", Name: "escape_filter_chars", Pos: pyPos(1, 0)})
		values = append(values,
			pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 4, 40),
			pyValue("escaped", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("escape_filter_chars"), 4, 4),
		)
		calls = append(calls, pythonprogram.Call{
			ID: "app.py:4:4", CallerID: route.ID, Callee: pyName("escape_filter_chars"),
			Arguments: []pythonprogram.Argument{{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(4, 40)}},
			ResultID:  "escaped", Pos: pyPos(4, 4),
		})
		filterArg = pythonprogram.Argument{Value: pyCallRef("escape_filter_chars"), ValueID: "escaped", Pos: pyPos(5, 32)}
	} else {
		values = append(values, pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 5, 32))
		filterArg = pythonprogram.Argument{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(5, 32)}
	}
	document.Values = values
	calls = append(calls, pythonprogram.Call{
		ID: "app.py:5:4", CallerID: route.ID, Callee: pyAttr("ldap", "search_s"),
		Arguments: []pythonprogram.Argument{
			{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "base-lit", Pos: pyPos(5, 20)},
			{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "scope-lit", Pos: pyPos(5, 26)},
			filterArg,
		},
		ResultID: "search-result", Pos: pyPos(5, 4),
	})
	document.Calls = calls
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

// TestPythonValueFlowXPathInjection is the end-to-end positive + parameterized-safe twin for the XPath
// class: a request that reaches the lxml xpath EXPRESSION (positional arg 0) is a finding, but the same
// request bound as an XPath VARIABLE keyword (root.xpath("//u[@id=$id]", id=request)) is not, because the
// expression itself is a constant.
func TestPythonValueFlowXPathInjection(t *testing.T) {
	for _, parameterized := range []bool{false, true} {
		doc := xpathPythonDocument(parameterized)
		resolution, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		graph, err := BuildPythonValueGraph(doc, resolution, DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		_, found := pythonFindingFor(graph.Vulnerabilities(), TaintXPath, "python-taint-xpath")
		if parameterized && found {
			t.Error("a request bound as an XPath VARIABLE keyword (safe parameterized form) must NOT be a finding")
		}
		if !parameterized && !found {
			t.Error("a request concatenated into the XPath expression must be a finding")
		}
	}
}

// xpathPythonDocument builds a route whose parameter reaches root.xpath(...). When parameterized, the
// request is passed as the `id` variable keyword and the expression is a constant; otherwise the request
// is the expression (positional arg 0).
func xpathPythonDocument(parameterized bool) pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "request", Pos: pyPos(2, 10)}}
	document.Symbols = append(document.Symbols, route)
	// The parsed element the xpath method is called on. `root = etree.fromstring(...)` resolves the
	// receiver to lxml.etree so root.xpath matches the sink; its argument decides the verdict.
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "lxml.etree", Name: "fromstring", Pos: pyPos(1, 0)}}

	values := []pythonprogram.Value{
		pyValue("request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("doc-lit", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 3, 20),
		pyValue("root", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("fromstring"), 3, 4),
		pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 4, 30),
		pyValue("xpath-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("root", "xpath"), 4, 4),
	}
	document.Assignments = []pythonprogram.Assignment{{ScopeID: route.ID, Targets: []pythonprogram.Reference{pyName("root")}, Value: pyCallRef("fromstring"), ValueID: "root", Pos: pyPos(3, 4)}}

	var xpathArgs []pythonprogram.Argument
	if parameterized {
		// root.xpath("//u[@id=$id]", id=request): expression is a literal, request is a variable keyword.
		xpathArgs = []pythonprogram.Argument{
			{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "expr-lit", Pos: pyPos(4, 20)},
			{Keyword: "id", Value: pyName("request"), ValueID: "request-use", Pos: pyPos(4, 30)},
		}
		values = append(values, pyValue("expr-lit", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 4, 20))
	} else {
		// root.xpath(request): the request IS the expression.
		xpathArgs = []pythonprogram.Argument{{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(4, 20)}}
	}
	document.Values = values
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyName("fromstring"), Arguments: []pythonprogram.Argument{{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "doc-lit", Pos: pyPos(3, 20)}}, ResultID: "root", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("root", "xpath"), Arguments: xpathArgs, ReceiverValueID: "root", ResultID: "xpath-result", Pos: pyPos(4, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

// The deserialization class covers the wider pickle-backed loader ecosystem, and continues to EXCLUDE the
// safe alternatives (json.load, numpy.load without allow_pickle).
func TestPythonCatalogBroadDeserialization(t *testing.T) {
	catalog := DefaultPythonCatalog()
	isSink := func(callee string) bool {
		for _, sink := range catalog.Sinks {
			if sink.Class == TaintDeserialization && callMatches(sink.Pattern, []string{callee}, "") {
				return true
			}
		}
		return false
	}
	for _, callee := range []string{
		"python:pandas:read_pickle", "python:torch:load", "python:joblib:load",
		"python:shelve:open", "python:pickle:Unpickler",
	} {
		if !isSink(callee) {
			t.Errorf("%q must be a deserialization sink", callee)
		}
	}
	// The safe loaders must NOT be deserialization sinks.
	for _, callee := range []string{"python:json:load", "python:json:loads", "python:numpy:load"} {
		if isSink(callee) {
			t.Errorf("%q is a safe loader and must not be a deserialization sink", callee)
		}
	}
}

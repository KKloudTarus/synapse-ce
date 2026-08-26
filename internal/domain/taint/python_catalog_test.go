package taint

import "testing"

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

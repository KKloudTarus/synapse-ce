package taint

import "testing"

func TestPythonCatalogCoversInitialFrameworkMatrix(t *testing.T) {
	catalog := DefaultPythonCatalog()
	if !catalog.EntrypointParameters {
		t.Fatal("FastAPI/Flask/Django route parameters must be modeled as request sources")
	}
	for _, raw := range []string{
		"flask.request.args.get", "request.GET.get", "request.query_params.get", "request.json",
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
		{"python:pathlib:Path", TaintPathTraversal},
		{"python:httpx:get", TaintSSRF},
		{"python:flask:render_template_string", TaintXSS},
		{"python:pickle:loads", TaintDeserialization},
		{"python:starlette.responses:RedirectResponse", TaintRedirect},
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

func containsTaintClass(values []TaintClass, want TaintClass) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

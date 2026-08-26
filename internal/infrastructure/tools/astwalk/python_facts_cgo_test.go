//go:build cgo

package astwalk

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
)

func TestPythonFactsForExtractsSemanticFactsDeterministically(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app/api.py", "import os, json as js\n"+
		"from flask import Flask, request as req\n"+
		"from .service import save\n"+
		"app = Flask(__name__)\n"+
		"@app.post(\"/users\")\n"+
		"async def create_user(request, *args, dry_run=False, **options):\n"+
		"    value = request.args.get(\"name\")\n"+
		"    return save(value)\n")
	writeFile(t, root, "app/service.py", "class Base:\n    pass\n\nclass Service(Base):\n    def save(self, value):\n        return value\n\ndef save(value):\n    return value\n")

	first, err := PythonFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("PythonFactsFor: %v", err)
	}
	second, err := PythonFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("PythonFactsFor second run: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		left, _ := json.Marshal(first)
		right, _ := json.Marshal(second)
		t.Fatalf("facts are not deterministic:\n%s\n%s", left, right)
	}
	if !first.Complete() || first.FilesSeen != 2 || first.FilesParsed != 2 {
		t.Fatalf("coverage = seen:%d parsed:%d complete:%v gaps:%+v", first.FilesSeen, first.FilesParsed, first.Complete(), first.CoverageGaps)
	}
	for _, module := range []string{"app.api", "app.service"} {
		if !hasPythonModule(first, module) {
			t.Errorf("missing module %q", module)
		}
	}
	create, ok := pythonSymbolByQualified(first, "app.api", "create_user")
	if !ok || create.Kind != pythonprogram.SymbolFunction || !create.Async {
		t.Fatalf("create_user symbol = %+v, found=%v", create, ok)
	}
	if len(create.Parameters) != 4 || create.Parameters[1].Kind != pythonprogram.ParameterVarArgs ||
		create.Parameters[2].Kind != pythonprogram.ParameterKeywordOnly || create.Parameters[3].Kind != pythonprogram.ParameterKwArgs {
		t.Fatalf("create_user parameters = %+v", create.Parameters)
	}
	for _, parameter := range create.Parameters {
		if parameter.ValueID == "" {
			t.Errorf("parameter %q has no value slot", parameter.Name)
		}
	}
	if !hasPythonEntrypoint(first, create.ID, "framework_route") {
		t.Errorf("missing framework route hint for %s", create.ID)
	}
	service, ok := pythonSymbolByQualified(first, "app.service", "Service")
	if !ok || len(service.Bases) != 1 || joinPythonReference(service.Bases[0]) != "Base" {
		t.Errorf("Service bases = %+v, found=%v", service.Bases, ok)
	}
	for _, want := range []string{"Flask", "app.post", "request.args.get", "save"} {
		if !hasPythonCall(first, want) {
			t.Errorf("missing call %q (calls: %+v)", want, first.Calls)
		}
	}
	if len(first.Imports) != 5 {
		t.Errorf("imports = %+v, want five bindings", first.Imports)
	}
	if len(first.Assignments) < 2 || len(first.Returns) != 3 {
		t.Errorf("assignments=%d returns=%d", len(first.Assignments), len(first.Returns))
	}
	if len(first.Values) == 0 || len(first.Flows) == 0 {
		t.Errorf("value extraction missing: values=%d flows=%d", len(first.Values), len(first.Flows))
	}
	for _, call := range first.Calls {
		if call.ResultID == "" {
			t.Errorf("call %q has no result value", call.ID)
		}
		for _, argument := range call.Arguments {
			if argument.ValueID == "" {
				t.Errorf("call %q has an argument without a value slot", call.ID)
			}
		}
	}
}

func TestPythonFactsForReportsDynamicAndRecoveryGaps(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "dynamic.py", "import importlib\ndef load(name):\n    module = importlib.import_module(name)\n    return eval(name)\n")
	writeFile(t, root, "broken.py", "def broken(:\n    return 1\n")

	document, err := PythonFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("PythonFactsFor: %v", err)
	}
	if document.Complete() {
		t.Fatal("dynamic or recovered source must not support a negative proof")
	}
	for _, want := range []pythonprogram.GapKind{
		pythonprogram.GapDynamicImport,
		pythonprogram.GapDynamicExecution,
		pythonprogram.GapParseRecovery,
	} {
		if !hasPythonGap(document, want) {
			t.Errorf("missing coverage gap %q (all: %+v)", want, document.CoverageGaps)
		}
	}
}

func TestPythonFactsForExtractsLoopComprehensionAndWithBindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bindings.py", "def process(values, manager):\n"+
		"    for item in values:\n"+
		"        consume(item)\n"+
		"    result = [consume(element) for element in values]\n"+
		"    with manager() as resource:\n"+
		"        consume(resource)\n")

	document, err := PythonFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("PythonFactsFor: %v", err)
	}
	for _, name := range []string{"item", "element", "resource"} {
		if !hasPythonBinding(document, name) {
			t.Errorf("missing value-flow binding for %q (assignments: %+v)", name, document.Assignments)
		}
	}
}

func TestPythonFactsForRootPackageInit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "__init__.py", "def create():\n    return 1\n")
	document, err := PythonFactsFor(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPythonModule(document, "__init__") || !document.Complete() {
		t.Fatalf("root package facts = %+v", document)
	}
}

func hasPythonModule(document pythonprogram.Document, want string) bool {
	for _, module := range document.Modules {
		if module.Name == want {
			return true
		}
	}
	return false
}

func pythonSymbolByQualified(document pythonprogram.Document, module, qualified string) (pythonprogram.Symbol, bool) {
	for _, symbol := range document.Symbols {
		if symbol.Module == module && symbol.QualifiedName == qualified {
			return symbol, true
		}
	}
	return pythonprogram.Symbol{}, false
}

func hasPythonCall(document pythonprogram.Document, want string) bool {
	for _, call := range document.Calls {
		if joinPythonReference(call.Callee) == want {
			return true
		}
	}
	return false
}

func joinPythonReference(ref pythonprogram.Reference) string {
	var out string
	for _, segment := range ref.Segments {
		if out != "" {
			out += "."
		}
		out += segment
	}
	return out
}

func hasPythonEntrypoint(document pythonprogram.Document, symbolID, kind string) bool {
	for _, hint := range document.Entrypoints {
		if hint.SymbolID == symbolID && hint.Kind == kind {
			return true
		}
	}
	return false
}

func hasPythonGap(document pythonprogram.Document, kind pythonprogram.GapKind) bool {
	for _, gap := range document.CoverageGaps {
		if gap.Kind == kind {
			return true
		}
	}
	return false
}

func hasPythonBinding(document pythonprogram.Document, name string) bool {
	for _, assignment := range document.Assignments {
		for i, target := range assignment.Targets {
			if joinPythonReference(target) == name && i < len(assignment.TargetIDs) && assignment.TargetIDs[i] != "" && assignment.ValueID != "" {
				return true
			}
		}
	}
	return false
}

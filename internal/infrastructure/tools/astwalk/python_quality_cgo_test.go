//go:build cgo

package astwalk

import (
	"context"
	"testing"
)

func TestQualityForPythonSeed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "rules.py", `
import unused
import used
from package import *

assert value
if value == None: pass
if type(value) != str: pass
if len(items) == 0: pass
logger.info(f"value={value}")

def mutable(items=list()): pass

def eight(a, b, c, d, e, f, g, h): pass

def globals():
    global state

try:
    work()
except:
    pass

try:
    work()
finally:
    return

values = {'a': 1, "a": 2}
source = open(path)
raise Exception("bad")
used.dumps({})
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-mutable-default-argument", "python-bare-except", "python-return-in-finally", "python-duplicate-dict-key",
		"python-assert-for-validation", "python-eq-none", "python-star-import", "python-open-no-context",
		"python-type-eq-vs-isinstance", "python-global-statement", "python-too-many-args", "python-f-string-logging",
		"python-len-eq-zero", "python-unused-import", "python-broad-raise",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonSeedRegressions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "regressions.py", `
def seven(a: tuple[int, str], b, c, d, e, f, g): pass
with transaction():
    source = open(path)
import json
def outer(json):
    def inner():
        return json.loads("{}")
    return inner()
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	if got["python-too-many-args"] {
		t.Errorf("unexpected parameter finding: %+v", res.Findings)
	}
	if !got["python-unused-import"] {
		t.Errorf("shadowed import must be reported unused: %+v", res.Findings)
	}
	if !got["python-open-no-context"] {
		t.Errorf("open inside with body must be reported: %+v", res.Findings)
	}
}

func TestQualityForPythonMutableDefaultGuard(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "lambda_default.py", `
def callback(handler=lambda values=[]: values): pass
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range res.Findings {
		if f.Rule == "python-mutable-default-argument" {
			t.Errorf("lambda default must not be reported: %+v", res.Findings)
		}
	}
}

func TestQualityForPythonSeedGuards(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "clean.py", `
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import type_only

import used
__all__ = ["used"]

def seven(self, a, b, c, d, e, f, g, *args, **kwargs):
    with open(path) as source:
        return source.read()

try:
    work()
except ValueError:
    recover()

if value is None: pass
if isinstance(value, str): pass
if not items: pass
logger.info("value=%s", value)
raise ValueError("bad")
used.dumps({})
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("guard corpus produced findings: %+v", res.Findings)
	}
}

func TestQualityForPythonExtendedRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "extended.py", `
if status is 404:
    handle()

try:
    work()
except Exception:
    recover()

area = lambda r: r * r
import os, sys
message = f'ready'
subprocess.run(command, shell=True)
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-is-literal", "python-broad-except", "python-lambda-assignment",
		"python-multiple-imports", "python-fstring-no-placeholder", "python-subprocess-shell",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonExtendedNoFalsePositives(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "clean.py", `
if value is None:
    return

try:
    work()
except ValueError:
    recover()

handler = compute
import os
message = f'hello {name}'
subprocess.run(['ls', '-la'])
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range res.Findings {
		switch f.Rule {
		case "python-is-literal", "python-broad-except", "python-lambda-assignment",
			"python-multiple-imports", "python-fstring-no-placeholder", "python-subprocess-shell":
			t.Errorf("false positive %s on clean code: %+v", f.Rule, f)
		}
	}
}

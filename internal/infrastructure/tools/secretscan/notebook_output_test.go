package secretscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// notebookWithOutput builds a minimal .ipynb whose code cell holds a credential in its SOURCE and a
// catalogue dump plus a provider token in its OUTPUT.
const notebookFixture = `{
 "cells": [
  {
   "cell_type": "code",
   "source": ["api_key = \"kjZ8xQ2mNp4rLw7sTv3yBc6dEf1gHi0aB\"\n"],
   "outputs": [
    {"output_type": "stream", "text": ["//prod-asset/bi/202603/urban_web_crawler_product_2026-03-17_x\n", "lading-zone_web_crawler_product_2026-03-17_5sfashion\n"]},
    {"output_type": "stream", "text": ["%s\n"]}
   ]
  }
 ],
 "metadata": {},
 "nbformat": 4
}`

// TestNotebookOutputsAreMaskedForTheEntropyRuleOnly pins the cut that removed 1,999 of 2,844 keyword-free
// entropy findings across a real estate. A cell's output is what running the code printed, not what anyone
// wrote, and a printed catalogue dump is indistinguishable from keys to an entropy rule. What must NOT
// change: a credential in the cell SOURCE is still found, and a provider token printed into an OUTPUT is
// still found, because the prefix-anchored rules keep reading the whole file.
func TestNotebookOutputsAreMaskedForTheEntropyRuleOnly(t *testing.T) {
	dir := t.TempDir()
	// The key is assembled here rather than written as one constant, so this test file carries no
	// key-shaped literal of its own.
	body := fmt.Sprintf(notebookFixture, "AKIA"+"QRSTUVWX2345YZ67")
	if err := os.WriteFile(filepath.Join(dir, "debug.ipynb"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byRule := map[string]int{}
	for _, f := range report.Findings {
		byRule[f.RuleID]++
	}

	if byRule["generic-secret"] == 0 {
		t.Error("the credential in the cell source must still be reported")
	}
	if byRule["aws-access-key-id"] == 0 {
		t.Error("a provider token printed into a cell output is still a leaked credential and must be reported")
	}
	if n := byRule["generic-high-entropy"]; n > 0 {
		t.Errorf("keyword-free entropy fired %d time(s) inside a cell output; it must stand down there", n)
	}
}

// TestMaskNotebookOutputsPreservesOffsets pins the contract every mask here keeps: byte length and newline
// positions survive, so a match offset and a line count still index the original file.
func TestMaskNotebookOutputsPreservesOffsets(t *testing.T) {
	in := []byte(fmt.Sprintf(notebookFixture, "AKIA"+"QRSTUVWX2345YZ67"))
	out := maskNotebookOutputs("debug.ipynb", in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), len(out))
	}
	if strings.Count(string(out), "\n") != strings.Count(string(in), "\n") {
		t.Fatal("newline count changed")
	}
	if strings.Contains(string(out), "lading-zone_web_crawler") {
		t.Error("output content was not masked")
	}
	if !strings.Contains(string(out), "api_key") {
		t.Error("cell source must not be masked")
	}
	// A file that is not a notebook is returned untouched.
	plain := []byte(`{"outputs": ["kept"]}`)
	if string(maskNotebookOutputs("config.json", plain)) != string(plain) {
		t.Error("a non-notebook file must be left alone")
	}
}

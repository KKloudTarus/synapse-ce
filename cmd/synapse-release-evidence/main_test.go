package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestExecuteGenerateAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.tar.gz"), []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--dir", dir, "--repository", "KKloudTarus/synapse-ce", "--revision", revision, "--release", "v1.2.3"}
	var stdout, stderr bytes.Buffer
	if err := execute(append([]string{"generate"}, common...), &stdout, &stderr); err != nil {
		t.Fatalf("generate error = %v, stderr = %q", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "with 1 release assets") {
		t.Fatalf("generate output = %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := execute(append([]string{"verify"}, common...), &stdout, &stderr); err != nil {
		t.Fatalf("verify error = %v, stderr = %q", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "verified v1.2.3 at "+revision) {
		t.Fatalf("verify output = %q", stdout.String())
	}
}

func TestExecuteFailsClosedForMissingIdentityAndUnknownCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.tar.gz"), []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := [][]string{
		{"generate", "--dir", dir, "--repository", "KKloudTarus/synapse-ce", "--release", "v1.0.0"},
		{"verify", "--dir", dir, "--repository", "KKloudTarus/synapse-ce", "--revision", revision},
		{"unknown"},
		{},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if err := execute(args, &stdout, &stderr); err == nil {
			t.Fatalf("execute(%v) succeeded", args)
		}
	}
}

func TestExecuteHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := execute([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "generate|verify") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

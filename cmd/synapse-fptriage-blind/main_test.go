package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunRejectsInvalidModeBeforeWriting(t *testing.T) {
	err := run("invalid", "", "", "", "", "", "", "", "", filepath.Join(t.TempDir(), "output.json"))
	if err == nil || !strings.Contains(err.Error(), "--mode must be export, import, or join") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRequiresNewOutputPath(t *testing.T) {
	if err := run("export", "", "", "", "", "", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("run() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("export", "", "", "", "", "", "", "", "", path); err == nil || !strings.Contains(err.Error(), "new private file") {
		t.Fatalf("run() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("existing output was modified: %q", data)
	}
}

func TestReadStrictJSONRejectsUnknownAndTrailingContent(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "unknown", data: `{"reviewers":["human"],"unexpected":true}`},
		{name: "trailing", data: `{"reviewers":["human"]}{}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			var value struct {
				Reviewers []string `json:"reviewers"`
			}
			if err := readStrictJSON(path, &value); err == nil {
				t.Fatal("invalid JSON was accepted")
			}
		})
	}
}

func TestWritePrivateJSONFailsClosedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific fail-closed behavior")
	}
	path := filepath.Join(t.TempDir(), "output.json")
	err := writePrivateJSON(path, map[string]bool{"ok": true})
	if err == nil || !strings.Contains(err.Error(), "disabled on Windows") {
		t.Fatalf("writePrivateJSON() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("output was created despite fail-closed behavior: %v", err)
	}
}

func TestWritePrivateJSONCreatesExclusivePrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command intentionally fails closed on Windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "output.json")
	if err := writePrivateJSON(path, map[string]string{"status": "ok"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output permissions = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["status"] != "ok" {
		t.Fatalf("output = %v", decoded)
	}
	if err := writePrivateJSON(path, decoded); err == nil {
		t.Fatal("existing output was overwritten")
	}
}

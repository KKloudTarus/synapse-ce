package gitdiff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestChangedIgnoresDiffPresentationAndConverters(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, tc := range []struct {
		name       string
		config     [][2]string
		attributes string
	}{
		{name: "mnemonic prefixes", config: [][2]string{{"diff.mnemonicPrefix", "true"}}},
		{name: "no prefixes", config: [][2]string{{"diff.noprefix", "true"}}},
		{name: "custom prefixes", config: [][2]string{{"diff.srcPrefix", "old/"}, {"diff.dstPrefix", "new/"}}},
		{name: "external diff", config: [][2]string{{"diff.external", "missing-diff-converter"}}},
		{name: "text conversion", config: [][2]string{{"diff.untrusted.textconv", "missing-text-converter"}}, attributes: "calc.go diff=untrusted\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			git := func(args ...string) {
				t.Helper()
				cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			write := func(name, content string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			git("init", "-q")
			write("calc.go", "package calc\n\nfunc Add() int { return 1 }\n")
			write(".gitattributes", tc.attributes)
			git("add", "calc.go", ".gitattributes")
			git("-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--no-gpg-sign", "-qm", "test: seed diff fixture")
			for _, setting := range tc.config {
				git("config", setting[0], setting[1])
			}
			write("calc.go", "package calc\n\nfunc Add() int { return 2 }\n")
			got, err := Changed(context.Background(), root, "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			want := ChangedLines{"calc.go": {3: true}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("changed lines = %v, want %v", got, want)
			}
		})
	}
}

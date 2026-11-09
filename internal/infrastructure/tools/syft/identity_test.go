package syft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type deniedIdentityRunner struct{}

func (deniedIdentityRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{Stderr: []byte("secret-from-runner")}, errors.New("secret-from-runner")
}

func TestIdentityDoesNotBypassUnavailableRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	bin := filepath.Join(dir, "syft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, cacheable, err := New(bin).WithRunner(deniedIdentityRunner{}).SBOMProducerIdentity(context.Background(), dir)
	if cacheable || identity != "" || (err != nil && strings.Contains(err.Error(), "secret-from-runner")) {
		t.Fatalf("unsafe identity result: %q %v %v", identity, cacheable, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("sandbox failure caused native execution: %v", err)
	}
}

func TestIdentityChangesForEqualMetadataExecutableReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	dir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "syft")
	first := "#!/bin/sh\nprintf 'enrich: []\\n'\n# a\n"
	second := "#!/bin/sh\nprintf 'enrich: []\\n'\n# b\n"
	if err := os.WriteFile(bin, []byte(first), 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1000000000, 0)
	if err := os.Chtimes(bin, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	gen := New(bin)
	id1, ok, err := gen.SBOMProducerIdentity(context.Background(), dir)
	if err != nil || !ok {
		t.Fatalf("first identity unavailable: %v", err)
	}
	if err := os.WriteFile(bin, []byte(second), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bin, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	id2, ok, err := gen.SBOMProducerIdentity(context.Background(), dir)
	if err != nil || !ok || id1 == id2 {
		t.Fatalf("replacement reused identity: %v", err)
	}
}

func TestIdentityDeclinesExternalResolutionInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	dir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "syft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'enrich: []\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gen := New(bin)
	if _, ok, err := gen.SBOMProducerIdentity(context.Background(), dir); err != nil || !ok {
		t.Fatalf("ordinary input not cacheable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := gen.SBOMProducerIdentity(context.Background(), dir); err != nil || ok {
		t.Fatalf("Maven input was cacheable: %v", err)
	}
}

type identityResultRunner struct {
	result ports.ToolResult
	err    error
}

func (r identityResultRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return r.result, r.err
}

func TestIdentityDeclinesBareExecutableWithSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	binDir := t.TempDir()
	marker := filepath.Join(binDir, "executed")
	bin := filepath.Join(binDir, "syft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	identity, cacheable, err := New("syft").WithRunner(identityResultRunner{
		result: ports.ToolResult{Stdout: []byte("enrich: []\n")},
	}).SBOMProducerIdentity(context.Background(), t.TempDir())
	if err != nil || cacheable || identity != "" {
		t.Fatalf("bare sandbox executable accepted: %q %v %v", identity, cacheable, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("bare sandbox executable ran natively: %v", err)
	}
}

func TestIdentityDeclinesUnsuccessfulConfigResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	binDir := t.TempDir()
	marker := filepath.Join(binDir, "executed")
	bin := filepath.Join(binDir, "syft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	valid := []byte("enrich: []\n")
	secret := "secret-from-config-command"
	tests := []struct {
		name   string
		result ports.ToolResult
		err    error
	}{
		{"runner error", ports.ToolResult{Stdout: valid, Stderr: []byte(secret)}, errors.New(secret)},
		{"nonzero exit", ports.ToolResult{Stdout: valid, Stderr: []byte(secret), ExitCode: 1}, nil},
		{"timeout", ports.ToolResult{Stdout: valid, Stderr: []byte(secret), TimedOut: true}, nil},
		{"truncated", ports.ToolResult{Stdout: valid, Stderr: []byte(secret), Truncated: true}, nil},
		{"empty output", ports.ToolResult{Stderr: []byte(secret)}, nil},
		{"oversized stdout", ports.ToolResult{Stdout: []byte(strings.Repeat("x", (1<<20)+1)), Stderr: []byte(secret)}, nil},
		{"oversized stderr", ports.ToolResult{Stdout: valid, Stderr: []byte(strings.Repeat(secret, (1<<20)/len(secret)+1))}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, cacheable, err := New(bin).WithRunner(identityResultRunner{result: tt.result, err: tt.err}).
				SBOMProducerIdentity(context.Background(), t.TempDir())
			if cacheable || identity != "" || (err != nil && strings.Contains(err.Error(), secret)) {
				t.Fatalf("unsafe config result: %q %v %v", identity, cacheable, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("runner failure caused native execution: %v", err)
			}
		})
	}
}

func TestIdentityDeclinesFailedConfigProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	bin := filepath.Join(t.TempDir(), "syft")
	secret := "secret-from-failed-config"
	script := "#!/bin/sh\nprintf 'enrich: []\\n'\nprintf '" + secret + "' >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, cacheable, err := New(bin).SBOMProducerIdentity(context.Background(), t.TempDir())
	if cacheable || identity != "" || (err != nil && strings.Contains(err.Error(), secret)) {
		t.Fatalf("failed config process accepted or leaked output: %q %v %v", identity, cacheable, err)
	}
}

func TestIdentityConfigPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX executable fixture")
	}
	tests := []struct {
		name      string
		config    string
		cacheable bool
	}{
		{"local directory control", "enrich: []\n", true},
		{"malformed yaml", "enrich: [\n", false},
		{"non mapping yaml", "- enrich\n", false},
		{"absent enrich", "golang: {}\n", false},
		{"invalid enrich type", "enrich: true\n", false},
		{"enrichment enabled", "enrich: [all]\n", false},
		{"go local module licenses", "enrich: []\ngolang:\n  search-local-mod-cache-licenses: true\n", false},
		{"go vendor licenses", "enrich: []\ngolang:\n  search-local-vendor-licenses: true\n", false},
		{"go remote licenses", "enrich: []\ngolang:\n  search-remote-licenses: true\n", false},
		{"go packages library", "enrich: []\ngolang:\n  use-packages-lib: true\n", false},
		{"javascript remote licenses", "enrich: []\njavascript:\n  search-remote-licenses: true\n", false},
		{"python remote licenses", "enrich: []\npython:\n  search-remote-licenses: true\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "syft")
			script := "#!/bin/sh\nprintf '%s' '" + tt.config + "'\n"
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			identity, cacheable, err := New(bin).SBOMProducerIdentity(context.Background(), t.TempDir())
			if err != nil || cacheable != tt.cacheable || (identity != "") != tt.cacheable {
				t.Fatalf("unexpected config policy result: %q %v %v", identity, cacheable, err)
			}
		})
	}
}

func TestIdentityDeclinesUnrepresentableInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX executable and symlink fixtures")
	}
	bin := filepath.Join(t.TempDir(), "syft")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'enrich: []\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		symlink bool
	}{
		{"oci layout", "oci-layout", false},
		{"pom", "dependency.POM", false},
		{"jar", "dependency.jar", false},
		{"war", "dependency.war", false},
		{"ear", "dependency.ear", false},
		{"jpi", "dependency.jpi", false},
		{"hpi", "dependency.hpi", false},
		{"zip", "archive.zip", false},
		{"tar", "archive.tar", false},
		{"gzip", "archive.gz", false},
		{"tgz", "archive.tgz", false},
		{"symlink", "link", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.path)
			var err error
			if tt.symlink {
				err = os.Symlink(t.TempDir(), path)
			} else {
				err = os.WriteFile(path, []byte("fixture"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			identity, cacheable, err := New(bin).SBOMProducerIdentity(context.Background(), dir)
			if err != nil || cacheable || identity != "" {
				t.Fatalf("unsafe input accepted: %q %v %v", identity, cacheable, err)
			}
		})
	}
}

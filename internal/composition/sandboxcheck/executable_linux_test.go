package sandboxcheck

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
)

func TestReplaceProbeExecutableRejectsChangedBinaryWhileOldInodeRuns(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(sleep)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	registry := binregistry.New(nil, true)
	if _, err := registry.Verify(path); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, syscall.ETXTBSY) {
		t.Fatalf("running executable write error = %v, want ETXTBSY", err)
	}
	if err := replaceProbeExecutable(path, append(contents, '\n')); err != nil {
		t.Fatalf("replace executing probe: %v", err)
	}
	if _, err := registry.Verify(path); !errors.Is(err, binregistry.ErrIntegrity) {
		t.Fatalf("replacement verification = %v, want integrity rejection", err)
	}
}

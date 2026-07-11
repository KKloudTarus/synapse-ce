//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestSandboxHidesHostSecrets proves F2: with a curated rootfs (no whole-host-root bind),
// a tool cannot reach $HOME secrets (~/.ssh etc.) – the path is absent – while the OS tree
// it needs (/etc, /usr) is present. Run as root (sudo) so $HOME=/root.
func TestSandboxHidesHostSecrets(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	sb, err := sandbox.NewRunner(30*time.Second, 8<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	secret := "SYNAPSE_CANARY_TOPSECRET_a1b2c3"
	sshDir := home + "/.ssh"
	_ = os.MkdirAll(sshDir, 0o700)
	canary := sshDir + "/synapse_canary"
	if err := os.WriteFile(canary, []byte(secret), 0o600); err != nil {
		t.Skipf("cannot write canary (need a writable HOME): %v", err)
	}
	defer os.Remove(canary)

	// Read the canary ($HOME secret) AND /etc/shadow (root-readable secret) – both must be
	// absent from the curated sandbox – while TLS trust (CA certs) + nsswitch remain.
	script := "cat " + canary + " 2>&1; echo __MARK__; " +
		"( test -e /etc/ssl/certs || test -e /etc/pki/tls/certs ) && echo CA_OK; " +
		"test -e /etc/nsswitch.conf && echo NSS_OK; " +
		"test -e /usr/bin && echo USR_OK; " +
		"test -e /etc/shadow && echo SHADOW_PRESENT || echo SHADOW_ABSENT; " +
		"test -e " + home + " && echo HOME_VISIBLE || echo HOME_ABSENT"
	res, err := sb.Run(context.Background(), ports.ToolSpec{Name: "sh", Args: []string{"-c", script}})
	if err != nil {
		t.Fatalf("probe run: %v", err)
	}
	out := string(res.Stdout)
	t.Logf("probe output:\n%s", out)

	if strings.Contains(out, secret) {
		t.Fatalf("HOST SECRET LEAKED into the sandbox: %s/.ssh/canary was readable", home)
	}
	for _, want := range []string{"CA_OK", "NSS_OK", "USR_OK", "SHADOW_ABSENT", "HOME_ABSENT"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q (curated /etc: CA+nsswitch present, shadow+home absent): %s", want, out)
		}
	}
}

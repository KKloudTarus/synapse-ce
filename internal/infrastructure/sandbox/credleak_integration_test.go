//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestCredentialLeakChannels behaviorally probes Part 4: a tool that ECHOES an injected
// secret raw vs base64 vs hex – which channels does the redaction chokepoint catch?
func TestCredentialLeakChannels(t *testing.T) {
	for _, b := range []string{"bwrap", "base64", "xxd", "sh"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	sb, err := sandbox.NewRunner(30*time.Second, 16<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	c, _ := vault.NewCipher(make([]byte, 32))
	mv := vault.NewMemoryVault(c, nil)
	const secret = "S3CR3T_TOKEN_DEADBEEF"
	_ = mv.Put(context.Background(), "eng1", "TOK", []byte(secret))
	sb.SetVault(mv)

	dir := t.TempDir()
	// The tool echoes the secret three ways: raw, base64, hex.
	script := `printf 'RAW=%s\n' "$TOK"; printf 'B64=%s\n' "$(printf %s "$TOK" | base64)"; printf 'HEX=%s\n' "$(printf %s "$TOK" | xxd -p)"`
	res, err := sb.Run(context.Background(), ports.ToolSpec{
		Name: "sh", Args: []string{"-c", script}, Workdir: dir,
		EngagementID: "eng1", Env: []string{"TOK={{secret:TOK}}"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := string(res.Stdout) // this is what gets SEALED into evidence + sent to the log broker
	t.Logf("\n===== sealed/logged tool output (post-redaction) =====\n%s\n======================================================", out)
	rawLeak := strings.Contains(out, secret)
	import_b64 := "UzNDUjNUX1RPS0VOX0RFQURCRUVG" // base64 of the secret
	b64Leak := strings.Contains(out, import_b64)
	hexLeak := strings.Contains(strings.ToLower(out), "53334352335424f4b454e5f4445414442454546") || strings.Contains(out, "533343523354")
	t.Logf("LEAK raw=%v base64=%v hex=%v", rawLeak, b64Leak, hexLeak)
	if rawLeak {
		t.Errorf("RAW secret leaked into sealed output (redaction should catch exact match)")
	}
	// base64/hex leaks are the DOCUMENTED residual – record what actually happens.
	if b64Leak || hexLeak {
		t.Logf("CONFIRMED residual: encoded secret survives the substring redactor (base64=%v hex=%v)", b64Leak, hexLeak)
	}
	_ = os.WriteFile(filepath.Join(dir, ".keep"), nil, 0o600)
}

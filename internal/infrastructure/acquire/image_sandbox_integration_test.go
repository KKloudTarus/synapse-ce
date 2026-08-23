package acquire_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireImageSandboxedEgress proves a daemonless image pull (crane) runs
// inside the sandbox with egress restricted to the registry, producing an OCI layout that
// syft scans into a real SBOM. Needs crane + syft + bubblewrap + CAP_NET_ADMIN (sudo).
func TestAcquireImageSandboxedEgress(t *testing.T) {
	for _, bin := range []string{"crane", "syft", "bwrap"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	sb, err := sandbox.NewRunner(5*time.Minute, 64<<20, 2<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	app, err := egress.NewApplier()
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	ctx := context.Background()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := app.Probe(pctx)
	cancel()
	if perr != nil {
		t.Skipf("egress not usable (run with sudo for CAP_NET_ADMIN): %v", perr)
	}
	sb.SetEgress(app)

	acq := acquire.New().WithSandbox(authoritativeTestRunner{ToolRunner: sb}, true)
	ws, err := acq.Acquire(ctx, ports.AcquireRequest{Kind: ports.TargetImage, Value: "alpine:latest"})
	if err != nil {
		t.Fatalf("sandboxed image pull failed: %v", err)
	}
	defer func() {
		if ws.Cleanup != nil {
			_ = ws.Cleanup()
		}
	}()
	if _, err := os.Stat(filepath.Join(ws.Dir, "oci-layout")); err != nil {
		t.Fatalf("workspace is not an OCI layout: %v", err)
	}
	// syft auto-detects the OCI layout and scans the image's packages.
	doc, err := syft.New("syft").Generate(ctx, ws.Dir)
	if err != nil {
		t.Fatalf("syft scan of pulled image: %v", err)
	}
	if len(doc.Components) == 0 {
		t.Fatal("image SBOM has no packages (oci-dir scan failed?)")
	}
	t.Logf("sandboxed image SCA OK: %d packages from alpine:latest", len(doc.Components))
}

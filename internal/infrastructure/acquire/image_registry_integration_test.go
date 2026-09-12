package acquire_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireImageInProcessRealRegistry pulls a small public image from Docker Hub entirely
// in-process (go-containerregistry as a library, no external crane binary) through the
// egress-pinned transport, exercising the real token + blob-CDN redirect flow the in-memory
// httptest registry cannot, and scans the resulting OCI layout with syft. Needs outbound
// network to Docker Hub + syft; skips (does not fail) in an offline CI sandbox.
func TestAcquireImageInProcessRealRegistry(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed")
	}
	// Reachability probe so a network-isolated CI sandbox skips rather than fails.
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, derr := dialer.DialContext(context.Background(), "tcp", "registry-1.docker.io:443")
	if derr != nil {
		t.Skipf("Docker Hub unreachable (offline CI): %v", derr)
	}
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ws, err := acquire.New().Acquire(ctx, ports.AcquireRequest{Kind: ports.TargetImage, Value: "alpine:3.20"})
	if err != nil {
		t.Fatalf("in-process image pull failed: %v", err)
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
	t.Logf("in-process image SCA OK: %d packages from alpine:3.20", len(doc.Components))
}

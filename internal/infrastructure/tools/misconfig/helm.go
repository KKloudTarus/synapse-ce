package misconfig

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	helmRenderTimeout = 45 * time.Second // bound a single `helm template` render
	maxRenderedBytes  = 16 << 20         // cap the rendered manifest stream fed to the K8s rules
)

// scanHelmChart renders a Helm chart with `helm template` (argv array, never a shell string) and runs
// the Kubernetes rules over the rendered manifests. Rendering a chart's defaults is how comprehensive
// scanners (Trivy) evaluate Helm — the raw templates carry Go-template directives and are not valid
// YAML. Best-effort: a missing helm binary, or a chart needing required values / unbuilt dependencies,
// yields no findings and never fails the scan. `helm template` only renders templates locally; it runs
// no chart hooks and executes no arbitrary code (unlike `helm install`).
func scanHelmChart(ctx context.Context, helmBin, chartDir, relDir string) []ports.MisconfigRawFinding {
	if helmBin == "" {
		return nil
	}
	if _, err := exec.LookPath(helmBin); err != nil {
		return nil // helm not installed: Helm charts are silently skipped, as before
	}
	cctx, cancel := context.WithTimeout(ctx, helmRenderTimeout)
	defer cancel()
	// Fixed release name (no interpolation), skip test hooks. No cluster is contacted.
	cmd := exec.CommandContext(cctx, helmBin, "template", "synapse-scan", chartDir, "--skip-tests")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil // a chart that will not render with defaults is best-effort skipped
	}
	rendered := stdout.Bytes()
	if len(rendered) > maxRenderedBytes {
		rendered = rendered[:maxRenderedBytes]
	}
	// scanKubernetes handles the multi-document stream `helm template` emits; attribute findings to the chart.
	return scanKubernetes(filepath.Join(relDir, "Chart.yaml"), rendered)
}

package misconfig

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	helmRenderTimeout = 45 * time.Second // bound a single `helm template` render
	maxRenderedBytes  = 16 << 20         // cap the rendered manifest stream fed to the K8s rules
)

// scanHelmChart renders a Helm chart and runs the Kubernetes rules over the output – the raw templates
// carry Go-template directives and are not valid YAML, so rendering is how comprehensive scanners
// evaluate Helm. `helm template` on an UNTRUSTED chart must not run unprotected on the host: Helm's
// Sprig engine exposes getHostByName (live DNS), an SSRF / blind-exfil vector. So this mirrors the
// maven/gradle resolvers exactly – a caller-supplied ToolRunner confines the exec (the API path, with
// egress denied), or an explicit trusted-local direct exec is used (the CLI). With NEITHER set, Helm
// rendering is skipped. Always argv (never a shell), fixed release name, no chart hooks; best-effort.
func scanHelmChart(ctx context.Context, runner ports.ToolRunner, direct bool, helmBin, chartDir, relDir string) []ports.MisconfigRawFinding {
	if helmBin == "" {
		return nil
	}
	args := []string{"template", "synapse-scan", chartDir, "--skip-tests"}
	var rendered []byte
	switch {
	case runner != nil:
		// Sandboxed: bind the chart dir read-only, DENY all egress (rendering needs no network, so this
		// neutralizes getHostByName), and cap output + time via the spec.
		res, err := runner.Run(ctx, ports.ToolSpec{
			Name:           helmBin,
			Args:           args,
			ReadOnlyPaths:  []string{chartDir},
			Timeout:        helmRenderTimeout,
			MaxOutputBytes: maxRenderedBytes,
			// No EgressPolicy: `helm template` needs no network, so leave it nil for full network isolation
			// (--unshare-all, no interface at all) rather than a filtered veth – stronger, and it does not
			// depend on the egress applier being present. This neutralizes Helm's Sprig getHostByName.
		})
		if err != nil || res.ExitCode != 0 {
			return nil
		}
		rendered = res.Stdout
	case direct:
		// Trusted-local (CLI) direct exec, matching the CLI's maven/gradle posture. Output is capped
		// DURING capture so a chart rendering gigabytes cannot OOM the process before a post-hoc cap.
		if _, err := exec.LookPath(helmBin); err != nil {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, helmRenderTimeout)
		defer cancel()
		cmd := exec.CommandContext(cctx, helmBin, args...)
		cw := &cappedBuffer{max: maxRenderedBytes}
		cmd.Stdout, cmd.Stderr = cw, io.Discard
		if err := cmd.Run(); err != nil {
			return nil
		}
		rendered = cw.buf.Bytes()
	default:
		return nil // Helm rendering not enabled (no sandbox runner, not trusted-local)
	}
	if len(rendered) > maxRenderedBytes {
		rendered = rendered[:maxRenderedBytes]
	}
	return scanKubernetes(filepath.Join(relDir, "Chart.yaml"), rendered)
}

// cappedBuffer accumulates at most max bytes and silently discards the rest, so a chart that renders
// gigabytes bounds memory instead of OOMing the process. Write always reports a full write so the child
// process is not killed by a short-write error; the timeout still bounds a runaway render.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

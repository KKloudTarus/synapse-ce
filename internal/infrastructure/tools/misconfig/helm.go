package misconfig

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	helmRenderTimeout  = 45 * time.Second // bound a single `helm template` render
	maxRenderedBytes   = 16 << 20         // cap the rendered manifest stream fed to the K8s rules
	maxHelmStderrBytes = 8 << 10          // enough for helm's one-line refusal, bounded like every other read
)

// scanHelmChart renders a Helm chart and runs the Kubernetes rules over the output – the raw templates
// carry Go-template directives and are not valid YAML, so rendering is how comprehensive scanners
// evaluate Helm. `helm template` on an UNTRUSTED chart must not run unprotected on the host: Helm's
// Sprig engine exposes getHostByName (live DNS), an SSRF / blind-exfil vector. So this mirrors the
// maven/gradle resolvers exactly – a caller-supplied ToolRunner confines the exec (the API path, with
// egress denied), or an explicit trusted-local direct exec is used (the CLI). With NEITHER set, Helm
// rendering is skipped. Always argv (never a shell), fixed release name, no chart hooks; best-effort.
func scanHelmChart(ctx context.Context, runner ports.ToolRunner, direct bool, helmBin, chartDir, relDir string) k8sScanResult {
	if helmBin == "" {
		return k8sScanResult{}
	}
	// A chart that will not render is NOT a chart with no findings, and the difference has to reach the
	// caller. On one live repository 112 of 126 charts refused to render and the scan reported nothing about
	// it, so every one of those apps read as clean.
	failed := func(reason string) k8sScanResult {
		return k8sScanResult{chartRenderFailures: 1, chartRenderReasons: []string{reason}}
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
			return failed(helmFailureReason(res.Stderr))
		}
		rendered = res.Stdout
	case direct:
		// Trusted-local (CLI) direct exec, matching the CLI's maven/gradle posture. Output is capped
		// DURING capture so a chart rendering gigabytes cannot OOM the process before a post-hoc cap.
		if _, err := exec.LookPath(helmBin); err != nil {
			return k8sScanResult{} // helm is absent: not a per-chart failure, the whole feature is off
		}
		cctx, cancel := context.WithTimeout(ctx, helmRenderTimeout)
		defer cancel()
		cmd := exec.CommandContext(cctx, helmBin, args...)
		cw := &cappedBuffer{max: maxRenderedBytes}
		var stderr cappedBuffer
		stderr.max = maxHelmStderrBytes
		cmd.Stdout, cmd.Stderr = cw, &stderr
		if err := cmd.Run(); err != nil {
			return failed(helmFailureReason(stderr.buf.Bytes()))
		}
		rendered = cw.buf.Bytes()
	default:
		return k8sScanResult{} // Helm rendering not enabled (no sandbox runner, not trusted-local)
	}
	if len(rendered) > maxRenderedBytes {
		rendered = rendered[:maxRenderedBytes]
	}
	return scanKubernetes(filepath.ToSlash(filepath.Join(relDir, "Chart.yaml")), rendered)
}

// helmFailureReason reduces helm's stderr to the short, actionable sentence a reader can act on. Helm states
// its refusal on one line prefixed "Error:"; anything else is summarised rather than passed through, so an
// untrusted chart cannot write arbitrary text into a finding.
func helmFailureReason(stderr []byte) string {
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		rest, found := strings.CutPrefix(line, "Error:")
		if !found {
			continue
		}
		rest = strings.TrimSpace(rest)
		switch {
		case strings.Contains(rest, "missing in charts/"):
			return "a declared chart dependency is not vendored (run `helm dependency build`)"
		case strings.Contains(rest, "chart.metadata.name is required"):
			return "Chart.yaml declares no name"
		case strings.Contains(rest, "values"):
			return "the chart needs values the scan cannot supply"
		}
		return clip(rest)
	}
	return "helm template refused to render the chart"
}

// cappedBuffer accumulates at most max bytes and silently discards the rest, so a chart that renders
// gigabytes bounds memory instead of OOMing the process. Write always reports a full write so the child
// process is not killed by a short-write error; the timeout still bounds a runaway render.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool // set when output overflowed the cap and was discarded
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

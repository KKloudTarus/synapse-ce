package misconfig

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	helmRenderTimeout     = 45 * time.Second // bound a single `helm template` render
	maxRenderedBytes      = 16 << 20         // cap the rendered manifest stream fed to the K8s rules
	maxHelmStderrBytes    = 8 << 10          // enough for helm's one-line refusal, bounded like every other read
	maxChartMetadataBytes = 1 << 20          // a Chart.yaml is tiny; cap the read defensively
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
	// A LIBRARY chart ships template helpers for other charts and declares no resources of its own, so
	// `helm template` refusing it is correct and there is nothing to evaluate. Counting it as a chart the scan
	// could not cover reported a coverage gap that does not exist.
	if isHelmLibraryChart(chartDir) {
		return k8sScanResult{}
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
	return scanKubernetesFrom(filepath.ToSlash(filepath.Join(relDir, "Chart.yaml")), rendered,
		helmOriginIndex(chartDir, relDir, rendered))
}

// helmOriginIndex maps each rendered document back to the template that produced it.
//
// Without it every finding from a chart carries the chart's Chart.yaml and a line number into the rendered
// stream, which is the one path a reader cannot open to fix anything: a chart with 40 templates reports 40
// templates' findings at one file. `helm template` already states the answer, printing
// `# Source: <chart>/templates/<file>.yaml` above each document, so this reads it back.
//
// A path is only used when a reader can open it, so a Source line this does not understand leaves the finding
// on the aggregator path rather than moving it to a path that opens nothing. A subchart vendored as a package
// resolves to the PACKAGE, because nothing inside a tarball has a path of its own; that still names the
// subchart to change, which the umbrella chart's Chart.yaml does not.
//
// The line is resolved inside the named file too. A position in the render stream is a line the source
// template usually does not have (a 718-line template reported at line 16628), so the document's own `kind:`
// is located in the template when it appears exactly once there, and line 1 stands otherwise.
func helmOriginIndex(chartDir, relDir string, rendered []byte) k8sOrigin {
	type origin struct {
		path string
		line int
	}
	index := map[string]origin{}
	aliases := helmDependencyAliases(chartDir)
	kindLines := map[string]map[string]int{} // source path -> kind -> unique line (0 when ambiguous)
	for _, chunk := range bytes.Split(rendered, []byte("\n---")) {
		source := helmSourceComment(chunk)
		if source == "" {
			continue
		}
		// The first segment of a Source path is the chart NAME from Chart.yaml, which need not match the
		// directory it was read from, so it is replaced by the directory rather than trusted.
		parts := strings.SplitN(source, "/", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		within, packaged := helmSourceOnDisk(chartDir, helmResolveAlias(parts[1], aliases))
		if within == "" {
			continue
		}
		rel := filepath.ToSlash(filepath.Join(relDir, within))
		if !packaged {
			if _, seen := kindLines[within]; !seen {
				kindLines[within] = helmTemplateKindLines(filepath.Join(chartDir, filepath.FromSlash(within)))
			}
		}
		dec := yaml.NewDecoder(bytes.NewReader(chunk))
		for {
			var doc k8sDoc
			if err := dec.Decode(&doc); err != nil {
				break
			}
			key := k8sDocKey(doc)
			if key == "" {
				continue
			}
			if _, taken := index[key]; taken {
				continue // first declaration wins; a duplicate key is ambiguous, not better
			}
			line := 0
			if !packaged {
				line = kindLines[within][doc.Kind]
			}
			index[key] = origin{path: rel, line: line}
		}
	}
	if len(index) == 0 {
		return nil
	}
	return func(doc k8sDoc) (string, int) {
		o := index[k8sDocKey(doc)]
		return o.path, o.line
	}
}

// helmSourceOnDisk turns a chart-relative Source path into one a reader can open. It returns the path and
// whether it is a PACKAGED subchart, whose templates have no path of their own.
func helmSourceOnDisk(chartDir, within string) (string, bool) {
	if _, err := os.Stat(filepath.Join(chartDir, filepath.FromSlash(within))); err == nil {
		return within, false
	}
	// A dependency vendored as `charts/<name>-<version>.tgz` renders as `charts/<name>/templates/...`, so the
	// directory the Source names does not exist. The package does, and it is what a reader opens.
	if !strings.HasPrefix(within, "charts/") {
		return "", false
	}
	name, _, found := strings.Cut(strings.TrimPrefix(within, "charts/"), "/")
	if !found || name == "" || strings.ContainsAny(name, `/\*?[`) {
		return "", false
	}
	matches, err := filepath.Glob(filepath.Join(chartDir, "charts", name+"-*.tgz"))
	if err != nil || len(matches) != 1 {
		return "", false // zero is nothing to name; more than one is a guess
	}
	return "charts/" + filepath.Base(matches[0]), true
}

// helmTemplateKindLines locates each Kubernetes kind a template declares, keeping only the kinds it declares
// exactly once. A template that emits two ClusterRoles cannot say which one a finding belongs to, so it
// reports none and the finding lands on line 1 of the right file.
func helmTemplateKindLines(path string) map[string]int {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || int64(len(data)) > maxFileBytes {
		return nil
	}
	out := map[string]int{}
	seen := map[string]int{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(stripYAMLComment(strings.TrimRight(raw, "\r")))
		rest, ok := strings.CutPrefix(line, "kind:")
		if !ok {
			continue
		}
		kind := strings.Trim(strings.TrimSpace(rest), `"'`)
		// A templated kind names nothing until it is rendered.
		if kind == "" || strings.ContainsAny(kind, "{}$") {
			continue
		}
		seen[kind]++
		if seen[kind] == 1 {
			out[kind] = i + 1
		} else {
			out[kind] = 0
		}
	}
	return out
}

// helmDependencyAliases maps a subchart's alias to the directory name it was vendored under. A dependency
// declared with an `alias` renders under the alias, so the Source path names a `charts/<alias>` directory that
// does not exist: datadog vendors datadog-operator and renders it as `charts/operator`.
func helmDependencyAliases(chartDir string) map[string]string {
	out := map[string]string{}
	// apiVersion v2 declares dependencies in Chart.yaml; v1 declares them in requirements.yaml.
	for _, name := range []string{"Chart.yaml", "requirements.yaml", "requirements.yml"} {
		data, err := os.ReadFile(filepath.Join(chartDir, name))
		if err != nil || len(data) == 0 || int64(len(data)) > maxChartMetadataBytes {
			continue
		}
		var meta struct {
			Dependencies []struct {
				Name  string `yaml:"name"`
				Alias string `yaml:"alias"`
			} `yaml:"dependencies"`
		}
		if yaml.Unmarshal(data, &meta) != nil {
			continue
		}
		for _, dep := range meta.Dependencies {
			alias := strings.TrimSpace(dep.Alias)
			depName := strings.TrimSpace(dep.Name)
			if alias == "" || depName == "" || strings.ContainsAny(alias+depName, "/\\") {
				continue
			}
			if _, taken := out[alias]; !taken {
				out[alias] = depName
			}
		}
	}
	return out
}

// helmResolveAlias rewrites a `charts/<alias>/...` prefix to the directory the subchart was vendored under.
func helmResolveAlias(path string, aliases map[string]string) string {
	if len(aliases) == 0 || !strings.HasPrefix(path, "charts/") {
		return path
	}
	rest := strings.TrimPrefix(path, "charts/")
	segment, tail, found := strings.Cut(rest, "/")
	if !found {
		return path
	}
	name, ok := aliases[segment]
	if !ok {
		return path
	}
	return "charts/" + name + "/" + tail
}

// helmSourceComment returns the template path one rendered document names, or "" when it names none.
func helmSourceComment(chunk []byte) string {
	const marker = "# Source:"
	for _, line := range strings.Split(string(chunk), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, marker) {
			// Only the leading comment block can carry it; a document's body cannot. A bare document
			// separator is part of that block, since the stream's first document begins with one.
			if trimmed != "" && trimmed != "---" && trimmed != "..." && !strings.HasPrefix(trimmed, "#") {
				return ""
			}
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(trimmed, marker))
		// A rendered path is chart-relative. Refuse anything that could climb out of the chart directory.
		if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return ""
		}
		return filepath.ToSlash(path)
	}
	return ""
}

// isHelmLibraryChart reports whether the chart declares `type: library`. Such a chart is not installable by
// design, so its render refusal is expected rather than a gap in coverage. An unreadable or unparsable
// Chart.yaml is treated as an ordinary chart, so a real gap is never hidden by a failed read.
func isHelmLibraryChart(chartDir string) bool {
	data, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil || len(data) > maxChartMetadataBytes {
		return false
	}
	var meta struct {
		Type string `yaml:"type"`
	}
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(meta.Type), "library")
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

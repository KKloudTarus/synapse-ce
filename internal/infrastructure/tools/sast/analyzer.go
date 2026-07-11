// Package sast is a deterministic, pure-Go pattern scanner: it walks a source tree
// and flags high-signal weaknesses (weak crypto, hardcoded secrets/keys, insecure TLS config) by
// regex, emitting one finding per (file, line, rule). It NEVER executes anything and reads bounded
// (skips vendored/binary/oversized files, follows no symlinks), mirroring the go-enry library
// adapter (light pure-Go tools as in-process libraries).
package sast

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFileBytes = 1 << 20 // skip files larger than 1 MiB (generated/data, not hand-written source)
	maxLineBytes = 4096    // skip minified/blob lines
	maxFindings  = 500     // cap total hits so a hostile/huge tree can't flood the report
)

// skipDirs are heavy vendored/build trees never worth scanning for first-party weaknesses.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true, ".tox": true,
}

var skipExts = map[string]bool{
	".log": true, ".map": true, ".min.js": true,
}

// Analyzer is the pure-Go pattern-SAST adapter.
type Analyzer struct{ rules []rule }

type sourceFile struct {
	Path  string
	Rel   string
	Lines []string
}

// New returns an analyzer with the built-in tier-1 rule set.
func New() *Analyzer { return &Analyzer{rules: builtinRules()} }

var _ ports.SASTAnalyzer = (*Analyzer)(nil)

// Name identifies the analyzer (recorded as the finding's source/provenance).
func (a *Analyzer) Name() string { return "synapse-pattern-sast" }

// AnalyzeSource walks root and returns deterministic SAST findings, oldest-path first. It honors ctx
// cancellation and never aborts the whole scan on a single unreadable file.
func (a *Analyzer) AnalyzeSource(ctx context.Context, root string) ([]ports.SASTRawFinding, error) {
	if root == "" {
		return nil, nil
	}
	var files []sourceFile
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; don't abort the engagement's scan
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // never follow symlinks/devices
			return nil
		}
		if skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		lines := readSourceLines(path)
		if len(lines) == 0 {
			return nil
		}
		files = append(files, sourceFile{Path: path, Rel: rel, Lines: lines})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr // only ctx cancellation reaches here (fs.SkipDir is swallowed)
	}

	project := buildProjectContext(files)
	var out []ports.SASTRawFinding
	for _, file := range files {
		for _, h := range a.scanLines(file.Rel, file.Lines, project) {
			if len(out) >= maxFindings {
				break
			}
			out = append(out, h)
		}
		if len(out) >= maxFindings {
			break
		}
	}
	return out, nil
}

// readSourceLines reads one file (bounded, binary-skipping) and returns source lines.
func readSourceLines(path string) []string {
	info, err := os.Lstat(path)
	if err != nil || info.Size() == 0 || info.Size() > maxFileBytes {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- path is from WalkDir under the acquired workspace root, verified a regular (non-symlink) file via d.Type().IsRegular() + os.Lstat
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Binary sniff: a NUL byte in the first chunk ⇒ not source, skip.
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	// A mid-file read error, or an over-long line (only possible above the file-size cap, so not
	// reachable here), stops the scanner; return the hits gathered so far rather than failing the scan.
	_ = sc.Err()
	return lines
}

// scanLines applies rules to an already-read source file.
func (a *Analyzer) scanLines(rel string, lines []string, project projectContext) []ports.SASTRawFinding {
	var hits []ports.SASTRawFinding
	ext := strings.ToLower(filepath.Ext(rel))
	for i, text := range lines {
		line := i + 1
		if len(text) > maxLineBytes {
			continue // minified/blob line
		}
		for ri := range a.rules {
			r := &a.rules[ri]
			if !r.appliesTo(ext) {
				continue // language-gated rule on a non-matching file type
			}
			if r.re.MatchString(text) && !r.skip(text) {
				h := ports.SASTRawFinding{
					File: rel, Line: line, RuleID: r.id, CWE: r.cwe,
					Severity: r.severity, Title: r.title, Description: r.desc,
				}
				enrichAppSecContext(&h, lines, line, rel, project)
				hits = append(hits, h)
			}
		}
	}
	hits = append(hits, a.contextualFindings(rel, lines, project)...)
	return dedupeFindings(hits)
}

func (a *Analyzer) contextualFindings(rel string, lines []string, project projectContext) []ports.SASTRawFinding {
	var hits []ports.SASTRawFinding
	for i := 0; i < len(lines); i++ {
		line := i + 1
		text := lines[i]
		if len(text) > maxLineBytes || commentOnlyLine(text) {
			continue
		}
		if !contextualStartLine(strings.ToLower(text)) {
			continue
		}
		block := boundedStatementBlock(lines, i, 18)
		lowerBlock := strings.ToLower(block)
		switch {
		case looksLikePrismaObjectByID(lowerBlock):
			if h, ok := a.findingFromRule(rel, line, "possible-idor-prisma-id-only", lines, project); ok {
				calibrateContextBlockFinding(&h, block, line)
				hits = append(hits, h)
			}
		case looksLikeMassAssignment(lowerBlock):
			if h, ok := a.findingFromRule(rel, line, "mass-assignment-request-body", lines, project); ok {
				calibrateContextBlockFinding(&h, block, line)
				hits = append(hits, h)
			}
		}
	}
	return dedupeFindings(hits)
}

func contextualStartLine(line string) bool {
	return strings.Contains(line, "prisma.") ||
		strings.Contains(line, ".create(") ||
		strings.Contains(line, ".update(") ||
		strings.Contains(line, "new ")
}

func calibrateContextBlockFinding(h *ports.SASTRawFinding, block string, line int) {
	lower := strings.ToLower(block)
	source, sourceEvidence := sourceFromContextBlock(lower, line)
	if source != "" {
		h.Source = source
		h.SourceEvidence = sourceEvidence
	}
	if h.Source == "unknown" {
		return
	}
	if h.DataFlowConfidence == "context-only" || h.DataFlowConfidence == "missing" {
		h.DataFlowEvidence = "variable-derived: request/source cue and sink fields appear in the same bounded statement block"
		h.DataFlowConfidence = "variable-derived"
		h.DataFlow = dataflowSummary(h.Source, h.Sink, h.Route)
	}
	ctx := ruleContext{
		RuleID:         h.RuleID,
		CWE:            h.CWE,
		Route:          h.Route,
		Source:         h.Source,
		Counter:        h.CounterEvidence,
		FlowConfidence: h.DataFlowConfidence,
		Rel:            h.File,
		Lines:          strings.Split(block, "\n"),
	}
	if reason := staticFalsePositiveReason(ctx); reason != "" {
		h.CounterEvidence = "static false-positive counter-pattern: " + reason
		ctx.Counter = h.CounterEvidence
	}
	h.ValidationRubric = validationRubric(h.Route, h.Source, h.Sink, h.AuthScope, h.Exposure, h.CounterEvidence, h.DataFlowConfidence)
	h.ValidationDisposition = validationDisposition(ctx)
	if h.ValidationDisposition == "false-positive-static" {
		h.Exploitability = "not exploitable in static triage: " + strings.TrimPrefix(h.CounterEvidence, "static false-positive counter-pattern: ")
		h.AttackPath = "No attack path: deterministic framework/context counter-pattern closes this as a static false positive."
		h.SeverityRationale = "Closed as a static false positive by deterministic counter-pattern evidence; do not promote unless a human reopens it with new evidence."
		h.Confidence = "low"
	} else {
		h.Exploitability = exploitabilitySummary(h.AuthScope, h.Route, h.Source, h.Sink, h.DataFlowConfidence)
		h.SeverityRationale = severityRationale(h.CWE, string(h.Severity), h.AuthScope, h.Source, h.Route, h.CounterEvidence, h.DataFlowConfidence)
		h.Confidence = confidenceSummary(h.Route, h.Source, h.Sink, h.AuthScope, h.CounterEvidence, h.DataFlowConfidence)
	}
}

func sourceFromContextBlock(lower string, line int) (source, evidence string) {
	switch {
	case strings.Contains(lower, "req.params") || strings.Contains(lower, "params[") || strings.Contains(lower, "c.param"):
		return "HTTP route parameter", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP route parameter cue"
	case strings.Contains(lower, "req.query") || strings.Contains(lower, "request.args"):
		return "HTTP query parameter", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP query parameter cue"
	case strings.Contains(lower, "req.body") || strings.Contains(lower, "request.body") || strings.Contains(lower, "request.data") || strings.Contains(lower, "$_post"):
		return "HTTP request body", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP request body cue"
	default:
		return "", ""
	}
}

func (a *Analyzer) findingFromRule(rel string, line int, ruleID string, lines []string, project projectContext) (ports.SASTRawFinding, bool) {
	ext := strings.ToLower(filepath.Ext(rel))
	for ri := range a.rules {
		r := &a.rules[ri]
		if r.id != ruleID {
			continue
		}
		if !r.appliesTo(ext) {
			return ports.SASTRawFinding{}, false // honor the language gate on the contextual path too
		}
		h := ports.SASTRawFinding{
			File: rel, Line: line, RuleID: r.id, CWE: r.cwe,
			Severity: r.severity, Title: r.title, Description: r.desc,
		}
		enrichAppSecContext(&h, lines, line, rel, project)
		return h, true
	}
	return ports.SASTRawFinding{}, false
}

func boundedStatementBlock(lines []string, start, maxLines int) string {
	end := min(len(lines), start+maxLines)
	var out []string
	depth := 0
	started := false
	for i := start; i < end; i++ {
		line := lines[i]
		out = append(out, line)
		for _, ch := range line {
			switch ch {
			case '(', '{', '[':
				depth++
				started = true
			case ')', '}', ']':
				if depth > 0 {
					depth--
				}
			}
		}
		trimmed := strings.TrimSpace(line)
		if started && depth == 0 && (strings.HasSuffix(trimmed, ")") || strings.HasSuffix(trimmed, ");") || strings.HasSuffix(trimmed, "})")) {
			break
		}
	}
	return strings.Join(out, "\n")
}

func looksLikePrismaObjectByID(block string) bool {
	if !(strings.Contains(block, "prisma.") &&
		(strings.Contains(block, ".findunique(") || strings.Contains(block, ".update(") || strings.Contains(block, ".delete("))) {
		return false
	}
	if !strings.Contains(block, "where") || !strings.Contains(block, "id") {
		return false
	}
	return strings.Contains(block, "req.params") || strings.Contains(block, "req.query") ||
		strings.Contains(block, "request.args") || strings.Contains(block, "params[") ||
		strings.Contains(block, "c.param") || strings.Contains(block, "formvalue")
}

func looksLikeMassAssignment(block string) bool {
	if !(strings.Contains(block, ".create(") || strings.Contains(block, ".update(") || strings.Contains(block, "new ")) {
		return false
	}
	if !(strings.Contains(block, "data") || strings.Contains(block, "attributes") || strings.Contains(block, "create")) {
		return false
	}
	return strings.Contains(block, "req.body") || strings.Contains(block, "request.body") ||
		strings.Contains(block, "request.data") || strings.Contains(block, "$_post") ||
		strings.Contains(block, "params")
}

func dedupeFindings(in []ports.SASTRawFinding) []ports.SASTRawFinding {
	seen := map[string]bool{}
	out := make([]ports.SASTRawFinding, 0, len(in))
	for _, h := range in {
		key := h.File + "\x00" + h.RuleID + "\x00" + h.CWE + "\x00" + h.Route + "\x00" + h.Sink
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

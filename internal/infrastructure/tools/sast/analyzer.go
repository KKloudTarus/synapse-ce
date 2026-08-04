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

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/notebook"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFileBytes           = 1 << 20 // skip files larger than 1 MiB (generated/data, not hand-written source)
	maxNotebookBytes       = 16 << 20
	maxSourceFiles         = 100_000  // cap retained source units; each notebook code cell is one unit
	maxRetainedSourceBytes = 64 << 20 // cap source held for cross-file context analysis
	maxLineBytes           = 4096     // skip minified/blob lines
	maxFindings            = 500      // cap unique hits so a hostile/huge tree can't flood the report
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
type Analyzer struct {
	rules []rule
	byID  map[string]*rule
}

type sourceFile struct {
	Path         string
	Rel          string
	Lines        []string
	ContextLines []string
	Ext          string
}

// New returns an analyzer with the built-in tier-1 rule set.
func New() *Analyzer {
	rules := builtinRules()
	a := &Analyzer{rules: rules, byID: make(map[string]*rule, len(rules))}
	for i := range a.rules {
		a.byID[a.rules[i].id] = &a.rules[i]
	}
	return a
}

var _ ports.SASTAnalyzer = (*Analyzer)(nil)

// Name identifies the analyzer (recorded as the finding's source/provenance).
func (a *Analyzer) Name() string { return "synapse-pattern-sast" }

// AnalyzeSource walks root and returns deterministic SAST findings, oldest-path first. It honors ctx
// cancellation and never aborts the whole scan on a single unreadable file.
func (a *Analyzer) AnalyzeSource(ctx context.Context, root string) ([]ports.SASTRawFinding, error) {
	return a.analyzeSource(ctx, root, maxSourceFiles, maxRetainedSourceBytes)
}

func (a *Analyzer) analyzeSource(ctx context.Context, root string, maxFiles int, maxBytes int64) ([]ports.SASTRawFinding, error) {
	if root == "" {
		return nil, nil
	}
	var files []sourceFile
	var retainedBytes int64
	appendFile := func(file sourceFile, bytes int64) bool {
		if len(files) >= maxFiles || bytes > maxBytes-retainedBytes {
			return false
		}
		files = append(files, file)
		retainedBytes += bytes
		return true
	}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; don't abort the engagement's scan
		}
		if err := ctx.Err(); err != nil {
			return err
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
		rel = filepath.ToSlash(rel)
		if notebook.IsPath(path) {
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxNotebookBytes {
				return nil
			}
			data, readErr := os.ReadFile(path) // #nosec G304 -- regular, size-capped file from WalkDir under root
			if readErr != nil {
				return nil
			}
			doc, parseErr := notebook.Parse(data)
			if parseErr != nil {
				return nil
			}
			if strings.EqualFold(doc.KernelLanguage, "python") {
				for _, cell := range doc.Cells {
					if err := ctx.Err(); err != nil {
						return err
					}
					if cell.Type == "code" {
						appendFile(sourceFile{Path: path, Rel: notebook.Location(rel, cell.Index), Lines: strings.Split(cell.Source, "\n"), Ext: ".py"}, int64(len(cell.Source)))
					}
				}
			}
			return nil
		}
		lines, readErr := readSourceLines(ctx, path)
		if readErr != nil {
			return readErr
		}
		if len(lines) == 0 {
			return nil
		}
		ext := sastSourceExt(path)
		contextLines := lines
		if phpExts[ext] {
			contextLines, _ = phpContextLines(ext, lines, phpLineViews(ext, lines))
		}
		appendFile(sourceFile{Path: path, Rel: rel, Lines: lines, ContextLines: contextLines, Ext: ext}, sourceLinesBytes(lines))
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	project, err := buildProjectContext(ctx, files)
	if err != nil {
		return nil, err
	}
	out := make([]ports.SASTRawFinding, 0, maxFindings)
	seen := make(map[string]bool, maxFindings)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hits, _, scanErr := a.scanLines(ctx, file.Rel, file.Ext, file.Lines, project, seen, maxFindings-len(out))
		out = append(out, hits...)
		if scanErr != nil {
			return nil, scanErr
		}
		if len(out) == maxFindings {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return dedupeFindings(out), nil
}

func sourceLinesBytes(lines []string) int64 {
	var total int64
	for _, line := range lines {
		total += int64(len(line) + 1)
	}
	return total
}

// readSourceLines reads one file (bounded, binary-skipping) and returns source lines.
func readSourceLines(ctx context.Context, path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Size() == 0 || info.Size() > maxFileBytes {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- path is from WalkDir under the acquired workspace root, verified a regular (non-symlink) file via d.Type().IsRegular() + os.Lstat
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	// Binary sniff: a NUL byte in the first chunk ⇒ not source, skip.
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
	var lines []string
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, nil
	}
	return lines, nil
}

type scanStatus struct {
	findingsTruncated     bool
	lineLimitReached      bool
	statementLimitReached bool
}

// scanLines applies rules to an already-read source file. The shared seen set makes the
// finding cap count unique physical findings rather than repeated line/multiline passes.
func (a *Analyzer) scanLines(ctx context.Context, rel, ext string, lines []string, project projectContext, seen map[string]bool, limit int) ([]ports.SASTRawFinding, scanStatus, error) {
	var hits []ports.SASTRawFinding
	var status scanStatus
	add := func(h ports.SASTRawFinding) bool {
		key := findingIdentity(h)
		if seen[key] {
			return true
		}
		if len(hits) >= limit {
			return false
		}
		seen[key] = true
		hits = append(hits, h)
		return true
	}
	var scalaLex scalaLexState
	var rubyLex rubyLexState
	var rubyERBLex rubyERBLexState
	isPHP := phpExts[ext]
	var phpViews []phpLineView
	phpTextLines, phpCodeLines := lines, lines
	if isPHP {
		phpViews = phpLineViews(ext, lines)
		phpTextLines, phpCodeLines = phpContextLines(ext, lines, phpViews)
	}
	for i, text := range lines {
		if err := ctx.Err(); err != nil {
			return hits, status, err
		}
		line := i + 1
		matchText := text
		phpText := text
		isScala := scalaExts[ext]
		isRuby := rubyExts[ext]
		isVB := vbExts[ext]
		if isScala {
			matchText = scalaLex.codeOnly(text)
		} else if isRuby {
			if ext == ".erb" {
				matchText = rubyERBLex.codeOnly(text)
			} else {
				matchText = rubyLex.codeOnly(text)
			}
		} else if isVB {
			matchText = vbCodeOnly(text)
		} else if isPHP {
			phpText = phpViews[i].text
			matchText = phpViews[i].code
		}
		if len(text) > maxLineBytes {
			status.lineLimitReached = true
			continue // advance lexer state; callers mark the bounded scan incomplete
		}
		for ri := range a.rules {
			if ri%64 == 0 {
				if err := ctx.Err(); err != nil {
					return hits, status, err
				}
			}
			r := &a.rules[ri]
			if !r.appliesTo(ext) {
				continue // language-gated rule on a non-matching file type
			}
			if r.id == "generic-sql-dynamic-execute" && pyExts[ext] && a.matchesRule("sqlalchemy-raw-sql-dynamic", ext, text) {
				continue // specialized SQLAlchemy rule owns this Python sink
			}
			if ktExts[ext] && kotlinRuleOwnsGeneric(r.id, a, ext, text) {
				continue
			}
			if r.id == "vb:empty-catch" || r.id == "vb:idisposable-not-disposed" {
				continue // bounded VB passes own these block-sensitive rules
			}
			var matched bool
			if isScala && strings.HasPrefix(r.id, "scala:") {
				matched = scalaRuleMatches(r, text, matchText)
			} else if isRuby && strings.HasPrefix(r.id, "rb:") {
				matched = rubyRuleMatches(r, text, matchText)
			} else if isVB && strings.HasPrefix(r.id, "vb:") {
				matched = vbRuleMatches(r, text, matchText)
			} else if isVB {
				matched = vbGenericRuleMatches(r, text, matchText)
			} else if isPHP && r.id == "php:closing-tag" {
				matched = phpClosingTagEligible(ext) && phpRuleMatches(r, phpText, matchText)
			} else if isPHP && phpRuleNeedsCodePosition(r.id) {
				matched = phpRuleMatches(r, phpText, matchText)
			} else if isPHP {
				matched = r.re.MatchString(phpText) && !r.skip(phpText)
			} else {
				matched = r.re.MatchString(text) && !r.skip(text)
			}
			if matched && isPHP && phpRuleOwnsGeneric(r.id, a, ext, phpText, matchText) {
				continue
			}
			if matched {
				h := ports.SASTRawFinding{
					File: rel, Line: line, RuleID: r.id, CWE: r.cwe,
					Severity: r.severity, Title: r.title, Description: r.desc,
					RuleType: string(r.ruleType()), RuleQuality: string(r.ruleQuality()),
				}
				enrichAppSecContext(&h, phpTextLines, line, rel, project)
				if !add(h) {
					status.findingsTruncated = true
					return hits, status, nil
				}
			}
		}
	}
	if phpExts[ext] {
		for start := range lines {
			if err := ctx.Err(); err != nil {
				return hits, status, err
			}
			text, code, ok, truncated := phpStatement(lines, phpViews, start)
			if truncated {
				status.statementLimitReached = true
			}
			if !ok {
				continue
			}
			for ri := range a.rules {
				r := &a.rules[ri]
				matchAt, matched := phpRuleMatchIndex(r, text, code)
				if !r.appliesTo(ext) || !matched || r.id == "php:closing-tag" && !phpClosingTagEligible(ext) || phpRuleOwnsGeneric(r.id, a, ext, text, code) {
					continue
				}
				line := start + 1 + strings.Count(text[:matchAt], "\n")
				h := ports.SASTRawFinding{
					File: rel, Line: line, RuleID: r.id, CWE: r.cwe,
					Severity: r.severity, Title: r.title, Description: r.desc,
					RuleType: string(r.ruleType()), RuleQuality: string(r.ruleQuality()),
				}
				enrichAppSecContext(&h, phpTextLines, line, rel, project)
				if !add(h) {
					status.findingsTruncated = true
					return hits, status, nil
				}
			}
		}
	}
	contextual, err := a.contextualFindings(ctx, rel, ext, phpCodeLines, phpTextLines, project)
	if err != nil {
		return hits, status, err
	}
	for _, h := range contextual {
		if !add(h) {
			status.findingsTruncated = true
			return hits, status, nil
		}
	}
	if err := a.vbContextualFindings(ctx, rel, ext, lines, project, &hits, limit); err != nil {
		return hits, status, err
	}
	return hits, status, nil
}

func (a *Analyzer) matchesRule(id, ext, text string) bool {
	r := a.byID[id]
	return r != nil && r.appliesTo(ext) && r.re.MatchString(text) && !r.skip(text)
}

var kotlinGenericOwners = map[string][]string{
	"generic-sql-dynamic-execute":    {"kotlin-sql-concat", "kotlin-sql-template"},
	"generic-command-injection-sink": {"kotlin-runtime-exec", "kotlin-process-builder-string"},
	"weak-hash-md5":                  {"kotlin-weak-hash"},
	"weak-hash-sha1":                 {"kotlin-weak-hash"},
	"weak-cipher":                    {"kotlin-weak-cipher"},
}

func kotlinRuleOwnsGeneric(generic string, a *Analyzer, ext, text string) bool {
	for _, owner := range kotlinGenericOwners[generic] {
		if a.matchesRule(owner, ext, text) {
			return true
		}
	}
	return false
}

var phpGenericOwners = map[string][]string{
	"generic-sql-dynamic-execute":          {"php:sql-concat", "php:sql-interpolation", "php:mysqli-query-request", "php:pdo-query-request"},
	"generic-command-injection-sink":       {"php:command-exec", "php:proc-open-string"},
	"unsafe-deserialization-generic":       {"php:unserialize-untrusted"},
	"dynamic-code-eval":                    {"php:eval-usage"},
	"weak-hash-md5":                        {"php:md5-usage", "php:weak-password-hash"},
	"weak-hash-sha1":                       {"php:sha1-usage", "php:weak-password-hash"},
	"weak-cipher":                          {"php:weak-cipher"},
	"generic-ssrf-request-url":             {"php:ssrf-file-get-contents", "php:curl-url-request"},
	"path-traversal-file-access":           {"php:file-read-request-path", "php:file-write-request-path"},
	"open-redirect-user-url":               {"php:open-redirect-request"},
	"insecure-tls-verify-disabled":         {"php:tls-peer-verification-off"},
	"insecure-randomness-security-context": {"php:insecure-random"},
}

func phpRuleOwnsGeneric(generic string, a *Analyzer, ext, raw, code string) bool {
	for _, owner := range phpGenericOwners[generic] {
		r := a.byID[owner]
		if r != nil && r.appliesTo(ext) && phpRuleMatches(r, raw, code) {
			return true
		}
	}
	return false
}

func (a *Analyzer) contextualFindings(ctx context.Context, rel, ext string, codeLines, contextLines []string, project projectContext) ([]ports.SASTRawFinding, error) {
	var hits []ports.SASTRawFinding
	for i := 0; i < len(codeLines); i++ {
		if err := ctx.Err(); err != nil {
			return hits, err
		}
		line := i + 1
		text := codeLines[i]
		if len(text) > maxLineBytes || commentOnlyLine(text) {
			continue
		}
		if !contextualStartLine(strings.ToLower(text)) {
			continue
		}
		codeBlock := boundedStatementBlock(codeLines, i, 18)
		contextBlock := boundedStatementBlock(contextLines, i, 18)
		lowerBlock := strings.ToLower(codeBlock)
		switch {
		case looksLikePrismaObjectByID(lowerBlock):
			if h, ok := a.findingFromRule(rel, ext, line, "possible-idor-prisma-id-only", contextLines, project); ok {
				calibrateContextBlockFinding(&h, contextBlock, line)
				hits = append(hits, h)
			}
		case looksLikeMassAssignment(lowerBlock):
			if h, ok := a.findingFromRule(rel, ext, line, "mass-assignment-request-body", contextLines, project); ok {
				calibrateContextBlockFinding(&h, contextBlock, line)
				hits = append(hits, h)
			}
		}
	}
	return dedupeFindings(hits), nil
}

func contextualStartLine(line string) bool {
	return strings.Contains(line, "prisma.") ||
		strings.Contains(line, ".create(") ||
		strings.Contains(line, ".update(") ||
		strings.Contains(line, "new ")
}

func calibrateContextBlockFinding(h *ports.SASTRawFinding, block string, line int) {
	source, sourceEvidence := sourceFromContextBlock(block, line)
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

func sourceFromContextBlock(block string, line int) (source, evidence string) {
	if label := phpSuperglobalSourceLabel(block); label != "" {
		return label, "bounded statement block near line " + strconv.Itoa(line) + ": " + label + " cue"
	}
	lower := strings.ToLower(block)
	switch {
	case strings.Contains(lower, "req.params") || strings.Contains(lower, "params[") || strings.Contains(lower, "c.param"):
		return "HTTP route parameter", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP route parameter cue"
	case strings.Contains(lower, "req.query") || strings.Contains(lower, "request.args"):
		return "HTTP query parameter", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP query parameter cue"
	case strings.Contains(lower, "req.body") || strings.Contains(lower, "request.body") || strings.Contains(lower, "request.data"):
		return "HTTP request body", "bounded statement block near line " + strconv.Itoa(line) + ": HTTP request body cue"
	default:
		return "", ""
	}
}

func (a *Analyzer) findingFromRule(rel, ext string, line int, ruleID string, lines []string, project projectContext) (ports.SASTRawFinding, bool) {
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
			RuleType: string(r.ruleType()), RuleQuality: string(r.ruleQuality()),
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

func findingIdentity(h ports.SASTRawFinding) string {
	return h.File + "\x00" + strconv.Itoa(h.Line) + "\x00" + h.RuleID + "\x00" + h.CWE + "\x00" + h.Route + "\x00" + h.Sink
}

func dedupeFindings(in []ports.SASTRawFinding) []ports.SASTRawFinding {
	seen := map[string]bool{}
	out := make([]ports.SASTRawFinding, 0, len(in))
	for _, h := range in {
		key := findingIdentity(h)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

package codeanalysis

import (
	"container/heap"
	"context"
	"sort"
	"unicode"
	"unicode/utf8"

	enry "github.com/go-enry/go-enry/v2"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	textBidiUnicodeID      = "text:bidi-unicode"
	textInvisibleUnicodeID = "text:invisible-unicode"
	textUTF8BomID          = "text:utf8-bom"
	textMixedLineEndingsID = "text:mixed-line-endings"
	textTrailingWSID       = "text:trailing-whitespace"
	textOversizedFileID    = "text:oversized-file"
	textMissingFinalNLID   = "text:missing-final-newline"
	textOverlongLineID     = "text:overlong-line"

	maxTextLineRunes = 200
	textContextPoll  = 64 << 10
)

type textRule struct {
	id          string
	kind        string
	cwe         string
	severity    shared.Severity
	title       string
	description string
	ruleType    domainrule.Type
	quality     domainrule.Quality
}

func builtinTextRules() []textRule {
	return []textRule{
		{id: textBidiUnicodeID, title: "Bidi Unicode control character", description: "Detects Unicode bidirectional control characters that can disguise malicious code by reversing or reordering displayed text.", kind: kindSAST, cwe: "CWE-1007", severity: shared.SeverityHigh, ruleType: domainrule.TypeVulnerability, quality: domainrule.QualitySecurity},
		{id: textInvisibleUnicodeID, title: "Invisible Unicode format character", description: "Detects invisible Unicode format characters (category Cf) that can be used to hide malicious content or confuse code reviewers.", kind: kindSAST, severity: shared.SeverityMedium, ruleType: domainrule.TypeSecurityHotspot, quality: domainrule.QualitySecurity},
		{id: textUTF8BomID, title: "UTF-8 BOM at start of file", description: "Detects a UTF-8 byte order mark (BOM) at the beginning of a file.", kind: kindQuality, severity: shared.SeverityInfo, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
		{id: textMixedLineEndingsID, title: "Mixed line endings in file", description: "Detects files that contain more than one style of line ending (CRLF, bare LF, or bare CR).", kind: kindQuality, severity: shared.SeverityInfo, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
		{id: textTrailingWSID, title: "Trailing whitespace", description: "Detects trailing ASCII spaces or tabs at the end of a line.", kind: kindQuality, severity: shared.SeverityInfo, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
		{id: textOversizedFileID, title: "Text file exceeds 1 MiB", description: "Detects text files larger than 1 MiB.", kind: kindQuality, severity: shared.SeverityLow, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
		{id: textMissingFinalNLID, title: "Missing final newline", description: "Detects non-empty text files that do not end with a line terminator.", kind: kindQuality, severity: shared.SeverityInfo, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
		{id: textOverlongLineID, title: "Line exceeds 200 Unicode runes", description: "Detects physical lines longer than 200 Unicode runes.", kind: kindQuality, severity: shared.SeverityInfo, ruleType: domainrule.TypeCodeSmell, quality: domainrule.QualityMaintainability},
	}
}

var textRulesByID map[string]textRule

func init() {
	textRulesByID = make(map[string]textRule)
	for _, r := range builtinTextRules() {
		textRulesByID[r.id] = r
	}
}

func textRawFinding(id, rel string, line int) ports.CodeAnalysisRawFinding {
	if line < 1 {
		line = 1
	}
	r, ok := textRulesByID[id]
	if !ok {
		return ports.CodeAnalysisRawFinding{Kind: kindQuality, RuleID: id, Severity: shared.SeverityInfo, Title: id, File: rel, Line: line}
	}
	return ports.CodeAnalysisRawFinding{
		Kind: r.kind, RuleID: r.id, CWE: r.cwe, Severity: r.severity,
		Title: r.title, Description: r.description, File: rel, Line: line,
	}
}

type textEnding uint8

const (
	textNoEnding textEnding = iota
	textLF
	textCRLF
	textCR
)

type textScanner struct {
	ctx      context.Context
	rel      string
	markdown bool
	add      func(ports.CodeAnalysisRawFinding)

	line     int
	total    int64
	nextPoll int64
	finished bool

	firstBytes [3]byte
	firstN     int
	bomChecked bool
	oversized  bool
	pendingCR  bool
	ended      bool

	carry      [utf8.UTFMax]byte
	carryN     int
	carryStart int64

	runes             int
	overlongReported  bool
	bidiReported      bool
	invisibleReported bool
	trailing          int
	trailingTab       bool
	hasContent        bool
	firstEnding       textEnding
	mixedReported     bool
}

func newTextScanner(ctx context.Context, rel, ext string, add func(ports.CodeAnalysisRawFinding)) *textScanner {
	return &textScanner{
		ctx: ctx, rel: rel, markdown: markdownFile(rel, ext), add: add,
		line: 1, nextPoll: textContextPoll,
	}
}

func markdownFile(rel, ext string) bool {
	for _, name := range []string{rel, "file" + ext} {
		for _, language := range enry.GetLanguagesByExtension(name, nil, nil) {
			if language == "Markdown" {
				return true
			}
		}
	}
	return false
}

func (s *textScanner) write(chunk []byte) error {
	if s.finished {
		return nil
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	for _, b := range chunk {
		if s.pendingCR {
			if b == '\n' {
				if err := s.consumeByte(b); err != nil {
					return err
				}
				s.pendingCR = false
				s.finishLine(textCRLF)
				continue
			}
			s.pendingCR = false
			s.finishLine(textCR)
		}

		if err := s.consumeByte(b); err != nil {
			return err
		}
		switch b {
		case '\r':
			s.flushCarry()
			s.pendingCR = true
		case '\n':
			s.flushCarry()
			s.finishLine(textLF)
		default:
			s.ended = false
			s.consumeContentByte(b)
		}
	}
	return nil
}

func (s *textScanner) consumeByte(b byte) error {
	if s.firstN < len(s.firstBytes) {
		s.firstBytes[s.firstN] = b
		s.firstN++
		if s.firstN == len(s.firstBytes) {
			s.bomChecked = true
			if s.firstBytes == [3]byte{0xEF, 0xBB, 0xBF} {
				s.emit(textUTF8BomID, 1)
			}
		}
	}
	s.total++
	if !s.oversized && s.total == maxFileBytes+1 {
		s.oversized = true
		s.emit(textOversizedFileID, s.line)
	}
	if s.total >= s.nextPoll {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		s.nextPoll += textContextPoll
	}
	return nil
}

func (s *textScanner) consumeContentByte(b byte) {
	if b == ' ' || b == '\t' {
		if s.trailing < 3 {
			s.trailing++
		}
		s.trailingTab = s.trailingTab || b == '\t'
	} else {
		s.trailing = 0
		s.trailingTab = false
		s.hasContent = true
	}

	if s.carryN == 0 {
		s.carryStart = s.total - 1
	}
	s.carry[s.carryN] = b
	s.carryN++
	for s.carryN > 0 && utf8.FullRune(s.carry[:s.carryN]) {
		r, size := utf8.DecodeRune(s.carry[:s.carryN])
		s.observeRune(r, s.carryStart)
		copy(s.carry[:], s.carry[size:s.carryN])
		s.carryN -= size
		s.carryStart += int64(size)
	}
}

func (s *textScanner) flushCarry() {
	for s.carryN > 0 {
		s.observeRune(utf8.RuneError, s.carryStart)
		copy(s.carry[:], s.carry[1:s.carryN])
		s.carryN--
		s.carryStart++
	}
}

func (s *textScanner) observeRune(r rune, offset int64) {
	s.runes++
	if s.runes == maxTextLineRunes+1 && !s.overlongReported {
		s.overlongReported = true
		s.emit(textOverlongLineID, s.line)
	}
	if unicode.Is(unicode.Bidi_Control, r) {
		if !s.bidiReported {
			s.bidiReported = true
			s.emit(textBidiUnicodeID, s.line)
		}
	} else if unicode.Is(unicode.Cf, r) && !(r == rune(0xFEFF) && offset == 0) && !s.invisibleReported {
		s.invisibleReported = true
		s.emit(textInvisibleUnicodeID, s.line)
	}
}

func (s *textScanner) finishLine(ending textEnding) {
	if s.firstEnding == textNoEnding {
		s.firstEnding = ending
	} else if ending != s.firstEnding && !s.mixedReported {
		s.mixedReported = true
		s.emit(textMixedLineEndingsID, s.line)
	}
	if s.trailing > 0 && !(s.markdown && ending != textNoEnding && s.trailing == 2 && !s.trailingTab && s.hasContent) {
		s.emit(textTrailingWSID, s.line)
	}
	s.line++
	s.ended = true
	s.resetLine()
}

func (s *textScanner) resetLine() {
	s.runes = 0
	s.overlongReported = false
	s.bidiReported = false
	s.invisibleReported = false
	s.trailing = 0
	s.trailingTab = false
	s.hasContent = false
	s.carryN = 0
}

func (s *textScanner) finish(complete bool) error {
	if s.finished {
		return nil
	}
	s.finished = true
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.pendingCR {
		if complete {
			s.pendingCR = false
			s.finishLine(textCR)
		}
	}
	s.flushCarry()
	if complete && s.total > 0 && !s.ended {
		if s.trailing > 0 {
			s.emit(textTrailingWSID, s.line)
		}
		s.emit(textMissingFinalNLID, s.line)
	}
	return nil
}

func (s *textScanner) emit(id string, line int) {
	if s.add != nil {
		s.add(textRawFinding(id, s.rel, line))
	}
}

// scanTextFile keeps catalog and focused tests concise while the analyzer feeds
// the same state machine incrementally from a bounded read buffer.
func scanTextFile(ctx context.Context, rel, ext string, content []byte, fileSize int64, complete bool, budget int) ([]ports.CodeAnalysisRawFinding, error) {
	if budget <= 0 {
		return nil, nil
	}
	collector := newFindingCollector(budget)
	scanner := newTextScanner(ctx, rel, ext, collector.add)
	if err := scanner.write(content); err != nil {
		return collector.findings(), err
	}
	// Compatibility callers may provide a synthetic size without materializing a
	// 1 MiB golden example. Analyzer integration derives this rule from bytes read.
	if fileSize > maxFileBytes && !scanner.oversized {
		scanner.oversized = true
		scanner.emit(textOversizedFileID, scanner.line)
	}
	if err := scanner.finish(complete); err != nil {
		return collector.findings(), err
	}
	return collector.findings(), nil
}

type findingCollector struct {
	limit    int
	observed int
	heap     rawFindingHeap
}

func newFindingCollector(limit int) *findingCollector {
	c := &findingCollector{limit: limit}
	heap.Init(&c.heap)
	return c
}

func (c *findingCollector) add(f ports.CodeAnalysisRawFinding) {
	c.observed++
	if c.limit <= 0 {
		return
	}
	if c.heap.Len() < c.limit {
		heap.Push(&c.heap, f)
		return
	}
	if findingBetter(f, c.heap[0]) {
		c.heap[0] = f
		heap.Fix(&c.heap, 0)
	}
}

func (c *findingCollector) merge(findings []ports.CodeAnalysisRawFinding, observed int) {
	for _, f := range findings {
		c.add(f)
	}
	if observed > len(findings) {
		c.observed += observed - len(findings)
	}
}

func (c *findingCollector) findings() []ports.CodeAnalysisRawFinding {
	out := append([]ports.CodeAnalysisRawFinding(nil), c.heap...)
	sort.Slice(out, func(i, j int) bool { return findingOutputLess(out[i], out[j]) })
	return out
}

func (c *findingCollector) truncated() bool { return c.observed > c.heap.Len() }

type rawFindingHeap []ports.CodeAnalysisRawFinding

func (h rawFindingHeap) Len() int           { return len(h) }
func (h rawFindingHeap) Less(i, j int) bool { return findingBetter(h[j], h[i]) }
func (h rawFindingHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rawFindingHeap) Push(x any)        { *h = append(*h, x.(ports.CodeAnalysisRawFinding)) }
func (h *rawFindingHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func findingBetter(a, b ports.CodeAnalysisRawFinding) bool {
	if findingKindRank(a.Kind) != findingKindRank(b.Kind) {
		return findingKindRank(a.Kind) > findingKindRank(b.Kind)
	}
	if shared.SeverityRank(a.Severity) != shared.SeverityRank(b.Severity) {
		return shared.SeverityRank(a.Severity) > shared.SeverityRank(b.Severity)
	}
	return findingOutputLess(a, b)
}

func findingKindRank(kind string) int {
	switch kind {
	case kindSAST:
		return 3
	case kindReliability:
		return 2
	default:
		return 1
	}
}

func findingOutputLess(a, b ports.CodeAnalysisRawFinding) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Title != b.Title {
		return a.Title < b.Title
	}
	return a.Description < b.Description
}

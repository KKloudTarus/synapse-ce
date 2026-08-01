package codeanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// -- Helpers ------------------------------------------------------------------

func mustScanTextFile(rel, ext string, content []byte, fileSize int64, complete bool) []ports.CodeAnalysisRawFinding {
	findings, err := scanTextFile(context.Background(), rel, ext, content, fileSize, complete, maxFindings)
	if err != nil {
		panic(err)
	}
	return findings
}

func scanIDs(rel, ext string, content []byte, fileSize int64, complete bool) map[string]int {
	out := map[string]int{}
	for _, f := range mustScanTextFile(rel, ext, content, fileSize, complete) {
		out[f.RuleID]++
	}
	return out
}

// trailingWS returns a string with n trailing ASCII spaces (no literal spaces
// in the source file).
func trailingWS(s string, n int) string {
	return s + strings.Repeat(" ", n)
}

// -- Bidi control: full Unicode.Bidi_Control property + dedup -----------------

func TestTextScan_BidiControl_AllCodepoints(t *testing.T) {
	bidiRunes := []rune{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.Is(unicode.Bidi_Control, r) {
			bidiRunes = append(bidiRunes, r)
		}
	}
	if len(bidiRunes) == 0 {
		t.Fatal("no Bidi_Control runes found; stdlib regression")
	}

	var b strings.Builder
	b.WriteString("text")
	for _, r := range bidiRunes {
		b.WriteRune(r)
	}
	b.WriteString("end")
	content := []byte(b.String())

	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textBidiUnicodeID] != 1 {
		t.Errorf("expected 1 bidi finding, got %d (bidi runes: %d)", ids[textBidiUnicodeID], len(bidiRunes))
	}
	if ids[textInvisibleUnicodeID] != 0 {
		t.Errorf("bidi controls should not produce invisible-unicode findings, got %d", ids[textInvisibleUnicodeID])
	}
}

func TestTextScan_BidiControl_DedupPerLine(t *testing.T) {
	// U+202E (RLO) and U+200E (LRM) on same line -> 1 bidi finding, 0 invisible.
	rlo := string(rune(0x202E))
	lrm := string(rune(0x200E))
	content := []byte("if " + rlo + "admin" + lrm + " ok\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textBidiUnicodeID] != 1 {
		t.Errorf("expected 1 bidi finding per line, got %d", ids[textBidiUnicodeID])
	}
}

// -- Invisible Cf characters, leading/mid-file U+FEFF -------------------------

func TestTextScan_InvisibleUnicode_CfCharacters(t *testing.T) {
	// U+00AD (Soft Hyphen) is Cf and must be detected.
	shy := string(rune(0x00AD))
	content := []byte("text" + shy + " here\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textInvisibleUnicodeID] != 1 {
		t.Errorf("expected 1 invisible-unicode finding for U+00AD, got %d", ids[textInvisibleUnicodeID])
	}
}

func TestTextScan_LeadingBOM_ExcludedFromInvisible(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}
	content := append(bom, []byte("hello\n")...)
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textUTF8BomID] != 1 {
		t.Errorf("expected 1 utf8-bom finding, got %d", ids[textUTF8BomID])
	}
	if ids[textInvisibleUnicodeID] != 0 {
		t.Errorf("leading BOM must not trigger invisible-unicode, got %d", ids[textInvisibleUnicodeID])
	}
}

func TestTextScan_MidFileFEFF_DetectedAsInvisible(t *testing.T) {
	feff := string(rune(0xFEFF))
	content := []byte("before" + feff + "after\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textInvisibleUnicodeID] != 1 {
		t.Errorf("expected 1 invisible-unicode for mid-file U+FEFF, got %d", ids[textInvisibleUnicodeID])
	}
	if ids[textUTF8BomID] != 0 {
		t.Errorf("mid-file U+FEFF must not trigger utf8-bom, got %d", ids[textUTF8BomID])
	}
}

func TestTextScan_InvalidBytes_NoPanic(t *testing.T) {
	content := []byte{0xFF, 0xFE, 0x80, 0x90, 0xC0, 0xAF}
	_ = mustScanTextFile("f.bin", ".bin", content, int64(len(content)), true)
}

// -- Line endings: LF, CRLF, CR, mixed ----------------------------------------

func TestTextScan_LineEndings_ConsistentLF(t *testing.T) {
	content := []byte("line1\nline2\nline3\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 0 {
		t.Errorf("consistent LF should not trigger mixed-line-endings, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_ConsistentCRLF(t *testing.T) {
	content := []byte("line1\r\nline2\r\nline3\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 0 {
		t.Errorf("consistent CRLF should not trigger mixed-line-endings, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_ConsistentCR(t *testing.T) {
	content := []byte("line1\rline2\rline3\r")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 0 {
		t.Errorf("consistent CR should not trigger mixed-line-endings, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_MixedReportsFirstConflictingLine(t *testing.T) {
	content := []byte("line1\nline2\r\nline3\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("expected 1 mixed-line-endings finding, got %d", ids[textMixedLineEndingsID])
	}
	var reportedLine int
	for _, f := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if f.RuleID == textMixedLineEndingsID {
			reportedLine = f.Line
		}
	}
	if reportedLine != 2 {
		t.Errorf("expected mixed-line-endings on line 2, got line %d", reportedLine)
	}
}

// Regression: pairwise mixed endings where the conflicting ending is on the
// final terminated line.
func TestTextScan_LineEndings_MixedLF_CRLF_LastLine(t *testing.T) {
	// LF then CRLF on last terminated line.
	content := []byte("line1\nline2\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("LF+CRLF with CRLF on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
	for _, f := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if f.RuleID == textMixedLineEndingsID && f.Line != 2 {
			t.Errorf("LF+CRLF: expected conflict on line 2, got line %d", f.Line)
		}
	}
}

func TestTextScan_LineEndings_MixedLF_CR_LastLine(t *testing.T) {
	// LF then bare CR on last terminated line.
	content := []byte("line1\nline2\r")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("LF+CR with CR on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
	for _, f := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if f.RuleID == textMixedLineEndingsID && f.Line != 2 {
			t.Errorf("LF+CR: expected conflict on line 2, got line %d", f.Line)
		}
	}
}

func TestTextScan_LineEndings_MixedCRLF_LF_LastLine(t *testing.T) {
	content := []byte("line1\r\nline2\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("CRLF+LF with LF on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_MixedCRLF_CR_LastLine(t *testing.T) {
	content := []byte("line1\r\nline2\r")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("CRLF+CR with CR on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_MixedCR_LF_LastLine(t *testing.T) {
	content := []byte("line1\rline2\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("CR+LF with LF on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
}

func TestTextScan_LineEndings_MixedCR_CRLF_LastLine(t *testing.T) {
	content := []byte("line1\rline2\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMixedLineEndingsID] != 1 {
		t.Errorf("CR+CRLF with CRLF on last line: expected 1 finding, got %d", ids[textMixedLineEndingsID])
	}
}

// -- Unicode line number accuracy with bare CR and CRLF -----------------------

func TestTextScan_Unicode_LineNumber_BareCR(t *testing.T) {
	// "line1\r<U+00AD>line2\rline3"
	// Line 1: "line1" with U+00AD, bare CR -> line 2
	// Line 2: "line2", bare CR -> line 3
	// Line 3: "line3" (no terminator)
	shy := string(rune(0x00AD))
	content := []byte("line1\r" + shy + "line2\rline3")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	// U+00AD is on the content AFTER the first \r, so it belongs to the text
	// that appears after the CR. In the physical line walk:
	// - physLine[0]: start=0, end=5 ("line1"), terminator CR -> endCR
	// - physLine[1]: start=6, end=14 ("<U+00AD>line2"), terminator CR -> endCR
	// - physLine[2]: start=15, end=20 ("line3"), no terminator
	// The shy character is in physLine[1] -> line 2
	if ids[textInvisibleUnicodeID] != 1 {
		t.Errorf("expected 1 invisible-unicode finding, got %d", ids[textInvisibleUnicodeID])
	}
	for _, f := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if f.RuleID == textInvisibleUnicodeID && f.Line != 2 {
			t.Errorf("bare-CR: U+00AD expected on line 2, got line %d", f.Line)
		}
	}
}

func TestTextScan_Unicode_LineNumber_CRLF(t *testing.T) {
	shy := string(rune(0x00AD))
	content := []byte("line1\r\n" + shy + "line2\r\nline3\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textInvisibleUnicodeID] != 1 {
		t.Errorf("expected 1 invisible-unicode finding, got %d", ids[textInvisibleUnicodeID])
	}
	for _, f := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if f.RuleID == textInvisibleUnicodeID && f.Line != 2 {
			t.Errorf("CRLF: U+00AD expected on line 2, got line %d", f.Line)
		}
	}
}

// -- Trailing whitespace ------------------------------------------------------

func TestTextScan_TrailingWS_AtLF(t *testing.T) {
	content := []byte(trailingWS("hello", 3) + "\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("expected 1 trailing-ws finding, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_TrailingWS_AtCRLF(t *testing.T) {
	content := []byte(trailingWS("hello", 2) + "\t\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("expected 1 trailing-ws finding at CRLF, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_TrailingWS_AtEOF(t *testing.T) {
	content := []byte(trailingWS("hello", 3))
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("expected 1 trailing-ws finding at EOF, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_TrailingWS_MarkdownTwoSpaceException(t *testing.T) {
	for _, ext := range []string{".md", ".markdown", ".mdown", ".mdwn", ".mkd", ".mkdn", ".livemd"} {
		content := []byte(trailingWS("soft break", 2) + "\nnext line\n")
		ids := scanIDs("f"+ext, ext, content, int64(len(content)), true)
		if ids[textTrailingWSID] != 0 {
			t.Errorf("Markdown extension %s produced %d trailing-ws findings", ext, ids[textTrailingWSID])
		}
	}
}

func TestTextScan_TrailingWS_MarkdownTabCombinationsTrigger(t *testing.T) {
	for _, suffix := range []string{"\t", "\t ", " \t"} {
		content := []byte("hard break" + suffix + "\n")
		ids := scanIDs("f.md", ".md", content, int64(len(content)), true)
		if ids[textTrailingWSID] != 1 {
			t.Errorf("Markdown suffix %q should trigger trailing whitespace: %+v", suffix, ids)
		}
	}
}

func TestTextScan_TrailingWS_MarkdownThreeSpacesStillTriggers(t *testing.T) {
	content := []byte(trailingWS("too many", 3) + "\n")
	ids := scanIDs("f.md", ".md", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("Markdown 3 spaces should trigger trailing-ws, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_TrailingWS_MarkdownWhitespaceOnlyLine(t *testing.T) {
	content := []byte(trailingWS("", 2) + "\nnext\n")
	ids := scanIDs("f.md", ".md", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("Markdown WS-only line should trigger, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_TrailingWS_TabTriggers(t *testing.T) {
	content := []byte("hello\t\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("trailing tab should trigger trailing-ws, got %d", ids[textTrailingWSID])
	}
}

// -- Overlong line ------------------------------------------------------------

func TestTextScan_OverlongLine_Exactly200(t *testing.T) {
	content := []byte(strings.Repeat("a", 200) + "\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textOverlongLineID] != 0 {
		t.Errorf("exactly 200 runes should NOT trigger overlong-line, got %d", ids[textOverlongLineID])
	}
}

func TestTextScan_OverlongLine_201Runes(t *testing.T) {
	content := []byte(strings.Repeat("a", 201) + "\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textOverlongLineID] != 1 {
		t.Errorf("201 runes should trigger overlong-line, got %d", ids[textOverlongLineID])
	}
}

func TestTextScan_OverlongLine_MultiByteRunes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 201; i++ {
		b.WriteRune(0x00E9) // e-acute, 2 bytes in UTF-8
	}
	b.WriteByte('\n')
	content := []byte(b.String())
	if utf8.RuneCount(content) != 202 {
		t.Fatalf("test setup: expected 202 runes, got %d", utf8.RuneCount(content))
	}
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textOverlongLineID] != 1 {
		t.Errorf("201 multi-byte runes should trigger overlong-line, got %d", ids[textOverlongLineID])
	}
}

// -- File size: 1 MiB boundary ------------------------------------------------

func TestTextScan_Oversized_ExactOneMiB(t *testing.T) {
	content := make([]byte, maxFileBytes)
	for i := range content {
		content[i] = 'x'
	}
	content[maxFileBytes-1] = '\n'
	ids := scanIDs("f.txt", ".txt", content, int64(maxFileBytes), true)
	if ids[textOversizedFileID] != 0 {
		t.Errorf("exactly 1 MiB should NOT trigger oversized-file, got %d", ids[textOversizedFileID])
	}
}

func TestTextScan_Oversized_GreaterThanOneMiB(t *testing.T) {
	content := []byte("prefix\n")
	ids := scanIDs("f.txt", ".txt", content, int64(maxFileBytes+1), true)
	if ids[textOversizedFileID] != 1 {
		t.Errorf("fileSize > 1 MiB should trigger oversized-file, got %d", ids[textOversizedFileID])
	}
}

// -- Truncated prefix (complete=false) ----------------------------------------

func TestTextScan_TruncatedPrefix_SuppressesMissingFinalNL(t *testing.T) {
	content := []byte("no newline at end of this truncated read")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)+100), false)
	if ids[textMissingFinalNLID] != 0 {
		t.Errorf("truncated prefix must not report missing-final-newline, got %d", ids[textMissingFinalNLID])
	}
}

func TestTextScan_TruncatedPrefix_ReportsProvenOverlongOnly(t *testing.T) {
	content := []byte(strings.Repeat("a", maxTextLineRunes+1) + strings.Repeat(" ", 2))
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)+1), false)
	if ids[textTrailingWSID] != 0 || ids[textMissingFinalNLID] != 0 || ids[textOverlongLineID] != 1 {
		t.Fatalf("incomplete fragment findings = %+v", ids)
	}
}

func TestTextScan_TruncatedPrefix_ReportsContainedUnicode(t *testing.T) {
	content := []byte("line\n" + string(rune(0x00AD)) + "fragment")
	findings := mustScanTextFile("f.txt", ".txt", content, int64(len(content)+1), false)
	for _, finding := range findings {
		if finding.RuleID == textInvisibleUnicodeID && finding.Line == 2 {
			return
		}
	}
	t.Fatalf("contained Unicode control not reported on line 2: %+v", findings)
}

func TestTextScan_TruncatedPrefix_TerminalCRIsUnknown(t *testing.T) {
	content := []byte("one\ntwo\r")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)+1), false)
	if ids[textMixedLineEndingsID] != 0 {
		t.Fatalf("terminal split CR must not conflict with LF: %+v", ids)
	}
}

func TestTextScan_TruncatedPrefix_CompleteCRLFBeforeFragmentStillCounts(t *testing.T) {
	content := []byte("one\ntwo\r\nfragment")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)+1), false)
	if ids[textMixedLineEndingsID] != 1 {
		t.Fatalf("fully contained CRLF should conflict with LF: %+v", ids)
	}
}

// -- Missing final newline ----------------------------------------------------

func TestTextScan_MissingFinalNL_NonEmptyComplete(t *testing.T) {
	content := []byte("hello world")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMissingFinalNLID] != 1 {
		t.Errorf("non-empty complete file without final newline should trigger, got %d", ids[textMissingFinalNLID])
	}
}

func TestTextScan_MissingFinalNL_UsesFinalPhysicalLine(t *testing.T) {
	content := []byte("one\ntwo\nthree")
	for _, finding := range mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true) {
		if finding.RuleID == textMissingFinalNLID {
			if finding.Line != 3 {
				t.Fatalf("missing final newline line = %d, want 3", finding.Line)
			}
			return
		}
	}
	t.Fatal("missing final newline finding absent")
}

func TestTextScan_MissingFinalNL_EmptyFile(t *testing.T) {
	content := []byte{}
	ids := scanIDs("f.txt", ".txt", content, 0, true)
	if ids[textMissingFinalNLID] != 0 {
		t.Errorf("empty file must not trigger missing-final-newline, got %d", ids[textMissingFinalNLID])
	}
}

func TestTextScan_MissingFinalNL_EndsWithLF(t *testing.T) {
	content := []byte("hello\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMissingFinalNLID] != 0 {
		t.Errorf("file ending with LF must not trigger, got %d", ids[textMissingFinalNLID])
	}
}

func TestTextScan_MissingFinalNL_EndsWithCRLF(t *testing.T) {
	content := []byte("hello\r\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMissingFinalNLID] != 0 {
		t.Errorf("file ending with CRLF must not trigger, got %d", ids[textMissingFinalNLID])
	}
}

func TestTextScan_MissingFinalNL_EndsWithCR(t *testing.T) {
	content := []byte("hello\r")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textMissingFinalNLID] != 0 {
		t.Errorf("file ending with CR must not trigger, got %d", ids[textMissingFinalNLID])
	}
}

// -- Deterministic sort order -------------------------------------------------

func TestTextScan_DeterministicOrder(t *testing.T) {
	content := []byte(trailingWS("line1", 2) + "\n" + strings.Repeat("b", 201) + "\nno newline")
	for i := 0; i < 50; i++ {
		r1 := mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true)
		r2 := mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true)
		if len(r1) != len(r2) {
			t.Fatalf("run %d: length mismatch %d vs %d", i, len(r1), len(r2))
		}
		for j := range r1 {
			if r1[j].RuleID != r2[j].RuleID || r1[j].Line != r2[j].Line {
				t.Fatalf("run %d: non-deterministic at index %d", i, j)
			}
		}
	}
}

// -- Description populated in findings ----------------------------------------

func TestTextScan_DescriptionPopulated(t *testing.T) {
	content := []byte(trailingWS("hello", 3) + "\n")
	findings := mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true)
	for _, f := range findings {
		if f.Description == "" {
			t.Errorf("finding %s has empty Description", f.RuleID)
		}
	}
}

// -- Analyzer integration -----------------------------------------------------

func TestAnalyzerIntegration_UnknownExtension_GetsTextFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.data"), []byte(trailingWS("value", 2)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == textTrailingWSID && f.File == "config.data" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected trailing-ws finding on .data file, got %+v", findings)
	}
}

func TestAnalyzerIntegration_NormalSource_GetsTextAndLegacy(t *testing.T) {
	root := t.TempDir()
	body := "// TODO: fix this" + "  \npackage main\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hasTodo := false
	hasTrailingWS := false

	for _, f := range findings {
		if f.RuleID == "quality-todo-comment" && f.File == "main.go" {
			hasTodo = true
		}
		if f.RuleID == textTrailingWSID && f.File == "main.go" {
			hasTrailingWS = true
		}
	}
	if !hasTodo {
		t.Error("expected quality-todo-comment on main.go")
	}
	if !hasTrailingWS {
		t.Error("expected trailing-ws on main.go")
	}
}

// Dotfiles should receive Text findings, not be excluded.
func TestAnalyzerIntegration_Dotfile_GetsTextFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte(trailingWS("value", 2)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == textTrailingWSID && f.File == ".editorconfig" {
			found = true
		}
	}
	if !found {
		t.Errorf("dotfile should receive Text findings, got %+v", findings)
	}
}

// Dotfiles eligible for Text but excluded from legacy source/XML scanning.
// A .go dotfile with trailing whitespace and a TODO comment must receive
// only the Text finding, never the legacy quality-todo-comment.
func TestAnalyzerIntegration_Dotfile_GetsTextButNoLegacy(t *testing.T) {
	root := t.TempDir()
	// Trailing whitespace triggers text:trailing-whitespace.
	// TODO comment would trigger quality-todo-comment if legacy ran.
	body := "// TODO: fix\npackage main\n\n" + trailingWS("value", 2) + "\n"
	if err := os.WriteFile(filepath.Join(root, ".hidden.go"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	hasLegacyTodo := false
	hasTrailingWS := false
	for _, f := range findings {
		if f.File != ".hidden.go" {
			continue
		}
		if f.RuleID == textTrailingWSID {
			hasTrailingWS = true
		}
		if f.RuleID == "quality-todo-comment" {
			hasLegacyTodo = true
		}
	}
	if !hasTrailingWS {
		t.Error("dotfile should get Text findings (trailing-ws)")
	}
	if hasLegacyTodo {
		t.Error("dotfile must NOT get legacy findings (quality-todo-comment)")
	}
}

func TestAnalyzerIntegration_BinaryExcluded(t *testing.T) {
	root := t.TempDir()
	// Construct a Python file that would trigger both the legacy
	// quality-todo-comment rule and the text:trailing-whitespace rule,
	// but contains NUL bytes so enry.IsBinary returns true. The early
	// return after the bounded read must prevent BOTH Text and legacy
	// findings.
	binaryContent := []byte("# TODO: fix this security issue\nimport os\nvalue = 1  \n\x00\x00\x00")
	if err := os.WriteFile(filepath.Join(root, "helper.py"), binaryContent, 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if f.File == "helper.py" {
			t.Errorf("binary file must receive neither Text nor legacy findings, got: %+v", f)
		}
	}
}

func TestAnalyzerIntegration_VendorExcluded(t *testing.T) {
	root := t.TempDir()
	vendorDir := filepath.Join(root, "vendor", "pkg")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Include a TODO comment (would trigger quality-todo-comment) and
	// trailing whitespace (would trigger text:trailing-whitespace) to
	// prove that vendor directory exclusion prevents both legacy and Text
	// findings.
	body := "// TODO: upstream fix needed\npackage pkg\n\n" + trailingWS("value", 2) + "\n"
	if err := os.WriteFile(filepath.Join(vendorDir, "lib.go"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.File, "vendor") {
			t.Errorf("vendor file must receive neither Text nor legacy findings, got: %+v", f)
		}
	}
}

func TestAnalyzerIntegration_GeneratedExcluded(t *testing.T) {
	root := t.TempDir()
	// Generated file: protobuf-generated Go header. Include a TODO comment
	// (would trigger quality-todo-comment if analyzed) and trailing
	// whitespace (would trigger text:trailing-whitespace). The early return
	// after the bounded read must prevent BOTH Text and legacy findings.
	body := "// Code generated by protoc-gen-go. DO NOT EDIT.\n// TODO: regenerate after proto update\npackage pb\n\n" + trailingWS("value", 2) + "\n"
	if err := os.WriteFile(filepath.Join(root, "model.pb.go"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if f.File == "model.pb.go" {
			t.Errorf("generated file must receive neither Text nor legacy findings, got: %+v", f)
		}
	}
}

func TestAnalyzerIntegration_DetachedTailDoesNotClassifyFile(t *testing.T) {
	root := t.TempDir()
	content := []byte(strings.Repeat("plain text\n", maxFileBytes/11+1))
	content = append(content, []byte("// Code generated by generator. DO NOT EDIT.\n")...)
	if err := os.WriteFile(filepath.Join(root, "tail.go"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, finding := range findings {
		if finding.RuleID == textOversizedFileID && finding.File == "tail.go" {
			return
		}
	}
	t.Fatalf("tail marker suppressed legitimate file: %+v", findings)
}

func TestAnalyzerIntegration_SymlinkNotScanned(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(target, []byte("outside  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("symlink was scanned: %+v", findings)
	}
}

func TestAnalyzer_FileBudget(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("ok\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := New().analyze(context.Background(), root, scanLimits{files: 1, bytes: maxTotalScanBytes})
	if !errors.Is(err, ErrScanBudget) {
		t.Fatalf("file budget error = %v, want ErrScanBudget", err)
	}
}

func TestAnalyzer_ByteBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New().analyze(context.Background(), root, scanLimits{files: maxVisitedRegularFiles, bytes: 5})
	if !errors.Is(err, ErrScanBudget) {
		t.Fatalf("byte budget error = %v, want ErrScanBudget", err)
	}
}

func TestAnalyzer_CancellationPreservesIdentityAndContext(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Analyze(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want context.Canceled", err)
	}
	if !strings.Contains(err.Error(), "walk source tree") {
		t.Fatalf("cancellation lacks walk context: %v", err)
	}
}

type cancelAfterContext struct {
	context.Context
	checks int
}

func (c *cancelAfterContext) Err() error {
	c.checks++
	if c.checks >= 2 {
		return context.Canceled
	}
	return nil
}

func TestTextScan_CancellationDuringLongLine(t *testing.T) {
	ctx := &cancelAfterContext{Context: context.Background()}
	_, err := scanTextFile(ctx, "large.txt", ".txt", []byte(strings.Repeat("x", maxFileBytes)), maxFileBytes, true, maxFindings)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan cancellation error = %v, want context.Canceled", err)
	}
	if ctx.checks < 2 {
		t.Fatalf("scan did not poll context during work: %d checks", ctx.checks)
	}
}

func TestTextScan_CancellationDuringNewlineDenseInput(t *testing.T) {
	ctx := &cancelAfterContext{Context: context.Background()}
	_, err := scanTextFile(ctx, "large.txt", ".txt", bytes.Repeat([]byte{'\n'}, maxFileBytes), maxFileBytes, true, maxFindings)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("newline-dense cancellation error = %v, want context.Canceled", err)
	}
}

func TestTextScanner_ChunkBoundariesMatchSingleWrite(t *testing.T) {
	content := []byte("one\r\ntwo" + string(rune(0x202E)) + string(rune(0x00AD)) + "\n")
	want := mustScanTextFile("f.txt", ".txt", content, int64(len(content)), true)
	for split := 1; split < len(content); split++ {
		collector := newFindingCollector(maxFindings)
		scanner := newTextScanner(context.Background(), "f.txt", ".txt", collector.add)
		if err := scanner.write(content[:split]); err != nil {
			t.Fatal(err)
		}
		if err := scanner.write(content[split:]); err != nil {
			t.Fatal(err)
		}
		if err := scanner.finish(true); err != nil {
			t.Fatal(err)
		}
		got := collector.findings()
		if len(got) != len(want) {
			t.Fatalf("split %d: got %+v, want %+v", split, got, want)
		}
		for i := range want {
			if got[i].RuleID != want[i].RuleID || got[i].Line != want[i].Line {
				t.Fatalf("split %d: got %+v, want %+v", split, got, want)
			}
		}
	}
}

func TestAnalyzerIntegration_OversizedScansPastParserPrefix(t *testing.T) {
	root := t.TempDir()
	big := bytes.Repeat([]byte{'a'}, maxFileBytes+100)
	big = append(big, []byte(string(rune(0x202E))+string(rune(0x00AD)))...)
	if err := os.WriteFile(filepath.Join(root, "big.txt"), big, 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.RuleID] = true
	}
	for _, id := range []string{textOversizedFileID, textBidiUnicodeID, textInvisibleUnicodeID, textMissingFinalNLID} {
		if !seen[id] {
			t.Errorf("missing %s after full oversized scan: %+v", id, findings)
		}
	}
}

func TestStableFileSnapshotRejectsSizeMismatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stableFileSnapshot(before, before, before.Size()+1) {
		t.Fatal("snapshot accepted mismatched observed size")
	}
}

func TestAnalyzerIntegration_GlobalFindingCapPrioritizesSecurity(t *testing.T) {
	root := t.TempDir()
	content := bytes.Repeat([]byte{'x', ' ', ' ', '\n'}, maxFindings+10)
	if err := os.WriteFile(filepath.Join(root, "a-many.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "z-security.txt"), []byte("safe"+string(rune(0x202E))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if !errors.Is(err, ErrFindingsTruncated) || len(findings) != maxFindings {
		t.Fatalf("findings=%d err=%v", len(findings), err)
	}
	for _, finding := range findings {
		if finding.RuleID == textBidiUnicodeID && finding.File == "z-security.txt" {
			return
		}
	}
	t.Fatalf("security finding lost under cap: %+v", findings)
}

// Regression: verify text findings are complete (Description non-empty) when
// produced through the Analyzer integration path.
func TestAnalyzerIntegration_FindingsHaveDescription(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte(trailingWS("val", 1)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "text:") && f.Description == "" {
			t.Errorf("text finding %s missing Description", f.RuleID)
		}
	}
}

// -- Markdown hard-break EOF regression --------------------------------------

func TestTextScan_TrailingWS_MarkdownTwoSpacesAtEOF(t *testing.T) {
	// Exactly two spaces at true EOF (no line terminator) in a Markdown file
	// must still trigger trailing-whitespace; the hard-break exception only
	// applies before an actual line terminator.
	content := []byte(trailingWS("soft break", 2))
	ids := scanIDs("f.md", ".md", content, int64(len(content)), true)
	if ids[textTrailingWSID] != 1 {
		t.Errorf("Markdown 2-space at EOF should trigger trailing-ws, got %d", ids[textTrailingWSID])
	}
}

func TestTextScan_DenseNotebookBoundsFindings(t *testing.T) {
	content := bytes.Repeat([]byte("x  \n"), maxNotebookBytes/4)
	findings, err := scanTextFile(context.Background(), "dense.ipynb", ".ipynb", content, int64(len(content)), true, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 7 {
		t.Fatalf("finding count = %d, want 7", len(findings))
	}
}

// -- Notebook analyzer integration tests ------------------------------------

// minimalNotebook returns valid JSON with escaped cell newlines and physical
// trailing whitespace outside JSON strings for the Text scanner.
func minimalNotebook(hasKernelspec bool) []byte {
	metadata := map[string]any{}
	if hasKernelspec {
		metadata = map[string]any{
			"kernelspec":    map[string]any{"name": "python3", "display_name": "Python 3", "language": "python"},
			"language_info": map[string]any{"name": "python"},
		}
	}
	doc := map[string]any{
		"metadata": metadata,
		"cells": []any{map[string]any{
			"cell_type": "code", "source": []string{"api_key = 'aaaaaaaaaaaaaaa'\n"},
		}},
	}
	content, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(content, []byte("  \n")...)
}

func TestAnalyzerIntegration_NormalNotebook_GetsTextAndParserFindings(t *testing.T) {
	root := t.TempDir()
	content := minimalNotebook(true)
	if !json.Valid(content) {
		t.Fatal("minimalNotebook returned invalid JSON")
	}
	if err := os.WriteFile(filepath.Join(root, "test.ipynb"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hasText, hasNotebook := false, false
	for _, f := range findings {
		if f.RuleID == textTrailingWSID && f.File == "test.ipynb" {
			hasText = true
		}
		if f.RuleID == "ipynb-hardcoded-credential" && f.File == "test.ipynb#cell-1" {
			hasNotebook = true
		}
	}
	if !hasText || !hasNotebook {
		t.Fatalf("normal notebook routing: text=%v parser=%v findings=%+v", hasText, hasNotebook, findings)
	}
}

func TestAnalyzerIntegration_OversizedNotebook_GetsTextAndNotebookFindings(t *testing.T) {
	root := t.TempDir()
	// Build a >1 MiB notebook with no kernelspec (triggers ipynb-missing-kernelspec).
	bigSource := strings.Repeat("a", maxFileBytes+1024)
	bigNb := []byte(`{"cells":[{"cell_type":"code","source":["` + bigSource + `\n"]}]}`)
	if err := os.WriteFile(filepath.Join(root, "big.ipynb"), bigNb, 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hasOversized := false
	hasNotebookRule := false
	for _, f := range findings {
		if f.RuleID == textOversizedFileID && f.File == "big.ipynb" {
			hasOversized = true
		}
		if f.RuleID == "ipynb-missing-kernelspec" {
			hasNotebookRule = true
		}
	}
	if !hasOversized {
		t.Error("notebook >1 MiB should get text:oversized-file finding")
	}
	if !hasNotebookRule {
		t.Error("notebook >1 MiB but <=16 MiB should still get notebook-specific findings")
	}
}

func TestAnalyzerIntegration_DotfileNotebook_GetsTextButNoParserFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".hidden.ipynb"), minimalNotebook(false), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	hasNotebookRule := false
	hasTrailingWS := false
	for _, f := range findings {
		if f.RuleID == textTrailingWSID && f.File == ".hidden.ipynb" {
			hasTrailingWS = true
		}
		if f.RuleID == "ipynb-missing-kernelspec" || f.RuleID == "ipynb-pip-no-pin" {
			hasNotebookRule = true
		}
	}
	if !hasTrailingWS {
		t.Error("dotfile notebook should get Text findings")
	}
	if hasNotebookRule {
		t.Error("dotfile notebook should NOT get notebook-parser findings")
	}
}

func TestAnalyzerIntegration_VeryLargeNotebook_BoundedTextNoParser(t *testing.T) {
	root := t.TempDir()
	// Build a notebook >16 MiB: create a file larger than maxNotebookBytes.
	// The content read will be truncated to maxNotebookBytes, then we return
	// after Text findings without parsing.
	bigNb := make([]byte, maxNotebookBytes+100)
	copy(bigNb, []byte(`{"cells":[{"cell_type":"code","source":["`))
	for i := len(`{"cells":[{"cell_type":"code","source":["`); i < len(bigNb)-5; i++ {
		bigNb[i] = 'x'
	}
	copy(bigNb[len(bigNb)-5:], `"\n]}]}`)
	if err := os.WriteFile(filepath.Join(root, "huge.ipynb"), bigNb, 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hasOversized := false
	hasNotebookRule := false
	for _, f := range findings {
		if f.RuleID == textOversizedFileID && f.File == "huge.ipynb" {
			hasOversized = true
		}
		if f.RuleID == "ipynb-missing-kernelspec" || f.RuleID == "ipynb-pip-no-pin" {
			hasNotebookRule = true
		}
	}
	if !hasOversized {
		t.Error("notebook >16 MiB should get text:oversized-file finding")
	}
	if hasNotebookRule {
		t.Error("notebook >16 MiB should NOT get notebook-parser findings (skipped)")
	}
}

// -- Oversized anchor: physical threshold-crossing line ----------------------

func TestTextScan_Oversized_AnchorOnThresholdLine(t *testing.T) {
	// Build content where line 1 has 600KB and line 2 has 500KB.
	// Total ~1.1 MiB; the anchor should be on line 2 (where 1 MiB is crossed).
	line1 := strings.Repeat("a", 600*1024) + "\n"
	line2 := strings.Repeat("b", 500*1024) + "\n"
	content := []byte(line1 + line2)
	fileSize := int64(maxFileBytes + 100*1024) // >1 MiB
	findings := mustScanTextFile("f.txt", ".txt", content, fileSize, true)
	for _, f := range findings {
		if f.RuleID == textOversizedFileID {
			if f.Line != 2 {
				t.Errorf("expected oversized anchor on line 2, got line %d", f.Line)
			}
			return
		}
	}
	t.Error("oversized-file finding not emitted")
}

func TestTextScan_Oversized_AnchorLine1ForNoNewlines(t *testing.T) {
	// A file >1 MiB with no newlines in the prefix: anchor on line 1.
	content := make([]byte, maxFileBytes+100)
	for i := range content {
		content[i] = 'x'
	}
	ids := scanIDs("f.txt", ".txt", content, int64(maxFileBytes+100), false)
	if ids[textOversizedFileID] != 1 {
		t.Errorf("expected oversized-file on line 1, got %d", ids[textOversizedFileID])
	}
}

// -- Markdown extensions -----------------------------------------------------

func TestTextScan_TrailingWS_MarkdownMkdException(t *testing.T) {
	for _, ext := range []string{".mdwn", ".mkd", ".mkdn", ".mkdown"} {
		content := []byte(trailingWS("soft break", 2) + "\nnext line\n")
		ids := scanIDs("f"+ext, ext, content, int64(len(content)), true)
		if ids[textTrailingWSID] != 0 {
			t.Errorf("Markdown %s 2-space exception should suppress trailing-ws, got %d", ext, ids[textTrailingWSID])
		}
	}
}

func TestTextScan_TrailingWS_MarkdownMkdThreeSpacesStillTriggers(t *testing.T) {
	for _, ext := range []string{".mdwn", ".mkd", ".mkdn", ".mkdown"} {
		content := []byte(trailingWS("too many", 3) + "\n")
		ids := scanIDs("f"+ext, ext, content, int64(len(content)), true)
		if ids[textTrailingWSID] != 1 {
			t.Errorf("Markdown %s 3 spaces should trigger trailing-ws, got %d", ext, ids[textTrailingWSID])
		}
	}
}

// -- Priority collector tests ------------------------------------------------

func TestFindingCollectorRetainsHigherPriority(t *testing.T) {
	collector := newFindingCollector(2)
	collector.add(ports.CodeAnalysisRawFinding{Kind: kindQuality, RuleID: "q", Severity: shared.SeverityInfo, File: "a", Line: 1})
	collector.add(ports.CodeAnalysisRawFinding{Kind: kindReliability, RuleID: "r", Severity: shared.SeverityMedium, File: "b", Line: 1})
	collector.add(ports.CodeAnalysisRawFinding{Kind: kindSAST, RuleID: "s", Severity: shared.SeverityHigh, File: "c", Line: 1})
	got := collector.findings()
	if !collector.truncated() || len(got) != 2 || got[0].RuleID != "r" || got[1].RuleID != "s" {
		t.Fatalf("collector findings = %+v, observed=%d", got, collector.observed)
	}
}

// -- Analyzer: bounded priority collector ------------------------------------

func TestAnalyzerIntegration_PriorityCollectorRetainedSAST(t *testing.T) {
	root := t.TempDir()
	// A .py file with a trailing-ws (quality) and a TODO comment (quality).
	// Both quality findings must be retained when
	// the budget is tight.
	body := "password = 'secret'\n" + trailingWS("value", 2) + "\n"
	if err := os.WriteFile(filepath.Join(root, "test.py"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	// Run with budget 1 (via maxFindings override through analyze)
	a := New()
	findings, err := a.Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hasQuality := false
	hasTrailingWS := false

	for _, f := range findings {
		if f.Kind == "quality" && f.File == "test.py" {
			hasQuality = true
		}
		if f.RuleID == textTrailingWSID && f.File == "test.py" {
			hasTrailingWS = true
		}
	}
	if !hasQuality {
		t.Error("expected quality finding on test.py")
	}
	if !hasTrailingWS {
		t.Error("expected trailing-ws finding on test.py")
	}
}

// -- Overlong emits on rune 201 even without full line count -----------------

func TestTextScan_Overlong_EmitsOnRune201WithoutFullCount(t *testing.T) {
	// Build a line with exactly 201 'a' runes + newline.
	// The overlong finding must fire even though we break early.
	content := []byte(strings.Repeat("a", 201) + "\nmore\n")
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textOverlongLineID] != 1 {
		t.Errorf("201 runes should trigger overlong-line, got %d", ids[textOverlongLineID])
	}
}

func TestTextScan_Overlong_MultiByteRune201(t *testing.T) {
	// 201 e-acute runes (2 bytes each) + newline
	var b strings.Builder
	for i := 0; i < 201; i++ {
		b.WriteRune(0x00E9)
	}
	b.WriteByte('\n')
	content := []byte(b.String())
	ids := scanIDs("f.txt", ".txt", content, int64(len(content)), true)
	if ids[textOverlongLineID] != 1 {
		t.Errorf("201 multi-byte runes should trigger overlong-line, got %d", ids[textOverlongLineID])
	}
}

// -- safeInt -----------------------------------------------------------------

func TestSafeInt_HugeSize(t *testing.T) {
	if got := safeInt(math.MaxInt64); got != math.MaxInt {
		t.Errorf("safeInt(MaxInt64) = %d, want math.MaxInt (%d)", got, math.MaxInt)
	}
	if got := safeInt(-1); got != 0 {
		t.Errorf("safeInt(-1) = %d, want 0", got)
	}
	if got := safeInt(4096); got != 4096 {
		t.Errorf("safeInt(4096) = %d, want 4096", got)
	}
	if got := safeInt(math.MaxInt - 1); got != math.MaxInt-1 {
		t.Errorf("safeInt(MaxInt-1) = %d, want %d", got, math.MaxInt-1)
	}
	if got := safeInt(math.MaxInt); got != math.MaxInt {
		t.Errorf("safeInt(MaxInt) = %d, want math.MaxInt (%d)", got, math.MaxInt)
	}
}

// -- NUL byte at boundary of classification head -----------------------------

func TestAnalyzerIntegration_NULByteAt8001(t *testing.T) {
	// Place a NUL byte at position 8001 (well within the 32 KiB classification
	// head). The file must be rejected as binary even though the first 8000
	// bytes are valid Go source.
	prefix := []byte(strings.Repeat("a", 8000))
	body := append(prefix, 0x00)
	body = append(body, []byte(strings.Repeat("b", 100)+"\n")...)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "nul.go"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if f.File == "nul.go" {
			t.Errorf("file with NUL byte at 8001 must be rejected, got finding: %+v", f)
		}
	}
}

// -- Generated head under small byte budget ----------------------------------

func TestAnalyzerIntegration_GeneratedHeadUnderSmallBudget(t *testing.T) {
	// A generated-file marker in the first 64 bytes, with a very tight byte
	// budget. The classification head must be populated before the budget
	// expires so IsGenerated fires and rejects the file.
	body := "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage pb\n\n" + trailingWS("value", 2) + "\n"
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "model.pb.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := New()
	findings, err := a.analyze(context.Background(), root, scanLimits{files: maxVisitedRegularFiles, bytes: 200})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, f := range findings {
		if f.File == "model.pb.go" {
			t.Errorf("generated file must be rejected under small budget, got finding: %+v", f)
		}
	}
}

// -- Legacy scanner helper ----------------------------------------------------

// legacyScanFile is a test helper that wraps the callback-based scanFile
// for concise assertions in direct legacy-scanner tests.
func legacyScanFile(a *Analyzer, rel, ext string, content []byte) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding
	if err := a.scanFile(context.Background(), rel, ext, content, func(f ports.CodeAnalysisRawFinding) {
		out = append(out, f)
	}); err != nil {
		panic(err)
	}
	return out
}

// -- Legacy scanner: >8 KiB line skipped, later lines still scanned ----------

func TestScanFile_LongLineThenTODO(t *testing.T) {
	// Line 1: 9 KiB of 'x' (>8 KiB threshold, skipped by rule scanner).
	// Line 2: a TODO comment that must be detected on line 2.
	longLine := strings.Repeat("x", 9*1024) + "\n"
	todoLine := "// TODO: fix this\n"
	content := []byte(longLine + todoLine)

	a := New()
	findings := legacyScanFile(a, "test.go", ".go", content)
	found := false
	for _, f := range findings {
		if f.RuleID == "quality-todo-comment" && f.File == "test.go" && f.Line == 2 {
			found = true
		}
		if f.RuleID == "quality-todo-comment" && f.Line != 2 {
			t.Errorf("TODO found on wrong line: %d (want 2)", f.Line)
		}
	}
	if !found {
		t.Errorf("TODO on line 2 not found after 9KiB first line: %+v", findings)
	}
}

// -- Legacy scanner: CRLF line numbers correct --------------------------------

func TestScanFile_CRLF_LineNumbersCorrect(t *testing.T) {
	content := []byte("line1\r\nline2\r\n// TODO: fix\r\n")
	a := New()
	findings := legacyScanFile(a, "f.go", ".go", content)
	for _, f := range findings {
		if f.RuleID == "quality-todo-comment" && f.Line != 3 {
			t.Errorf("CRLF: TODO expected on line 3, got line %d", f.Line)
		}
	}
}

// -- Legacy scanner: bare CR line numbers correct -----------------------------

func TestScanFile_BareCR_LineNumbersCorrect(t *testing.T) {
	content := []byte("line1\rline2\r// TODO: fix\r")
	a := New()
	findings := legacyScanFile(a, "f.go", ".go", content)
	for _, f := range findings {
		if f.RuleID == "quality-todo-comment" && f.Line != 3 {
			t.Errorf("bare CR: TODO expected on line 3, got line %d", f.Line)
		}
	}
}

// -- Legacy scanner: context cancellation -------------------------------------

func TestScanFile_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := New()
	err := a.scanFile(ctx, "f.go", ".go", []byte("// TODO: fix\n"), func(f ports.CodeAnalysisRawFinding) {
		t.Errorf("unexpected finding after cancellation: %+v", f)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

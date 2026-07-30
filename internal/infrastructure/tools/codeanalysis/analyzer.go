// Package codeanalysis is a deterministic, pure-Go maintainability and reliability rule engine. It never
// executes target code. Every accepted text byte is scanned in fixed-size chunks; only bounded prefixes
// needed by legacy source, XML, and notebook analyzers are retained.
package codeanalysis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/notebook"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// maxFileBytes caps the prefix retained for legacy source and XML scanning.
	// Files beyond this size still receive text-level findings (oversized-file,
	// unicode, etc.) but skip rule-based and XML analysis. This is an
	// intentional performance ceiling, not a defect.
	maxFileBytes = 1 << 20 // 1 MiB

	// maxNotebookBytes caps the prefix retained for notebook parsing. Files
	// larger than this receive text-level findings only; notebook-specific
	// parser findings are intentionally skipped. This ceiling prevents
	// unbounded JSON parsing of adversarial or accidental large notebooks.
	maxNotebookBytes = 16 << 20 // 16 MiB

	maxFindings = 2000

	maxVisitedRegularFiles = 100_000
	maxTotalScanBytes      = 1 << 30
	classificationBytes    = 32 << 10
	readChunkBytes         = 64 << 10
)

var (
	ErrScanBudget        = errors.New("code analysis scan budget exceeded")
	ErrFindingsTruncated = errors.New("code analysis findings truncated")
	ErrFileChanged       = errors.New("code analysis file changed during scan")
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true,
	".vscode": true, ".tox": true, ".hg": true, ".svn": true,
}

type Analyzer struct{ rules []rule }

func New() *Analyzer { return &Analyzer{rules: builtinRules()} }

var _ ports.CodeAnalyzer = (*Analyzer)(nil)

type scanLimits struct {
	files int
	bytes int64
}

func (a *Analyzer) Analyze(ctx context.Context, root string) ([]ports.CodeAnalysisRawFinding, error) {
	return a.analyze(ctx, root, scanLimits{files: maxVisitedRegularFiles, bytes: maxTotalScanBytes})
}

func (a *Analyzer) analyze(ctx context.Context, root string, limits scanLimits) (out []ports.CodeAnalysisRawFinding, err error) {
	if root == "" {
		return nil, nil
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("analyze root %q: %w", root, err)
	}
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("open analysis root %q: %w", root, err)
	}
	defer func() {
		if closeErr := rootDir.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close analysis root %q: %w", root, closeErr))
		}
	}()

	collector := newFindingCollector(maxFindings)
	visited := 0
	var bytesRead int64
	walkErr := fs.WalkDir(rootDir.FS(), ".", func(path string, d fs.DirEntry, walkEntryErr error) error {
		if walkEntryErr != nil {
			return fmt.Errorf("walk entry %q: %w", path, walkEntryErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		visited++
		if visited > limits.files {
			return fmt.Errorf("%w: regular file limit %d reached", ErrScanBudget, limits.files)
		}

		// enry.IsVendor check before expensive open/read.
		if enry.IsVendor(path) {
			return nil
		}

		walkInfo, infoErr := d.Info()
		if infoErr != nil {
			return fmt.Errorf("stat walk entry %q: %w", path, infoErr)
		}
		if !walkInfo.Mode().IsRegular() {
			return nil
		}
		f, openedInfo, openErr := openRegularBeneath(rootDir, path, walkInfo)
		if openErr != nil {
			return fmt.Errorf("open %q: %w", path, openErr)
		}

		remaining := limits.bytes - bytesRead
		if remaining < 0 {
			_ = f.Close()
			return fmt.Errorf("%w: byte limit %d reached", ErrScanBudget, limits.bytes)
		}
		rel := filepath.ToSlash(path)
		result, readErr := scanOpenedFile(ctx, f, openedInfo, rel, notebook.IsPath(path), remaining)
		bytesRead += result.bytesRead
		if readErr != nil {
			return readErr
		}
		if result.rejected {
			return nil
		}
		collector.merge(result.textFindings, result.textObserved)

		if result.notebook {
			if result.actualSize > maxNotebookBytes || enry.IsDotFile(path) {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			doc, parseErr := notebook.Parse(result.prefix)
			if parseErr != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if findingsErr := notebookFindings(ctx, doc, rel, collector.add); findingsErr != nil {
				return findingsErr
			}
			if strings.EqualFold(doc.KernelLanguage, "python") {
				for _, cell := range doc.Cells {
					if err := ctx.Err(); err != nil {
						return err
					}
					if cell.Type != "code" {
						continue
					}
					if err := a.scanFile(ctx, notebook.Location(rel, cell.Index), ".py", []byte(cell.Source), collector.add); err != nil {
						return err
					}
				}
			}
			return nil
		}

		if enry.IsDotFile(path) || result.actualSize > maxFileBytes {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		lang := enry.GetLanguage(filepath.Base(path), result.prefix)
		isXML := isXMLSource(ext, lang)
		if lang == "" && !isXML {
			return nil
		}
		if !isXML {
			switch enry.GetLanguageType(lang) {
			case enry.Programming, enry.Markup:
			default:
				return nil
			}
		}
		if isXML {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, hit := range scanXMLFile(rel, result.prefix) {
				collector.add(hit)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err := a.scanFile(ctx, rel, ext, result.prefix, collector.add); err != nil {
			return err
		}
		return ctx.Err()
	})
	if walkErr != nil {
		return collector.findings(), fmt.Errorf("analyze %q: walk source tree: %w", root, walkErr)
	}
	if err := ctx.Err(); err != nil {
		return collector.findings(), fmt.Errorf("analyze %q: %w", root, err)
	}
	out = collector.findings()
	if collector.truncated() {
		return out, fmt.Errorf("%w: %d retained of %d observed", ErrFindingsTruncated, len(out), collector.observed)
	}
	return out, nil
}

func openRegularBeneath(root *os.Root, rel string, walkInfo fs.FileInfo) (*os.File, fs.FileInfo, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := func(err error) (*os.File, fs.FileInfo, error) {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("stat opened file %q: %w", rel, err))
	}
	if !info.Mode().IsRegular() || !os.SameFile(walkInfo, info) {
		return closeOnError(fmt.Errorf("%w: %q identity mismatch after open", ErrFileChanged, rel))
	}
	return f, info, nil
}

type scannedFile struct {
	prefix       []byte
	textFindings []ports.CodeAnalysisRawFinding
	textObserved int
	bytesRead    int64
	actualSize   int64
	rejected     bool
	notebook     bool
}

// safeInt clamps an int64 to the int range so capacity hints from fs.FileInfo.Size
// never silently wrap on 32-bit or small-int platforms.
func safeInt(v int64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	if v < 0 {
		return 0
	}
	return int(v)
}

func scanOpenedFile(ctx context.Context, f *os.File, before fs.FileInfo, rel string, isNotebook bool, byteBudget int64) (result scannedFile, err error) {
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close scanned file %q: %w", rel, closeErr))
		}
	}()

	prefixLimit := maxFileBytes + 1
	if isNotebook {
		prefixLimit = maxNotebookBytes + 1
	}
	result.notebook = isNotebook
	result.prefix = make([]byte, 0, safeInt(min(int64(prefixLimit), before.Size())))
	head := make([]byte, 0, safeInt(min(int64(classificationBytes), before.Size())))
	fileCollector := newFindingCollector(maxFindings)
	scanner := newTextScanner(ctx, rel, strings.ToLower(filepath.Ext(rel)), fileCollector.add)
	buffer := make([]byte, readChunkBytes)
	classified := false

	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		allowed := byteBudget - result.bytesRead
		if allowed < 0 {
			return result, fmt.Errorf("%w: byte limit reached while reading %q", ErrScanBudget, rel)
		}
		readBuffer := buffer
		if !classified && len(head) < classificationBytes {
			readBuffer = readBuffer[:min(len(readBuffer), classificationBytes-len(head))]
		}
		if allowed < int64(len(readBuffer)) {
			readBuffer = readBuffer[:allowed+1]
		}
		n, readErr := f.Read(readBuffer)
		if n > 0 {
			result.bytesRead += int64(n)
			if result.bytesRead > byteBudget {
				return result, fmt.Errorf("%w: byte limit reached while reading %q", ErrScanBudget, rel)
			}
			chunk := readBuffer[:n]
			if !classified {
				head = append(head, chunk...)
			} else if writeErr := scanner.write(chunk); writeErr != nil {
				return result, writeErr
			}
			if len(result.prefix) < prefixLimit {
				take := min(len(chunk), prefixLimit-len(result.prefix))
				result.prefix = append(result.prefix, chunk[:take]...)
			}
		}

		eof := errors.Is(readErr, io.EOF)
		if !classified && (len(head) == classificationBytes || eof) {
			classified = true
			result.rejected = enry.IsGenerated(rel, head) || enry.IsBinary(head) || bytes.IndexByte(head, 0) >= 0
			if result.rejected {
				after, statErr := f.Stat()
				if statErr != nil || !stableFileMetadata(before, after) {
					return result, fmt.Errorf("%w: %q", ErrFileChanged, rel)
				}
				return result, nil
			}
			if writeErr := scanner.write(head); writeErr != nil {
				return result, writeErr
			}
		}
		if readErr != nil {
			if eof {
				break
			}
			return result, fmt.Errorf("read file %q: %w", rel, readErr)
		}
	}
	result.actualSize = result.bytesRead
	if err := scanner.finish(true); err != nil {
		return result, err
	}

	after, statErr := f.Stat()
	if statErr != nil {
		return result, fmt.Errorf("%w: stat %q after read: %v", ErrFileChanged, rel, statErr)
	}
	// ponytail: same-size writes that preserve modification time require a filesystem
	// snapshot or file lock; add one if adversarial concurrent writers enter scope.
	if !stableFileSnapshot(before, after, result.actualSize) {
		return result, fmt.Errorf("%w: %q", ErrFileChanged, rel)
	}
	result.textFindings = fileCollector.findings()
	result.textObserved = fileCollector.observed
	return result, nil
}

func stableFileMetadata(before, after fs.FileInfo) bool {
	return before.Mode().IsRegular() && after.Mode().IsRegular() && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func stableFileSnapshot(before, after fs.FileInfo, bytesRead int64) bool {
	return stableFileMetadata(before, after) && after.Size() == bytesRead
}

// maxRuleScanLine is the byte threshold beyond which a physical line is skipped
// by the legacy rule scanner. Lines exceeding this limit are still counted so
// that subsequent line numbers remain correct.
const maxRuleScanLine = 8 << 10 // 8 KiB

// legacyContextPoll is the number of content bytes between context cancellation
// checks in scanFile so that long-running legacy scans remain cancellable.
const legacyContextPoll = 64 << 10 // 64 KiB

// scanFile applies every applicable legacy rule to each retained line and emits
// findings directly via the callback, avoiding unbounded intermediate
// allocations. Lines longer than maxRuleScanLine are skipped but still counted
// so that physical line numbers stay correct. The ctx is polled periodically so
// long scans remain cancellable; the caller receives context.Canceled or
// context.DeadlineExceeded when the context expires.
func (a *Analyzer) scanFile(ctx context.Context, rel, ext string, content []byte, emit func(ports.CodeAnalysisRawFinding)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nextPoll := legacyContextPoll
	checkCtx := func(offset int) error {
		if offset >= nextPoll {
			if err := ctx.Err(); err != nil {
				return err
			}
			nextPoll += legacyContextPoll
		}
		return nil
	}
	scanLine := func(lineNo int, line []byte) error {
		if len(line) <= maxRuleScanLine {
			for j := range a.rules {
				r := &a.rules[j]
				if !r.appliesTo(ext) || !r.hit(string(line)) {
					continue
				}
				emit(ports.CodeAnalysisRawFinding{
					Kind: r.kind, RuleID: r.id, CWE: r.cwe, Severity: r.severity,
					Title: r.title, Description: r.desc, File: rel, Line: lineNo,
				})
			}
		}
		return nil
	}
	lineNo := 0
	start := 0
	for i := 0; i < len(content); {
		if err := checkCtx(i); err != nil {
			return err
		}
		if content[i] == '\n' {
			lineNo++
			if err := scanLine(lineNo, trimCR(content[start:i])); err != nil {
				return err
			}
			i++
			start = i
		} else if content[i] == '\r' {
			lineNo++
			if err := scanLine(lineNo, trimCR(content[start:i])); err != nil {
				return err
			}
			i++
			if i < len(content) && content[i] == '\n' {
				i++ // consume LF in CRLF
			}
			start = i
		} else {
			i++
		}
	}
	// Final unterminated line.
	if start < len(content) {
		lineNo++
		if err := scanLine(lineNo, trimCR(content[start:])); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// trimCR removes a trailing \r from the byte slice (handles bare CR at end of CRLF).
func trimCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}

// Package codeanalysis is a deterministic, pure-Go maintainability + reliability rule engine: it walks a
// source tree and flags code smells (Kind=quality) and likely bugs (Kind=reliability) per (file, line),
// mirroring the SAST pattern analyzer. It NEVER executes the target and reads bounded (skips vendored/
// binary/oversized files, follows no symlinks). Metric-derived quality signals (complexity, duplication)
// are layered on top by the codequality usecase.
package codeanalysis

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/notebook"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFileBytes     = 1 << 20
	maxNotebookBytes = 16 << 20
	maxLineBytes     = 4096
	maxFindings      = 2000
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true,
	".vscode": true, ".tox": true, ".hg": true, ".svn": true,
}

// Analyzer is the pure-Go maintainability/reliability pattern engine.
type Analyzer struct{ rules []rule }

// New returns an analyzer with the built-in rule set.
func New() *Analyzer { return &Analyzer{rules: builtinRules()} }

var _ ports.CodeAnalyzer = (*Analyzer)(nil)

// Analyze walks root and returns deterministic quality/reliability findings, oldest-path first. It honors
// ctx cancellation and never aborts the whole scan on a single unreadable file.
func (a *Analyzer) Analyze(ctx context.Context, root string) ([]ports.CodeAnalysisRawFinding, error) {
	if root == "" {
		return nil, nil
	}
	var out []ports.CodeAnalysisRawFinding
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(out) >= maxFindings {
			return fs.SkipAll
		}
		fi, lerr := os.Lstat(path)
		maxBytes := int64(maxFileBytes)
		if notebook.IsPath(path) {
			maxBytes = maxNotebookBytes
		}
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > maxBytes {
			return nil
		}
		content, rerr := os.ReadFile(path) // #nosec G304 -- regular file, size-capped via Lstat above, under the walked root
		if rerr != nil {
			return nil
		}
		if enry.IsVendor(path) || enry.IsDotFile(path) || enry.IsGenerated(path, content) || enry.IsBinary(content) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if notebook.IsPath(path) {
			doc, err := notebook.Parse(content)
			if err != nil {
				return nil
			}
			hits := notebookFindings(doc, rel)
			remaining := maxFindings - len(out)
			if len(hits) > remaining {
				hits = hits[:remaining]
			}
			out = append(out, hits...)
			if strings.EqualFold(doc.KernelLanguage, "python") {
				for _, cell := range doc.Cells {
					if cell.Type != "code" {
						continue
					}
					remaining := maxFindings - len(out)
					if remaining <= 0 {
						return fs.SkipAll
					}
					hits := a.scanFile(notebook.Location(rel, cell.Index), ".py", []byte(cell.Source))
					if len(hits) > remaining {
						hits = hits[:remaining]
					}
					out = append(out, hits...)
				}
			}
			if len(out) >= maxFindings {
				return fs.SkipAll
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		lang := enry.GetLanguage(filepath.Base(path), content)
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
			out = append(out, scanXMLFile(rel, content)...)
		}
		out = append(out, a.scanFile(rel, ext, content)...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

// scanFile applies every applicable rule to each line of one file.
func (a *Analyzer) scanFile(rel, ext string, content []byte) []ports.CodeAnalysisRawFinding {
	var out []ports.CodeAnalysisRawFinding
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes*2)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if len(line) > maxLineBytes {
			continue // minified/blob line
		}
		for i := range a.rules {
			r := &a.rules[i]
			if !r.appliesTo(ext) || !r.hit(line) {
				continue
			}
			out = append(out, ports.CodeAnalysisRawFinding{
				Kind:        r.kind,
				RuleID:      r.id,
				CWE:         r.cwe,
				Severity:    r.severity,
				Title:       r.title,
				Description: r.desc,
				File:        rel,
				Line:        lineNo,
			})
		}
	}
	return out
}

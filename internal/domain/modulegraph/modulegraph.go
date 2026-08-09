// Package modulegraph defines the deterministic, source-only JavaScript and
// TypeScript module graph used by the first phase of import reachability.
//
// This package is intentionally pure domain code. It performs no filesystem,
// parser, package-manager, network, SCA, judgment, or OpenVEX work.
package modulegraph

import "strings"

// Dialect identifies the source grammar family associated with a module.
type Dialect string

const (
	DialectJavaScript Dialect = "javascript"
	DialectJSX        Dialect = "jsx"
	DialectTypeScript Dialect = "typescript"
	DialectTSX        Dialect = "tsx"
)

// Valid reports whether d is a supported source dialect.
func (d Dialect) Valid() bool {
	switch d {
	case DialectJavaScript, DialectJSX, DialectTypeScript, DialectTSX:
		return true
	default:
		return false
	}
}

// Module is a first-party JavaScript or TypeScript source module.
type Module struct {
	// Path is a normalized repository-relative slash path.
	Path string
	// Dialect records the lexical grammar family selected from Path.
	Dialect Dialect
	// DeclarationOnly is true only for .d.ts, .d.mts, and .d.cts files.
	DeclarationOnly bool
}

// ImportKind identifies a statically observed module-loading form.
type ImportKind string

const (
	ImportESMStatic       ImportKind = "esm-static"
	ImportESMDynamic      ImportKind = "esm-dynamic-literal"
	ImportCommonJS        ImportKind = "commonjs-literal"
	ImportReExport        ImportKind = "re-export"
	ImportTypeScriptEqual ImportKind = "typescript-import-equals"
)

// Valid reports whether k is a supported import kind.
func (k ImportKind) Valid() bool {
	switch k {
	case ImportESMStatic, ImportESMDynamic, ImportCommonJS, ImportReExport, ImportTypeScriptEqual:
		return true
	default:
		return false
	}
}

// Binding describes statically observable symbol binding information.
type Binding struct {
	Imported  string
	Local     string
	Default   bool
	Namespace bool
	TypeOnly  bool
}

// Position is a 1-based source position. Zero values mean unavailable.
type Position struct {
	Line   int
	Column int
}

// Edge is an observed module relationship.
type Edge struct {
	// From is always a normalized repository-relative source path.
	From string
	// To is set only for a uniquely resolved first-party relative import.
	// External or unresolved specifiers leave To empty.
	To string
	// Specifier preserves the scanner's normalized module specifier.
	Specifier string
	Kind      ImportKind
	Bindings  []Binding
	TypeOnly  bool
	Position  Position
}

// LocalUseKind classifies what a module does with a local name bound by an import.
//
// It exists for Tier-2 (affected-symbol) reachability: a named import already says which export is
// bound, but a whole-module binding (`import * as _`, `import _ from`, `const _ = require(...)`) reaches
// a specific export only through what the module then DOES with that local.
type LocalUseKind string

const (
	// LocalUseProperty is an observable property read: `_.template`. It names one export.
	LocalUseProperty LocalUseKind = "property"
	// LocalUseOpaque is any other reference to the local. The whole module object escapes, so ANY export
	// could be reached through it and no symbol-level negative is safe.
	LocalUseOpaque LocalUseKind = "opaque"
)

// Valid reports whether k is a known local use kind.
func (k LocalUseKind) Valid() bool {
	switch k {
	case LocalUseProperty, LocalUseOpaque:
		return true
	default:
		return false
	}
}

// LocalUse is one observed reference to a local name inside a module.
//
// The scanner emits one per reference to a local that some import in the same module binds. A local no
// import binds could never contribute evidence, so filtering those out is a memory decision rather than
// a semantic one; a local that is rebound or shadowed still contributes ALL its references, which
// over-approximates toward reachable.
type LocalUse struct {
	// Module is the normalized repository-relative path of the referencing module.
	Module string
	// Local is the identifier being referenced.
	Local string
	// Property is the member name for LocalUseProperty, empty otherwise.
	Property string
	Kind     LocalUseKind
	// Detail explains an opaque reference in words ("indexed with a computed key"). It never carries
	// source text.
	Detail string
	Line   int
}

// CoverageIssueKind identifies a condition that prevents a later analyzer from
// treating absence of an edge as a definitive negative proof.
type CoverageIssueKind string

const (
	CoverageUnreadableFile            CoverageIssueKind = "unreadable-file"
	CoverageSymlink                   CoverageIssueKind = "symlink"
	CoverageInvalidUTF8               CoverageIssueKind = "invalid-utf8"
	CoverageFileTooLarge              CoverageIssueKind = "file-too-large"
	CoverageFileCountBudgetExceeded   CoverageIssueKind = "file-count-budget-exceeded"
	CoverageTotalByteBudgetExceeded   CoverageIssueKind = "total-byte-budget-exceeded"
	CoverageMalformedSource           CoverageIssueKind = "malformed-source"
	CoverageUnsupportedSyntax         CoverageIssueKind = "unsupported-syntax"
	CoverageDynamicRequire            CoverageIssueKind = "dynamic-require"
	CoverageDynamicImport             CoverageIssueKind = "dynamic-import"
	CoverageEval                      CoverageIssueKind = "eval"
	CoverageNewFunction               CoverageIssueKind = "new-function"
	CoverageRequireContext            CoverageIssueKind = "require-context"
	CoverageImportMetaGlob            CoverageIssueKind = "import-meta-glob"
	CoverageModuleCreateRequire       CoverageIssueKind = "module-create-require"
	CoverageUnsupportedLoader         CoverageIssueKind = "unsupported-loader"
	CoverageUnresolvedRelativeImport  CoverageIssueKind = "unresolved-relative-import"
	CoverageAmbiguousRelativeImport   CoverageIssueKind = "ambiguous-relative-import"
	CoverageRelativeImportEscapesRoot CoverageIssueKind = "relative-import-escapes-root"
	// The remaining budgets are distinct kinds so a consumer can tell WHICH bound fired. Reusing one
	// kind for several bounds hides, for example, a truncated coverage list behind a file-count message.
	CoverageEntryBudgetExceeded CoverageIssueKind = "entry-budget-exceeded"
	CoverageEdgeBudgetExceeded  CoverageIssueKind = "edge-budget-exceeded"
	CoverageIssueBudgetExceeded CoverageIssueKind = "issue-budget-exceeded"
	// CoverageSkippedDirectory records a directory excluded from the scan that nonetheless contained
	// supported source. Excluding build output or a tool directory is a policy choice, but the modules
	// inside it are unobserved, so their imports must not be read as absent.
	CoverageSkippedDirectory CoverageIssueKind = "skipped-directory"
	// CoverageSymbolEvidenceIncomplete records that a module's symbol references could not be fully
	// enumerated. It appears only in SymbolEvidence.Coverage: the import graph is unaffected.
	CoverageSymbolEvidenceIncomplete CoverageIssueKind = "symbol-evidence-incomplete"
)

// Valid reports whether k is a known R1 coverage issue kind.
func (k CoverageIssueKind) Valid() bool {
	switch k {
	case CoverageUnreadableFile,
		CoverageSymlink,
		CoverageInvalidUTF8,
		CoverageFileTooLarge,
		CoverageFileCountBudgetExceeded,
		CoverageTotalByteBudgetExceeded,
		CoverageMalformedSource,
		CoverageUnsupportedSyntax,
		CoverageDynamicRequire,
		CoverageDynamicImport,
		CoverageEval,
		CoverageNewFunction,
		CoverageRequireContext,
		CoverageImportMetaGlob,
		CoverageModuleCreateRequire,
		CoverageUnsupportedLoader,
		CoverageUnresolvedRelativeImport,
		CoverageAmbiguousRelativeImport,
		CoverageRelativeImportEscapesRoot,
		CoverageEntryBudgetExceeded,
		CoverageEdgeBudgetExceeded,
		CoverageIssueBudgetExceeded,
		CoverageSkippedDirectory,
		CoverageSymbolEvidenceIncomplete:
		return true
	default:
		return false
	}
}

// CoverageIssue records a deterministic and attributable coverage limitation.
type CoverageIssue struct {
	Kind   CoverageIssueKind
	Path   string
	Line   int
	Detail string
}

// Graph is the normalized scanner output for one repository root.
type Graph struct {
	Modules []Module
	Edges   []Edge
	// Roots contains structural roots only: modules with no incoming resolved
	// first-party edge. It is not a set of verified runtime entrypoints.
	Roots []string
	// SymbolEvidence is the Tier-2 view: what each module does with the locals its imports bind. It is
	// a POINTER so "not collected" and "collected and empty" are different states — the distinction is
	// the whole safety property, because only the second one permits a negative conclusion. Use
	// Complete() rather than testing the slice.
	SymbolEvidence *SymbolEvidence
	Coverage       []CoverageIssue
	FilesScanned   int
	BytesScanned   int64
}

// SymbolEvidence carries the Tier-2 symbol observations for one scan.
type SymbolEvidence struct {
	// Uses are the observed references, deterministically ordered.
	Uses []LocalUse
	// JSXModules are the modules that actually contain JSX, whatever their extension. JSX desugars into
	// calls on the runtime binding that never appear as source tokens, so a whole-module binding in one
	// of these modules cannot be narrowed by its visible property reads.
	JSXModules []string
	// Coverage records limitations of the SYMBOL evidence specifically.
	//
	// It is deliberately separate from Graph.Coverage. A Tier-2 budget breach says nothing about whether
	// the import graph is complete, and folding it into the graph's coverage would make a Tier-2-only
	// limitation refuse a Tier-1 answer that is still perfectly sound.
	Coverage []CoverageIssue
}

// Complete reports whether the symbol evidence may be used to conclude that an export is NOT reached.
// A nil receiver (never collected) and any coverage limitation both mean no.
func (e *SymbolEvidence) Complete() bool { return e != nil && len(e.Coverage) == 0 }

// DialectForPath returns the dialect selected by a supported source extension.
func DialectForPath(p string) (Dialect, bool) {
	lower := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lower, ".tsx"):
		return DialectTSX, true
	case strings.HasSuffix(lower, ".jsx"):
		return DialectJSX, true
	case strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".mts"), strings.HasSuffix(lower, ".cts"):
		return DialectTypeScript, true
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".mjs"), strings.HasSuffix(lower, ".cjs"):
		return DialectJavaScript, true
	default:
		return "", false
	}
}

// IsDeclarationPath reports whether p is a TypeScript declaration source file.
func IsDeclarationPath(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".d.ts") ||
		strings.HasSuffix(lower, ".d.mts") ||
		strings.HasSuffix(lower, ".d.cts")
}

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
		CoverageRelativeImportEscapesRoot:
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
	Roots        []string
	Coverage     []CoverageIssue
	FilesScanned int
	BytesScanned int64
}

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

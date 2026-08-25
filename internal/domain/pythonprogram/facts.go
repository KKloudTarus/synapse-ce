// Package pythonprogram defines the deterministic, source-only semantic facts used by Python Tier-2
// reachability and value-flow taint. The model is parser-independent: tree-sitter is confined to the
// synapse-ast infrastructure sidecar and every document is validated here before a use case trusts it.
package pythonprogram

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// SchemaVersion is the only semantic-facts wire version this build understands.
	SchemaVersion = 1

	maxFiles       = 200_000
	maxSymbols     = 2_000_000
	maxFacts       = 4_000_000
	maxParameters  = 1_024
	maxArguments   = 4_096
	maxSegments    = 256
	maxStringBytes = 4_096
)

// SymbolKind identifies a Python declaration that owns a lexical scope or can appear in a call graph.
type SymbolKind string

const (
	SymbolModule   SymbolKind = "module"
	SymbolClass    SymbolKind = "class"
	SymbolFunction SymbolKind = "function"
	SymbolMethod   SymbolKind = "method"
	SymbolLambda   SymbolKind = "lambda"
)

func (k SymbolKind) Valid() bool {
	switch k {
	case SymbolModule, SymbolClass, SymbolFunction, SymbolMethod, SymbolLambda:
		return true
	}
	return false
}

// ParameterKind preserves Python's argument-binding semantics without carrying annotations/default text.
type ParameterKind string

const (
	ParameterPositional  ParameterKind = "positional"
	ParameterVarArgs     ParameterKind = "varargs"
	ParameterKwArgs      ParameterKind = "kwargs"
	ParameterKeywordOnly ParameterKind = "keyword_only"
)

func (k ParameterKind) Valid() bool {
	return k == ParameterPositional || k == ParameterVarArgs || k == ParameterKwArgs || k == ParameterKeywordOnly
}

// ReferenceKind describes a bounded expression shape. It intentionally excludes arbitrary source text.
type ReferenceKind string

const (
	ReferenceName      ReferenceKind = "name"
	ReferenceAttribute ReferenceKind = "attribute"
	ReferenceCall      ReferenceKind = "call"
	ReferenceLiteral   ReferenceKind = "literal"
	ReferenceUnknown   ReferenceKind = "unknown"
)

func (k ReferenceKind) Valid() bool {
	switch k {
	case ReferenceName, ReferenceAttribute, ReferenceCall, ReferenceLiteral, ReferenceUnknown:
		return true
	}
	return false
}

// GapKind is a closed reason code explaining why absence cannot be treated as proof.
type GapKind string

const (
	GapParseRecovery        GapKind = "parse_recovery"
	GapDynamicImport        GapKind = "dynamic_import"
	GapDynamicExecution     GapKind = "dynamic_execution"
	GapWildcardImport       GapKind = "wildcard_import"
	GapUnresolvedImport     GapKind = "unresolved_import"
	GapUnresolvedCall       GapKind = "unresolved_call"
	GapUnresolvedValue      GapKind = "unresolved_value"
	GapDynamicAttribute     GapKind = "dynamic_attribute"
	GapUnsupportedDecorator GapKind = "unsupported_decorator"
	GapUnsupportedNotebook  GapKind = "unsupported_notebook"
	GapBudget               GapKind = "budget"
	GapUnreadable           GapKind = "unreadable"
)

func (k GapKind) Valid() bool {
	switch k {
	case GapParseRecovery, GapDynamicImport, GapDynamicExecution, GapWildcardImport, GapUnresolvedImport,
		GapUnresolvedCall, GapUnresolvedValue,
		GapDynamicAttribute, GapUnsupportedDecorator, GapUnsupportedNotebook, GapBudget, GapUnreadable:
		return true
	}
	return false
}

// Position is a normalized, relative source location. Column is zero-based, Line is one-based.
type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// Reference is a safe expression summary such as ["request", "args", "get"]. No source body or
// literal value is retained. Literal references only carry Kind, not their value.
type Reference struct {
	Kind     ReferenceKind `json:"kind"`
	Segments []string      `json:"segments,omitempty"`
}

// Parameter is one callable parameter in declaration order.
type Parameter struct {
	Name string        `json:"name"`
	Kind ParameterKind `json:"kind"`
	Pos  Position      `json:"position"`
}

// Module associates a canonical module candidate with its source file.
type Module struct {
	Name string   `json:"name"`
	File string   `json:"file"`
	Pos  Position `json:"position"`
}

// Symbol is a module, class, function, method, or lambda declaration.
type Symbol struct {
	ID            string      `json:"id"`
	Module        string      `json:"module"`
	QualifiedName string      `json:"qualified_name"`
	Name          string      `json:"name"`
	ParentID      string      `json:"parent_id,omitempty"`
	Kind          SymbolKind  `json:"kind"`
	Pos           Position    `json:"position"`
	Parameters    []Parameter `json:"parameters,omitempty"`
	Decorators    []Reference `json:"decorators,omitempty"`
	Bases         []Reference `json:"bases,omitempty"`
	Async         bool        `json:"async,omitempty"`
}

// Import records one import binding. ScopeID is the module/function/class lexical owner. For
// `from ..pkg import item`, Module="pkg", Name="item", and Level=2.
type Import struct {
	ScopeID  string   `json:"scope_id"`
	Module   string   `json:"module"`
	Name     string   `json:"name,omitempty"`
	Alias    string   `json:"alias,omitempty"`
	Level    int      `json:"level,omitempty"`
	Wildcard bool     `json:"wildcard,omitempty"`
	Pos      Position `json:"position"`
}

// Argument is one positional or keyword call argument. Starred values carry Star=true; double-starred
// values carry Keyword="**". Value is a bounded reference summary.
type Argument struct {
	Keyword string    `json:"keyword,omitempty"`
	Star    bool      `json:"star,omitempty"`
	Value   Reference `json:"value"`
}

// Call is one syntactic call expression owned by CallerID. Callee is a name/attribute reference when
// statically expressible, otherwise ReferenceUnknown and a matching coverage gap is required.
type Call struct {
	ID        string     `json:"id"`
	CallerID  string     `json:"caller_id"`
	Callee    Reference  `json:"callee"`
	Arguments []Argument `json:"arguments,omitempty"`
	Pos       Position   `json:"position"`
	Await     bool       `json:"await,omitempty"`
}

// Assignment captures a binding/value relationship without retaining expression text.
type Assignment struct {
	ScopeID string      `json:"scope_id"`
	Targets []Reference `json:"targets"`
	Value   Reference   `json:"value"`
	Pos     Position    `json:"position"`
}

// Return captures a function return expression summary.
type Return struct {
	ScopeID string    `json:"scope_id"`
	Value   Reference `json:"value"`
	Pos     Position  `json:"position"`
}

// EntrypointHint is a syntactic framework/application entrypoint cue. Resolution decides whether it is
// usable; extraction does not silently promote an arbitrary decorator into an entrypoint.
type EntrypointHint struct {
	SymbolID string   `json:"symbol_id"`
	Kind     string   `json:"kind"`
	Pos      Position `json:"position"`
}

// CoverageGap is an explicit reason a complete negative is unsafe. Detail is a trusted closed label,
// not parser stderr or target source.
type CoverageGap struct {
	Kind     GapKind  `json:"kind"`
	SymbolID string   `json:"symbol_id,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Pos      Position `json:"position"`
}

// Document is the complete versioned facts result for one source root.
type Document struct {
	SchemaVersion int              `json:"schema_version"`
	Modules       []Module         `json:"modules"`
	Symbols       []Symbol         `json:"symbols"`
	Imports       []Import         `json:"imports"`
	Calls         []Call           `json:"calls"`
	Assignments   []Assignment     `json:"assignments"`
	Returns       []Return         `json:"returns"`
	Entrypoints   []EntrypointHint `json:"entrypoint_hints"`
	CoverageGaps  []CoverageGap    `json:"coverage_gaps"`
	FilesSeen     int              `json:"files_seen"`
	FilesParsed   int              `json:"files_parsed"`
	NodesSeen     int              `json:"nodes_seen"`
	Truncated     bool             `json:"truncated"`
}

// Complete reports whether the document can support a negative proof.
func (d Document) Complete() bool {
	return !d.Truncated && len(d.CoverageGaps) == 0 && d.FilesSeen > 0 && d.FilesSeen == d.FilesParsed
}

// Validate rejects malformed or unbounded sidecar output at the trust boundary.
func (d Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported python facts schema version %d", shared.ErrValidation, d.SchemaVersion)
	}
	if d.FilesSeen < 0 || d.FilesParsed < 0 || d.FilesParsed > d.FilesSeen || d.FilesSeen > maxFiles || d.NodesSeen < 0 {
		return fmt.Errorf("%w: invalid python facts coverage counters", shared.ErrValidation)
	}
	if len(d.Modules) > maxFiles || len(d.Symbols) > maxSymbols || len(d.Imports) > maxFacts ||
		len(d.Calls) > maxFacts || len(d.Assignments) > maxFacts || len(d.Returns) > maxFacts ||
		len(d.Entrypoints) > maxFacts || len(d.CoverageGaps) > maxFacts {
		return fmt.Errorf("%w: python facts document exceeds bounds", shared.ErrValidation)
	}
	moduleSet := make(map[string]bool, len(d.Modules))
	fileSet := make(map[string]bool, len(d.Modules))
	for _, m := range d.Modules {
		if !validDotted(m.Name) || validatePosition(m.Pos, true) != nil || m.File != m.Pos.File {
			return fmt.Errorf("%w: invalid python module fact", shared.ErrValidation)
		}
		if moduleSet[m.Name] || fileSet[m.File] {
			return fmt.Errorf("%w: duplicate python module or file", shared.ErrValidation)
		}
		moduleSet[m.Name], fileSet[m.File] = true, true
	}
	symbolSet := make(map[string]Symbol, len(d.Symbols))
	for _, s := range d.Symbols {
		validSymbolName := validName(s.Name)
		if s.Kind == SymbolLambda {
			validSymbolName = validSyntheticLambdaName(s.Name)
		}
		if !s.Kind.Valid() || !validText(s.ID) || !strings.HasPrefix(s.ID, "python:") || !moduleSet[s.Module] ||
			!validQualified(s.QualifiedName) || !validSymbolName || validatePosition(s.Pos, true) != nil || len(s.Parameters) > maxParameters {
			return fmt.Errorf("%w: invalid python symbol fact", shared.ErrValidation)
		}
		if _, duplicate := symbolSet[s.ID]; duplicate {
			return fmt.Errorf("%w: duplicate python symbol %q", shared.ErrValidation, s.ID)
		}
		for _, p := range s.Parameters {
			if !validName(p.Name) || !p.Kind.Valid() || validatePosition(p.Pos, true) != nil {
				return fmt.Errorf("%w: invalid python parameter fact", shared.ErrValidation)
			}
		}
		for _, decorator := range s.Decorators {
			if err := validateReference(decorator); err != nil {
				return err
			}
		}
		for _, base := range s.Bases {
			if err := validateReference(base); err != nil {
				return err
			}
		}
		symbolSet[s.ID] = s
	}
	for _, s := range d.Symbols {
		if s.ParentID != "" {
			if _, ok := symbolSet[s.ParentID]; !ok {
				return fmt.Errorf("%w: python symbol parent does not exist", shared.ErrValidation)
			}
		}
	}
	validScope := func(scope string) bool { _, ok := symbolSet[scope]; return ok }
	for _, item := range d.Imports {
		if !validScope(item.ScopeID) || item.Level < 0 || item.Level > maxSegments || !validOptionalDotted(item.Module) ||
			!validOptionalName(item.Name) || !validOptionalName(item.Alias) || validatePosition(item.Pos, true) != nil || item.Wildcard != (item.Name == "*") {
			return fmt.Errorf("%w: invalid python import fact", shared.ErrValidation)
		}
	}
	callSet := make(map[string]bool, len(d.Calls))
	for _, item := range d.Calls {
		if !validText(item.ID) || callSet[item.ID] || !validScope(item.CallerID) || len(item.Arguments) > maxArguments || validatePosition(item.Pos, true) != nil {
			return fmt.Errorf("%w: invalid python call fact", shared.ErrValidation)
		}
		if err := validateReference(item.Callee); err != nil {
			return err
		}
		for _, arg := range item.Arguments {
			if !validOptionalName(arg.Keyword) && arg.Keyword != "**" {
				return fmt.Errorf("%w: invalid python call keyword", shared.ErrValidation)
			}
			if err := validateReference(arg.Value); err != nil {
				return err
			}
		}
		callSet[item.ID] = true
	}
	for _, item := range d.Assignments {
		if !validScope(item.ScopeID) || len(item.Targets) == 0 || len(item.Targets) > maxArguments || validatePosition(item.Pos, true) != nil {
			return fmt.Errorf("%w: invalid python assignment fact", shared.ErrValidation)
		}
		for _, target := range item.Targets {
			if err := validateReference(target); err != nil {
				return err
			}
		}
		if err := validateReference(item.Value); err != nil {
			return err
		}
	}
	for _, item := range d.Returns {
		if !validScope(item.ScopeID) || validatePosition(item.Pos, true) != nil {
			return fmt.Errorf("%w: invalid python return fact", shared.ErrValidation)
		}
		if err := validateReference(item.Value); err != nil {
			return err
		}
	}
	for _, item := range d.Entrypoints {
		if !validScope(item.SymbolID) || !validText(item.Kind) || validatePosition(item.Pos, true) != nil {
			return fmt.Errorf("%w: invalid python entrypoint hint", shared.ErrValidation)
		}
	}
	for _, gap := range d.CoverageGaps {
		if !gap.Kind.Valid() || gap.SymbolID != "" && !validScope(gap.SymbolID) || !validOptionalText(gap.Detail) || validatePosition(gap.Pos, false) != nil {
			return fmt.Errorf("%w: invalid python coverage gap", shared.ErrValidation)
		}
	}
	return nil
}

func validateReference(ref Reference) error {
	if !ref.Kind.Valid() || len(ref.Segments) > maxSegments {
		return fmt.Errorf("%w: invalid python reference", shared.ErrValidation)
	}
	if (ref.Kind == ReferenceName || ref.Kind == ReferenceAttribute || ref.Kind == ReferenceCall) && len(ref.Segments) == 0 {
		return fmt.Errorf("%w: named python reference needs segments", shared.ErrValidation)
	}
	if (ref.Kind == ReferenceLiteral || ref.Kind == ReferenceUnknown) && len(ref.Segments) != 0 {
		return fmt.Errorf("%w: opaque python reference cannot carry text", shared.ErrValidation)
	}
	for _, segment := range ref.Segments {
		if !validName(segment) {
			return fmt.Errorf("%w: invalid python reference segment", shared.ErrValidation)
		}
	}
	return nil
}

func validatePosition(pos Position, requireFile bool) error {
	if pos.Line < 0 || pos.Column < 0 || requireFile && pos.Line == 0 {
		return fmt.Errorf("invalid position counters")
	}
	if pos.File == "" {
		if requireFile {
			return fmt.Errorf("position file is required")
		}
		return nil
	}
	if !validText(pos.File) || strings.ContainsAny(pos.File, "\\:") || strings.HasPrefix(pos.File, "/") || path.IsAbs(pos.File) || path.Clean(pos.File) != pos.File {
		return fmt.Errorf("position file must be normalized and relative")
	}
	for _, segment := range strings.Split(pos.File, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return fmt.Errorf("position file contains an unsafe segment")
		}
	}
	return nil
}

func validDotted(value string) bool {
	if !validText(value) {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > maxSegments {
		return false
	}
	for _, part := range parts {
		if !validName(part) {
			return false
		}
	}
	return true
}

func validQualified(value string) bool {
	if strings.Contains(value, "<module>") {
		return value == "<module>"
	}
	for _, part := range strings.Split(value, ".") {
		if validName(part) {
			continue
		}
		if validSyntheticLambdaName(part) {
			continue
		}
		return false
	}
	return validText(value)
}

func validSyntheticLambdaName(value string) bool {
	return strings.HasPrefix(value, "<lambda@") && strings.HasSuffix(value, ">") && validText(value)
}

func validName(value string) bool {
	if !validText(value) || value == "*" {
		return false
	}
	for i, r := range value {
		if r == '_' || unicode.IsLetter(r) || i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func validOptionalName(value string) bool   { return value == "" || value == "*" || validName(value) }
func validOptionalDotted(value string) bool { return value == "" || validDotted(value) }
func validOptionalText(value string) bool   { return value == "" || validText(value) }

func validText(value string) bool {
	if value == "" || len(value) > maxStringBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// SortCanonical makes serialization and downstream graph construction independent of map/parser order.
func (d *Document) SortCanonical() {
	if d == nil {
		return
	}
	sort.Slice(d.Modules, func(i, j int) bool { return d.Modules[i].File < d.Modules[j].File })
	sort.Slice(d.Symbols, func(i, j int) bool { return d.Symbols[i].ID < d.Symbols[j].ID })
	sort.Slice(d.Imports, func(i, j int) bool {
		a, b := d.Imports[i], d.Imports[j]
		return factKey(a.Pos, a.ScopeID, a.Module+"."+a.Name+"."+a.Alias) < factKey(b.Pos, b.ScopeID, b.Module+"."+b.Name+"."+b.Alias)
	})
	sort.Slice(d.Calls, func(i, j int) bool { return d.Calls[i].ID < d.Calls[j].ID })
	sort.Slice(d.Assignments, func(i, j int) bool {
		return factKey(d.Assignments[i].Pos, d.Assignments[i].ScopeID, "") < factKey(d.Assignments[j].Pos, d.Assignments[j].ScopeID, "")
	})
	sort.Slice(d.Returns, func(i, j int) bool {
		return factKey(d.Returns[i].Pos, d.Returns[i].ScopeID, "") < factKey(d.Returns[j].Pos, d.Returns[j].ScopeID, "")
	})
	sort.Slice(d.Entrypoints, func(i, j int) bool {
		return d.Entrypoints[i].SymbolID+"\x00"+d.Entrypoints[i].Kind < d.Entrypoints[j].SymbolID+"\x00"+d.Entrypoints[j].Kind
	})
	sort.Slice(d.CoverageGaps, func(i, j int) bool {
		return factKey(d.CoverageGaps[i].Pos, string(d.CoverageGaps[i].Kind), d.CoverageGaps[i].SymbolID) < factKey(d.CoverageGaps[j].Pos, string(d.CoverageGaps[j].Kind), d.CoverageGaps[j].SymbolID)
	})
}

func factKey(pos Position, first, second string) string {
	return fmt.Sprintf("%s\x00%010d\x00%010d\x00%s\x00%s", pos.File, pos.Line, pos.Column, first, second)
}

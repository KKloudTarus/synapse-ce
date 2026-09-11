// Package jsprogram defines the deterministic, source-only semantic facts used by JavaScript/TypeScript
// value-flow taint. It is the JS/TS twin of pythonprogram: the model is parser-independent, tree-sitter is
// confined to the synapse-ast infrastructure sidecar, and every document is validated here before a use
// case trusts it. The differences from Python are language-level: `$` is a legal identifier character,
// modules are identified by their source PATH (not a dotted package name), imports carry a JS ImportKind,
// and symbol ids use a "js:" prefix.
package jsprogram

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

// SymbolKind identifies a JS/TS declaration that owns a lexical scope or can appear in a call graph.
type SymbolKind string

const (
	SymbolModule   SymbolKind = "module"
	SymbolClass    SymbolKind = "class"
	SymbolFunction SymbolKind = "function"
	SymbolMethod   SymbolKind = "method"
	SymbolArrow    SymbolKind = "arrow" // the JS analog of a Python lambda (arrow / anonymous function expression)
)

func (k SymbolKind) Valid() bool {
	switch k {
	case SymbolModule, SymbolClass, SymbolFunction, SymbolMethod, SymbolArrow:
		return true
	}
	return false
}

// ParameterKind preserves JS/TS argument-binding semantics without carrying annotations/default text.
type ParameterKind string

const (
	ParameterPositional   ParameterKind = "positional"
	ParameterRest         ParameterKind = "rest"         // ...args
	ParameterDestructured ParameterKind = "destructured" // {a}/[a] pattern-bound name
	ParameterDefault      ParameterKind = "default"      // a = expr
)

func (k ParameterKind) Valid() bool {
	return k == ParameterPositional || k == ParameterRest || k == ParameterDestructured || k == ParameterDefault
}

// ImportKind records how a binding entered the module. Together with Module (the specifier) it lets the
// taint catalog match a sink/source to its package without resolving the module graph.
type ImportKind string

const (
	ImportNamed     ImportKind = "named"     // import { a as b } from 'm'
	ImportDefault   ImportKind = "default"   // import d from 'm'
	ImportNamespace ImportKind = "namespace" // import * as ns from 'm'
	ImportRequire   ImportKind = "require"   // const x = require('m')
	ImportReexport  ImportKind = "reexport"  // export ... from 'm'
)

func (k ImportKind) Valid() bool {
	switch k {
	case ImportNamed, ImportDefault, ImportNamespace, ImportRequire, ImportReexport:
		return true
	}
	return false
}

// ReferenceKind describes a bounded expression shape. It intentionally excludes arbitrary source text.
type ReferenceKind string

const (
	ReferenceName       ReferenceKind = "name"
	ReferenceAttribute  ReferenceKind = "attribute" // member access a.b.c
	ReferenceCall       ReferenceKind = "call"
	ReferenceExpression ReferenceKind = "expression"
	ReferenceLiteral    ReferenceKind = "literal"
	ReferenceUnknown    ReferenceKind = "unknown"
)

func (k ReferenceKind) Valid() bool {
	switch k {
	case ReferenceName, ReferenceAttribute, ReferenceCall, ReferenceExpression, ReferenceLiteral, ReferenceUnknown:
		return true
	}
	return false
}

// GapKind is a closed reason code explaining why absence cannot be treated as proof.
type GapKind string

const (
	GapParseRecovery    GapKind = "parse_recovery"
	GapDynamicImport    GapKind = "dynamic_import"
	GapDynamicExecution GapKind = "dynamic_execution"
	GapUnresolvedImport GapKind = "unresolved_import"
	GapUnresolvedCall   GapKind = "unresolved_call"
	GapUnresolvedValue  GapKind = "unresolved_value"
	GapDynamicAttribute GapKind = "dynamic_attribute"
	GapBudget           GapKind = "budget"
	GapUnreadable       GapKind = "unreadable"
)

func (k GapKind) Valid() bool {
	switch k {
	case GapParseRecovery, GapDynamicImport, GapDynamicExecution, GapUnresolvedImport, GapUnresolvedCall,
		GapUnresolvedValue, GapDynamicAttribute, GapBudget, GapUnreadable:
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

// Reference is a safe expression summary such as ["req", "query", "id"]. No source body or literal value
// is retained. Literal references only carry Kind, not their value.
type Reference struct {
	Kind     ReferenceKind `json:"kind"`
	Segments []string      `json:"segments,omitempty"`
}

// Parameter is one callable parameter in declaration order.
type Parameter struct {
	Name    string        `json:"name"`
	Kind    ParameterKind `json:"kind"`
	ValueID string        `json:"value_id,omitempty"`
	Pos     Position      `json:"position"`
}

// Module associates a canonical module candidate (its source path without extension) with its source file.
type Module struct {
	Name string   `json:"name"`
	File string   `json:"file"`
	Pos  Position `json:"position"`
}

// Symbol is a module, class, function, method, or arrow declaration.
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
	Bases         []Reference `json:"bases,omitempty"` // the class's `extends` clause (at most one in JS)
	Async         bool        `json:"async,omitempty"`
}

// Import records one import/require binding. Module is the specifier ("express", "./util", "@scope/pkg").
type Import struct {
	ScopeID string     `json:"scope_id"`
	Kind    ImportKind `json:"kind"`
	Module  string     `json:"module"`
	Name    string     `json:"name,omitempty"`  // imported binding name (a named import's original name, or "default")
	Alias   string     `json:"alias,omitempty"` // the local binding introduced in this module
	Pos     Position   `json:"position"`
}

// Argument is one positional or spread call argument. Spread values carry Spread=true.
type Argument struct {
	Spread  bool      `json:"spread,omitempty"`
	Value   Reference `json:"value"`
	ValueID string    `json:"value_id,omitempty"`
	Pos     Position  `json:"position,omitempty"`
}

// Call is one syntactic call (or `new`) expression owned by CallerID. Callee is a name/member reference
// when statically expressible, otherwise ReferenceUnknown; the extractor then also records a coverage gap
// (GapUnresolvedCall) so absence is not read as proof. Validate stays lenient about this pairing on purpose:
// a valid source file must never have its whole facts document rejected, so a missing gap is not an error.
type Call struct {
	ID              string     `json:"id"`
	CallerID        string     `json:"caller_id"`
	Callee          Reference  `json:"callee"`
	Arguments       []Argument `json:"arguments,omitempty"`
	ResultID        string     `json:"result_id,omitempty"`
	ReceiverValueID string     `json:"receiver_value_id,omitempty"`
	Pos             Position   `json:"position"`
	Await           bool       `json:"await,omitempty"`
	New             bool       `json:"new,omitempty"` // a `new X(...)` constructor call
}

// Assignment captures a binding/value relationship without retaining expression text.
type Assignment struct {
	ScopeID   string      `json:"scope_id"`
	Targets   []Reference `json:"targets"`
	TargetIDs []string    `json:"target_ids,omitempty"`
	Value     Reference   `json:"value"`
	ValueID   string      `json:"value_id,omitempty"`
	Pos       Position    `json:"position"`
}

// Return captures a function return expression summary.
type Return struct {
	ScopeID string    `json:"scope_id"`
	Value   Reference `json:"value"`
	ValueID string    `json:"value_id,omitempty"`
	SlotID  string    `json:"slot_id,omitempty"`
	Pos     Position  `json:"position"`
}

// ValueKind identifies a source-level value slot used by the interprocedural taint engine.
type ValueKind string

const (
	ValueParameter  ValueKind = "parameter"
	ValueBinding    ValueKind = "binding"
	ValueReference  ValueKind = "reference"
	ValueCallResult ValueKind = "call_result"
	ValueExpression ValueKind = "expression"
	ValueLiteral    ValueKind = "literal"
	ValueReturn     ValueKind = "return"
)

func (k ValueKind) Valid() bool {
	switch k {
	case ValueParameter, ValueBinding, ValueReference, ValueCallResult, ValueExpression, ValueLiteral, ValueReturn:
		return true
	}
	return false
}

// Value is one stable value slot. Ref carries only a bounded semantic shape; source text is never kept.
type Value struct {
	ID      string    `json:"id"`
	ScopeID string    `json:"scope_id"`
	Kind    ValueKind `json:"kind"`
	Name    string    `json:"name,omitempty"`
	Ref     Reference `json:"reference"`
	Pos     Position  `json:"position"`
}

// ValueFlowKind is a closed intra-procedural propagation operation emitted by the sidecar.
type ValueFlowKind string

const (
	FlowExpression ValueFlowKind = "expression"
	FlowAttribute  ValueFlowKind = "attribute"
	FlowAssignment ValueFlowKind = "assignment"
	FlowReturn     ValueFlowKind = "return"
)

func (k ValueFlowKind) Valid() bool {
	return k == FlowExpression || k == FlowAttribute || k == FlowAssignment || k == FlowReturn
}

// ValueFlow says a value can propagate from one slot to another inside the same JS function.
type ValueFlow struct {
	FromID string        `json:"from_id"`
	ToID   string        `json:"to_id"`
	Kind   ValueFlowKind `json:"kind"`
	Pos    Position      `json:"position"`
}

// EntrypointHint is a syntactic framework/application entrypoint cue.
type EntrypointHint struct {
	SymbolID string   `json:"symbol_id"`
	Kind     string   `json:"kind"`
	Pos      Position `json:"position"`
}

// CoverageGap is an explicit reason a complete negative is unsafe. Detail is a trusted closed label.
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
	Values        []Value          `json:"values"`
	Flows         []ValueFlow      `json:"flows"`
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
		return fmt.Errorf("%w: unsupported js facts schema version %d", shared.ErrValidation, d.SchemaVersion)
	}
	if d.FilesSeen < 0 || d.FilesParsed < 0 || d.FilesParsed > d.FilesSeen || d.FilesSeen > maxFiles || d.NodesSeen < 0 {
		return fmt.Errorf("%w: invalid js facts coverage counters", shared.ErrValidation)
	}
	if len(d.Modules) > maxFiles || len(d.Symbols) > maxSymbols || len(d.Imports) > maxFacts ||
		len(d.Calls) > maxFacts || len(d.Assignments) > maxFacts || len(d.Returns) > maxFacts ||
		len(d.Values) > maxFacts || len(d.Flows) > maxFacts || len(d.Entrypoints) > maxFacts || len(d.CoverageGaps) > maxFacts {
		return fmt.Errorf("%w: js facts document exceeds bounds", shared.ErrValidation)
	}
	moduleSet := make(map[string]bool, len(d.Modules))
	fileSet := make(map[string]bool, len(d.Modules))
	moduleFiles := make(map[string]string, len(d.Modules))
	for _, m := range d.Modules {
		if !validModulePath(m.Name) || validatePosition(m.Pos, true) != nil || m.File != m.Pos.File {
			return fmt.Errorf("%w: invalid js module fact", shared.ErrValidation)
		}
		if moduleSet[m.Name] || fileSet[m.File] {
			return fmt.Errorf("%w: duplicate js module or file", shared.ErrValidation)
		}
		moduleSet[m.Name], fileSet[m.File] = true, true
		moduleFiles[m.Name] = m.File
	}
	symbolSet := make(map[string]Symbol, len(d.Symbols))
	for _, s := range d.Symbols {
		if !s.Kind.Valid() || s.ID != canonicalSymbolID(s.Module, s.QualifiedName) || !moduleSet[s.Module] ||
			!validQualified(s.QualifiedName) || !validSymbolName(s) || validatePosition(s.Pos, true) != nil || len(s.Parameters) > maxParameters {
			return fmt.Errorf("%w: invalid js symbol fact", shared.ErrValidation)
		}
		if _, duplicate := symbolSet[s.ID]; duplicate {
			return fmt.Errorf("%w: duplicate js symbol %q", shared.ErrValidation, s.ID)
		}
		if s.Pos.File != moduleFiles[s.Module] {
			return fmt.Errorf("%w: js symbol position is outside its module", shared.ErrValidation)
		}
		for _, p := range s.Parameters {
			if !validName(p.Name) || !p.Kind.Valid() || validatePosition(p.Pos, true) != nil || p.Pos.File != s.Pos.File {
				return fmt.Errorf("%w: invalid js parameter fact", shared.ErrValidation)
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
	for module := range moduleSet {
		root, ok := symbolSet[canonicalSymbolID(module, "<module>")]
		if !ok || root.Kind != SymbolModule {
			return fmt.Errorf("%w: js module has no canonical module symbol", shared.ErrValidation)
		}
	}
	for _, s := range d.Symbols {
		if s.Kind == SymbolModule {
			if s.ParentID != "" || s.QualifiedName != "<module>" {
				return fmt.Errorf("%w: invalid js module symbol", shared.ErrValidation)
			}
			continue
		}
		if s.ParentID == "" {
			return fmt.Errorf("%w: non-module js symbol needs a parent", shared.ErrValidation)
		}
		if parent, ok := symbolSet[s.ParentID]; !ok {
			return fmt.Errorf("%w: js symbol parent does not exist", shared.ErrValidation)
		} else if parent.Module != s.Module {
			return fmt.Errorf("%w: js symbol parent crosses modules", shared.ErrValidation)
		}
	}
	validScope := func(scope string) bool { _, ok := symbolSet[scope]; return ok }
	positionMatchesScope := func(scope string, pos Position) bool {
		symbol, ok := symbolSet[scope]
		return ok && symbol.Pos.File == pos.File
	}
	valueSet := make(map[string]Value, len(d.Values))
	for _, value := range d.Values {
		if !validText(value.ID) || !validScope(value.ScopeID) || !value.Kind.Valid() ||
			validatePosition(value.Pos, true) != nil || !positionMatchesScope(value.ScopeID, value.Pos) {
			return fmt.Errorf("%w: invalid js value fact", shared.ErrValidation)
		}
		if value.Name != "" && !validName(value.Name) {
			return fmt.Errorf("%w: invalid js value name", shared.ErrValidation)
		}
		if err := validateReference(value.Ref); err != nil {
			return err
		}
		if _, duplicate := valueSet[value.ID]; duplicate {
			return fmt.Errorf("%w: duplicate js value fact", shared.ErrValidation)
		}
		valueSet[value.ID] = value
	}
	for _, flow := range d.Flows {
		from, fromOK := valueSet[flow.FromID]
		to, toOK := valueSet[flow.ToID]
		if !fromOK || !toOK || from.ScopeID != to.ScopeID || !flow.Kind.Valid() ||
			validatePosition(flow.Pos, true) != nil || !positionMatchesScope(from.ScopeID, flow.Pos) {
			return fmt.Errorf("%w: invalid js intra-procedural value flow", shared.ErrValidation)
		}
	}
	for _, symbol := range d.Symbols {
		for _, parameter := range symbol.Parameters {
			if parameter.ValueID == "" {
				continue
			}
			value, ok := valueSet[parameter.ValueID]
			if !ok || value.ScopeID != symbol.ID || value.Kind != ValueParameter || value.Name != parameter.Name {
				return fmt.Errorf("%w: js parameter references an invalid value", shared.ErrValidation)
			}
		}
	}
	for _, item := range d.Imports {
		if !validScope(item.ScopeID) || !item.Kind.Valid() || !validSpecifier(item.Module) ||
			!validOptionalName(item.Name) || !validOptionalName(item.Alias) || validatePosition(item.Pos, true) != nil ||
			!positionMatchesScope(item.ScopeID, item.Pos) {
			return fmt.Errorf("%w: invalid js import fact", shared.ErrValidation)
		}
	}
	callSet := make(map[string]bool, len(d.Calls))
	for _, item := range d.Calls {
		if !validText(item.ID) || callSet[item.ID] || !validScope(item.CallerID) || len(item.Arguments) > maxArguments ||
			validatePosition(item.Pos, true) != nil || !positionMatchesScope(item.CallerID, item.Pos) {
			return fmt.Errorf("%w: invalid js call fact", shared.ErrValidation)
		}
		if err := validateReference(item.Callee); err != nil {
			return err
		}
		for _, arg := range item.Arguments {
			if err := validateReference(arg.Value); err != nil {
				return err
			}
			if arg.ValueID != "" {
				if value, ok := valueSet[arg.ValueID]; !ok || value.ScopeID != item.CallerID ||
					validatePosition(arg.Pos, true) != nil || !positionMatchesScope(item.CallerID, arg.Pos) {
					return fmt.Errorf("%w: js call argument references an invalid value", shared.ErrValidation)
				}
			}
		}
		if item.ResultID != "" {
			if value, ok := valueSet[item.ResultID]; !ok || value.ScopeID != item.CallerID || value.Kind != ValueCallResult {
				return fmt.Errorf("%w: js call references an invalid result value", shared.ErrValidation)
			}
		}
		if item.ReceiverValueID != "" {
			if value, ok := valueSet[item.ReceiverValueID]; !ok || value.ScopeID != item.CallerID {
				return fmt.Errorf("%w: js call references an invalid receiver value", shared.ErrValidation)
			}
		}
		callSet[item.ID] = true
	}
	for _, item := range d.Assignments {
		if !validScope(item.ScopeID) || len(item.Targets) == 0 || len(item.Targets) > maxArguments ||
			validatePosition(item.Pos, true) != nil || !positionMatchesScope(item.ScopeID, item.Pos) {
			return fmt.Errorf("%w: invalid js assignment fact", shared.ErrValidation)
		}
		for _, target := range item.Targets {
			if err := validateReference(target); err != nil {
				return err
			}
		}
		if err := validateReference(item.Value); err != nil {
			return err
		}
		if item.ValueID != "" {
			if value, ok := valueSet[item.ValueID]; !ok || value.ScopeID != item.ScopeID {
				return fmt.Errorf("%w: js assignment references an invalid source value", shared.ErrValidation)
			}
		}
		for _, id := range item.TargetIDs {
			if value, ok := valueSet[id]; !ok || value.ScopeID != item.ScopeID || value.Kind != ValueBinding {
				return fmt.Errorf("%w: js assignment references an invalid target value", shared.ErrValidation)
			}
		}
	}
	for _, item := range d.Returns {
		if !validScope(item.ScopeID) || validatePosition(item.Pos, true) != nil || !positionMatchesScope(item.ScopeID, item.Pos) {
			return fmt.Errorf("%w: invalid js return fact", shared.ErrValidation)
		}
		if err := validateReference(item.Value); err != nil {
			return err
		}
		if item.ValueID != "" {
			if value, ok := valueSet[item.ValueID]; !ok || value.ScopeID != item.ScopeID {
				return fmt.Errorf("%w: js return references an invalid value", shared.ErrValidation)
			}
		}
		if item.SlotID != "" {
			if value, ok := valueSet[item.SlotID]; !ok || value.ScopeID != item.ScopeID || value.Kind != ValueReturn {
				return fmt.Errorf("%w: js return references an invalid slot", shared.ErrValidation)
			}
		}
	}
	for _, item := range d.Entrypoints {
		if !validScope(item.SymbolID) || !validText(item.Kind) || validatePosition(item.Pos, true) != nil || !positionMatchesScope(item.SymbolID, item.Pos) {
			return fmt.Errorf("%w: invalid js entrypoint hint", shared.ErrValidation)
		}
	}
	for _, gap := range d.CoverageGaps {
		if !gap.Kind.Valid() || gap.SymbolID != "" && !validScope(gap.SymbolID) || !validOptionalText(gap.Detail) || validatePosition(gap.Pos, false) != nil ||
			gap.SymbolID != "" && gap.Pos.File != "" && !positionMatchesScope(gap.SymbolID, gap.Pos) {
			return fmt.Errorf("%w: invalid js coverage gap", shared.ErrValidation)
		}
	}
	return nil
}

func validateReference(ref Reference) error {
	if !ref.Kind.Valid() || len(ref.Segments) > maxSegments {
		return fmt.Errorf("%w: invalid js reference", shared.ErrValidation)
	}
	if (ref.Kind == ReferenceName || ref.Kind == ReferenceAttribute || ref.Kind == ReferenceCall) && len(ref.Segments) == 0 {
		return fmt.Errorf("%w: named js reference needs segments", shared.ErrValidation)
	}
	if (ref.Kind == ReferenceLiteral || ref.Kind == ReferenceExpression || ref.Kind == ReferenceUnknown) && len(ref.Segments) != 0 {
		return fmt.Errorf("%w: opaque js reference cannot carry text", shared.ErrValidation)
	}
	for _, segment := range ref.Segments {
		if !validName(segment) {
			return fmt.Errorf("%w: invalid js reference segment", shared.ErrValidation)
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

// validModulePath validates a module name derived from a source path, e.g. "src/routes/user" or "index".
func validModulePath(value string) bool {
	if !validText(value) {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) == 0 || len(parts) > maxSegments {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || !validPathSegment(part) {
			return false
		}
	}
	return true
}

func validPathSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r == '_' || r == '$' || r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

// validSpecifier validates a module specifier: a bare package, a relative path, a scoped package, or a
// subpath ("express", "./util", "../lib/db", "@scope/pkg", "lodash/fp").
func validSpecifier(value string) bool {
	if !validText(value) {
		return false
	}
	for _, r := range value {
		if r == '_' || r == '$' || r == '-' || r == '.' || r == '/' || r == '@' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func validSymbolName(s Symbol) bool {
	if s.Kind == SymbolArrow {
		return validSyntheticFnName(s.Name)
	}
	return validName(s.Name)
}

func validQualified(value string) bool {
	if strings.Contains(value, "<module>") {
		return value == "<module>"
	}
	for _, part := range strings.Split(value, ".") {
		if validName(part) || validSyntheticFnName(part) || validDisambiguatedName(part) {
			continue
		}
		return false
	}
	return validText(value)
}

// validSyntheticFnName recognizes the extractor's name for an anonymous function/arrow, "<fn@line_col>".
func validSyntheticFnName(value string) bool {
	return strings.HasPrefix(value, "<fn@") && strings.HasSuffix(value, ">") && validText(value)
}

// validDisambiguatedName recognizes a position-suffixed qualified segment "<name>@<line>_<col>", which the
// extractor emits when two valid declarations share a name (a TS overload signature, a duplicate method), so
// each keeps a unique symbol id instead of the whole document being rejected as a duplicate.
func validDisambiguatedName(value string) bool {
	at := strings.LastIndexByte(value, '@')
	if at <= 0 {
		return false
	}
	name, suffix := value[:at], value[at+1:]
	if !validName(name) {
		return false
	}
	us := strings.IndexByte(suffix, '_')
	if us <= 0 || us == len(suffix)-1 {
		return false
	}
	return isDigits(suffix[:us]) && isDigits(suffix[us+1:])
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// validName accepts a JS identifier. Unlike Python, '$' is a legal identifier character.
func validName(value string) bool {
	if !validText(value) || value == "*" {
		return false
	}
	for i, r := range value {
		if r == '_' || r == '$' || unicode.IsLetter(r) || i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func validOptionalName(value string) bool { return value == "" || value == "*" || validName(value) }
func validOptionalText(value string) bool { return value == "" || validText(value) }

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

// CanonicalSymbolID builds the stable id for a JS symbol: "js:" + module path + ":" + qualified name.
func CanonicalSymbolID(module, qualified string) string { return canonicalSymbolID(module, qualified) }

func canonicalSymbolID(module, qualified string) string {
	return "js:" + module + ":" + qualified
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
	sort.Slice(d.Values, func(i, j int) bool { return d.Values[i].ID < d.Values[j].ID })
	sort.Slice(d.Flows, func(i, j int) bool {
		left := d.Flows[i].FromID + "\x00" + d.Flows[i].ToID + "\x00" + string(d.Flows[i].Kind)
		right := d.Flows[j].FromID + "\x00" + d.Flows[j].ToID + "\x00" + string(d.Flows[j].Kind)
		return left < right
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

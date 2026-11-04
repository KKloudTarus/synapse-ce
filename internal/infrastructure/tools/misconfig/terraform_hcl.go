package misconfig

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Bounded Terraform evaluation.
//
// The rules in terraform.go read one normalized line at a time. This file gives them the EFFECTIVE value
// of each attribute instead of its source spelling: the file is parsed with the same HCL library Terraform
// uses, every attribute expression is evaluated against the module's variables and locals, and each
// attribute whose value is known is rewritten in place as `name = <literal>`. Line numbers are preserved,
// so a finding still points at the line the operator wrote.
//
// The contract is deliberately bounded:
//
//   - Variables resolve from the module's own `variable` defaults, the automatically loaded variable files
//     (terraform.tfvars, *.auto.tfvars, and their .json forms) in Terraform's precedence order, and the
//     inputs a parent module call binds. Nothing else is consulted.
//   - Locals resolve by repeated substitution, bounded by tfMaxEvalRounds.
//   - Functions are a fixed, pure allowlist. No function reads the filesystem, the network, a provider, or
//     the Terraform state.
//   - Anything else (a data source, a resource attribute, a count/each reference, an undeclared variable,
//     a module call that is not a local directory) stays UNKNOWN. An unknown attribute keeps its source
//     text, so a rule can only match what was literally written, and is reported as unresolved.
//
// An unknown value is never guessed, so evaluation can turn a missed finding into a reported one but can
// never manufacture one from a value Terraform would not produce.
const (
	// tfMaxEvalRounds bounds local-value and module-input propagation. Each round resolves one more level
	// of dependency; a configuration that needs more is left unresolved rather than iterated to a fixpoint.
	tfMaxEvalRounds = 8
	// tfMaxInlineLen caps a rewritten literal, so a generated multi-megabyte list cannot be pushed into the
	// normalized source a rule then scans.
	tfMaxInlineLen = 512
	// tfMaxValueDepth caps nesting inside one rewritten literal.
	tfMaxValueDepth = 6
	// tfMaxScenarios caps the number of extra, manually selected variable-file scenarios evaluated across
	// the whole workspace. Each one re-resolves every module, so the bound is on the workspace, not a
	// per-directory count that would multiply.
	tfMaxScenarios = 8
	// tfMaxValueBytes caps a single resolved variable, input or local. A target controls its own
	// configuration, so an expression it writes must not be able to grow a value without limit inside the
	// scanner: a value over this size is not stored and stays unknown. Combined with the fixed function
	// table, which contains no width- or count-driven expander, this bounds every allocation evaluation
	// can be made to perform.
	tfMaxValueBytes = 64 << 10
	// tfMaxExprRefs caps how many variable or local references one expression may read. A template or a
	// comprehension concatenates its operands, so without this an otherwise ordinary expression could
	// chain thousands of budget-sized values together in a single evaluation.
	tfMaxExprRefs = 64
)

// errEvaluationBound refuses a call whose output cannot be shown to fit the budget BEFORE it runs. The
// refusal reaches the caller as an ordinary expression error, so the attribute stays unknown and is
// reported as unresolved rather than silently treated as absent.
var errEvaluationBound = errors.New("refused: the projected result exceeds the evaluation budget")

// boundedFunction wraps f so the projected output size is checked before f executes. Checking the stored
// result afterwards is too late: the allocation the bound exists to prevent has already happened, and a
// small final result (length(...) of a large intermediate) hides it entirely.
func boundedFunction(name string, f function.Function) function.Function {
	guard := func(args []cty.Value) error {
		if projectedResultSize(name, args) > tfMaxValueBytes {
			return errEvaluationBound
		}
		return nil
	}
	return function.New(&function.Spec{
		Params:   f.Params(),
		VarParam: f.VarParam(),
		Type: func(args []cty.Value) (cty.Type, error) {
			if err := guard(args); err != nil {
				return cty.NilType, err
			}
			return f.ReturnTypeForValues(args)
		},
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			if err := guard(args); err != nil {
				return cty.NilVal, err
			}
			return f.Call(args)
		},
	})
}

// projectedResultSize is a conservative upper bound on what a call will produce, computed from the
// arguments alone. Anything not named here cannot produce more than the sum of its inputs.
func projectedResultSize(name string, args []cty.Value) int {
	total := 0
	for _, a := range args {
		total += measuredSize(a)
	}
	switch name {
	case "join":
		// The separator is repeated between every pair, which is how a small separator and a short list
		// still multiply into a large string.
		if len(args) == 2 {
			sep := measuredSize(args[0])
			if n := elementCount(args[1]); n > 1 {
				return measuredSize(args[1]) + sep*(n-1)
			}
		}
	case "split":
		// Every character can become its own element, each carrying collection overhead.
		if len(args) == 2 {
			return measuredSize(args[1]) * 24
		}
	case "jsonencode":
		// Escaping and punctuation can expand the rendering several times over.
		return total*6 + 64
	}
	return total
}

// measuredSize is the byte size of v, saturating just past the budget so an oversized value costs no
// more to measure than an acceptable one.
func measuredSize(v cty.Value) int {
	n, ok := tfValueSize(v, tfMaxValueBytes)
	if !ok {
		return tfMaxValueBytes + 1
	}
	return n
}

func elementCount(v cty.Value) int {
	if !v.IsKnown() || v.IsNull() {
		return 0
	}
	t := v.Type()
	if !t.IsListType() && !t.IsSetType() && !t.IsTupleType() {
		return 0
	}
	return v.LengthInt()
}

// tfEvaluable reports whether an expression is within the reference bound. One that is not stays unknown,
// which keeps it out of the rules and into the unresolved report.
func tfEvaluable(expr hcl.Expression) bool {
	return len(expr.Variables()) <= tfMaxExprRefs
}

// tfValueWithinBudget reports whether v fits in budget bytes, walking only until the budget is exceeded so
// a large value costs no more to reject than a small one does to accept.
func tfValueWithinBudget(v cty.Value, budget int) bool {
	_, ok := tfValueSize(v, budget)
	return ok
}

func tfValueSize(v cty.Value, budget int) (int, bool) {
	if !v.IsKnown() || v.IsNull() {
		return 0, true
	}
	t := v.Type()
	switch {
	case t == cty.String:
		n := len(v.AsString())
		return n, n <= budget
	case t == cty.Bool, t == cty.Number:
		return 8, budget >= 8
	case t.IsListType(), t.IsSetType(), t.IsTupleType(), t.IsObjectType(), t.IsMapType():
		total := 0
		for it := v.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			if kv.Type() == cty.String && kv.IsKnown() && !kv.IsNull() {
				total += len(kv.AsString())
			}
			n, ok := tfValueSize(ev, budget-total)
			total += n + 16
			if !ok || total > budget {
				return total, false
			}
		}
		return total, total <= budget
	}
	return 0, true
}

// strContainsFunc is Terraform's strcontains: a substring test on two strings. The collection-membership
// function it was bound to errors on strings, and a try() around it then took a fallback Terraform never
// takes.
var strContainsFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "substr", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.Contains(args[0].AsString(), args[1].AsString())), nil
	},
})

// toListFunc is Terraform's tolist: a genuine conversion to a list, including of an empty collection. The
// coalesce-list function it was bound to rejects an empty input, which again diverted try() to a fallback.
var toListFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "v", Type: cty.DynamicPseudoType, AllowDynamicType: true, AllowNull: true}},
	Type: func(args []cty.Value) (cty.Type, error) {
		// A null or unknown input has no length to inspect; Terraform's own conversion preserves null,
		// so asking for one here turned a true expression into a function error and sent try() to a
		// fallback.
		if args[0].IsNull() || !args[0].IsKnown() {
			return cty.List(cty.String), nil
		}
		if t := args[0].Type(); (t.IsTupleType() && t.Length() == 0) || ((t.IsSetType() || t.IsListType()) && args[0].LengthInt() == 0) {
			return cty.List(cty.String), nil
		}
		converted, err := convert.Convert(args[0], cty.List(cty.DynamicPseudoType))
		if err != nil {
			return cty.NilType, err
		}
		return converted.Type(), nil
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if args[0].IsNull() {
			return cty.NullVal(retType), nil
		}
		if !args[0].IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		if retType.IsListType() && args[0].LengthInt() == 0 {
			return cty.ListValEmpty(retType.ElementType()), nil
		}
		return convert.Convert(args[0], retType)
	},
})

// tfSource is one parsed Terraform configuration file.
type tfSource struct {
	rel  string
	data []byte
	file *hcl.File
	// json is true for a .tf.json file, which is rendered to HCL rather than rewritten in place.
	json bool
}

// tfModule is one directory. A Terraform module is a directory, so that is the unit of variable scope.
type tfModule struct {
	dir     string
	sources []*tfSource
	// defaults are the module's own `variable "x" { default = ... }` values.
	defaults map[string]cty.Value
	// fileVars are the automatically loaded variable files, with precedence already applied.
	fileVars map[string]cty.Value
	// scenarios are manually selected variable files (`-var-file`), each evaluated as its own overlay.
	scenarios []tfScenario
	// contributions are the inputs each parent call site binds, keyed by that site's identity. Keying by
	// site is what separates one call whose value is refined across resolution rounds from two different
	// calls that genuinely disagree: only the second is a conflict.
	contributions map[string]map[string]cty.Value
	// declaredVars names every `variable` block, whether or not a value was found for it. A declared
	// variable with no value is UNKNOWN rather than absent, so an expression that reads it propagates
	// uncertainty instead of behaving as though the variable did not exist.
	declaredVars map[string]bool
	vars         map[string]cty.Value
	locals       map[string]cty.Value
	localAttrs   []*hclsyntax.Attribute
	calls        []*hclsyntax.Block
	ctx          *hcl.EvalContext
}

// tfScenario is one manually selected variable file.
type tfScenario struct {
	name string
	vars map[string]cty.Value
}

// parseTFSource parses one .tf or .tf.json file. A file that does not parse returns nil, and the caller
// falls back to scanning its raw text, so a syntax error never hides the rules.
func parseTFSource(rel string, data []byte) *tfSource {
	p := hclparse.NewParser()
	isJSON := strings.HasSuffix(strings.ToLower(rel), ".tf.json")
	var f *hcl.File
	var diags hcl.Diagnostics
	if isJSON {
		f, diags = p.ParseJSON(data, rel)
	} else {
		f, diags = p.ParseHCL(data, rel)
	}
	if diags.HasErrors() || f == nil || f.Body == nil {
		return nil
	}
	return &tfSource{rel: rel, data: data, file: f, json: isJSON}
}

// isTFVarsFileName recognises a Terraform variable-values file in either syntax.
func isTFVarsFileName(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".tfvars") || strings.HasSuffix(l, ".tfvars.json")
}

// tfVarFileRank orders the automatically loaded variable files the way Terraform does: terraform.tfvars
// first, then terraform.tfvars.json, then every *.auto.tfvars / *.auto.tfvars.json in lexical order. A
// later file overrides an earlier one. A file that Terraform loads only when it is named on the command
// line returns false and is evaluated as a separate scenario instead.
func tfVarFileRank(name string) (int, bool) {
	l := strings.ToLower(name)
	switch l {
	case "terraform.tfvars":
		return 0, true
	case "terraform.tfvars.json":
		return 1, true
	}
	if strings.HasSuffix(l, ".auto.tfvars") || strings.HasSuffix(l, ".auto.tfvars.json") {
		return 2, true
	}
	return 0, false
}

// tfFunctions is the pure, fixed function table expressions are evaluated against. Every entry is a value
// transformation: none reads a file, a provider, the network, or the Terraform state, so evaluating an
// expression can never have an effect outside the scan.
//
// No entry expands its output beyond the size of its inputs. format, formatlist and indent are deliberately
// absent: their width and count parameters let a one-line configuration ask for an arbitrarily large string,
// and that allocation happens inside the scanner before any limit on the rendered result could reject it.
// An expression that calls one of them does not evaluate, so the attribute keeps its source text.
func tfFunctions() map[string]function.Function {
	bounded := map[string]function.Function{}
	for name, f := range rawTFFunctions() {
		bounded[name] = boundedFunction(name, f)
	}
	return bounded
}

func rawTFFunctions() map[string]function.Function {
	return map[string]function.Function{
		"abs":          stdlib.AbsoluteFunc,
		"ceil":         stdlib.CeilFunc,
		"chomp":        stdlib.ChompFunc,
		"coalesce":     stdlib.CoalesceFunc,
		"coalescelist": stdlib.CoalesceListFunc,
		"compact":      stdlib.CompactFunc,
		"concat":       stdlib.ConcatFunc,
		"contains":     stdlib.ContainsFunc,
		"distinct":     stdlib.DistinctFunc,
		"element":      stdlib.ElementFunc,
		"flatten":      stdlib.FlattenFunc,
		"floor":        stdlib.FloorFunc,
		"join":         stdlib.JoinFunc,
		"jsondecode":   stdlib.JSONDecodeFunc,
		"jsonencode":   stdlib.JSONEncodeFunc,
		"keys":         stdlib.KeysFunc,
		"length":       stdlib.LengthFunc,
		"lookup":       stdlib.LookupFunc,
		"lower":        stdlib.LowerFunc,
		"max":          stdlib.MaxFunc,
		"merge":        stdlib.MergeFunc,
		"min":          stdlib.MinFunc,
		"reverse":      stdlib.ReverseListFunc,
		"setunion":     stdlib.SetUnionFunc,
		"slice":        stdlib.SliceFunc,
		"sort":         stdlib.SortFunc,
		"split":        stdlib.SplitFunc,
		"strcontains":  strContainsFunc,
		"title":        stdlib.TitleFunc,
		"tolist":       toListFunc,
		"trimspace":    stdlib.TrimSpaceFunc,
		"try":          tryfunc.TryFunc,
		"upper":        stdlib.UpperFunc,
		"values":       stdlib.ValuesFunc,
		"zipmap":       stdlib.ZipmapFunc,
	}
}

// evalContext builds the evaluation context for this module's expressions. Only `var` and `local` are
// bound: every other root (a data source, another resource, count, each, path) stays undefined, so an
// expression that reads one fails to evaluate and its attribute keeps its source text.
func (m *tfModule) evalContext() *hcl.EvalContext {
	return tfEvalContextFor(m.vars, m.locals)
}

func tfEvalContextFor(vars, locals map[string]cty.Value) *hcl.EvalContext {
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var":   tfObject(vars),
			"local": tfObject(locals),
		},
		Functions: tfFunctions(),
	}
}

// withPolicyData binds the module's aws_iam_policy_document data sources, so a resource that references one
// is assessed against the document it will carry. No other data source is bound: every other data.* read
// stays unknown.
func (m *tfModule) withPolicyData(ctx *hcl.EvalContext) *hcl.EvalContext {
	data, _ := tfPolicyDocData(m, ctx)
	if data == cty.NilVal {
		return ctx
	}
	out := tfEvalContextFor(m.vars, m.locals)
	out.Variables["data"] = data
	return out
}

func tfObject(m map[string]cty.Value) cty.Value {
	if len(m) == 0 {
		return cty.EmptyObjectVal
	}
	clean := make(map[string]cty.Value, len(m))
	for k, v := range m {
		if v == cty.NilVal {
			continue
		}
		clean[k] = v
	}
	if len(clean) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(clean)
}

// collectDeclarations reads the module's `variable` defaults and remembers its `locals` and `module`
// blocks for the resolution rounds.
func (m *tfModule) collectDeclarations() {
	m.defaults = map[string]cty.Value{}
	m.declaredVars = map[string]bool{}
	empty := tfEvalContextFor(nil, nil)
	for _, src := range m.sources {
		body, ok := src.file.Body.(*hclsyntax.Body)
		if !ok {
			// A .tf.json module: read its variable defaults and locals through the generic body API.
			m.collectJSONDeclarations(src)
			continue
		}
		for _, blk := range body.Blocks {
			switch {
			case blk.Type == "variable" && len(blk.Labels) == 1:
				m.declaredVars[blk.Labels[0]] = true
				if attr, ok := blk.Body.Attributes["default"]; ok {
					if v, d := attr.Expr.Value(empty); !d.HasErrors() && v.IsWhollyKnown() && tfValueWithinBudget(v, tfMaxValueBytes) {
						m.defaults[blk.Labels[0]] = v
					}
				}
			case blk.Type == "locals":
				for _, attr := range blk.Body.Attributes {
					m.localAttrs = append(m.localAttrs, attr)
				}
			case blk.Type == "module" && len(blk.Labels) == 1:
				m.calls = append(m.calls, blk)
			}
		}
	}
	sort.Slice(m.localAttrs, func(i, j int) bool {
		return m.localAttrs[i].SrcRange.Start.Byte < m.localAttrs[j].SrcRange.Start.Byte
	})
}

// collectJSONDeclarations reads `variable` defaults from a .tf.json module file.
func (m *tfModule) collectJSONDeclarations(src *tfSource) {
	content, _, _ := src.file.Body.PartialContent(tfRootSchema)
	empty := tfEvalContextFor(nil, nil)
	for _, blk := range content.Blocks {
		if blk.Type != "variable" || len(blk.Labels) != 1 {
			continue
		}
		if m.declaredVars == nil {
			m.declaredVars = map[string]bool{}
		}
		m.declaredVars[blk.Labels[0]] = true
		attrs, _ := blk.Body.JustAttributes()
		if attr, ok := attrs["default"]; ok {
			if v, d := attr.Expr.Value(empty); !d.HasErrors() && v.IsWhollyKnown() && tfValueWithinBudget(v, tfMaxValueBytes) {
				m.defaults[blk.Labels[0]] = v
			}
		}
	}
}

// tfRootSchema is the subset of Terraform's top-level block grammar this scanner reads. It exists for the
// JSON syntax, where blocks are otherwise indistinguishable from object attributes.
var tfRootSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "module", LabelNames: []string{"name"}},
		{Type: "variable", LabelNames: []string{"name"}},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "locals"},
		{Type: "terraform"},
	},
}

// resolveVars applies Terraform's precedence: a parent module call's input beats an automatically loaded
// variable file, which beats the module's own default.
func (m *tfModule) resolveVars(extra map[string]cty.Value) map[string]cty.Value {
	out := make(map[string]cty.Value, len(m.defaults)+len(m.fileVars)+len(extra))
	for k, v := range m.defaults {
		out[k] = v
	}
	for k, v := range m.fileVars {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	inputs, conflict := m.effectiveInputs()
	for k, v := range inputs {
		out[k] = v
	}
	// A variable that DIFFERENT call sites bind differently has no single effective value.
	for k := range conflict {
		delete(out, k)
	}
	return out
}

// effectiveInputs reduces the per-call-site contributions to one value per name, and names those that
// distinct sites disagree about.
func (m *tfModule) effectiveInputs() (map[string]cty.Value, map[string]bool) {
	out := map[string]cty.Value{}
	conflict := map[string]bool{}
	sites := make([]string, 0, len(m.contributions))
	for site := range m.contributions {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	for _, site := range sites {
		for k, v := range m.contributions[site] {
			prev, seen := out[k]
			if seen && !prev.RawEquals(v) {
				conflict[k] = true
				continue
			}
			out[k] = v
		}
	}
	return out, conflict
}

// tfResolveLocals evaluates local values by repeated substitution. A local that still fails to evaluate
// after tfMaxEvalRounds (a cycle, or a reference outside the supported contract) stays absent, so every
// expression that reads it keeps its source text.
func tfResolveLocals(attrs []*hclsyntax.Attribute, vars map[string]cty.Value) map[string]cty.Value {
	locals := map[string]cty.Value{}
	for round := 0; round < tfMaxEvalRounds; round++ {
		progress := false
		// A local that is declared but not resolved YET is unknown, not missing. Presenting it as missing
		// let try() take a fallback on the first round and froze that answer, because the local was then
		// recorded as resolved and never revisited.
		view := make(map[string]cty.Value, len(attrs))
		for _, attr := range attrs {
			view[attr.Name] = cty.DynamicVal
		}
		for k, v := range locals {
			view[k] = v
		}
		ctx := tfEvalContextFor(vars, view)
		for _, attr := range attrs {
			if _, done := locals[attr.Name]; done {
				continue
			}
			if !tfEvaluable(attr.Expr) {
				continue
			}
			v, d := attr.Expr.Value(ctx)
			if d.HasErrors() || !v.IsWhollyKnown() || !tfValueWithinBudget(v, tfMaxValueBytes) {
				continue
			}
			locals[attr.Name] = v
			progress = true
		}
		if !progress {
			break
		}
	}
	return locals
}

// evaluate resolves the module's variables and locals, optionally with one manually selected variable file
// layered on top, and returns the context its expressions are evaluated in.
func (m *tfModule) evaluate(extra map[string]cty.Value) *hcl.EvalContext {
	m.vars = m.resolveVars(extra)
	// Locals are resolved against the SAME unknown-aware variable view the final attributes use. Handing
	// local resolution the raw map let a declared variable with no value look absent, so try() resolved
	// to its fallback and that answer was then stored; a later unknown-aware context cannot undo it.
	m.locals = tfResolveLocals(m.localAttrs, m.unknownAwareVars())
	varView, localView := m.unknownAwareView()
	m.ctx = m.withPolicyData(tfEvalContextFor(varView, localView))
	return m.ctx
}

// unknownAwareVars presents every declared variable, with the ones that did not resolve marked unknown.
func (m *tfModule) unknownAwareVars() map[string]cty.Value {
	vars := make(map[string]cty.Value, len(m.declaredVars)+len(m.vars))
	for name := range m.declaredVars {
		vars[name] = cty.DynamicVal
	}
	for k, v := range m.vars {
		vars[k] = v
	}
	return vars
}

// unknownAwareView presents every declared variable and local, with the ones that did not resolve marked
// unknown. An expression reading one then yields an unknown value rather than an error, so uncertainty
// propagates through try() and the conditional instead of being mistaken for an absent name.
func (m *tfModule) unknownAwareView() (vars, locals map[string]cty.Value) {
	vars = m.unknownAwareVars()
	locals = make(map[string]cty.Value, len(m.localAttrs)+len(m.locals))
	for _, attr := range m.localAttrs {
		locals[attr.Name] = cty.DynamicVal
	}
	for k, v := range m.locals {
		locals[k] = v
	}
	return vars, locals
}

// moduleCallInputs evaluates one `module` block's input attributes in the PARENT's context and returns the
// child directory it targets. A module whose source is not a local directory binds nothing.
func (m *tfModule) moduleCallInputs(blk *hclsyntax.Block) (childDir string, inputs map[string]cty.Value, ok bool) {
	srcAttr, has := blk.Body.Attributes["source"]
	if !has {
		return "", nil, false
	}
	ctx := m.evalContext()
	sv, d := srcAttr.Expr.Value(ctx)
	if d.HasErrors() || !sv.IsWhollyKnown() || sv.Type() != cty.String {
		return "", nil, false
	}
	rel := sv.AsString()
	if !strings.HasPrefix(rel, "./") && !strings.HasPrefix(rel, "../") {
		return "", nil, false // a registry or VCS module: not a directory in this workspace
	}
	child := path.Clean(path.Join(m.dir, rel))
	if child == "." {
		child = ""
	}
	inputs = map[string]cty.Value{}
	for name, attr := range blk.Body.Attributes {
		switch name {
		case "source", "version", "providers", "count", "for_each", "depends_on":
			continue
		}
		if !tfEvaluable(attr.Expr) {
			continue
		}
		v, d := attr.Expr.Value(ctx)
		if d.HasErrors() || !v.IsWhollyKnown() || !tfValueWithinBudget(v, tfMaxValueBytes) {
			continue
		}
		inputs[name] = v
	}
	return child, inputs, true
}

// bindInputsFrom records one call site's inputs on the child module, REPLACING whatever that same site
// contributed in an earlier resolution round. A value refined as the parent's own variables settle is the
// same binding becoming accurate, not a second opinion; only a different site disagreeing is a conflict.
func (m *tfModule) bindInputsFrom(site string, inputs map[string]cty.Value) {
	if m.contributions == nil {
		m.contributions = map[string]map[string]cty.Value{}
	}
	m.contributions[site] = inputs
}

// tfRenderValue writes a known cty value as the HCL literal the rules will read. It refuses anything that
// would disturb the normalized source the rules scan line by line: a value containing a brace or a newline
// keeps its source text instead.
func tfRenderValue(v cty.Value) (string, bool) {
	var b strings.Builder
	if !tfWriteValue(&b, v, 0) {
		return "", false
	}
	s := b.String()
	if len(s) > tfMaxInlineLen {
		return "", false
	}
	return s, true
}

func tfWriteValue(b *strings.Builder, v cty.Value, depth int) bool {
	if depth > tfMaxValueDepth || !v.IsKnown() {
		return false
	}
	if v.IsNull() {
		b.WriteString("null")
		return true
	}
	t := v.Type()
	switch {
	case t == cty.String:
		s := v.AsString()
		if strings.ContainsAny(s, "{}\n\r") {
			return false
		}
		fmt.Fprintf(b, "%q", s)
		return true
	case t == cty.Bool:
		if v.True() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return true
	case t == cty.Number:
		b.WriteString(v.AsBigFloat().Text('f', -1))
		return true
	case t.IsListType(), t.IsSetType(), t.IsTupleType():
		b.WriteByte('[')
		first := true
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if !first {
				b.WriteString(", ")
			}
			first = false
			if !tfWriteValue(b, ev, depth+1) {
				return false
			}
		}
		b.WriteByte(']')
		return true
	case t.IsObjectType(), t.IsMapType():
		b.WriteString("{ ")
		first := true
		for it := v.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			if !first {
				b.WriteString(", ")
			}
			first = false
			k := kv.AsString()
			if tfIsIdentifier(k) {
				b.WriteString(k)
			} else {
				fmt.Fprintf(b, "%q", k)
			}
			b.WriteString(" = ")
			if !tfWriteValue(b, ev, depth+1) {
				return false
			}
		}
		b.WriteString(" }")
		return true
	}
	return false
}

func tfIsIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// lowerTFSource rewrites one parsed file so every attribute whose value is known carries that value. It
// returns the normalized source with the original line numbering, and the attributes it could not resolve.
func lowerTFSource(src *tfSource, ctx *hcl.EvalContext) (string, []string) {
	if src.json {
		return renderTFJSON(src, ctx)
	}
	body, ok := src.file.Body.(*hclsyntax.Body)
	if !ok {
		return string(src.data), nil
	}
	type repl struct {
		start, end int
		text       string
		newlines   int
	}
	var reps []repl
	var unresolved []string
	// Only an attribute of a resource, data or module block carries a configuration VALUE. A variable's
	// `type = list(string)`, a validation's condition and a lifecycle's ignore_changes are grammar, not
	// values, so leaving them unevaluated is not a gap and reporting them would bury the ones that are.
	var walk func(b *hclsyntax.Body, carriesValues bool)
	walk = func(b *hclsyntax.Body, carriesValues bool) {
		for _, attr := range b.Attributes {
			rng := attr.Expr.Range()
			if rng.Start.Byte < 0 || rng.End.Byte > len(src.data) || rng.End.Byte < rng.Start.Byte {
				continue
			}
			source := string(src.data[rng.Start.Byte:rng.End.Byte])
			if !tfEvaluable(attr.Expr) {
				unresolved = append(unresolved, fmt.Sprintf("%s:%d: %s (reference bound)", src.rel, rng.Start.Line, attr.Name))
				continue
			}
			v, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() || !v.IsWhollyKnown() {
				if carriesValues && len(attr.Expr.Variables()) > 0 {
					unresolved = append(unresolved, fmt.Sprintf("%s:%d: %s", src.rel, rng.Start.Line, attr.Name))
				}
				continue
			}
			text, ok := tfRenderValue(v)
			if !ok || text == source {
				continue
			}
			reps = append(reps, repl{rng.Start.Byte, rng.End.Byte, text, rng.End.Line - rng.Start.Line})
		}
		for _, blk := range b.Blocks {
			if blk.Body == nil {
				continue
			}
			nested := carriesValues
			switch blk.Type {
			case "resource", "data", "module":
				nested = true
			case "variable", "output", "terraform", "provider", "locals", "lifecycle", "validation", "moved", "import", "check":
				nested = false
			}
			walk(blk.Body, nested)
		}
	}
	walk(body, false)
	if len(reps) == 0 {
		return string(src.data), unresolved
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].start > reps[j].start })
	out := make([]byte, len(src.data))
	copy(out, src.data)
	for _, r := range reps {
		// The replacement carries the newlines the original expression spanned, so every later line keeps
		// its number and a finding still points at the line the operator wrote.
		text := r.text + strings.Repeat("\n", r.newlines)
		out = append(out[:r.start], append([]byte(text), out[r.end:]...)...)
	}
	return string(out), unresolved
}

// renderTFJSON writes a .tf.json file as equivalent HCL, placing each construct on the line its JSON
// counterpart starts on so findings keep their location. An attribute whose value cannot be evaluated
// within the bounded contract is omitted and reported as unresolved, never guessed.
func renderTFJSON(src *tfSource, ctx *hcl.EvalContext) (string, []string) {
	total := strings.Count(string(src.data), "\n") + 2
	r := &tfLineWriter{lines: make([]string, total+1)}
	var unresolved []string
	content, _, _ := src.file.Body.PartialContent(tfRootSchema)
	for _, blk := range content.Blocks {
		if blk.Type != "resource" && blk.Type != "module" && blk.Type != "data" {
			continue
		}
		head := blk.Type
		for _, l := range blk.Labels {
			head += fmt.Sprintf(" %q", l)
		}
		at := r.put(blk.DefRange.Start.Line, head+" {")
		attrs, _ := blk.Body.JustAttributes()
		names := make([]string, 0, len(attrs))
		for n := range attrs {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			return attrs[names[i]].Range.Start.Byte < attrs[names[j]].Range.Start.Byte
		})
		last := at
		for _, n := range names {
			attr := attrs[n]
			v, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() || !v.IsWhollyKnown() {
				unresolved = append(unresolved, fmt.Sprintf("%s:%d: %s", src.rel, attr.Range.Start.Line, n))
				continue
			}
			line := attr.Range.Start.Line
			if line <= at {
				line = at + 1
			}
			if used := r.emitValue(n, v, line); used > last {
				last = used
			}
		}
		r.put(last+1, "}")
	}
	return r.String(), unresolved
}

// tfLineWriter places generated HCL on specific lines, moving a construct forward only when the line it
// asked for is already taken.
type tfLineWriter struct {
	lines []string
}

func (w *tfLineWriter) put(line int, text string) int {
	if line < 1 {
		line = 1
	}
	for line >= len(w.lines) {
		w.lines = append(w.lines, "")
	}
	for w.lines[line] != "" {
		line++
		for line >= len(w.lines) {
			w.lines = append(w.lines, "")
		}
	}
	w.lines[line] = text
	return line
}

// emitValue writes one attribute. An object becomes a nested block and a list of objects becomes repeated
// blocks, so a JSON `"ingress": {"cidr_blocks": [...]}` reads to the rules exactly as the HCL form does.
func (w *tfLineWriter) emitValue(name string, v cty.Value, line int) int {
	t := v.Type()
	switch {
	case !v.IsNull() && (t.IsObjectType() || t.IsMapType()):
		at := w.put(line, name+" {")
		last := at
		for it := v.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			if used := w.emitValue(kv.AsString(), ev, last+1); used > last {
				last = used
			}
		}
		return w.put(last+1, "}")
	case !v.IsNull() && (t.IsTupleType() || t.IsListType() || t.IsSetType()) && tfAllObjects(v):
		last := line
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			last = w.emitValue(name, ev, last)
		}
		return last
	}
	text, ok := tfRenderValue(v)
	if !ok {
		return line - 1
	}
	return w.put(line, name+" = "+text)
}

func tfAllObjects(v cty.Value) bool {
	n := 0
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.IsNull() {
			return false
		}
		et := ev.Type()
		if !et.IsObjectType() && !et.IsMapType() {
			return false
		}
		n++
	}
	return n > 0
}

func (w *tfLineWriter) String() string {
	if len(w.lines) == 0 {
		return ""
	}
	return strings.Join(w.lines[1:], "\n")
}

// tfInputFile is one Terraform file read during the walk, kept for the second pass.
type tfInputFile struct {
	rel  string
	data []byte
}

// tfWorkspace is every Terraform module in the scanned tree, resolved together so a child module sees the
// inputs its parent binds.
type tfWorkspace struct {
	modules map[string]*tfModule
	// raw holds the files that did not parse; they are scanned as plain text, exactly as before.
	raw []tfInputFile
}

// buildTFWorkspace parses every Terraform file, applies variable-file precedence per module, and
// propagates module-call inputs down the tree within the bounded number of rounds.
func buildTFWorkspace(configs, varFiles []tfInputFile) *tfWorkspace {
	ws := &tfWorkspace{modules: map[string]*tfModule{}}
	moduleFor := func(dir string) *tfModule {
		m, ok := ws.modules[dir]
		if !ok {
			m = &tfModule{dir: dir}
			ws.modules[dir] = m
		}
		return m
	}
	for _, f := range configs {
		src := parseTFSource(f.rel, f.data)
		if src == nil {
			ws.raw = append(ws.raw, f)
			continue
		}
		m := moduleFor(path.Dir(f.rel))
		m.sources = append(m.sources, src)
	}
	// Variable files, in Terraform's own precedence order. A file Terraform loads only when it is named on
	// the command line is kept as a separate scenario instead of being silently applied.
	type ranked struct {
		rank int
		name string
		vars map[string]cty.Value
	}
	auto := map[string][]ranked{}
	for _, f := range varFiles {
		src := parseTFSource(strings.TrimSuffix(f.rel, ".tfvars")+".tf", f.data)
		if strings.HasSuffix(strings.ToLower(f.rel), ".json") {
			src = parseTFSource(f.rel+".tf.json", f.data)
		}
		if src == nil {
			continue
		}
		vals := map[string]cty.Value{}
		attrs, _ := src.file.Body.JustAttributes()
		empty := tfEvalContextFor(nil, nil)
		for name, attr := range attrs {
			if v, d := attr.Expr.Value(empty); !d.HasErrors() && v.IsWhollyKnown() {
				vals[name] = v
			}
		}
		dir := path.Dir(f.rel)
		m := moduleFor(dir)
		base := path.Base(f.rel)
		if rank, ok := tfVarFileRank(base); ok {
			auto[dir] = append(auto[dir], ranked{rank: rank, name: base, vars: vals})
			continue
		}
		if len(m.scenarios) < tfMaxScenarios {
			m.scenarios = append(m.scenarios, tfScenario{name: base, vars: vals})
		}
	}
	for dir, files := range auto {
		sort.Slice(files, func(i, j int) bool {
			if files[i].rank != files[j].rank {
				return files[i].rank < files[j].rank
			}
			return files[i].name < files[j].name
		})
		m := moduleFor(dir)
		m.fileVars = map[string]cty.Value{}
		for _, f := range files {
			for k, v := range f.vars {
				m.fileVars[k] = v
			}
		}
	}
	for _, m := range ws.modules {
		m.collectDeclarations()
	}
	ws.resolveAll(nil)
	return ws
}

// sortedDirs lists the workspace's module directories in a stable order.
func (ws *tfWorkspace) sortedDirs() []string {
	dirs := make([]string, 0, len(ws.modules))
	for dir := range ws.modules {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}

// resolveAll resolves every module in the workspace under one configuration, where extra optionally layers
// a manually selected variable file onto the named directory. Each round resolves one more level of the
// module tree: a parent's own variables settle, its calls bind the children's inputs, and the next round
// evaluates those children. Resolving the WHOLE workspace per configuration is what carries a variable-file
// scenario down a module edge; resolving only the directory that owns the file left every descendant on the
// default binding.
func (ws *tfWorkspace) resolveAll(extra map[string]map[string]cty.Value) {
	dirs := ws.sortedDirs()
	for _, dir := range dirs {
		ws.modules[dir].contributions = map[string]map[string]cty.Value{}
	}
	for round := 0; round < tfMaxEvalRounds; round++ {
		for _, dir := range dirs {
			m := ws.modules[dir]
			m.evaluate(extra[dir])
			for i, blk := range m.calls {
				child, inputs, ok := m.moduleCallInputs(blk)
				if !ok {
					continue
				}
				if cm, exists := ws.modules[child]; exists {
					cm.bindInputsFrom(fmt.Sprintf("%s#%d", m.dir, i), inputs)
				}
			}
		}
	}
	for _, dir := range dirs {
		ws.modules[dir].evaluate(extra[dir])
	}
}

// scanWorkspace returns the findings for every Terraform file in the tree, plus the attributes evaluation
// could not resolve. A module that carries manually selected variable files is also evaluated under each
// of them, because each is a configuration an operator applies; the findings are unioned, never averaged.
func (ws *tfWorkspace) scanWorkspace() ([]ports.MisconfigRawFinding, []string, int) {
	var out []ports.MisconfigRawFinding
	var unresolved []string
	seen := map[string]bool{}
	dirs := ws.sortedDirs()
	for _, dir := range dirs {
		m := ws.modules[dir]
		sort.Slice(m.sources, func(i, j int) bool { return m.sources[i].rel < m.sources[j].rel })
	}
	// scanPass scans every module under the configuration already resolved into each module's context.
	scanPass := func(record bool) {
		for _, dir := range dirs {
			m := ws.modules[dir]
			var facts tfBucketFacts
			var batch []ports.MisconfigRawFinding
			// Policy documents are assessed as statements, not as lines. The spans they occupy are kept so
			// the line rules do not report the same wildcard tokens under weaker reasoning.
			sites, policyUnresolved, spans := tfCollectPolicySites(m, m.ctx)
			for _, site := range sites {
				spans.add(site.file, site.line, site.endLine)
				batch = append(batch, site.assess()...)
			}
			if record {
				unresolved = append(unresolved, policyUnresolved...)
			}
			for _, src := range m.sources {
				text, un := lowerTFSource(src, m.ctx)
				if record {
					unresolved = append(unresolved, un...)
				}
				batch = append(batch, scanTerraformText(src.rel, text, &facts, spans)...)
			}
			for _, f := range facts.apply(batch) {
				key := fmt.Sprintf("%s|%s|%d", f.RuleID, f.File, f.Line)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, f)
			}
		}
	}
	scanPass(true)
	// Every manually selected variable file is a configuration an operator applies, so each is resolved as
	// its own whole-workspace pass and the findings are unioned. The bound is on the workspace.
	budget := tfMaxScenarios
	skipped := 0
	for _, dir := range dirs {
		for _, sc := range ws.modules[dir].scenarios {
			if budget <= 0 {
				// A scenario the cap refused is work that was NOT done. It is reported as a coverage gap
				// rather than passing silently, because the configuration it describes was never scanned.
				skipped++
				continue
			}
			budget--
			ws.resolveAll(map[string]map[string]cty.Value{dir: sc.vars})
			scanPass(false)
		}
	}
	if budget < tfMaxScenarios {
		ws.resolveAll(nil) // leave the workspace on its default configuration
	}
	for _, f := range ws.raw {
		var facts tfBucketFacts
		out = append(out, facts.apply(scanTerraformText(f.rel, string(f.data), &facts, nil))...)
	}
	return out, unresolved, skipped
}

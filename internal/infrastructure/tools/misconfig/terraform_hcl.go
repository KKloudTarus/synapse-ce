package misconfig

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
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
	// tfMaxScenarios caps the number of extra, manually selected variable files evaluated per module.
	tfMaxScenarios = 8
)

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
	// inputs are the values a parent module call binds. A name bound to different values by different call
	// sites is absent, because the module is then evaluated differently per instance.
	inputs map[string]cty.Value
	// inputConflict names the inputs that were dropped for that reason.
	inputConflict map[string]bool
	vars          map[string]cty.Value
	locals        map[string]cty.Value
	localAttrs    []*hclsyntax.Attribute
	calls         []*hclsyntax.Block
	unresolved    []string
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
func tfFunctions() map[string]function.Function {
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
		"format":       stdlib.FormatFunc,
		"formatlist":   stdlib.FormatListFunc,
		"indent":       stdlib.IndentFunc,
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
		"strcontains":  stdlib.ContainsFunc,
		"title":        stdlib.TitleFunc,
		"tolist":       stdlib.CoalesceListFunc,
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
				if attr, ok := blk.Body.Attributes["default"]; ok {
					if v, d := attr.Expr.Value(empty); !d.HasErrors() && v.IsWhollyKnown() {
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
		attrs, _ := blk.Body.JustAttributes()
		if attr, ok := attrs["default"]; ok {
			if v, d := attr.Expr.Value(empty); !d.HasErrors() && v.IsWhollyKnown() {
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
	out := make(map[string]cty.Value, len(m.defaults)+len(m.fileVars)+len(m.inputs)+len(extra))
	for k, v := range m.defaults {
		out[k] = v
	}
	for k, v := range m.fileVars {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range m.inputs {
		out[k] = v
	}
	// A variable a parent binds inconsistently across call sites has no single effective value.
	for k := range m.inputConflict {
		delete(out, k)
	}
	return out
}

// tfResolveLocals evaluates local values by repeated substitution. A local that still fails to evaluate
// after tfMaxEvalRounds (a cycle, or a reference outside the supported contract) stays absent, so every
// expression that reads it keeps its source text.
func tfResolveLocals(attrs []*hclsyntax.Attribute, vars map[string]cty.Value) map[string]cty.Value {
	locals := map[string]cty.Value{}
	for round := 0; round < tfMaxEvalRounds; round++ {
		progress := false
		ctx := tfEvalContextFor(vars, locals)
		for _, attr := range attrs {
			if _, done := locals[attr.Name]; done {
				continue
			}
			v, d := attr.Expr.Value(ctx)
			if d.HasErrors() || !v.IsWhollyKnown() {
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
	m.locals = tfResolveLocals(m.localAttrs, m.vars)
	return tfEvalContextFor(m.vars, m.locals)
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
		v, d := attr.Expr.Value(ctx)
		if d.HasErrors() || !v.IsWhollyKnown() {
			continue
		}
		inputs[name] = v
	}
	return child, inputs, true
}

// bindInputs records one call site's inputs on the child module, marking a name whose value disagrees with
// an earlier call site as conflicting rather than picking one.
func (m *tfModule) bindInputs(inputs map[string]cty.Value) {
	if m.inputs == nil {
		m.inputs = map[string]cty.Value{}
		m.inputConflict = map[string]bool{}
	}
	for k, v := range inputs {
		prev, seen := m.inputs[k]
		if seen && !prev.RawEquals(v) {
			m.inputConflict[k] = true
			continue
		}
		m.inputs[k] = v
	}
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
	var walk func(b *hclsyntax.Body)
	walk = func(b *hclsyntax.Body) {
		for _, attr := range b.Attributes {
			rng := attr.Expr.Range()
			if rng.Start.Byte < 0 || rng.End.Byte > len(src.data) || rng.End.Byte < rng.Start.Byte {
				continue
			}
			source := string(src.data[rng.Start.Byte:rng.End.Byte])
			v, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() || !v.IsWhollyKnown() {
				if len(attr.Expr.Variables()) > 0 {
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
			if blk.Body != nil {
				walk(blk.Body)
			}
		}
	}
	walk(body)
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
	// Each round resolves one more level of the module tree: a parent's own variables settle, its calls bind
	// the children's inputs, and the next round evaluates those children.
	dirs := make([]string, 0, len(ws.modules))
	for dir := range ws.modules {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for round := 0; round < tfMaxEvalRounds; round++ {
		for _, dir := range dirs {
			m := ws.modules[dir]
			m.evaluate(nil)
			for _, blk := range m.calls {
				child, inputs, ok := m.moduleCallInputs(blk)
				if !ok {
					continue
				}
				if cm, exists := ws.modules[child]; exists {
					cm.bindInputs(inputs)
				}
			}
		}
	}
	for _, dir := range dirs {
		ws.modules[dir].evaluate(nil)
	}
	return ws
}

// scanWorkspace returns the findings for every Terraform file in the tree, plus the attributes evaluation
// could not resolve. A module that carries manually selected variable files is also evaluated under each
// of them, because each is a configuration an operator applies; the findings are unioned, never averaged.
func (ws *tfWorkspace) scanWorkspace() ([]ports.MisconfigRawFinding, []string) {
	var out []ports.MisconfigRawFinding
	var unresolved []string
	dirs := make([]string, 0, len(ws.modules))
	for dir := range ws.modules {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		m := ws.modules[dir]
		sort.Slice(m.sources, func(i, j int) bool { return m.sources[i].rel < m.sources[j].rel })
		seen := map[string]bool{}
		collect := func(ctx *hcl.EvalContext, record bool) {
			var facts tfBucketFacts
			var batch []ports.MisconfigRawFinding
			for _, src := range m.sources {
				text, un := lowerTFSource(src, ctx)
				if record {
					unresolved = append(unresolved, un...)
				}
				batch = append(batch, scanTerraformText(src.rel, text, &facts)...)
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
		collect(m.evaluate(nil), true)
		for _, sc := range m.scenarios {
			collect(m.evaluate(sc.vars), false)
		}
	}
	for _, f := range ws.raw {
		var facts tfBucketFacts
		out = append(out, facts.apply(scanTerraformText(f.rel, string(f.data), &facts))...)
	}
	return out, unresolved
}

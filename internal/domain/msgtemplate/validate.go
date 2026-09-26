package msgtemplate

import (
	"strings"
	"text/template/parse"
)

// dotKind says what the dot (.) refers to in the current scope.
type dotKind int

const (
	dotRoot   dotKind = iota // the render context; bare {{.}} would print all of it
	dotItem                  // one list item inside range; bare {{.}} would print the whole map
	dotScalar                // the value of a with pipe
)

// variable is a range-declared variable: the index when item is empty, else the item of that list.
type variable struct {
	item string
}

type scope struct {
	dot      dotKind
	item     string // list whose item is dot, when dot == dotItem
	dotValue kind   // static type of dot, when dot == dotScalar
	vars     map[string]variable
}

// validator walks a parsed tree and denies every node, identifier and variable reference it does
// not explicitly allow. Unknown node types, including any a future Go release adds, are rejected.
// It tracks the static bounds in limits.go as it goes. Expression checks live in validate_expr.go.
type validator struct {
	source  string
	schema  compiledSchema
	nodes   int
	cost    int
	control int // current if/with/range nesting
	ranges  int // current range nesting
	product int // product of the list caps of the enclosing ranges
}

func newValidator(source string, schema compiledSchema) *validator {
	return &validator{source: source, schema: schema, product: 1}
}

func (v *validator) fail(code Code, node parse.Node, detail string) error {
	line := 0
	if node != nil {
		line = lineOf(v.source, int(node.Position()))
	}
	return invalid(code, line, detail)
}

// count bounds both the size of the tree and the number of node evaluations in the worst case: a
// node inside ranges is weighted by the product of their caps.
func (v *validator) count(node parse.Node) error {
	v.nodes++
	if v.nodes > MaxNodes {
		return v.fail(CodeTooManyNodes, node, "")
	}
	v.cost += v.product
	if v.cost > MaxEvaluationCost {
		return v.fail(CodeCostBoundExceeded, node, "")
	}
	return nil
}

func (v *validator) list(list *parse.ListNode, sc scope) error {
	if list == nil {
		return nil
	}
	if err := v.count(list); err != nil {
		return err
	}
	for _, node := range list.Nodes {
		if err := v.node(node, sc); err != nil {
			return err
		}
	}
	return nil
}

func (v *validator) node(node parse.Node, sc scope) error {
	if err := v.count(node); err != nil {
		return err
	}
	switch n := node.(type) {
	case *parse.TextNode:
		return v.text(n)
	case *parse.CommentNode, *parse.BreakNode, *parse.ContinueNode:
		return nil
	case *parse.ActionNode:
		return v.action(n, sc)
	case *parse.IfNode:
		return v.branch(&n.BranchNode, sc, false, false)
	case *parse.WithNode:
		return v.branch(&n.BranchNode, sc, true, false)
	case *parse.RangeNode:
		return v.rangeNode(n, sc)
	case *parse.TemplateNode:
		return v.fail(CodeForbiddenTemplateCall, n, n.Name)
	}
	return v.fail(CodeForbiddenNode, node, "")
}

// text rejects literal text ending in an odd number of backslashes: that backslash would cancel the
// escape of the value that follows it.
func (v *validator) text(n *parse.TextNode) error {
	trailing := len(n.Text) - len(strings.TrimRight(string(n.Text), `\`))
	if trailing%2 == 1 {
		return v.fail(CodeDanglingEscape, n, "")
	}
	return nil
}

// action validates an output action; it must print a scalar, never a whole list.
func (v *validator) action(n *parse.ActionNode, sc scope) error {
	result, err := v.pipe(n.Pipe, sc)
	if err != nil {
		return err
	}
	if result.isList() {
		return v.fail(CodeListMisuse, n, result.list)
	}
	return nil
}

// branch validates if and with. An else-if or else-with chain stays at the nesting level of its
// first branch, so a five-way severity switch is not mistaken for five levels of nesting.
func (v *validator) branch(b *parse.BranchNode, sc scope, with, chained bool) error {
	if !chained {
		if err := v.enterControl(b); err != nil {
			return err
		}
		defer v.leaveControl()
	}
	result, err := v.pipe(b.Pipe, sc)
	if err != nil {
		return err
	}
	if result.isList() {
		return v.fail(CodeListMisuse, b, result.list)
	}
	inner := sc
	if with {
		inner = scope{dot: dotScalar, dotValue: result.kind, vars: sc.vars}
	}
	if err := v.list(b.List, inner); err != nil {
		return err
	}
	if next, ok := chainedBranch(b.ElseList, with); ok {
		if err := v.count(b.ElseList); err != nil {
			return err
		}
		if err := v.count(next); err != nil {
			return err
		}
		return v.branch(next, sc, with, true)
	}
	return v.list(b.ElseList, sc)
}

// chainedBranch returns the branch of an else-if (or else-with) written as {{else if ...}}.
func chainedBranch(elseList *parse.ListNode, with bool) (*parse.BranchNode, bool) {
	if elseList == nil || len(elseList.Nodes) != 1 {
		return nil, false
	}
	switch next := elseList.Nodes[0].(type) {
	case *parse.IfNode:
		return &next.BranchNode, !with
	case *parse.WithNode:
		return &next.BranchNode, with
	}
	return nil, false
}

// rangeNode validates a range over one declared list and the declared loop variables. The body is
// weighted by the list cap; the else branch runs at most once and is not.
func (v *validator) rangeNode(n *parse.RangeNode, sc scope) error {
	if err := v.enterControl(n); err != nil {
		return err
	}
	defer v.leaveControl()
	v.ranges++
	defer func() { v.ranges-- }()
	if v.ranges > MaxRangeNesting {
		return v.fail(CodeRangeNestingTooDeep, n, "")
	}
	listName, err := v.rangeList(n, sc)
	if err != nil {
		return err
	}
	list := v.schema.lists[listName]
	if v.product*list.cap > MaxIterationProduct {
		return v.fail(CodeIterationBoundExceeded, n, listName)
	}
	vars, err := v.declare(n.Pipe, sc, listName)
	if err != nil {
		return err
	}
	saved := v.product
	v.product *= list.cap
	err = v.list(n.List, scope{dot: dotItem, item: listName, vars: vars})
	v.product = saved
	if err != nil {
		return err
	}
	return v.list(n.ElseList, sc)
}

// rangeList returns the list a range iterates. The pipe must be exactly one declared list: .name at
// the root, or $.name anywhere. Ranging over an integer, a scalar or a pipeline is rejected.
func (v *validator) rangeList(n *parse.RangeNode, sc scope) (string, error) {
	pipe := n.Pipe
	if err := v.count(pipe); err != nil {
		return "", err
	}
	if pipe.IsAssign {
		return "", v.fail(CodeForbiddenAssignment, pipe, "")
	}
	if len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return "", v.fail(CodeInvalidRange, n, "")
	}
	name := ""
	switch arg := pipe.Cmds[0].Args[0].(type) {
	case *parse.FieldNode:
		if sc.dot == dotRoot && len(arg.Ident) == 1 {
			name = arg.Ident[0]
		}
	case *parse.VariableNode:
		if len(arg.Ident) == 2 && arg.Ident[0] == "$" {
			name = arg.Ident[1]
		}
	}
	if _, ok := v.schema.lists[name]; !ok {
		return "", v.fail(CodeInvalidRange, n, name)
	}
	return name, nil
}

// declare returns the variables visible in a range body: the enclosing ones plus the range's own
// index and item variables. Range is the only place a template may declare a variable.
func (v *validator) declare(pipe *parse.PipeNode, sc scope, listName string) (map[string]variable, error) {
	vars := make(map[string]variable, len(sc.vars)+len(pipe.Decl))
	for name, info := range sc.vars {
		vars[name] = info
	}
	switch len(pipe.Decl) {
	case 0:
	case 1:
		vars[pipe.Decl[0].Ident[0]] = variable{item: listName}
	case 2:
		vars[pipe.Decl[0].Ident[0]] = variable{}
		vars[pipe.Decl[1].Ident[0]] = variable{item: listName}
	default:
		return nil, v.fail(CodeForbiddenDeclaration, pipe, "")
	}
	return vars, nil
}

func (v *validator) enterControl(node parse.Node) error {
	v.control++
	if v.control > MaxControlNesting {
		return v.fail(CodeNestingTooDeep, node, "")
	}
	return nil
}

func (v *validator) leaveControl() { v.control-- }

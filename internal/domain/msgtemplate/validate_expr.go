package msgtemplate

import (
	"strings"
	"text/template/parse"
)

// pipe validates a pipeline and returns the static type of its result. Declarations and
// assignments are rejected here; range declarations are handled by rangeNode before this runs.
func (v *validator) pipe(pipe *parse.PipeNode, sc scope) (value, error) {
	if pipe == nil {
		return value{}, v.fail(CodeForbiddenNode, nil, "")
	}
	if err := v.count(pipe); err != nil {
		return value{}, err
	}
	if pipe.IsAssign {
		return value{}, v.fail(CodeForbiddenAssignment, pipe, "")
	}
	if len(pipe.Decl) > 0 {
		return value{}, v.fail(CodeForbiddenDeclaration, pipe, "")
	}
	if len(pipe.Cmds) == 0 {
		return value{}, v.fail(CodeForbiddenNode, pipe, "")
	}
	var result value
	for i, cmd := range pipe.Cmds {
		var err error
		result, err = v.command(cmd, sc, i > 0, result)
		if err != nil {
			return value{}, err
		}
	}
	return result, nil
}

// command validates one pipeline stage. A stage after the first must be a function call, which
// receives the previous stage's value as its last argument.
func (v *validator) command(cmd *parse.CommandNode, sc scope, piped bool, input value) (value, error) {
	if err := v.count(cmd); err != nil {
		return value{}, err
	}
	if len(cmd.Args) == 0 {
		return value{}, v.fail(CodeForbiddenNode, cmd, "")
	}
	ident, isCall := cmd.Args[0].(*parse.IdentifierNode)
	if !isCall {
		if piped || len(cmd.Args) > 1 {
			return value{}, v.fail(CodeInvalidPipeline, cmd, "")
		}
		return v.operand(cmd.Args[0], sc)
	}
	return v.call(ident, cmd.Args[1:], sc, piped, input)
}

// call type-checks a call to an allowlisted function.
func (v *validator) call(ident *parse.IdentifierNode, operands []parse.Node, sc scope, piped bool, input value) (value, error) {
	if err := v.count(ident); err != nil {
		return value{}, err
	}
	spec, ok := funcSpecs[ident.Ident]
	if !ok {
		return value{}, v.fail(CodeForbiddenFunction, ident, ident.Ident)
	}
	args := make([]value, 0, len(operands)+1)
	for _, operand := range operands {
		arg, err := v.operand(operand, sc)
		if err != nil {
			return value{}, err
		}
		args = append(args, arg)
	}
	if piped {
		args = append(args, input)
	}
	result, code, ok := spec.check(args)
	if !ok {
		return value{}, v.fail(code, ident, ident.Ident)
	}
	if ident.Ident == "join" {
		if err := v.joinField(ident, operands, args); err != nil {
			return value{}, err
		}
	}
	return result, nil
}

// joinField requires join's field argument to be a literal field of the joined list, so a join can
// never fail at render time on an unknown field.
func (v *validator) joinField(ident *parse.IdentifierNode, operands []parse.Node, args []value) error {
	list := args[len(args)-1].list
	if field, ok := operands[0].(*parse.StringNode); ok && v.schema.lists[list].fields[field.Text] {
		return nil
	}
	return v.fail(CodeUnknownField, ident, list)
}

// operand validates a function argument or a single-value command and returns its static type.
func (v *validator) operand(node parse.Node, sc scope) (value, error) {
	if err := v.count(node); err != nil {
		return value{}, err
	}
	switch n := node.(type) {
	case *parse.StringNode:
		return stringValue, nil
	case *parse.BoolNode:
		return boolValue, nil
	case *parse.NumberNode:
		return numberValue(n), nil
	case *parse.FieldNode:
		return v.fieldNode(n, sc)
	case *parse.VariableNode:
		return v.variableNode(n, sc)
	case *parse.DotNode:
		if sc.dot == dotScalar {
			return value{kind: sc.dotValue}, nil
		}
		return value{}, v.fail(CodeDotOutsideScope, n, "")
	case *parse.PipeNode:
		return v.pipe(n, sc)
	case *parse.IdentifierNode:
		// A function name in argument position is a niladic call; every allowlisted function needs
		// arguments.
		if _, ok := funcSpecs[n.Ident]; ok {
			return value{}, v.fail(CodeWrongArgumentCount, n, n.Ident)
		}
		return value{}, v.fail(CodeForbiddenFunction, n, n.Ident)
	}
	return value{}, v.fail(CodeForbiddenNode, node, "")
}

// numberValue mirrors text/template's typing of an untyped constant passed as an interface value.
func numberValue(n *parse.NumberNode) value {
	if n.IsInt && !strings.ContainsAny(n.Text, ".eEpP") {
		return intValue
	}
	return floatValue
}

// fieldNode resolves .name: a top-level variable at the root, an item field inside range. Chains
// such as .title.Len would reach methods and are rejected.
func (v *validator) fieldNode(n *parse.FieldNode, sc scope) (value, error) {
	if len(n.Ident) != 1 {
		return value{}, v.fail(CodeInvalidField, n, strings.Join(n.Ident, "."))
	}
	switch sc.dot {
	case dotRoot:
		return v.root(n, n.Ident[0])
	case dotItem:
		return v.field(n, sc.item, n.Ident[0])
	}
	return value{}, v.fail(CodeInvalidField, n, n.Ident[0])
}

// variableNode resolves $.name (a top-level variable), $item.field (an item field) and $i (an index).
// A bare $ or $item would print the whole context or item and is rejected.
func (v *validator) variableNode(n *parse.VariableNode, sc scope) (value, error) {
	if n.Ident[0] == "$" {
		if len(n.Ident) != 2 {
			return value{}, v.fail(CodeInvalidVariable, n, strings.Join(n.Ident, "."))
		}
		return v.root(n, n.Ident[1])
	}
	info, ok := sc.vars[n.Ident[0]]
	switch {
	case !ok:
		return value{}, v.fail(CodeInvalidVariable, n, n.Ident[0])
	case info.item != "" && len(n.Ident) == 2:
		return v.field(n, info.item, n.Ident[1])
	case info.item == "" && len(n.Ident) == 1:
		return intValue, nil
	}
	return value{}, v.fail(CodeInvalidVariable, n, strings.Join(n.Ident, "."))
}

// root resolves a top-level name to a scalar variable or a list.
func (v *validator) root(node parse.Node, name string) (value, error) {
	if v.schema.vars[name] {
		return stringValue, nil
	}
	if _, ok := v.schema.lists[name]; ok {
		return value{kind: kList, list: name}, nil
	}
	return value{}, v.fail(CodeUnknownVariable, node, name)
}

// field resolves a field of an item of list.
func (v *validator) field(node parse.Node, list, name string) (value, error) {
	if v.schema.lists[list].fields[name] {
		return stringValue, nil
	}
	return value{}, v.fail(CodeUnknownField, node, list+"."+name)
}

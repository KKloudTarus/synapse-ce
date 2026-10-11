package msgtemplate

import "text/template/parse"

// escapeOutputs appends the escape function to every output action, the way html/template rewrites
// its trees. Conditions and range pipes are not output and stay raw, so comparisons see the real
// value. It runs only after validation, which rejects any template calling the escape function
// itself.
func escapeOutputs(tree *parse.Tree, list *parse.ListNode) {
	if list == nil {
		return
	}
	for _, node := range list.Nodes {
		switch n := node.(type) {
		case *parse.ActionNode:
			n.Pipe.Cmds = append(n.Pipe.Cmds, escapeCommand(tree, n.Pos))
		case *parse.IfNode:
			escapeBranch(tree, &n.BranchNode)
		case *parse.WithNode:
			escapeBranch(tree, &n.BranchNode)
		case *parse.RangeNode:
			escapeBranch(tree, &n.BranchNode)
		}
	}
}

func escapeBranch(tree *parse.Tree, branch *parse.BranchNode) {
	escapeOutputs(tree, branch.List)
	escapeOutputs(tree, branch.ElseList)
}

func escapeCommand(tree *parse.Tree, pos parse.Pos) *parse.CommandNode {
	ident := parse.NewIdentifier(escapeFunc).SetTree(tree).SetPos(pos)
	return &parse.CommandNode{NodeType: parse.NodeCommand, Pos: pos, Args: []parse.Node{ident}}
}

package msgtemplate

import (
	"testing"
	"text/template/parse"
)

// TestEveryActionEndsWithEscape walks the whole compiled tree independently of rewrite.go and
// requires every output action to end with the escape step. It catches an output position that
// escapeOutputs misses, including one a future node type introduces, which a table of known
// positions cannot.
func TestEveryActionEndsWithEscape(t *testing.T) {
	sources := []string{
		`{{.title}}{{if .title}}{{.title}}{{else if .owner}}{{.owner}}{{else}}{{.summary}}{{end}}`,
		`{{with .title}}{{.}}{{else}}{{.owner}}{{end}}`,
		`{{range $i, $x := .items}}{{$i}}{{$x.title}}{{range $.affected}}{{.host}}{{end}}{{else}}{{.title}}{{end}}`,
		`{{.title | upper | truncate 5}}{{join "title" "," .items}}{{count .items}}`,
	}
	for _, source := range sources {
		tmpl := mustCompile(t, source)
		actions := 0
		walkActions(tmpl.tmpl.Root, func(action *parse.ActionNode) {
			actions++
			last := action.Pipe.Cmds[len(action.Pipe.Cmds)-1]
			ident, ok := last.Args[0].(*parse.IdentifierNode)
			if !ok || ident.Ident != escapeFunc {
				t.Errorf("%s: action %s does not end with the escape step", source, action)
			}
		})
		if actions == 0 {
			t.Fatalf("%s: no actions found", source)
		}
	}
}

func walkActions(node parse.Node, visit func(*parse.ActionNode)) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkActions(child, visit)
		}
	case *parse.ActionNode:
		visit(n)
	case *parse.IfNode:
		walkActions(n.List, visit)
		walkActions(n.ElseList, visit)
	case *parse.WithNode:
		walkActions(n.List, visit)
		walkActions(n.ElseList, visit)
	case *parse.RangeNode:
		walkActions(n.List, visit)
		walkActions(n.ElseList, visit)
	}
}

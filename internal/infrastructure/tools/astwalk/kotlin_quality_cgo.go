//go:build cgo

package astwalk

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

var kotlinRules = map[string]pythonRule{
	"empty-catch":            {"quality", "kotlin-empty-catch", "", "medium", "Empty catch block", "An empty catch block silently discards a failure. Handle the expected failure or preserve diagnostic context."},
	"return-finally":         {"quality", "kotlin-return-in-finally", "", "medium", "Return from finally block", "Returning from finally can replace the original result or suppress an active exception. Perform cleanup without changing control flow."},
	"blocking-coroutine":     {"quality", "kotlin-blocking-in-coroutine", "", "medium", "Blocking sleep in coroutine", "Thread.sleep blocks the coroutine worker thread. Use delay or move blocking work to an appropriate dispatcher."},
	"future-get-coroutine":   {"quality", "kotlin-future-get-in-coroutine", "", "medium", "Blocking Future get in coroutine", "Future.get blocks the coroutine worker thread. Use a suspending await bridge instead."},
	"latch-await-coroutine":  {"quality", "kotlin-latch-await-in-coroutine", "", "medium", "Blocking latch await in coroutine", "Blocking latch or barrier waits occupy a coroutine worker thread. Use a suspending coordination primitive."},
	"run-blocking-suspend":   {"quality", "kotlin-run-blocking-in-suspend", "", "medium", "runBlocking inside suspend function", "runBlocking blocks a thread and defeats suspension inside an existing suspend function. Call suspending code directly or use coroutineScope."},
	"synchronized-suspend":   {"quality", "kotlin-synchronized-in-suspend", "", "medium", "Synchronized block in suspend function", "A monitor held around suspending work can block threads and serialize unrelated coroutines. Use a coroutine Mutex."},
	"cancellation-swallowed": {"quality", "kotlin-cancellation-swallowed", "", "medium", "Cancellation exception swallowed", "Catching CancellationException without rethrowing it prevents structured cancellation from propagating."},
	"not-null-assertion":     {"quality", "kotlin-not-null-assertion", "", "medium", "Not-null assertion", "The !! operator turns a nullable value into a possible runtime failure. Preserve nullability with a safe call, Elvis expression, or explicit check."},
}

func kotlinFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := kotlinRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

func kotlinFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	var out []QualityFinding
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Type() {
		case "catch_block":
			if kotlinCatchBodyEmpty(n, src) {
				out = append(out, kotlinFinding("empty-catch", n, rel))
			}
			if name, ok := kotlinCancellationParameter(n, src); ok && !kotlinThrowsName(n, src, name) {
				out = append(out, kotlinFinding("cancellation-swallowed", n, rel))
			}
		case "finally_block":
			if kotlinHasJump(n, src, "return") {
				out = append(out, kotlinFinding("return-finally", n, rel))
			}
		case "function_declaration":
			if kotlinSuspendFunction(n, src) {
				out = append(out, kotlinCoroutineBodyFindings(n, src, rel, true)...)
			}
		case "call_expression":
			if kotlinCoroutineBuilder(n, src) && !kotlinInsideSuspendFunction(n, src) {
				out = append(out, kotlinCoroutineBodyFindings(n, src, rel, false)...)
			}
		case "postfix_expression", "_postfix_unary_expression":
			if kotlinHasDirectToken(n, "!!") && !kotlinParentHasDirectToken(n, "!!") {
				out = append(out, kotlinFinding("not-null-assertion", n, rel))
			}
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

func kotlinCoroutineBodyFindings(owner *sitter.Node, src []byte, rel string, suspendOnly bool) []QualityFinding {
	var out []QualityFinding
	stack := []*sitter.Node{owner}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n != owner && (n.Type() == "function_declaration" || n.Type() == "anonymous_function") {
			continue
		}
		if n.Type() == "call_expression" {
			call := kotlinCallName(n, src)
			switch {
			case call == "Thread.sleep":
				out = append(out, kotlinFinding("blocking-coroutine", n, rel))
			case call == "latch.await" || call == "barrier.await":
				out = append(out, kotlinFinding("latch-await-coroutine", n, rel))
			case kotlinFutureGetCall(call):
				out = append(out, kotlinFinding("future-get-coroutine", n, rel))
			case suspendOnly && call == "runBlocking":
				out = append(out, kotlinFinding("run-blocking-suspend", n, rel))
			case suspendOnly && call == "synchronized":
				out = append(out, kotlinFinding("synchronized-suspend", n, rel))
			}
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return out
}

func kotlinFutureGetCall(call string) bool {
	if !strings.HasSuffix(call, ".get") {
		return false
	}
	receiver := strings.TrimSuffix(call, ".get")
	if i := strings.LastIndexByte(receiver, '.'); i >= 0 {
		receiver = receiver[i+1:]
	}
	// ponytail: lexical receiver names favor precision; use Kotlin type resolution to recognize arbitrary Future values.
	return receiver == "future" || strings.HasSuffix(receiver, "Future")
}

func kotlinCallName(n *sitter.Node, src []byte) string {
	text := strings.TrimSpace(n.Content(src))
	if i := strings.IndexAny(text, "({"); i >= 0 {
		text = text[:i]
	}
	return strings.Join(strings.Fields(text), "")
}

func kotlinCoroutineBuilder(n *sitter.Node, src []byte) bool {
	call := kotlinCallName(n, src)
	return call == "launch" || call == "async" || strings.HasSuffix(call, ".launch") || strings.HasSuffix(call, ".async")
}

func kotlinSuspendFunction(n *sitter.Node, src []byte) bool {
	text := strings.TrimSpace(n.Content(src))
	fun := strings.Index(text, "fun")
	if fun < 0 {
		return false
	}
	for _, field := range strings.Fields(text[:fun]) {
		if field == "suspend" {
			return true
		}
	}
	return false
}

func kotlinInsideSuspendFunction(n *sitter.Node, src []byte) bool {
	for parent := n.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Type() == "function_declaration" {
			return kotlinSuspendFunction(parent, src)
		}
	}
	return false
}

func kotlinCatchBodyEmpty(n *sitter.Node, src []byte) bool {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type() != "statements" {
			continue
		}
		for j := 0; j < int(child.NamedChildCount()); j++ {
			t := child.NamedChild(j).Type()
			if t != "line_comment" && t != "multiline_comment" {
				return false
			}
		}
		return true
	}
	text := n.Content(src)
	start, end := strings.LastIndexByte(text, '{'), strings.LastIndexByte(text, '}')
	return start >= 0 && end > start && strings.TrimSpace(text[start+1:end]) == ""
}

func kotlinCancellationParameter(n *sitter.Node, src []byte) (string, bool) {
	text := n.Content(src)
	start, end := strings.IndexByte(text, '('), strings.IndexByte(text, ')')
	if start < 0 || end <= start {
		return "", false
	}
	parameter := text[start+1 : end]
	colon := strings.IndexByte(parameter, ':')
	if colon < 0 || strings.TrimSpace(parameter[colon+1:]) != "CancellationException" {
		return "", false
	}
	name := strings.TrimSpace(parameter[:colon])
	return name, name != ""
}

func kotlinThrowsName(root *sitter.Node, src []byte, name string) bool {
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n != root && (n.Type() == "function_declaration" || n.Type() == "anonymous_function" || n.Type() == "lambda_literal") {
			continue
		}
		if n.Type() == "jump_expression" && strings.TrimSpace(n.Content(src)) == "throw "+name {
			return true
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return false
}

func kotlinHasJump(root *sitter.Node, src []byte, keyword string) bool {
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n != root && (n.Type() == "function_declaration" || n.Type() == "anonymous_function" || n.Type() == "lambda_literal") {
			continue
		}
		if n.Type() == "jump_expression" && strings.HasPrefix(strings.TrimSpace(n.Content(src)), keyword) {
			return true
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return false
}

func kotlinHasDirectToken(n *sitter.Node, token string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if n.Child(i).Type() == token {
			return true
		}
	}
	return false
}

func kotlinParentHasDirectToken(n *sitter.Node, token string) bool {
	parent := n.Parent()
	return parent != nil && kotlinHasDirectToken(parent, token)
}

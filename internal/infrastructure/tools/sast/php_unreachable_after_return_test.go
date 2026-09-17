package sast

import (
	"context"
	"testing"
)

// TestPhpUnreachableAfterReturn pins that php:unreachable-after-return fires only when a real statement
// follows a return in the same block, not on the common shapes where a return is the last statement of its
// block (before a closing brace, a switch case label, or an else branch). The rule runs over a joined PHP
// statement, so without the filter its `;\s*...` reached the block-closing `}` and falsely flagged nearly
// every PHP function.
//
// Covered non-firing shapes include a returned string/heredoc body that contains a semicolon and a
// brace-less guard `if ($x) return 1;` before reachable code. The one known residual limitation, requiring
// brace/scope awareness (an AST) to fix: dead code after a *later* return in a multi-branch switch or
// alternative-syntax block is silently missed, because a line regex cannot anchor the finding at the correct
// return, and a silent miss is preferred over a finding pointing at a clean earlier return.
func TestPhpUnreachableAfterReturn(t *testing.T) {
	src := `<?php
function ifReturn($x) {
    if ($x) {
        return 1;
    }
    return 2;
}
function switchReturn($x) {
    switch ($x) {
        case 1:
            return "a";
        case 2:
            return "b";
        default:
            return "c";
    }
}
function elseReturn($x) {
    if ($x) {
        return 1;
    } else {
        return 2;
    }
}
function lastStatement($x) {
    return $x * 2;
}
function realDeadCode($x) {
    return $x;
    echo "unreachable";
}
function realDeadAssignment($x) {
    return $x;
    $y = 1;
}
function returnStringWithSemicolon($x) {
    return "a; b";
}
function returnStringThenDead($x) {
    return "x;case";
    echo "dead";
}
function keywordPrefixedCall($x) {
    return $x;
    caseHandler();
}
function namespacedDeadCall($x) {
    return $x;
    \Acme\Log::write("dead");
}
function heredocReturn($x) {
    return <<<SQL
SELECT 1; DROP TABLE t;
SQL;
}
function bracelessGuard($x) {
    if ($x) return 1;
    doWork();
}
function bracedBlockThenDead($x) {
    if ($x) { doStuff(); }
    return $y;
    dead();
}
function nowdocReturn($x) {
    return <<<'EOT'
line; with EOT word inside
EOT;
}
`
	root := t.TempDir()
	writeFile(t, root, "sample.php", src)
	findings, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	var lines []int
	for _, f := range findings {
		if f.RuleID == "php:unreachable-after-return" {
			lines = append(lines, f.Line)
		}
	}
	// The rule anchors at the return that is followed by dead code. Only the returns with a real statement
	// after them must fire: realDeadCode (line 29), realDeadAssignment (line 33), and returnStringThenDead
	// (line 40). A return of a string literal containing a semicolon (line 37) must not fire, and the
	// semicolon-and-keyword inside the literal on line 40 must not hide the dead echo after it.
	// 44: dead code is a call that merely starts with the letters of a keyword (caseHandler), which must
	// not be mistaken for a `case` label. 48: a namespaced dead call (\Acme\Log::write) must fire. 62: a
	// braced block `if ($x) { doStuff(); }` before an unconditional return is not a guard, so the dead()
	// after that return must still fire (the `[^{}]` in the guard pattern keeps the braced block out).
	want := map[int]bool{29: true, 33: true, 40: true, 44: true, 48: true, 62: true}
	for _, l := range lines {
		if !want[l] {
			t.Errorf("false positive: php:unreachable-after-return at line %d", l)
		}
		delete(want, l)
	}
	for l := range want {
		t.Errorf("missed genuine unreachable code at line %d (findings: %v)", l, lines)
	}
}

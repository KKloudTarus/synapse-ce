package platform_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditIsTheLastStatementInABoundTransaction enforces the ordering rule the audit log depends
// on when it appends onto a caller's transaction.
//
// The append takes pg_advisory_xact_lock on a single deployment-wide key, and a transaction-scoped
// advisory lock is held until the transaction commits. Auditing early in a long transaction
// therefore serializes every other audit append in the deployment behind that caller's remaining
// work, and can deadlock against a transaction that takes the same row locks in the other order.
// Auditing last makes the hold as short as the commit itself.
//
// The rule: inside a tenant transaction body, the audit append is the final repository call. This
// walks each transaction closure and fails when a repository call follows the audit call.
func TestAuditIsTheLastStatementInABoundTransaction(t *testing.T) {
	root := filepath.Join("..", "usecase")
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isTransactionRun(call) {
				return true
			}
			body := transactionBody(call)
			if body == nil {
				return true
			}
			auditLine, lastRepoLine, lastRepoName := 0, 0, ""
			ast.Inspect(body, func(inner ast.Node) bool {
				innerCall, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := innerCall.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				field, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				line := fset.Position(innerCall.Pos()).Line
				if field.Sel.Name == "audit" && strings.HasPrefix(sel.Sel.Name, "Record") {
					if line > auditLine {
						auditLine = line
					}
					return true
				}
				// Any other call on a service field that takes the transaction context is a
				// repository call made inside the transaction.
				if takesTransactionContext(innerCall) && line > lastRepoLine {
					lastRepoLine, lastRepoName = line, field.Sel.Name+"."+sel.Sel.Name
				}
				return true
			})
			if auditLine > 0 && lastRepoLine > auditLine {
				violations = append(violations, filepath.ToSlash(path)+": audit appended at line "+
					itoa(auditLine)+" but "+lastRepoName+" runs after it at line "+itoa(lastRepoLine)+
					"; audit last in a bound transaction, the chain lock is held until commit")
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk usecase: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// isTransactionRun reports whether a call is <field>.Run(ctx, tenant, func(...) error {...}), the
// shape every tenant-bound transaction in the use-case layer takes.
func isTransactionRun(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" || len(call.Args) != 3 {
		return false
	}
	_, ok = call.Args[2].(*ast.FuncLit)
	return ok
}

func transactionBody(call *ast.CallExpr) *ast.BlockStmt {
	lit, ok := call.Args[2].(*ast.FuncLit)
	if !ok {
		return nil
	}
	return lit.Body
}

// takesTransactionContext reports whether a call's first argument is the transaction context the
// closure was handed, which is what marks it as work done inside the transaction.
func takesTransactionContext(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	return ok && (ident.Name == "txCtx" || ident.Name == "tctx")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

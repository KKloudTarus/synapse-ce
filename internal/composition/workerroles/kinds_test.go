package workerroles

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestRoleKindSetsAreDisjoint: no kind is claimed by both roles.
func TestRoleKindSetsAreDisjoint(t *testing.T) {
	for _, kind := range ControlKinds() {
		if IsExecution(kind) {
			t.Errorf("%q is in both role sets", kind)
		}
	}
}

// TestRoleKindSetsAreComplete: the union of the two role sets equals every job kind constant the use
// cases and domain declare, so a kind cannot be enqueued without a worker role that claims it.
func TestRoleKindSetsAreComplete(t *testing.T) {
	declared := declaredJobKinds(t)
	union := append(ControlKinds(), ExecutionKinds()...)
	sort.Strings(union)
	if strings.Join(declared, ",") != strings.Join(union, ",") {
		t.Fatalf("declared job kinds %v\nrole sets cover   %v\nadd the new kind to ControlKinds or ExecutionKinds", declared, union)
	}
}

var jobKindConst = regexp.MustCompile(`(^|[A-Z][A-Za-z]*)JobKind$`)

// declaredJobKinds walks internal/usecase and internal/domain for string constants named *JobKind.
func declaredJobKinds(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "internal")
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"usecase", "domain"} {
		if err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if !jobKindConst.MatchString(name.Name) || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						value, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("%s: %v", path, err)
						}
						seen[value] = true
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no job kind constants found; the walker is broken")
	}
	return out
}

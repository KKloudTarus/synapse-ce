package docs_test

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

	"github.com/KKloudTarus/synapse-ce/internal/composition/workerroles"
)

// The background ownership inventory (docs/guide/background-ownership.md, #1559) is the documented truth
// for which role owns each queue consumer, singleton, replica loop and startup barrier. These guards keep
// it in step with the code: a new job kind needs a consumer row with the right owner, and a new loop site
// in a composition root needs a topology marker that names a row or states why it is exempt.

const ownershipDoc = "guide/background-ownership.md"

var (
	jobKindConstName = regexp.MustCompile(`(^|[A-Z][A-Za-z]*)JobKind$`)
	topologyMarker   = regexp.MustCompile(`^\s*// topology: (id=([a-z:_.-]+)|exempt=(.+))$`)
)

type ownershipRow struct {
	id, class, target string
}

// ownershipRows parses the two inventory tables.
func ownershipRows(t *testing.T) map[string]ownershipRow {
	t.Helper()
	raw, err := os.ReadFile(ownershipDoc)
	if err != nil {
		t.Fatalf("read %s: %v", ownershipDoc, err)
	}
	rows := map[string]ownershipRow{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| id ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 4 {
			t.Fatalf("%s: row has %d cells: %q", ownershipDoc, len(cells), line)
		}
		row := ownershipRow{id: strings.TrimSpace(cells[0]), class: strings.TrimSpace(cells[1]), target: strings.TrimSpace(cells[3])}
		if _, dup := rows[row.id]; dup {
			t.Fatalf("%s: row %q is listed twice", ownershipDoc, row.id)
		}
		rows[row.id] = row
	}
	if len(rows) == 0 {
		t.Fatalf("%s: no inventory rows parsed", ownershipDoc)
	}
	return rows
}

// TestBackgroundOwnershipEveryRowHasOneTargetOwner: the point of the inventory is one final owner per row.
func TestBackgroundOwnershipEveryRowHasOneTargetOwner(t *testing.T) {
	for id, row := range ownershipRows(t) {
		switch row.target {
		case "api", "control", "execution":
		default:
			t.Errorf("%s: row %q target owner %q is not exactly one of api, control, execution", ownershipDoc, id, row.target)
		}
	}
}

// TestBackgroundOwnershipDocCoversEveryJobKind: each job kind constant has a consumer row whose target
// owner is the role that claims it.
func TestBackgroundOwnershipDocCoversEveryJobKind(t *testing.T) {
	rows := ownershipRows(t)
	kinds := declaredJobKinds(t)
	for kind, where := range kinds {
		row, ok := rows["consumer:"+kind]
		if !ok {
			t.Errorf("%s declares job kind %q but %s has no row consumer:%s", where, kind, ownershipDoc, kind)
			continue
		}
		want := "control"
		if workerroles.IsExecution(kind) {
			want = "execution"
		}
		if row.target != want {
			t.Errorf("row consumer:%s names target %q; workerroles says %q", kind, row.target, want)
		}
	}
	for id := range rows {
		if kind, ok := strings.CutPrefix(id, "consumer:"); ok && !strings.HasSuffix(kind, "-inline") {
			if _, declared := kinds[kind]; !declared {
				t.Errorf("row %q names a job kind no constant declares; remove the row or restore the kind", id)
			}
		}
	}
}

// TestBackgroundOwnershipDocCoversEveryLoopSite: every go statement, RunOnce barrier and maintenance
// registration in the composition roots carries a topology marker, and every marker id is a row.
func TestBackgroundOwnershipDocCoversEveryLoopSite(t *testing.T) {
	rows := ownershipRows(t)
	root := repoRoot(t)
	referenced := map[string]bool{}
	for _, dir := range []string{"cmd/synapse-api", "cmd/synapse-worker"} {
		files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			for _, site := range loopSites(t, file) {
				marker := markerAbove(site.lines, site.line)
				switch {
				case marker == "":
					t.Errorf("%s:%d: %s has no `// topology:` marker above it", rel(root, file), site.line, site.what)
				case strings.HasPrefix(marker, "exempt="):
				default:
					id := strings.TrimPrefix(marker, "id=")
					if _, ok := rows[id]; !ok {
						t.Errorf("%s:%d: marker names %q, which is not a row in %s", rel(root, file), site.line, id, ownershipDoc)
					}
					referenced[id] = true
				}
			}
		}
	}
	for id, row := range rows {
		switch row.class {
		case "consumer":
			continue // covered by the job kind test
		}
		if !referenced[id] {
			t.Errorf("%s: row %q (%s) has no marker in cmd/synapse-api or cmd/synapse-worker; the loop moved or the row is stale", ownershipDoc, id, row.class)
		}
	}
}

type loopSite struct {
	line  int
	what  string
	lines []string
}

// loopSites finds the statements that start background work: go statements, RunOnce barriers, and
// appends of a function (not a spread) to a maintenance list.
func loopSites(t *testing.T, file string) []loopSite {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	var sites []loopSite
	add := func(pos token.Pos, what string) {
		sites = append(sites, loopSite{line: fset.Position(pos).Line, what: what, lines: lines})
	}
	ast.Inspect(parsed, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GoStmt:
			add(node.Pos(), "go statement")
		case *ast.CallExpr:
			switch fn := node.Fun.(type) {
			case *ast.SelectorExpr:
				if fn.Sel.Name == "RunOnce" {
					add(node.Pos(), "RunOnce barrier")
				}
			case *ast.Ident:
				if fn.Name == "append" && len(node.Args) >= 2 && node.Ellipsis == token.NoPos && registersTask(node) {
					if len(node.Args) > 2 {
						t.Errorf("%s:%d: append registers %d tasks under one marker; register one task per append so each has its own row", file, fset.Position(node.Pos()).Line, len(node.Args)-1)
					}
					add(node.Pos(), "maintenance registration")
				}
			}
		}
		return true
	})
	return sites
}

// registersTask reports whether an append adds background work: the slice is a maintenance list, or an
// appended value is a function literal or a method value named Run, whatever the slice is called.
func registersTask(call *ast.CallExpr) bool {
	if strings.Contains(exprName(call.Args[0]), "aintenance") {
		return true
	}
	for _, arg := range call.Args[1:] {
		switch v := arg.(type) {
		case *ast.FuncLit:
			return true
		case *ast.SelectorExpr:
			if v.Sel.Name == "Run" {
				return true
			}
		}
	}
	return false
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprName(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}

// markerAbove returns the topology marker in the comment lines directly above line (1-based), or "".
func markerAbove(lines []string, line int) string {
	for i := line - 2; i >= 0; i-- {
		text := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(text, "//") {
			return ""
		}
		if m := topologyMarker.FindStringSubmatch(lines[i]); m != nil {
			if m[2] != "" {
				return "id=" + m[2]
			}
			return "exempt=" + m[3]
		}
	}
	return ""
}

func rel(root, file string) string {
	r, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	return r
}

// declaredJobKinds maps every *JobKind string constant under internal/usecase and internal/domain to the
// file that declares it.
func declaredJobKinds(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal/usecase", "internal/domain"} {
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
						if !jobKindConstName.MatchString(name.Name) || i >= len(vs.Values) {
							continue
						}
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							value, err := strconv.Unquote(lit.Value)
							if err != nil {
								return err
							}
							out[value] = rel(root, path)
						}
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no job kind constants found")
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out
}

package sast

import (
	"context"
	"testing"
)

// TestCrossLineSinkResolution covers the bounded look-back: a sink taking a bare identifier that an
// earlier line built from a format/concat expression or a request value fires, and the same sink
// over an identifier assigned a constant literal stays silent.
func TestCrossLineSinkResolution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    string
		content string
		rule    string
		want    bool
	}{
		{
			name: "flask percent format then execute",
			file: "app.py",
			content: `def search():
    search_term = content['search']
    str_query = "SELECT first_name FROM customer WHERE username = '%s';" % search_term

    search_query = db.engine.execute(str_query)
`,
			rule: "generic-sql-dynamic-execute", want: true,
		},
		{
			name: "python multi-line format then cursor execute",
			file: "student.py",
			content: `async def create(conn, name):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    async with conn.cursor() as cur:
        await cur.execute(q)
`,
			rule: "generic-sql-dynamic-execute", want: true,
		},
		{
			name: "python constant literal then execute",
			file: "clean.py",
			content: `def all_students(conn):
    q = "SELECT id, name FROM students"
    cur = conn.cursor()
    cur.execute(q)
`,
			rule: "generic-sql-dynamic-execute", want: false,
		},
		{
			name: "go sprintf then Exec",
			file: "store.go",
			content: `func del(db *sql.DB, id string) error {
	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
	_, err := db.Exec(query)
	return err
}
`,
			rule: "go-sql-dynamic-query", want: true,
		},
		{
			name: "go sprintf then ExecContext with a ctx argument",
			file: "storectx.go",
			content: `func del(ctx context.Context, db *sql.DB, id string) error {
	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
	_, err := db.ExecContext(ctx, query)
	return err
}
`,
			rule: "go-sql-dynamic-query", want: true,
		},
		{
			name: "go constant query then Exec",
			file: "clean.go",
			content: `func del(db *sql.DB, id string) error {
	query := "DELETE FROM users WHERE id = $1"
	_, err := db.Exec(query, id)
	return err
}
`,
			rule: "go-sql-dynamic-query", want: false,
		},
		{
			name: "express request value then redirect",
			file: "routes.js",
			content: `app.get("/go", function (req, res) {
  const target = req.query.next;
  res.redirect(target);
});
`,
			rule: "open-redirect-user-url", want: true,
		},
		{
			name: "express constant then redirect",
			file: "safe.js",
			content: `app.get("/go", function (req, res) {
  const target = "/dashboard";
  res.redirect(target);
});
`,
			rule: "open-redirect-user-url", want: false,
		},
		{
			name: "rails params then paren-less redirect_to",
			file: "sessions_controller.rb",
			content: `def create
  target = params[:return_to]
  redirect_to target
end
`,
			rule: "rb:open-redirect", want: true,
		},
		{
			name: "rails named route then redirect_to",
			file: "safe_controller.rb",
			content: `def create
  target = dashboard_path
  redirect_to target
end
`,
			rule: "rb:open-redirect", want: false,
		},
		{
			name: "assignment further back than the look-back window",
			file: "far.py",
			content: `q = "SELECT * FROM t WHERE a = '%s'" % v
x1 = 1
x2 = 2
x3 = 3
x4 = 4
x5 = 5
x6 = 6
x7 = 7
x8 = 8
x9 = 9
x10 = 10
x11 = 11
cur.execute(q)
`,
			rule: "generic-sql-dynamic-execute", want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, tc.content)
			got := findingsByRule(t, root)[tc.rule]
			if (len(got) > 0) != tc.want {
				t.Errorf("%s fired = %v, want %v (%+v)", tc.rule, len(got) > 0, tc.want, got)
			}
		})
	}
}

// TestCrossLineCallArgs pins the argument splitter that feeds the look-back.
func TestCrossLineCallArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		from int
		want []string
	}{
		{name: "single ident", line: "(query)", want: []string{"query"}},
		{name: "ctx first", line: "(ctx, query)", want: []string{"ctx", " query"}},
		{name: "nested call", line: "(fmt.Sprintf(\"a, b\", x), y)", want: []string{"fmt.Sprintf(\"a, b\", x)", " y"}},
		{name: "paren-less rails", line: " target", want: []string{"target"}},
		{name: "string with a close paren", line: "(\"a)b\", y)", want: []string{"\"a)b\"", " y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := crossLineCallArgs(tc.line, tc.from)
			if len(got) != len(tc.want) {
				t.Fatalf("args = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("arg %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestCrossLineDoesNotDoubleReport keeps the look-back from adding a second finding on a line the
// rule already matched by itself.
func TestCrossLineDoesNotDoubleReport(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "inline.go", "func q(db *sql.DB, id string) {\n\tdb.Exec(fmt.Sprintf(\"SELECT %s\", id))\n}\n")
	report, err := New().AnalyzeSourceReport(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	n := 0
	for _, f := range report.Findings {
		if f.RuleID == "go-sql-dynamic-query" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("go-sql-dynamic-query fired %d times, want 1", n)
	}
}

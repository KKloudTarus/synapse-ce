package sast

import "testing"

// TestRulePrecisionFixes pairs every tightened rule with the false positive it used to produce and
// the true positive it must still find. Each case is one file so a rule can be gated by extension.
func TestRulePrecisionFixes(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----"
	for _, tc := range []struct {
		name    string
		rule    string
		file    string
		content string
		want    bool
	}{
		// reflected-response-write: a word inside a quoted string is not a request value.
		{name: "response write constant newlines", rule: "reflected-response-write", file: "src/a.js", want: false,
			content: "function h(req, res) {\n  res.write(\"\\n\\n\")\n}\n"},
		{name: "response send constant string", rule: "reflected-response-write", file: "src/b.js", want: false,
			content: "function h(req, res) {\n  res.send(\"Hello world\")\n}\n"},
		{name: "response send request field", rule: "reflected-response-write", file: "src/c.js", want: true,
			content: "function h(req, res) {\n  res.send(req.query.name)\n}\n"},
		{name: "response send concatenated variable", rule: "reflected-response-write", file: "src/d.js", want: true,
			content: "function h(req, res) {\n  const name = req.query.name\n  res.send(\"<h1>\" + name + \"</h1>\")\n}\n"},
		{name: "go fprintf with a variable", rule: "reflected-response-write", file: "h.go", want: true,
			content: "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"n\")\n\tfmt.Fprintf(w, \"hello %s\", name)\n}\n"},
		{name: "go fprintln constant", rule: "reflected-response-write", file: "ok.go", want: false,
			content: "func h(w http.ResponseWriter) {\n\tfmt.Fprintln(w, \"ok\")\n}\n"},
		// []byte(x) is the idiomatic Go response write and must not hide the variable inside it.
		{name: "go write byte conversion of a variable", rule: "reflected-response-write", file: "bw.go", want: true,
			content: "func h(w http.ResponseWriter, s string) {\n\t_, _ = w.Write([]byte(s))\n}\n"},
		{name: "go write byte conversion of a constant", rule: "reflected-response-write", file: "bwok.go", want: false,
			content: "func h(w http.ResponseWriter) {\n\t_, _ = w.Write([]byte(\"ok\"))\n}\n"},
		{name: "gin c.String with a variable", rule: "reflected-response-write", file: "gin.go", want: true,
			content: "func h(c *gin.Context) {\n\tname := c.Query(\"n\")\n\tc.String(http.StatusOK, name)\n}\n"},

		// go-command-dynamic: a constant argv is not dynamic input.
		{name: "constant argv", rule: "go-command-dynamic", file: "cmd.go", want: false,
			content: "func run() {\n\texec.Command(\"git\", \"status\")\n}\n"},
		{name: "constant argv with context", rule: "go-command-dynamic", file: "cmdctx.go", want: false,
			content: "func run(ctx context.Context) {\n\texec.CommandContext(ctx, \"git\", \"status\")\n}\n"},
		{name: "variable argv", rule: "go-command-dynamic", file: "dyn.go", want: true,
			content: "func run(userVar string) {\n\texec.Command(\"sh\", userVar)\n}\n"},
		{name: "request derived argv", rule: "go-command-dynamic", file: "req.go", want: true,
			content: "func run(c *gin.Context) {\n\texec.Command(c.Query(\"cmd\"))\n}\n"},
		// The binary itself taken from an indexed variable is the strongest command-injection
		// shape there is, and an identifier-only pattern misses it because of the subscript.
		{name: "indexed argv", rule: "go-command-dynamic", file: "idx.go", want: true,
			content: "func run(args []string) {\n\texec.Command(args[0], args[1:]...)\n}\n"},
		{name: "indexed argv single", rule: "go-command-dynamic", file: "idx2.go", want: true,
			content: "func run(parts []string) {\n\t_ = exec.Command(parts[0]).Run()\n}\n"},

		// go-sql-dynamic-query: database/sql is Go only.
		{name: "js query concat", rule: "go-sql-dynamic-query", file: "src/db.js", want: false,
			content: "function q(db, id) {\n  return db.Query(\"SELECT * FROM t WHERE id=\" + id)\n}\n"},
		{name: "go query concat", rule: "go-sql-dynamic-query", file: "db.go", want: true,
			content: "func q(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id=\" + id)\n}\n"},

		// ssrf-fetch-user-url: a DOM-touching file makes fetch a browser call.
		{name: "browser fetch", rule: "ssrf-fetch-user-url", file: "src/ui.js", want: false,
			content: "const el = document.getElementById(\"x\")\nfunction load(target) {\n  return fetch(target)\n}\n"},
		{name: "server fetch", rule: "ssrf-fetch-user-url", file: "src/proxy.js", want: true,
			content: "async function proxy(req, res) {\n  const target = req.query.url\n  return fetch(target)\n}\n"},
		{name: "ruby hash fetch", rule: "ssrf-fetch-user-url", file: "db/seeds.rb", want: false,
			content: "row[:user_id] = user_map.fetch(row.delete(:user))\n"},

		// private-key-material: the header alone is a delimiter, not a key.
		{name: "pem header constant", rule: "private-key-material", file: "Pem.java", want: false,
			content: "class P {\n  String s = \"" + pem + "\\n\";\n}\n"},
		{name: "pem header stripped", rule: "private-key-material", file: "Strip.java", want: false,
			content: "class P {\n  String body = raw.replace(\"" + pem + "\", \"\");\n}\n"},
		{name: "real pem file", rule: "private-key-material", file: "key.pem", want: true,
			content: pem + "\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"},
		{name: "embedded pem body", rule: "private-key-material", file: "key.go", want: true,
			content: "var keyData = \"" + pem + "\\nMIIEvQIBADANBgkqhkiG9w0BAQEF\"\n"},

		// TLS verification: a JWT claim-validation flag is not a certificate check.
		{name: "jwt decode verify false", rule: "insecure-tls-verify-disabled", file: "auth.py", want: false,
			content: "def check(token):\n    return jwt.decode(token, verify=False)\n"},
		{name: "jwt decode verify false python pack", rule: "python-requests-verify-false", file: "auth2.py", want: false,
			content: "def check(token):\n    return jwt.decode(token, verify=False)\n"},
		{name: "requests verify false", rule: "python-requests-verify-false", file: "http.py", want: true,
			content: "def get(url):\n    return requests.get(url, verify=False)\n"},
		{name: "requests verify false tls rule", rule: "insecure-tls-verify-disabled", file: "http2.py", want: true,
			content: "def get(url):\n    return requests.get(url, verify=False)\n"},

		// Comment-only mentions.
		{name: "commented debug flag", rule: "debug-mode-enabled", file: "notes.py", want: false,
			content: "# DEBUG = True\nvalue = 1\n"},
		{name: "live debug flag", rule: "debug-mode-enabled", file: "settings.py", want: true,
			content: "DEBUG = True\n"},
		{name: "commented credential", rule: "hardcoded-credential", file: "notes.go", want: false,
			content: "// password = \"supersecretvalue\"\nvar x = 1\n"},
		{name: "js block comment credential", rule: "hardcoded-credential", file: "src/conf.js", want: false,
			content: "/*\npassword = \"supersecretvalue\"\n*/\nconst x = 1\n"},
		{name: "live credential", rule: "hardcoded-credential", file: "conf.go", want: true,
			content: "var password = \"supersecretvalue\"\n"},
		// Key shapes real config uses. The literals are the NodeGoat and Flask lines verbatim.
		{name: "camelCase credential key", rule: "hardcoded-credential", file: "config/env/all.js", want: true,
			content: "module.exports = {\n    cookieSecret: \"secret_here_or_whatever\",\n}\n"},
		{name: "bracket config credential key", rule: "hardcoded-credential", file: "app/app.py", want: true,
			content: "app.config['SECRET_KEY_HMAC'] = 'secret'\n"},
		{name: "bracket config credential key with suffix", rule: "hardcoded-credential", file: "app/app2.py", want: true,
			content: "app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'\n"},
		{name: "placeholder credential still skipped", rule: "hardcoded-credential", file: "app/tpl.py", want: false,
			content: "app.config['SECRET_KEY'] = os.environ['SECRET_KEY']\ncookieSecret: \"${COOKIE_SECRET}\"\n"},
		{name: "dependency version pin is not a credential", rule: "hardcoded-credential", file: "package-lock.json", want: false,
			content: "{\n  \"dependencies\": {\n    \"parse-passwd\": \"^1.0.0\",\n    \"registry-auth-token\": \"~3.0.1\"\n  }\n}\n"},

		// go-log-fatal-in-code: main and init are allowed to end the process.
		{name: "fatal in main", rule: "go-log-fatal-in-code", file: "main.go", want: false,
			content: "package main\n\nfunc main() {\n\tif err := run(); err != nil {\n\t\tlog.Fatalf(\"boom: %v\", err)\n\t}\n}\n"},
		{name: "fatal in init", rule: "go-log-fatal-in-code", file: "init.go", want: false,
			content: "package main\n\nfunc init() {\n\tlog.Fatal(\"boom\")\n}\n"},
		{name: "fatal in a helper", rule: "go-log-fatal-in-code", file: "lib.go", want: true,
			content: "package lib\n\nfunc Connect() {\n\tlog.Fatalf(\"cannot connect\")\n}\n"},

		// js-react-jsx-class-attribute: JSX/TSX only.
		{name: "class assignment in plain js", rule: "js-react-jsx-class-attribute", file: "src/dom.js", want: false,
			content: "const el = build()\nel.class = \"box\"\n"},
		{name: "class attribute in jsx", rule: "js-react-jsx-class-attribute", file: "src/App.jsx", want: true,
			content: "export const App = () => <div class=\"box\">hi</div>\n"},

		// java-mutable-public-static-array: a field, not a method returning an array.
		{name: "method returning an array", rule: "java-mutable-public-static-array", file: "A.java", want: false,
			content: "class A {\n  public static int[] getCodes() { return new int[]{1}; }\n}\n"},
		{name: "public static array field", rule: "java-mutable-public-static-array", file: "B.java", want: true,
			content: "class B {\n  public static int[] CODES = {1, 2};\n}\n"},

		// go-todo-marker: context.TODO() is not unfinished work.
		{name: "context TODO", rule: "go-todo-marker", file: "ctx.go", want: false,
			content: "func f() {\n\trun(context.TODO())\n}\n"},
		{name: "todo comment", rule: "go-todo-marker", file: "todo.go", want: true,
			content: "func f() {\n\t// TODO: handle the reconnect case\n}\n"},

		// python-assert-string-literal: only a whole-condition literal is always true.
		{name: "assert membership", rule: "python-assert-string-literal", file: "t1.py", want: false,
			content: "def t(y):\n    assert \"X\" in y\n"},
		{name: "assert equality", rule: "python-assert-string-literal", file: "t2.py", want: false,
			content: "def t(b):\n    assert 'a' == b\n"},
		{name: "assert format", rule: "python-assert-string-literal", file: "t3.py", want: false,
			content: "def t(v):\n    assert \"%s\" % v\n"},
		{name: "assert join", rule: "python-assert-string-literal", file: "t4.py", want: false,
			content: "def t(y):\n    assert \"\".join(y)\n"},
		{name: "assert bare literal", rule: "python-assert-string-literal", file: "t5.py", want: true,
			content: "def t():\n    assert \"must be configured\"\n"},

		// Comment masking must not silence the pragma rules, whose subject IS the comment.
		{name: "triple slash reference still fires", rule: "ts-triple-slash-reference", file: "src/types.ts", want: true,
			content: "/// <reference path=\"./types.d.ts\" />\nexport const x = 1\n"},
		{name: "ts-ignore pragma still fires", rule: "ts-ts-ignore", file: "src/x.ts", want: true,
			content: "// @ts-ignore\nexport const y = 1\n"},
		// A slash-star sequence inside a string literal must not open a comment.
		{name: "block comment marker inside a string", rule: "hardcoded-credential", file: "src/glob.js", want: true,
			content: "const glob = \"src/*\"\nconst password = \"supersecretvalue\"\n"},
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

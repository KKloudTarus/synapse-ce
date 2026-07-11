package sast

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzerFindsAndSkips(t *testing.T) {
	root := t.TempDir()
	// Test secrets are ASSEMBLED at runtime so no secret pattern appears literally in this source.
	awsKey := "AKIA" + strings.Repeat("Z", 16) // AKIA-format access key id
	pw := "hunter2" + "supersecret"            // a non-placeholder credential literal

	writeFile(t, root, "crypto.go", "package x\nimport \"crypto/md5\"\n")
	writeFile(t, root, "creds.txt", "aws_key = "+awsKey+"\npassword = \""+pw+"\"\n")
	writeFile(t, root, "ok.py", "password = os.environ[\"DB_PASS\"]\napi_key = \"${VAULT_TOKEN}\"\n") // env/placeholder → not flagged
	writeFile(t, root, "node_modules/dep/x.go", "import \"crypto/md5\"\n")                            // vendored → skipped
	// binary file (NUL byte) → skipped even though "MD5" appears
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), []byte{'M', 'D', '5', 0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	byRule := map[string][]ports.SASTRawFinding{}
	for _, f := range got {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
		if strings.HasPrefix(filepath.ToSlash(f.File), "node_modules") {
			t.Errorf("vendored dir must be skipped, got %+v", f)
		}
	}
	if n := len(byRule["weak-hash-md5"]); n != 1 { // crypto.go only (node_modules + binary skipped)
		t.Errorf("weak-hash-md5: want 1, got %d (%+v)", n, byRule["weak-hash-md5"])
	}
	if n := len(byRule["hardcoded-aws-access-key"]); n != 1 {
		t.Errorf("hardcoded-aws-access-key: want 1, got %d", n)
	}
	if n := len(byRule["hardcoded-credential"]); n != 1 { // the assembled pw only; env + ${...} placeholders skipped
		t.Errorf("hardcoded-credential: want 1 (placeholders skipped), got %d (%+v)", n, byRule["hardcoded-credential"])
	}
	a := byRule["hardcoded-aws-access-key"][0]
	if a.CWE != "CWE-798" || a.Severity != shared.SeverityCritical || filepath.ToSlash(a.File) != "creds.txt" || a.Line != 1 {
		t.Errorf("aws finding metadata wrong: %+v", a)
	}
}

func TestDebugModeDetection(t *testing.T) {
	root := t.TempDir()
	// positives – a literal debug=true (Django/generic), Flask app.run(debug=True), Gin debug mode.
	writeFile(t, root, "settings.py", "DEBUG = True\n")
	writeFile(t, root, "app.py", "app.run(host=\"0.0.0.0\", debug=True)\n")
	writeFile(t, root, "main.go", "func main() { gin.SetMode(gin.DebugMode) }\n")
	// negatives – env-derived (RHS not a literal true) and an explicit false.
	writeFile(t, root, "env.py", "DEBUG = os.environ.get(\"DEBUG\", False)\n")
	writeFile(t, root, "off.go", "cfg.Debug = false\n")

	hits := findingsByRule(t, root)["debug-mode-enabled"]
	if len(hits) != 3 {
		t.Fatalf("debug-mode-enabled: want 3, got %d (%+v)", len(hits), hits)
	}
	for _, h := range hits {
		if h.CWE != "CWE-489" || h.Severity != shared.SeverityMedium {
			t.Errorf("debug finding metadata wrong: %+v", h)
		}
	}
}

func TestPermissiveCORSDetection(t *testing.T) {
	root := t.TempDir()
	// positives – Go header Set form, a raw header (no colon), and a Go AllowedOrigins config.
	writeFile(t, root, "headers.go", "w.Header().Set(\"Access-Control-Allow-Origin\", \"*\")\n")
	writeFile(t, root, "site.conf", "add_header Access-Control-Allow-Origin *;\n")
	writeFile(t, root, "cors.go", "opts := cors.Options{AllowedOrigins: []string{\"*\"}}\n")
	// negatives – a specific origin is fine.
	writeFile(t, root, "ok.go", "w.Header().Set(\"Access-Control-Allow-Origin\", \"https://app.example.com\")\n")
	writeFile(t, root, "ok2.go", "AllowedOrigins: []string{\"https://trusted.com\"}\n")

	hits := findingsByRule(t, root)["permissive-cors-wildcard"]
	if len(hits) != 3 {
		t.Fatalf("permissive-cors-wildcard: want 3, got %d (%+v)", len(hits), hits)
	}
	for _, h := range hits {
		if h.CWE != "CWE-942" || h.Severity != shared.SeverityMedium {
			t.Errorf("cors finding metadata wrong: %+v", h)
		}
	}
}

// TestRuleCorpus is the per-rule true/false-positive regression corpus: for every built-in
// rule, each true-positive line MUST be flagged by that rule and each false-positive line MUST NOT be.
// It guards precision (SAST findings publish ungated) and catches drift when a pattern is edited.
// Secret-rule samples are ASSEMBLED at runtime so no real-looking secret literal sits in this source.
func TestRuleCorpus(t *testing.T) {
	awsKey := "AKIA" + strings.Repeat("Q", 16)                    // AKIA-format key id
	pemHeader := "-----BEGIN RSA PRIVATE" + " KEY-----"           // a PEM header, not a contiguous literal
	credLine := "password = \"" + "Hunter2" + "Str0ngPass" + "\"" // a non-placeholder credential literal

	corpus := []struct {
		rule string
		tp   []string // must be flagged by `rule`
		fp   []string // must NOT be flagged by `rule`
		file string   // fixture filename (default case.go); set for language-gated rules
	}{
		{
			rule: "weak-hash-md5",
			tp:   []string{`import "crypto/md5"`, `h := hashlib.md5(data)`},
			fp:   []string{`import "crypto/sha256"`, `// md5 usage is forbidden`},
		},
		{
			rule: "weak-hash-sha1",
			tp:   []string{`import "crypto/sha1"`, `d := sha1.new()`},
			fp:   []string{`import "crypto/sha512"`},
		},
		{
			rule: "weak-cipher",
			tp:   []string{`import "crypto/des"`, `Cipher.getInstance("RC4")`},
			fp:   []string{`import "crypto/aes"`},
		},
		{
			rule: "insecure-tls-verify-disabled",
			tp:   []string{`tls.Config{InsecureSkipVerify: true}`, `{ rejectUnauthorized: false }`},
			fp:   []string{`tls.Config{InsecureSkipVerify: false}`},
		},
		{
			rule: "debug-mode-enabled",
			tp:   []string{`DEBUG = True`, `app.run(host="0.0.0.0", debug=True)`, `gin.SetMode(gin.DebugMode)`},
			fp:   []string{`cfg.Debug = false`, `DEBUG = os.environ.get("DEBUG", False)`, `is_debug := true`},
		},
		{
			rule: "permissive-cors-wildcard",
			tp:   []string{`Access-Control-Allow-Origin: *`, `AllowedOrigins: []string{"*"}`},
			fp:   []string{`Access-Control-Allow-Origin: https://app.example.com`, `AllowedOrigins: []string{"https://x.com"}`},
		},
		{
			rule: "hardcoded-aws-access-key",
			tp:   []string{`awsKey := "` + awsKey + `"`},
			fp:   []string{`// rotate all AKIA keys regularly`},
		},
		{
			rule: "private-key-material",
			tp:   []string{pemHeader},
			fp:   []string{`// no private key is stored here`},
		},
		{
			rule: "hardcoded-credential",
			tp:   []string{credLine},
			fp:   []string{`password = os.environ["DB_PASS"]`, `api_key = "${VAULT_TOKEN}"`},
		},
		{
			rule: "password-md5-hash",
			tp:   []string{`const hashed = md5(password)`, `password: md5("admin123")`, `const h = md5(req.body.password)`},
			fp:   []string{`const checksum = md5(fileBytes)`, `// password md5 is forbidden`},
		},
		{
			rule: "prisma-raw-sql-unsafe",
			tp:   []string{`await prisma.$queryRawUnsafe(`},
			fp:   []string{`await prisma.$queryRaw` + "`SELECT * FROM users WHERE id = ${id}`"},
			file: "case.ts",
		},
		{
			rule: "template-sql-interpolation",
			tp:   []string{"`SELECT * FROM services WHERE name LIKE '%${search}%'`"},
			fp:   []string{"`SELECT * FROM services WHERE id = ?`"},
		},
		{
			rule: "generic-sql-dynamic-execute",
			tp: []string{
				`cursor.execute("SELECT * FROM users WHERE id=" + request.args["id"])`,
				`mysqli_query($db, "SELECT * FROM users WHERE id=".$_GET["id"])`,
				`stmt.executeQuery("SELECT * FROM users WHERE id=" + id)`,          // JDBC bare-execute TP survives the fix
				`mysqli_query($db, "SELECT * FROM users WHERE n='" . $name . "'")`, // PHP indirect concat via `.$`
				`cursor.execute("SELECT * FROM users WHERE n='{}'".format(name))`,  // Python str.format
				`cursor.execute(f"SELECT * FROM users WHERE id={uid}")`,            // Python f-string
			},
			fp: []string{
				`cursor.execute("SELECT * FROM users WHERE id=?", [id])`,
				// java.util.concurrent Executor / worker dispatch – NOT SQL. Used to match on the bare `.`.
				`taskExecutor.execute(decorator.decorate(command))`,
				`worker.execute(new KycContext(lookup(id)))`,
				`pool.execute(() -> counter.add(delta + 1))`,
				`cursor.execute("SELECT * FROM t WHERE x LIKE '%admin%'")`, // constant LIKE, not injection (guards the dropped `%`)
			},
		},
		{
			rule: "child-process-exec-template",
			tp:   []string{"exec(`file \"${savedPath}\"`)"},
			fp:   []string{`execFile("file", [savedPath])`},
			file: "case.js",
		},
		{
			rule: "generic-command-injection-sink",
			tp:   []string{`subprocess.run("convert " + request.args["file"], shell=True)`, `system($_GET["cmd"])`},
			fp:   []string{`subprocess.run(["convert", safe_file], check=True)`},
		},
		{
			rule: "unsafe-deserialization-node-serialize",
			tp:   []string{`const obj = unserialize(req.body.data)`},
			fp:   []string{`// unserialize user data would be unsafe`},
			file: "case.js",
		},
		{
			rule: "unsafe-deserialization-generic",
			tp:   []string{`pickle.loads(request.data)`, `yaml.load(body, Loader=yaml.Loader)`, `unserialize($_POST["payload"])`},
			fp:   []string{`json.loads(request.data)`, `yaml.safe_load(body)`},
		},
		{
			rule: "ssrf-fetch-user-url",
			tp:   []string{`const response = await fetch(url)`, `await axios.get(req.body.url)`},
			fp:   []string{`await fetch("https://api.example.com/health")`},
		},
		{
			rule: "generic-ssrf-request-url",
			tp:   []string{`requests.get(request.args["url"])`, `http.Get(r.URL.Query().Get("url"))`, `file_get_contents($_GET["url"])`},
			fp:   []string{`requests.get("https://api.example.com/health")`},
		},
		{
			rule: "react-dangerous-html",
			tp:   []string{`<div dangerouslySetInnerHTML={{ __html: note }} />`},
			fp:   []string{`// dangerouslySetInnerHTML would be unsafe for comments`},
			file: "case.tsx",
		},
		{
			rule: "server-template-injection",
			tp:   []string{`return render_template_string(request.args["tpl"])`, `tmpl = jinja2.Template("${name}")`},
			fp:   []string{`return render_template("profile.html", name=name)`},
		},
		{
			rule: "password-reset-token-disclosure",
			tp:   []string{`return { sent: false, debugToken: token }`, "`console.log(`Token   : ${token}`)`"},
			fp:   []string{`// debugToken should never be returned`, `token = process.env.RESET_TOKEN`},
		},
		{
			rule: "sensitive-data-logging",
			tp:   []string{`logger.info("Login attempt", { email, password, ip: req.ip })`},
			fp:   []string{`logger.info("Login attempt", { email, ip: req.ip })`},
		},
		{
			rule: "insecure-cookie-flags",
			tp:   []string{`res.cookie("sid", token, { httpOnly: false })`, `secure: false`, `sameSite: 'none'`},
			fp:   []string{`res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" })`},
		},
		{
			rule: "jwt-hardcoded-secret-or-none",
			tp:   []string{`jwt.sign(payload, "secret")`, `algorithm = "none"`},
			fp:   []string{`jwt.sign(payload, process.env.JWT_SECRET)`, `algorithm = "RS256"`},
		},
		{
			rule: "path-traversal-file-access",
			tp:   []string{`fs.readFile(req.query.path, cb)`, `send_file(params[:path])`, `os.Open(r.URL.Query().Get("path"))`},
			fp:   []string{`fs.readFile(path.join(baseDir, safeName), cb)`},
		},
		{
			rule: "possible-idor-prisma-id-only",
			tp:   []string{`await prisma.pet.update({ where: { id: petId }, data: body })`},
			fp:   []string{`await prisma.pet.update({ where: { id_ownerId: { id: petId, ownerId } }, data })`},
			file: "case.ts",
		},
		{
			rule: "mass-assignment-request-body",
			tp:   []string{`await prisma.user.update({ where: { id }, data: req.body })`, `User.create(params)`},
			fp:   []string{`await prisma.user.update({ where: { id }, data: { name, phone } })`},
		},
		{
			rule: "xxe-insecure-xml-parsing",
			tp:   []string{`parser = etree.XMLParser(resolve_entities=True)`, `libxml_disable_entity_loader(false);`, `dbf.setExpandEntityReferences(true);`},
			fp:   []string{`parser = etree.XMLParser(resolve_entities=False)`, `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`},
		},
		{
			rule: "dynamic-code-eval",
			tp:   []string{`result = eval("run_" + req.body.cmd)`, `eval($_GET["code"])`, `value = eval(input("expr: "))`},
			fp:   []string{`const total = eval("2 + 2")`, `// eval of user input is dangerous`},
		},
		{
			rule: "dom-xss-inner-html",
			tp:   []string{"el.innerHTML = `<h1>${req.query.name}</h1>`", `container.innerHTML = location.hash`, `document.write(location.search)`, `list.innerHTML += req.body.html`},
			fp:   []string{`el.innerHTML = ""`, `el.innerHTML = sanitize(userInput)`, "el.innerHTML = `<b>${count}</b>`"},
			file: "case.js",
		},
		{
			rule: "nosql-injection-request",
			tp:   []string{`db.users.find(req.body)`, `User.findOne({ $where: "this.n == 1" })`, `col.find({ user: req.query.user })`},
			fp:   []string{`db.users.find({ _id: ObjectId(id) })`, `User.findOne({ email: safeEmail })`},
		},
		{
			rule: "ldap-injection",
			tp: []string{
				`search(base, "(uid=" + user + ")")`,
				`conn.search(base, f"(uid={request.args['user']})")`,
				"ldap.search(base, `(&(objectClass=person)(uid=${req.query.user}))`)",
			},
			fp: []string{
				`ldap.search(base, "(uid=service-account)")`,
				`conn.search(base, f"(uid={escape_filter_chars(user)})")`,
				`ctx.search(base, "(uid={0})", new Object[]{user}, controls)`,
				`search(index, "uid=" + req.query.user)`,
				`logger.info(f"(uid={request.args['user']})")`,
				`// ldap.search(base, "(uid=" + req.query.user + ")")`,
			},
		},
		{
			rule: "open-redirect-user-url",
			tp:   []string{`res.redirect(req.query.next)`, `response.sendRedirect(request.getParameter("url"))`, `http.Redirect(w, r, r.URL.Query().Get("next"), 302)`},
			fp:   []string{`res.redirect("/login")`, `res.redirect(302, "/dashboard")`, "res.redirect(`${req.protocol}://${req.hostname}/dashboard`)"},
		},
		{
			rule: "insecure-randomness-security-context",
			tp:   []string{`const token = Math.random().toString(36)`, `otp = random.randint(1000, 9999)`, `$salt = mt_rand();`},
			fp:   []string{`const offset = Math.random() * width`, `jitter = random.random() * 0.5`},
		},
		{
			rule: "weak-rsa-key-size",
			tp:   []string{`rsa.GenerateKey(rand.Reader, 1024)`, `new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4)`},
			fp:   []string{`rsa.GenerateKey(rand.Reader, 2048)`, `new RSAKeyGenParameterSpec(2048, F4)`, `bufferPool.initialize(1024)`},
		},
		{
			rule: "world-writable-permissions",
			tp:   []string{`os.Chmod(path, 0777)`, `os.WriteFile(p, data, 0o777)`, `os.chmod(path, 0777)`},
			fp:   []string{`os.Chmod(path, 0644)`, `os.WriteFile(p, data, 0600)`, `os.WriteFile(p, data, 0644) // was 0777`},
		},
		{
			rule: "unsafe-c-string-function",
			file: "case.c",
			tp:   []string{`gets(buf);`, `strcpy(dest, src);`, `strcat(path, suffix);`},
			fp:   []string{`strncpy(dest, src, sizeof(dest));`, `snprintf(buf, sizeof(buf), "%s", s);`, `// strcpy is unsafe`},
		},
		{
			// The same C names in a non-C file (e.g. Ruby gets, PHP vsprintf) must NOT be flagged (ext gate).
			rule: "unsafe-c-string-function",
			file: "case.rb",
			fp:   []string{`line = gets(chomp: true)`, `out = vsprintf(fmt, args)`},
		},
		{
			rule: "xpath-injection",
			tp: []string{
				`nodes := xpath.evaluate("//user[name='" + name + "']")`,
				`doc.selectNodes("//account[@id=" + id + "]")`,
				`hits = tree.xpath(f"//user[@name='{name}']")`,
			},
			fp: []string{
				`nodes := xpath.evaluate("//user[name='admin']")`,
				`expr := xpath.compile(userQueryConst)`,
				`if doc.selectNodes("//user") { render() }`,
				`result = evaluate("total // count + 1")`,  // // inside a constant string, no string-concat
				`page.evaluate(expr) // TODO: fix + later`, // first arg is not a string literal
				`out := preEvaluate("//x[@id=" + id)`,      // preEvaluate is not the evaluate sink
			},
		},
		{
			rule: "redos-vulnerable-regex",
			tp: []string{
				`re := regexp.MustCompile("(a+)+$")`,
				`pat = re.compile(r"(.*)*")`,
				`const rx = new RegExp("(\\d+)*")`,
			},
			fp: []string{
				`re := regexp.MustCompile("(abc)+")`,
				`total := (base + tax) * qty`,
				`pat = re.compile("^[a-z]+$")`,
			},
		},
		{
			rule: "insecure-temp-file",
			tp: []string{
				`f, _ := os.Create("/tmp/app.log")`,
				`path := "/tmp/session_" + id`,
				`char *p = tmpnam(buf);`,
			},
			fp: []string{
				`d, _ := os.MkdirTemp("", "synapse")`,
				`f, _ := os.CreateTemp(dir, "prefix-")`,
				`tf = tempfile.NamedTemporaryFile()`,
			},
		},
	}

	for _, c := range corpus {
		fname := c.file
		if fname == "" {
			fname = "case.go"
		}
		for _, tp := range c.tp {
			root := t.TempDir()
			writeFile(t, root, fname, tp+"\n")
			if len(findingsByRule(t, root)[c.rule]) == 0 {
				t.Errorf("%s: true-positive %q was NOT flagged", c.rule, tp)
			}
		}
		for _, fp := range c.fp {
			root := t.TempDir()
			writeFile(t, root, fname, fp+"\n")
			if n := len(findingsByRule(t, root)[c.rule]); n > 0 {
				t.Errorf("%s: false-positive %q was wrongly flagged (%d hits)", c.rule, fp, n)
			}
		}
	}
}

// TestLanguageGatedRulesRespectExtensions locks the fix for the language-scoping bug: a rule whose
// idiom belongs to one ecosystem (Python SQLAlchemy, Prisma, React/DOM, node-serialize) must fire on
// its own file type and stay silent on a foreign one, so it can never mislabel e.g. a .java file.
func TestLanguageGatedRulesRespectExtensions(t *testing.T) {
	cases := []struct {
		rule    string
		snippet string
		firesIn string // extension where the rule should fire
		quietIn string // foreign extension where the rule must stay silent
	}{
		{"sqlalchemy-raw-sql-dynamic", `db.session.execute(f"SELECT * FROM users WHERE n = '{q}'")`, "svc.py", "Svc.java"},
		{"prisma-raw-sql-unsafe", `await prisma.$queryRawUnsafe(sql)`, "db.ts", "db.go"},
		{"react-dangerous-html", `<div dangerouslySetInnerHTML={{ __html: note }} />`, "View.tsx", "view.py"},
		{"unsafe-deserialization-node-serialize", `const o = unserialize(req.body.data)`, "d.js", "d.go"},
		// exercises the contextual (multi-line block) path in findingFromRule, not just scanLines
		{"possible-idor-prisma-id-only", `await prisma.pet.update({ where: { id: petId }, data: body })`, "svc.ts", "svc.go"},
		// .mts/.cts (TS ESM/CJS) and single-file components must still be scanned by the JS/TS rules
		{"prisma-raw-sql-unsafe", `await prisma.$queryRawUnsafe(sql)`, "handlers.mts", "handlers.go"},
		{"dom-xss-inner-html", `el.innerHTML = location.hash`, "App.vue", "app.py"},
	}
	for _, c := range cases {
		fires := t.TempDir()
		writeFile(t, fires, c.firesIn, c.snippet+"\n")
		if len(findingsByRule(t, fires)[c.rule]) == 0 {
			t.Errorf("%s: expected a finding in %s", c.rule, c.firesIn)
		}
		quiet := t.TempDir()
		writeFile(t, quiet, c.quietIn, c.snippet+"\n")
		if n := len(findingsByRule(t, quiet)[c.rule]); n > 0 {
			t.Errorf("%s: must not fire in foreign file %s (%d hits)", c.rule, c.quietIn, n)
		}
	}
}

// findingsByRule runs the analyzer over root and groups the hits by rule id.
func findingsByRule(t *testing.T, root string) map[string][]ports.SASTRawFinding {
	t.Helper()
	got, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	byRule := map[string][]ports.SASTRawFinding{}
	for _, f := range got {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}
	return byRule
}

func TestAnalyzerHonorsContextCancel(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "import \"crypto/md5\"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().AnalyzeSource(ctx, root); err == nil {
		t.Error("want context error on a cancelled scan")
	}
}

func TestAnalyzerEmptyRoot(t *testing.T) {
	got, err := New().AnalyzeSource(context.Background(), "")
	if err != nil || got != nil {
		t.Errorf("empty root: want nil,nil; got %v,%v", got, err)
	}
}

func TestAnalyzerEnrichesAppSecProofContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/users.js", `
router.post("/doctors/search", async (req, res) => {
  const search = req.query.search
  const rows = await prisma.$queryRawUnsafe(`+"`SELECT * FROM doctors WHERE name LIKE '%${search}%'`"+`)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one prisma raw sql hit, got %+v", hits)
	}
	h := hits[0]
	if h.Route != "POST /doctors/search" {
		t.Fatalf("route context not captured: %+v", h)
	}
	if h.AuthScope != "unauthenticated-or-public" {
		t.Fatalf("auth scope not calibrated: %+v", h)
	}
	if h.Exposure != "public-or-unauthenticated application route" || !strings.Contains(h.AuthEvidence, "no auth middleware cue") {
		t.Fatalf("public exposure/auth evidence not calibrated: %+v", h)
	}
	if !strings.Contains(h.DataFlow, "HTTP query parameter -> SQL execution sink") {
		t.Fatalf("dataflow summary missing source/sink: %q", h.DataFlow)
	}
	if h.OWASP2025 != "A05:2025 Injection" || h.EntryPoint != "POST /doctors/search" || h.Source != "HTTP query parameter" || h.Sink != "SQL execution sink" {
		t.Fatalf("static-analysis-grade proof tuple not enriched: %+v", h)
	}
	if !strings.Contains(h.SourceEvidence, "HTTP query parameter cue") || !strings.Contains(h.SinkEvidence, "line 4") || !strings.Contains(h.ControlEvidence, "route POST /doctors/search") {
		t.Fatalf("bounded evidence labels not captured: %+v", h)
	}
	if h.TrustBoundary == "" || h.Impact == "" || !strings.Contains(h.ValidationRubric, "source=present") || !strings.Contains(h.ValidationRubric, "control=present") || !strings.Contains(h.ValidationRubric, "sink=present") {
		t.Fatalf("validation closure tuple not captured: %+v", h)
	}
	if h.DataFlowConfidence != "propagated" || !strings.Contains(h.DataFlowEvidence, "search assigned from request/source") || !strings.Contains(h.ValidationRubric, "dataflow=propagated") {
		t.Fatalf("taint-lite propagated proof not captured: %+v", h)
	}
	if h.ValidationMethod != "static-code-understanding" || h.ValidationDisposition != "needs-runtime-proof" {
		t.Fatalf("validation receipt not calibrated: %+v", h)
	}
	if h.Preconditions == "" || h.CounterEvidence != "none observed in bounded local context" || h.SeverityRationale == "" {
		t.Fatalf("proof gaps/counterevidence/severity rationale not captured: %+v", h)
	}
	if h.Exploitability == "" || h.AttackPath == "" || h.Confidence != "high" {
		t.Fatalf("exploitability/attack path/confidence not enriched: %+v", h)
	}
}

func TestAnalyzerCapturesCounterEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/pets.js", `
router.get("/pets/:id", requireAuth, async (req, res) => {
  const ownerId = req.user.id
  const pet = await prisma.pet.update({ where: { id: req.params.id }, data: req.body })
  res.json(pet)
})
`)
	hits := findingsByRule(t, root)["possible-idor-prisma-id-only"]
	if len(hits) != 1 {
		t.Fatalf("want one IDOR candidate, got %+v", hits)
	}
	h := hits[0]
	if h.AuthScope != "authenticated" || !strings.Contains(h.AuthEvidence, "route-level authenticated middleware cue") || h.RouteMiddleware == "" {
		t.Fatalf("route-level auth middleware evidence missing: %+v", h)
	}
	if h.ValidationDisposition != "needs-review-counterevidence" {
		t.Fatalf("counterevidence should force review disposition: %+v", h)
	}
	if !strings.Contains(h.CounterEvidence, "owner/tenant predicate") {
		t.Fatalf("owner/tenant counterevidence missing: %+v", h)
	}
	if h.Confidence == "high" {
		t.Fatalf("counterevidence should prevent high confidence without verifier proof: %+v", h)
	}
}

func TestAnalyzerCapturesInheritedMiddleware(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/admin.js", `
router.use(requireAuth)
router.post("/admin/search", async (req, res) => {
  const q = req.query.q
  const rows = await prisma.$queryRawUnsafe(`+"`SELECT * FROM users WHERE name = '${q}'`"+`)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.Route != "POST /admin/search" {
		t.Fatalf("route not captured: %+v", h)
	}
	if h.AuthScope != "authenticated" {
		t.Fatalf("inherited auth scope not captured: %+v", h)
	}
	if !strings.Contains(h.AuthEvidence, "inherited authenticated middleware cue") || h.RouteMiddleware == "" {
		t.Fatalf("inherited middleware evidence missing: %+v", h)
	}
	if h.Exposure != "authenticated application route" {
		t.Fatalf("authenticated exposure not calibrated: %+v", h)
	}
}

func TestAnalyzerPropagatesMultiStepTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/search.js", `
router.post("/search", async (req, res) => {
  const q = req.query.q
  const like = "%" + q + "%"
  const where = "name LIKE '" + like + "'"
  const rows = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE " + where)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "propagated" {
		t.Fatalf("want propagated taint confidence, got %+v", h)
	}
	if !strings.Contains(h.DataFlowEvidence, "q<-source") || !strings.Contains(h.DataFlowEvidence, "where<-") {
		t.Fatalf("multi-step taint path not captured: %q", h.DataFlowEvidence)
	}
	if h.ValidationDisposition != "needs-runtime-proof" {
		t.Fatalf("propagated source-to-sink should survive static validation but require runtime proof before exploitability is claimed: %+v", h)
	}
}

func TestAnalyzerFlagsSanitizedFlowForReview(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/search.js", `
router.post("/search", async (req, res) => {
  const q = req.query.q
  const safe = sanitize(q)
  const rows = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE name = '" + safe + "'")
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "sanitized" {
		t.Fatalf("want sanitized taint confidence, got %+v", h)
	}
	if h.ValidationDisposition != "needs-review-counterevidence" {
		t.Fatalf("sanitized path should require counterevidence review: %+v", h)
	}
	if !strings.Contains(h.Exploitability, "sanitizer/validator") || !strings.Contains(h.SeverityRationale, "sanitizer/validator") {
		t.Fatalf("sanitized proof should calibrate exploitability/severity: %+v", h)
	}
}

func TestAnalyzerCapturesHelperFunctionTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/search.js", `
function buildWhere(term) {
  return "name LIKE '%" + term + "%'"
}

router.post("/search", async (req, res) => {
  const q = req.query.q
  const where = buildWhere(q)
  const rows = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE " + where)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "propagated" {
		t.Fatalf("want helper-propagated taint confidence, got %+v", h)
	}
	if !strings.Contains(h.DataFlowEvidence, "helper:buildWhere") {
		t.Fatalf("helper summary missing from taint path: %q", h.DataFlowEvidence)
	}
}

func TestAnalyzerCapturesSinkWrapperTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/search.js", `
async function runQuery(sql) {
  return prisma.$queryRawUnsafe(sql)
}

router.post("/search", async (req, res) => {
  const q = req.query.q
  const sql = "SELECT * FROM users WHERE name = '" + q + "'"
  const rows = await runQuery(sql)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "interprocedural" {
		t.Fatalf("want interprocedural wrapper confidence, got %+v", h)
	}
	if !strings.Contains(h.DataFlowEvidence, "sink wrapper runQuery") {
		t.Fatalf("sink wrapper evidence missing: %q", h.DataFlowEvidence)
	}
}

func TestAnalyzerCapturesCrossFileHelperTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "lib/search.js", `
export function buildWhere(term) {
  return "name LIKE '%" + term + "%'"
}
`)
	writeFile(t, root, "routes/search.js", `
import { buildWhere } from "../lib/search"

router.post("/search", async (req, res) => {
  const q = req.query.q
  const where = buildWhere(q)
  const rows = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE " + where)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "interprocedural" && h.DataFlowConfidence != "propagated" {
		t.Fatalf("want cross-file helper propagation, got %+v", h)
	}
	if !strings.Contains(h.DataFlowEvidence, "helper:buildWhere") || !strings.Contains(h.DataFlowEvidence, "lib") {
		t.Fatalf("cross-file helper summary missing from evidence: %q", h.DataFlowEvidence)
	}
}

func TestAnalyzerCapturesCrossFileSinkWrapperTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "lib/db.js", `
export async function runQuery(sql) {
  return prisma.$queryRawUnsafe(sql)
}
`)
	writeFile(t, root, "routes/search.js", `
import { runQuery } from "../lib/db"

router.post("/search", async (req, res) => {
  const q = req.query.q
  const sql = "SELECT * FROM users WHERE name = '" + q + "'"
  const rows = await runQuery(sql)
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "cross-file" {
		t.Fatalf("want cross-file wrapper confidence, got %+v", h)
	}
	if h.Source != "HTTP request input via caller" || !strings.Contains(h.SourceEvidence, "cross-file") {
		t.Fatalf("cross-file source evidence not promoted into envelope: %+v", h)
	}
	if !strings.Contains(h.DataFlowEvidence, "cross-file") || !strings.Contains(h.DataFlowEvidence, "routes") || !strings.Contains(h.DataFlowEvidence, "lib") {
		t.Fatalf("cross-file wrapper evidence missing: %q", h.DataFlowEvidence)
	}
}

func TestAnalyzerCapturesNestControllerDecoratorSource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "users.controller.ts", `
@Controller("users")
export class UsersController {
  @Get("search")
  async search(@Query("q") q: string) {
    return prisma.$queryRawUnsafe(`+"`SELECT * FROM users WHERE name LIKE '%${q}%'`"+`)
  }
}
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.Route != "GET /users/search" {
		t.Fatalf("Nest controller route not captured: %+v", h)
	}
	if h.Source != "framework query parameter" {
		t.Fatalf("decorated framework source not captured: %+v", h)
	}
	if h.DataFlowConfidence != "propagated" || !strings.Contains(h.DataFlowEvidence, "q<-decorated-source") {
		t.Fatalf("decorated parameter taint not propagated: %+v", h)
	}
}

func TestAnalyzerCapturesGraphQLResolverSource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "users.resolver.ts", `
@Resolver()
export class UsersResolver {
  @Query("users")
  async users(@Args("name") name: string) {
    return prisma.$queryRawUnsafe(`+"`SELECT * FROM users WHERE name = '${name}'`"+`)
  }
}
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.Route != "GRAPHQL QUERY users" {
		t.Fatalf("GraphQL route not captured: %+v", h)
	}
	if h.Source != "GraphQL argument" {
		t.Fatalf("GraphQL source not captured: %+v", h)
	}
	if h.DataFlowConfidence != "propagated" || !strings.Contains(h.DataFlowEvidence, "name<-decorated-source") {
		t.Fatalf("GraphQL argument taint not propagated: %+v", h)
	}
}

func TestAnalyzerDefersContextOnlyDataflow(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "routes/search.js", `
router.post("/search", async (req, res) => {
  const search = req.query.search
  const rows = await prisma.$queryRawUnsafe("SELECT * FROM doctors")
  res.json(rows)
})
`)
	hits := findingsByRule(t, root)["prisma-raw-sql-unsafe"]
	if len(hits) != 1 {
		t.Fatalf("want one raw SQL candidate, got %+v", hits)
	}
	h := hits[0]
	if h.DataFlowConfidence != "context-only" {
		t.Fatalf("want context-only dataflow, got %+v", h)
	}
	if h.ValidationDisposition != "deferred-proof-gap" {
		t.Fatalf("context-only flow must be deferred, got %+v", h)
	}
	if !strings.Contains(h.SeverityRationale, "source-to-sink value flow") {
		t.Fatalf("severity rationale should name value-flow proof gap: %q", h.SeverityRationale)
	}
}

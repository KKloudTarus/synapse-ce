package sast

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type parityCase struct {
	name             string
	files            map[string]string
	rule             string
	cwe              string
	owasp            string
	routeContains    string
	sourceContains   string
	dataflow         string
	disposition      string
	evidenceContains []string
	counterContains  string
	attackContains   string
}

// TestStaticTriageParityMatrix is a compact benchmark for the SAST capabilities
// Synapse needs to behave like a static-analysis-grade static triage engine while staying
// deterministic, bounded, and in-tree. It intentionally checks the validation envelope, not only
// rule hits: route/source/sink, dataflow confidence, disposition, and proof/counterevidence.
func TestStaticTriageParityMatrix(t *testing.T) {
	cases := codexSecurityParityCases()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := runParityCase(t, tc)
			assertParityCase(t, tc, h)
		})
	}
}

func codexSecurityParityCases() []parityCase {
	return []parityCase{
		{
			name: "public express sqli variable flow",
			files: map[string]string{"routes/search.js": `
router.get("/search", async (req, res) => {
  const q = req.query.q
  const sql = "SELECT * FROM users WHERE name = '" + q + "'"
  const rows = await prisma.$queryRawUnsafe(sql)
  res.json(rows)
})
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"q<-source", "sql<-q"},
		},
		{
			name: "cross file wrapper sqli",
			files: map[string]string{
				"lib/db.js": `
export async function runQuery(sql) {
  return prisma.$queryRawUnsafe(sql)
}
`,
				"routes/search.js": `
router.post("/search", async (req, res) => {
  const q = req.query.q
  const sql = "SELECT * FROM users WHERE name = '" + q + "'"
  return runQuery(sql)
})
`,
			},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			sourceContains:   "HTTP request input via caller",
			dataflow:         "cross-file",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"cross-file", "routes", "lib", "runQuery"},
		},
		{
			name: "sanitized flow deferred for verifier",
			files: map[string]string{"routes/search.js": `
router.post("/search", async (req, res) => {
  const q = req.query.q
  const safe = sanitize(q)
  return prisma.$queryRawUnsafe("SELECT * FROM users WHERE name = '" + safe + "'")
})
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "POST /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "sanitized",
			disposition:      "needs-review-counterevidence",
			evidenceContains: []string{"sanitizer/validator"},
		},
		{
			name: "nestjs decorated source",
			files: map[string]string{"users.controller.ts": `
@Controller("users")
export class UsersController {
  @Get("search")
  async search(@Query("q") q: string) {
    return prisma.$queryRawUnsafe(` + "`SELECT * FROM users WHERE name LIKE '%${q}%'`" + `)
  }
}
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /users/search",
			sourceContains:   "framework query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"decorated-source"},
		},
		{
			name: "graphql resolver args",
			files: map[string]string{"users.resolver.ts": `
@Resolver()
export class UsersResolver {
  @Query("users")
  async users(@Args("name") name: string) {
    return prisma.$queryRawUnsafe(` + "`SELECT * FROM users WHERE name = '${name}'`" + `)
  }
}
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GRAPHQL QUERY users",
			sourceContains:   "GraphQL argument",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"decorated-source"},
		},
		{
			name: "fastapi route parameter sqli",
			files: map[string]string{"app.py": `
@app.get("/search")
def search(q: str):
    return cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
`},
			rule:             "generic-sql-dynamic-execute",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "framework route/query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"framework-source"},
		},
		{
			name: "spring requestparam sqli",
			files: map[string]string{"SearchController.java": `
@RestController
class SearchController {
  @GetMapping("/search")
  public List<Map<String,Object>> search(@RequestParam String q) {
    return statement.execute("SELECT * FROM users WHERE name = '" + q + "'");
  }
}
`},
			rule:             "generic-sql-dynamic-execute",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "framework query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"framework-source"},
		},
		{
			name: "go gin query sqli",
			files: map[string]string{"handler.go": `
r.GET("/search", func(c *gin.Context) {
  q := c.Query("q")
  rows, _ := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
  _ = rows
})
`},
			rule:             "go-sql-dynamic-query",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP form/query value",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"q<-source"},
		},
		{
			name: "go nethttp query sqli",
			files: map[string]string{"handler.go": `
http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
  q := r.URL.Query().Get("q")
  rows, _ := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
  _ = rows
})
`},
			rule:             "go-sql-dynamic-query",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "/search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"q<-source"},
		},
		{
			name: "flask request args sqli",
			files: map[string]string{"app.py": `
@app.get("/search")
def search():
    q = request.GET.get("q")
    return cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
`},
			rule:             "generic-sql-dynamic-execute",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"q<-source"},
		},
		{
			name: "python sqlalchemy fstring sqli",
			files: map[string]string{"app.py": `
@app.get("/lookup")
def lookup():
    q = request.GET.get("q")
    return db.session.execute(f"SELECT * FROM users WHERE name = '{q}'")
`},
			rule:             "sqlalchemy-raw-sql-dynamic",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /lookup",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"q<-source"},
		},
		{
			name: "php mysqli get sqli",
			files: map[string]string{"search.php": `
<?php
mysqli_query($db, "SELECT * FROM users WHERE name = '" . $_GET["q"] . "'");
`},
			rule:             "php:sql-concat",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			sourceContains:   "HTTP query parameter",
			dataflow:         "direct",
			disposition:      "deferred-proof-gap",
			evidenceContains: []string{"direct"},
		},
		{
			name: "rails params raw sql",
			files: map[string]string{"users_controller.rb": `
def search
  name = params[:name]
  rows = ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE name = '#{name}'")
  render json: rows
end
`},
			rule:             "generic-sql-dynamic-execute",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			sourceContains:   "route/query parameter",
			dataflow:         "propagated",
			disposition:      "deferred-proof-gap",
			evidenceContains: []string{"name<-source"},
		},
		{
			name: "go command injection",
			files: map[string]string{"handler.go": `
r.GET("/ping", func(c *gin.Context) {
  host := c.Query("host")
  out, _ := exec.Command("ping", "-c", "1", host).Output()
  _, _ = c.Writer.Write(out)
})
`},
			rule:             "go-command-dynamic",
			cwe:              "CWE-78",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /ping",
			sourceContains:   "HTTP form/query value",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"host<-source"},
		},
		{
			name: "go ssrf dynamic url",
			files: map[string]string{"handler.go": `
http.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
  target := r.URL.Query().Get("url")
  resp, _ := http.Get(target)
  _ = resp
})
`},
			rule:             "go-ssrf-dynamic-url",
			cwe:              "CWE-918",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "/proxy",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"target<-source"},
		},
		{
			name: "go path traversal readfile",
			files: map[string]string{"handler.go": `
http.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
  file := r.URL.Query().Get("file")
  b, _ := os.ReadFile(file)
  _, _ = w.Write(b)
})
`},
			rule:             "path-traversal-file-access",
			cwe:              "CWE-22",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "/download",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"file<-source"},
		},
		{
			name: "express reflected xss",
			files: map[string]string{"routes/profile.js": `
router.get("/hello", (req, res) => {
  const name = req.query.name
  res.send("<h1>Hello " + name + "</h1>")
})
`},
			rule:             "reflected-response-write",
			cwe:              "CWE-79",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /hello",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"name<-source"},
		},
		{
			name: "django reflected xss",
			files: map[string]string{"views.py": `
@app.get("/hello")
def hello():
    name = request.GET.get("name")
    return HttpResponse("<h1>Hello " + name + "</h1>")
`},
			rule:             "reflected-response-write",
			cwe:              "CWE-79",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /hello",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"name<-source"},
		},
		{
			name: "ssrf request controlled url",
			files: map[string]string{"routes/proxy.js": `
router.get("/proxy", async (req, res) => {
  const target = req.query.url
  const r = await fetch(target)
  res.send(await r.text())
})
`},
			rule:             "ssrf-fetch-user-url",
			cwe:              "CWE-918",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "GET /proxy",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"target<-source"},
		},
		{
			name: "ssrf allowlist guard deferred",
			files: map[string]string{"routes/proxy.js": `
router.get("/proxy", async (req, res) => {
  const target = req.query.url
  const host = new URL(target).hostname
  if (!allowedHosts.has(host)) throw new Error("forbidden")
  const r = await fetch(target)
  res.send(await r.text())
})
`},
			rule:             "ssrf-fetch-user-url",
			cwe:              "CWE-918",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "GET /proxy",
			sourceContains:   "HTTP query parameter",
			dataflow:         "guarded",
			disposition:      "needs-review-counterevidence",
			evidenceContains: []string{"guarded", "allowedHosts"},
		},
		{
			name: "path traversal file access",
			files: map[string]string{"routes/download.js": `
router.get("/download", async (req, res) => {
  const file = req.query.file
  const content = await fs.readFile(file)
  res.send(content)
})
`},
			rule:             "path-traversal-file-access",
			cwe:              "CWE-22",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "GET /download",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"file<-source"},
		},
		{
			name: "multiline prisma idor route parameter",
			files: map[string]string{"routes/pets.js": `
router.get("/pets/:id", async (req, res) => {
  const pet = await prisma.pet.findUnique({
    where: {
      id: req.params.id,
    },
  })
  res.json(pet)
})
`},
			rule:             "possible-idor-prisma-id-only",
			cwe:              "CWE-639",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "GET /pets/:id",
			sourceContains:   "HTTP route parameter",
			dataflow:         "variable-derived",
			disposition:      "reportable-static-candidate",
			evidenceContains: []string{"bounded statement block"},
		},
		{
			name: "multiline mass assignment body",
			files: map[string]string{"routes/users.js": `
router.patch("/users/me", requireAuth, async (req, res) => {
  const user = await prisma.user.update({
    where: { id: req.user.id },
    data: req.body,
  })
  res.json(user)
})
`},
			rule:             "mass-assignment-request-body",
			cwe:              "CWE-915",
			owasp:            "A06:2025 Insecure Design",
			routeContains:    "PATCH /users/me",
			sourceContains:   "HTTP request body",
			dataflow:         "variable-derived",
			disposition:      "reportable-static-candidate",
			evidenceContains: []string{"bounded statement block"},
		},
		{
			name: "express destructured query alias sqli",
			files: map[string]string{"routes/search.ts": `
router.get("/search", async (req, res) => {
  const { q: search } = req.query
  const sql = "SELECT * FROM users WHERE name = '" + search + "'"
  const rows = await prisma.$queryRawUnsafe(sql)
  res.json(rows)
})
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"search<-destructured-source", "sql<-search"},
		},
		{
			name: "member assignment access path sqli",
			files: map[string]string{"routes/search.ts": `
router.get("/search", async (req, res) => {
  const sql = {}
  sql.text = req.query.q
  const rows = await prisma.$queryRawUnsafe(sql.text)
  res.json(rows)
})
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"sql.text<-member-source"},
		},
		{
			name: "ssrf destructured body callback",
			files: map[string]string{"routes/hooks.ts": `
router.post("/hook/test", async (req, res) => {
  const { callbackUrl } = req.body
  const r = await fetch(callbackUrl)
  res.send(await r.text())
})
`},
			rule:             "ssrf-fetch-user-url",
			cwe:              "CWE-918",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "POST /hook/test",
			sourceContains:   "HTTP request body",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"callbackUrl<-destructured-source"},
		},
		{
			name: "multiline object literal sqli container",
			files: map[string]string{"routes/search.ts": `
router.get("/search", async (req, res) => {
  const where = {
    name: req.query.q,
  }
  const rows = await prisma.$queryRawUnsafe(where)
  res.json(rows)
})
`},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP query parameter",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"where<-object-literal-source"},
		},
		{
			name: "object literal after destructuring ssrf",
			files: map[string]string{"routes/proxy.ts": `
router.post("/proxy", async (req, res) => {
  const { url } = req.body
  const opts = {
    target: url,
  }
  const r = await fetch(opts.target)
  res.send(await r.text())
})
`},
			rule:             "ssrf-fetch-user-url",
			cwe:              "CWE-918",
			owasp:            "A01:2025 Broken Access Control",
			routeContains:    "POST /proxy",
			sourceContains:   "HTTP request body",
			dataflow:         "propagated",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"url<-destructured-source", "opts<-object-literal(url)"},
		},
		{
			name: "cross file wrapper object literal sqli",
			files: map[string]string{
				"lib/db.ts": `
export function unsafeQuery(where) {
  return prisma.$queryRawUnsafe(where)
}
`,
				"routes/search.ts": `
router.get("/search", async (req, res) => {
  const where = { name: req.query.q }
  const rows = await unsafeQuery(where)
  res.json(rows)
})
`,
			},
			rule:             "prisma-raw-sql-unsafe",
			cwe:              "CWE-89",
			owasp:            "A05:2025 Injection",
			routeContains:    "GET /search",
			sourceContains:   "HTTP request input via caller",
			dataflow:         "cross-file",
			disposition:      "needs-runtime-proof",
			evidenceContains: []string{"cross-file", "where<-object-literal-source", "unsafeQuery"},
		},
		{
			name: "i18n password label false positive",
			files: map[string]string{"src/i18n/en.ts": `
export const en = {
  auth: {
    password: "Password",
    confirmPassword: "Confirm Password"
  }
}
`},
			rule:            "hardcoded-credential",
			cwe:             "CWE-798",
			owasp:           "A02:2025 Security Misconfiguration",
			sourceContains:  "source-code literal",
			dataflow:        "not-applicable",
			disposition:     "false-positive-static",
			counterContains: "localized UI label",
		},
		{
			name: "react jsonld dangerous html false positive",
			files: map[string]string{"src/components/ProductJsonLd.tsx": `
export function ProductJsonLd({ jsonLd }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
}
`},
			rule:            "react-dangerous-html",
			cwe:             "CWE-79",
			owasp:           "A05:2025 Injection",
			sourceContains:  "stored or rendered user content",
			dataflow:        "context-only",
			disposition:     "false-positive-static",
			counterContains: "JSON-LD structured data",
		},
		{
			name: "sse json framing false positive",
			files: map[string]string{"routes/stream.js": `
router.post("/ai-chat", (req, res) => {
  const delta = req.body.message
  res.write(` + "`data: ${JSON.stringify({ choices: [{ delta: { content: delta } }] })}\\n\\n`" + `)
})
`},
			rule:            "reflected-response-write",
			cwe:             "CWE-79",
			owasp:           "A05:2025 Injection",
			routeContains:   "POST /ai-chat",
			sourceContains:  "HTTP request body",
			dataflow:        "propagated",
			disposition:     "false-positive-static",
			counterContains: "server-sent-event JSON framing",
		},
		{
			name: "mobile local uri fetch false positive",
			files: map[string]string{"src/components/Uploader.tsx": `
export async function upload(localUri) {
  const blob = await (await fetch(localUri)).blob()
  return blob
}
`},
			rule:            "ssrf-fetch-user-url",
			cwe:             "CWE-918",
			owasp:           "A01:2025 Broken Access Control",
			sourceContains:  "unknown",
			dataflow:        "missing",
			disposition:     "false-positive-static",
			counterContains: "client/mobile local URI",
		},
		{
			name: "next client component fetch false positive",
			files: map[string]string{"app/uploader.tsx": `
"use client"

export async function upload(url) {
  const blob = await fetch(url).then(r => r.blob())
  return blob
}
`},
			rule:            "ssrf-fetch-user-url",
			cwe:             "CWE-918",
			owasp:           "A01:2025 Broken Access Control",
			sourceContains:  "URL variable",
			dataflow:        "variable-derived",
			disposition:     "false-positive-static",
			counterContains: "React/Next client component fetch",
			attackContains:  "No attack path",
		},
	}

}

func TestStaticTriageParityCoverageScore(t *testing.T) {
	cases := codexSecurityParityCases()
	passed := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := runParityCase(t, tc)
			assertParityCase(t, tc, h)
			passed++
		})
	}
	score := passed * 100 / len(cases)
	if score < 99 {
		t.Fatalf("static-analysis-grade static triage parity below target: got %d%% (%d/%d), want >=99%%", score, passed, len(cases))
	}
}

func runParityCase(t *testing.T, tc parityCase) ports.SASTRawFinding {
	t.Helper()
	root := t.TempDir()
	for rel, content := range tc.files {
		writeFile(t, root, rel, content)
	}
	hits, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for i := range hits {
		if hits[i].RuleID == tc.rule {
			return hits[i]
		}
	}
	t.Fatalf("missing rule %s in findings: %+v", tc.rule, hits)
	return ports.SASTRawFinding{}
}

func assertParityCase(t *testing.T, tc parityCase, h ports.SASTRawFinding) {
	t.Helper()
	if h.CWE != tc.cwe || h.OWASP2025 != tc.owasp {
		t.Fatalf("mapping mismatch: got cwe=%s owasp=%s finding=%+v", h.CWE, h.OWASP2025, h)
	}
	if tc.routeContains != "" && !strings.Contains(h.Route, tc.routeContains) {
		t.Fatalf("route mismatch: want contains %q got %+v", tc.routeContains, h)
	}
	if !strings.Contains(h.Source, tc.sourceContains) {
		t.Fatalf("source mismatch: want contains %q got %+v", tc.sourceContains, h)
	}
	if h.DataFlowConfidence != tc.dataflow {
		t.Fatalf("dataflow mismatch: want %q got %+v", tc.dataflow, h)
	}
	if h.ValidationDisposition != tc.disposition {
		t.Fatalf("disposition mismatch: want %q got %+v", tc.disposition, h)
	}
	if tc.counterContains != "" && !strings.Contains(h.CounterEvidence, tc.counterContains) {
		t.Fatalf("counterevidence missing marker %q: %+v", tc.counterContains, h)
	}
	if tc.attackContains != "" && !strings.Contains(h.AttackPath, tc.attackContains) {
		t.Fatalf("attack path missing marker %q: %+v", tc.attackContains, h)
	}
	for _, marker := range tc.evidenceContains {
		if !strings.Contains(h.DataFlowEvidence, marker) {
			t.Fatalf("evidence missing marker %q: %q", marker, h.DataFlowEvidence)
		}
	}
}

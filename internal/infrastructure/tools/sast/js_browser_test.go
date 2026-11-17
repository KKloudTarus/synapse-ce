package sast

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserEntrypointHTTPWrapper(t *testing.T) {
	for _, tc := range []struct {
		name, extra, config, entry string
		helperImport               string
		want, generic              int
	}{
		{name: "browser alias wrapper"},
		{name: "shared server wrapper", extra: "import http from './src/utils/fetch/http';\nexport const proxy = (req) => http.get(req.query.url);", want: 2, generic: 1},
		{name: "unknown importer", extra: "import http from './src/utils/fetch/http';\nexport const load = (url) => http.get(url);", want: 2},
		{name: "unknown loader", extra: "const other = require(moduleName);", want: 2},
		{name: "erased server import", extra: "import type { Options } from './src/utils/fetch/http';\nexport const proxy = (req) => req.query.url;"},
		{name: "computed config", config: "export default {resolve:{alias:{'@': chooseSourceRoot()}}};", want: 2},
		{name: "commented HTML entry", entry: "<!-- <script type='module' src='/src/main.ts'></script> -->", want: 2},
		{name: "external HTML entry", entry: "<script type='module' src='https://example.com/main.js'></script>", want: 2},
		{name: "inert template entry", entry: "<template><script type='module' src='/src/main.ts'></script></template>", want: 2},
		{name: "duplicate source attribute", entry: "<script type='module' src='https://example.com/main.js' src='/src/main.ts'></script>", want: 2},
		{name: "SVG script is not HTML module entry", entry: "<svg><script type='module' src='/src/main.ts'></script></svg>", want: 2},
		{name: "external base URL", entry: "<base href='https://example.com/'><script type='module' src='/src/main.ts'></script>", want: 2},
		{name: "Node builtin in browser graph", helperImport: "import 'node:fs';\n", want: 2, generic: 3},
		{name: "runtime alias named like asset", config: "export default {resolve:{alias:{'@':$SOURCE, 'client.json':$HELPER}}};", extra: "import http from 'client.json';\nexport const proxy = (req) => http.get(req.query.url);", want: 2, generic: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sourcePath, err := json.Marshal(filepath.Join(root, "src"))
			if err != nil {
				t.Fatal(err)
			}
			config := "import { defineConfig } from 'vite';\nexport default defineConfig({resolve:{alias:{'@':" + string(sourcePath) + "}}});\n"
			if tc.config != "" {
				helperPath, err := json.Marshal(filepath.Join(root, "src", "utils", "fetch", "http.ts"))
				if err != nil {
					t.Fatal(err)
				}
				config = strings.NewReplacer("$SOURCE", string(sourcePath), "$HELPER", string(helperPath)).Replace(tc.config)
			}
			entry := "<script type='module' src='/src/main.ts'></script>"
			if tc.entry != "" {
				entry = tc.entry
			}
			writeFile(t, root, "index.html", entry)
			writeFile(t, root, "package.json", `{"name":"browser-app","devDependencies":{"vite":"5.4.21"}}`)
			writeFile(t, root, "vite.config.ts", config)
			writeFile(t, root, "src/main.ts", "import { makeRepo } from './api/repos';\nimport './style.css';\nmakeRepo('/api').list({});\n")
			writeFile(t, root, "src/style.css", "body { color: black; }\n")
			writeFile(t, root, "src/api/repos.ts", "import http from '@/utils/fetch/http';\nexport const makeRepo = (BASE_URL: string) => ({\nlist: (params) => http.get(BASE_URL, { params }),\ngetOne: (id) => http.get(`${BASE_URL}/${id}`),\ncreate: (data) => http.post(BASE_URL, data),\n});\n")
			writeFile(t, root, "src/utils/fetch/http.ts", tc.helperImport+"export interface Options {}\nexport default {\nget: (url: string, options?: unknown) => fetch(url),\npost: (url: string, data: unknown) => fetch(url, { method: 'POST', body: JSON.stringify(data) }),\n};\n")
			if tc.extra != "" {
				writeFile(t, root, "other.ts", tc.extra)
			}
			findings := findingsByRule(t, root)
			if got := len(findings["ssrf-fetch-user-url"]); got != tc.want {
				t.Fatalf("fetch SSRF findings=%d; want %d: %+v", got, tc.want, findings["ssrf-fetch-user-url"])
			}
			if len(findings["go-ssrf-dynamic-url"]) != 0 || len(findings["generic-ssrf-request-url"]) != tc.generic {
				t.Fatalf("unexpected Go/generic SSRF findings: %+v %+v", findings["go-ssrf-dynamic-url"], findings["generic-ssrf-request-url"])
			}
		})
	}
}

func TestBrowserHTTPWrapperRetainsFindingsOnSourceLimit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "<script type='module' src='/a.ts'></script>")
	writeFile(t, root, "a.ts", "import './helper';\n")
	writeFile(t, root, "helper.ts", "export const get = (url) => fetch(url);\n")
	writeFile(t, root, "zzz.ts", "import { get } from './helper';\nexport const proxy = (req) => get(req.query.url);\n")
	report, err := New().analyzeSource(context.Background(), root, 3, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated || report.UnscannedFiles != 1 {
		t.Fatalf("source limit was not reported: %+v", report)
	}
	count := 0
	for _, f := range report.Findings {
		if f.RuleID == "ssrf-fetch-user-url" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("fetch findings=%d; want one retained candidate", count)
	}
}

func TestHTMLModuleRootEntries(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"/app.js", "app.js"},
		{"./app.js", "pages/app.js"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			files := []sourceFile{{Rel: "pages/index.html", Ext: ".html", Lines: []string{"<script type='module' src='" + tc.source + "'></script>"}}}
			entries, err := jsHTMLModuleEntries(context.Background(), files, map[string]bool{"app.js": false, "pages/app.js": false}, jsImportMetadata{})
			if err != nil || len(entries) != 1 || !entries[tc.want] {
				t.Fatalf("entries=%v, err=%v; want %s", entries, err, tc.want)
			}
		})
	}
}

func TestBrowserReachabilityRetainsWebRequestHandler(t *testing.T) {
	for _, handler := range []string{
		"export async function GET(request: Request) {\nconst target = new URL(request.url).searchParams.get('url');\nreturn fetch(target);\n}",
		"export async function GET(input: Request) {\nconst target = new URL(input.url).searchParams.get('url');\nreturn fetch(target);\n}",
		"export async function GET(request) {\nconst target = new URL(request.url).searchParams.get('url');\nreturn fetch(target);\n}",
	} {
		root := t.TempDir()
		writeFile(t, root, "index.html", "<script type='module' src='/main.ts'></script>")
		writeFile(t, root, "main.ts", "import { GET } from './app/api/proxy/route';\nconsole.log(GET.name);")
		writeFile(t, root, "app/api/proxy/route.ts", handler)
		if got := len(findingsByRule(t, root)["ssrf-fetch-user-url"]); got != 1 {
			t.Fatalf("fetch findings=%d; want one retained server handler finding for %s", got, handler)
		}
	}
}

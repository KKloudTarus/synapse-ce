package sast

import (
	"context"
	"testing"
)

// Browser HTTP wrappers must not inherit Go's net/http rules or turn configured
// REST paths into request-controlled server destinations.
func TestSSRFSourceContext(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    string
		content string
		caller  string
		want    []string
	}{
		{
			name: "browser repository factory", file: "src/api/repos.ts",
			content: "import http from \"@/utils/fetch/http\";\n" +
				"export const makeRepo = (BASE_URL: string) => ({\n" +
				"  list: (params) => http.get(BASE_URL, { params }),\n" +
				"  getOne: (id: string) => http.get(`${BASE_URL}/${id}`),\n" +
				"  create: (data) => http.post(BASE_URL, data),\n" +
				"});\n",
		},
		{
			name: "vite configured browser client", file: "src/api/client.ts",
			content: "import http from './http';\n" +
				"const BASE_URL = import.meta.env.VITE_API_URL;\n" +
				"export const load = () => http.get(BASE_URL);\n",
		},
		{
			name: "browser javascript wrapper", file: "src/api/client.js",
			content: "import http from './http';\nexport const load = (url) => http.get(url);\n",
		},
		{
			name: "browser wrapper with commented server example", file: "src/api/client.ts",
			content: "/* req.query.url; require('node:http'); */\n" +
				"import http from './http';\nexport const load = (url) => http.get(url);\n",
		},
		{
			name: "typescript uppercase method is not Go", file: "src/api/client.ts",
			content: "export const load = (url: string) => http.Get(url);\n",
		},
		{
			name: "browser component wrapper", file: "src/components/Repo.tsx",
			content: "const BASE_URL = '/api/repos';\nexport const load = () => http.get(BASE_URL);\n",
		},
		{
			name: "python wrapper is not Go", file: "client.py",
			content: "def load(target):\n    return http.Get(target)\n",
		},
		{
			name: "go dynamic destination", file: "proxy.go",
			content: "package proxy\nfunc load(target string) {\n  http.Get(target)\n}\n",
			want:    []string{"go-ssrf-dynamic-url"},
		},
		{
			name: "go request destination", file: "proxy.go",
			content: "package proxy\nfunc proxy(w http.ResponseWriter, r *http.Request) {\n" +
				"  http.Get(r.URL.Query().Get(\"url\"))\n}\n",
			want: []string{"generic-ssrf-request-url", "go-ssrf-dynamic-url", "go-ssrf-request-url"},
		},
		{
			name: "go literal destination", file: "client.go",
			content: "package client\nfunc load() {\n  http.Get(\"https://api.example.com/repos\")\n}\n",
		},
		{
			name: "node request destination", file: "server/proxy.ts",
			content: "import http from 'node:http';\n" +
				"export function proxy(req, res) { return http.get(req.query.url); }\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node request destination alias", file: "server/proxy.js",
			content: "const http = require('http');\n" +
				"function proxy(req, res) {\n  const url = req.query.url;\n  return http.get(url);\n}\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "server local wrapper with request destination", file: "server/proxy.ts",
			content: "import http from './http';\n" +
				"export const proxy = (req) => http.get(req.query.url);\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node http helper", file: "lib/proxy.ts",
			content: "import http from 'node:http';\n" +
				"export function load(url: string) { return http.get(url); }\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node commonjs helper", file: "lib/proxy.cjs",
			content: "const http = require('http');\n" +
				"exports.load = (url) => http.get(url);\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node multiline import helper", file: "lib/proxy.mts",
			content: "import http from\n  /* built-in client */\n  'node:http';\n" +
				"export function load(url: string) { return http.get(url); }\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node dynamic import helper", file: "lib/proxy.ts",
			content: "const http = await import('node:http');\n" +
				"export function load(url: string) { return http.get(url); }\n",
			caller: "import { load } from '../lib/proxy';\n" +
				"export function proxy(req) { return load(req.query.url); }\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node multiline dynamic import helper", file: "lib/proxy.mjs",
			content: "const http = await import(\n  /* built-in client */\n  'http'\n);\n" +
				"export function load(url) { return http.get(url); }\n",
			caller: "import { load } from '../lib/proxy.mjs';\n" +
				"export function proxy(req) { return load(req.query.url); }\n",
			want: []string{"generic-ssrf-request-url"},
		},
		{
			name: "node fetch request destination", file: "server/proxy.ts",
			content: "export function proxy(req) { return fetch(req.query.url); }\n",
			want:    []string{"ssrf-fetch-user-url"},
		},
		{
			name: "node axios request destination", file: "server/proxy.ts",
			content: "export function proxy(req) { return axios.get(req.body.url); }\n",
			want:    []string{"ssrf-fetch-user-url"},
		},
		{
			name: "python request destination", file: "proxy.py",
			content: "def proxy():\n    return requests.get(request.args['url'])\n",
			want:    []string{"generic-ssrf-request-url"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, tc.content)
			if tc.caller != "" {
				writeFile(t, root, "server/handler.ts", tc.caller)
			}
			report, err := New().AnalyzeSourceReport(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if report.Truncated || report.SkippedFiles != 0 || report.UnscannedFiles != 0 {
				t.Fatalf("incomplete scan: %+v", report)
			}
			want := make(map[string]bool, len(tc.want))
			for _, id := range tc.want {
				want[id] = true
			}
			for _, hit := range report.Findings {
				if hit.CWE != "CWE-918" {
					continue
				}
				if !want[hit.RuleID] {
					t.Errorf("unexpected SSRF finding: %+v", hit)
				}
				delete(want, hit.RuleID)
			}
			for id := range want {
				t.Errorf("missing SSRF rule %s", id)
			}
		})
	}
}

func TestSSRFLocalServerWrapperWithBrowserTwin(t *testing.T) {
	for _, call := range []struct {
		name string
		code string
	}{
		{"direct request argument", "return load(req.query.url);"},
		{"assigned request argument", "const target = req.query.url; return load(target);"},
	} {
		t.Run(call.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "server/http.ts", "import { get } from 'node:http';\nexport default { get };\n")
			writeFile(t, root, "server/client.ts", "import http from './http';\n"+
				"export function load(url: string) { return http.get(url); }\n")
			writeFile(t, root, "routes/proxy.ts", "import { load } from '../server/client';\n"+
				"export function proxy(req, res) { "+call.code+" }\n")
			writeFile(t, root, "browser/http.ts", "export default window.api;\n")
			writeFile(t, root, "browser/client.ts", "import http from './http';\n"+
				"export function load(BASE_URL: string) { return http.get(BASE_URL); }\n")
			byRule := findingsByRule(t, root)
			hits := byRule["generic-ssrf-request-url"]
			if len(hits) != 1 || hits[0].File != "server/client.ts" {
				t.Fatalf("want only server wrapper SSRF finding, got %+v", hits)
			}
			if hits := byRule["go-ssrf-dynamic-url"]; len(hits) != 0 {
				t.Fatalf("Go rule matched TypeScript: %+v", hits)
			}
		})
	}
}

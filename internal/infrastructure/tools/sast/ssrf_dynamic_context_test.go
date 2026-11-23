package sast

import (
	"strings"
	"testing"
)

func TestSSRFDynamicHTTPDestinationPreservesLanguages(t *testing.T) {
	for _, tc := range []struct {
		name, file, source string
		want               bool
	}{
		{"node javascript", "server/proxy.js", "const express = require('express');\nconst http = require('node:http');\nconst app = express();\napp.get('/p', (q, s) => { const dest = q.query.d; http.get(dest); });\nmodule.exports = app;\n", true},
		{"node typescript", "server/proxy.ts", "import http from 'node:http';\nexport const proxy = (q) => { const dest = q.query.d; return http.get(dest); };\n", true},
		{"node head request", "server/proxy.js", "const http = require('node:http');\nexports.proxy = (target) => http.head(target);\n", true},
		{"dart", "lib/proxy.dart", "import 'package:http/http.dart' as http;\nFuture proxy(String dest) { return http.get(dest); }\n", true},
		{"browser", "src/client.ts", "export const load = (dest: string) => http.get(dest);\n", false},
		{"node literal", "server/proxy.ts", "import http from 'node:http';\nexport const load = () => http.get('https://example.com/api');\n", false},
		{"node comment", "server/proxy.ts", "import http from 'node:http';\n// http.get(dest);\n", false},
		{"python control", "proxy.py", "def load(dest):\n    return http.Get(dest)\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, tc.source)
			byRule := findingsByRule(t, root)
			found := false
			for id, hits := range byRule {
				if strings.Contains(id, "ssrf") && len(hits) > 0 {
					found = true
				}
			}
			if found != tc.want {
				t.Fatalf("SSRF finding = %t, want %t: %+v", found, tc.want, byRule)
			}
			if len(byRule["go-ssrf-dynamic-url"]) > 0 {
				t.Fatalf("Go rule matched non-Go file: %+v", byRule["go-ssrf-dynamic-url"])
			}
		})
	}
}

func TestSSRFServerContextThroughTSConfigPaths(t *testing.T) {
	for _, config := range []struct{ name, file, source string }{
		{"strict JSON", "tsconfig.json", `{"compilerOptions":{"moduleResolution":"bundler","baseUrl":".","paths":{"@lib/*":["lib/*"]}}}`},
		{"comments and trailing commas", "tsconfig.json", `{
 // shared server transport
 "compilerOptions": { "moduleResolution": "bundler", "baseUrl": ".", "paths": { "@lib/*": ["lib/*",], }, },
}`},
		{"javascript config", "jsconfig.json", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["lib/*"]}}}`},
	} {
		for _, specifier := range []string{"../lib/http", "@lib/http"} {
			t.Run(config.name+"/"+specifier, func(t *testing.T) {
				root := t.TempDir()
				writeFile(t, root, config.file, config.source)
				writeFile(t, root, "lib/http.ts", "export { default } from 'node:http';\n")
				writeFile(t, root, "server/proxy.ts", "import http from '"+specifier+"';\nexport const load = (url: string) => http.get(url);\n")
				hits := findingsByRule(t, root)["generic-ssrf-request-url"]
				if len(hits) != 1 || hits[0].File != "server/proxy.ts" {
					t.Fatalf("server alias lost SSRF finding: %+v", hits)
				}
			})
		}
	}
}

func TestSSRFBrowserTSConfigAliasAndUncertainServerControls(t *testing.T) {
	for _, tc := range []struct {
		name, config, transport string
		server                  bool
		want                    int
	}{
		{"browser alias", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@app/*":["src/*"]}}}`, "export default { get: (url) => fetch(url) };\n", false, 0},
		{"node alias", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@app/*":["src/*"]}}}`, "export { default } from 'node:http';\n", true, 1},
		{"malformed config", `{"compilerOptions":`, "export { default } from 'node:http';\n", true, 1},
		{"inherited config", `{"extends":"./base.json"}`, "export { default } from 'node:http';\n", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "package.json", `{"name":"app","dependencies":{}}`)
			writeFile(t, root, "tsconfig.json", tc.config)
			writeFile(t, root, "index.html", "<script type='module' src='/src/main.ts'></script>")
			writeFile(t, root, "src/main.ts", "import http from '@app/http';\nexport const load = (dest: string) => http.get(dest);\n")
			writeFile(t, root, "src/http.ts", tc.transport)
			got := findingsByRule(t, root)
			if len(got["generic-ssrf-request-url"]) != tc.want {
				t.Fatalf("generic SSRF findings: %+v", got["generic-ssrf-request-url"])
			}
			if !tc.server && len(got["ssrf-fetch-user-url"]) != 0 {
				t.Fatalf("browser transport was not suppressed: %+v", got["ssrf-fetch-user-url"])
			}
		})
	}
}

func TestSSRFSkippedTSConfigRetainsCandidates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tsconfig.json", strings.Repeat(" ", maxFileBytes+1))
	writeFile(t, root, "lib/http.ts", "export { default } from 'node:http';\n")
	writeFile(t, root, "server/proxy.ts", "import http from '@lib/http';\nexport const load = (dest: string) => http.get(dest);\n")
	if len(findingsByRule(t, root)["generic-ssrf-request-url"]) != 1 {
		t.Fatal("skipped config must not suppress a runtime candidate")
	}
}

func TestSSRFLongRequestContextLinePreservesScannedSink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"server","dependencies":{"express":"5.1.0"}}`)
	writeFile(t, root, "proxy.js", "const express = require('express'); "+strings.Repeat(" ", maxLineBytes)+"\n\n\n\nexport const load = (dest) => http.get(dest);\n")
	if len(findingsByRule(t, root)["generic-ssrf-request-url"]) != 1 {
		t.Fatal("a long request-context line must not suppress a scanned sink")
	}
}

func TestSSRFAliasesPreferRuntimeFileOverDirectory(t *testing.T) {
	for _, specifier := range []string{"../lib/http", "@lib/http"} {
		t.Run(specifier, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "tsconfig.json", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["lib/*"]}}}`)
			writeFile(t, root, "lib/http.js", "export { default } from 'node:http';\n")
			writeFile(t, root, "lib/http/index.ts", "export default { get: (value: string) => value };\n")
			writeFile(t, root, "server/proxy.ts", "import http from '"+specifier+"';\nexport const load = (dest: string) => http.get(dest);\n")
			if len(findingsByRule(t, root)["generic-ssrf-request-url"]) != 1 {
				t.Fatal("directory index shadowed the server runtime file")
			}
		})
	}
}

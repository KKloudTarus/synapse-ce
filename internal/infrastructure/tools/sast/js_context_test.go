package sast

import (
	"context"
	"errors"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestJSServerImportContext(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		limit int
		want  []string
	}{
		{
			name: "facade cycle reaches Node HTTP", limit: 10,
			files: map[string]string{
				"a.ts":       "export { default } from './b';",
				"b.ts":       "import './a'; export { default } from './http';",
				"http.ts":    "import http from 'node:http'; export default http;",
				"browser.ts": "export const load = (BASE_URL) => http.get(BASE_URL);",
			},
			want: []string{"a.ts", "b.ts", "http.ts"},
		},
		{
			name: "emitted extension directory index and bundler suffixes", limit: 10,
			files: map[string]string{
				"client.ts":          "import './http.js?module'; import './transport#entry';",
				"http.ts":            "export { get } from 'node:http';",
				"transport/index.ts": "export { get } from 'node:https';",
			},
			want: []string{"client.ts", "http.ts", "transport/index.ts"},
		},
		{
			name: "type-only edges do not carry runtime context", limit: 10,
			files: map[string]string{
				"http.ts":    "export { get } from 'node:http';",
				"types.ts":   "import type { RequestOptions } from 'node:http';",
				"browser.ts": "import type { get } from './http';",
				"runtime.ts": "import { type get } from './http';",
			},
			want: []string{"http.ts", "runtime.ts"},
		},
		{
			name: "uncertain loader propagates to importer", limit: 10,
			files: map[string]string{
				"client.ts":  "import http from './http';",
				"http.ts":    "export default require(moduleName);",
				"browser.ts": "const docs = \"import('node:http')\";",
			},
			want: []string{"client.ts", "http.ts"},
		},
		{
			name: "request cues stay local", limit: 10,
			files: map[string]string{
				"server.ts":  "export const proxy = (req) => req.query.url;",
				"browser.ts": "import './server';",
			},
			want: []string{"server.ts"},
		},
		{
			name: "duplicate imports use one edge", limit: 1,
			files: map[string]string{
				"client.ts":  "import './http'; import './http';",
				"http.ts":    "export { get } from 'node:http';",
				"browser.ts": "export const load = (BASE_URL) => http.get(BASE_URL);",
			},
			want: []string{"client.ts", "http.ts"},
		},
		{
			name: "edge budget preserves all candidates", limit: 1,
			files: map[string]string{
				"client.ts":  "import './http'; import './other';",
				"http.ts":    "export { get } from 'node:http';",
				"other.ts":   "export default {};",
				"browser.ts": "export const load = (BASE_URL) => http.get(BASE_URL);",
			},
			want: []string{"browser.ts", "client.ts", "http.ts", "other.ts"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var files []sourceFile
			for rel, source := range tc.files {
				files = append(files, sourceFile{Rel: rel, Ext: path.Ext(rel), Lines: strings.Split(source, "\n")})
			}
			sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
			server, err := buildJSServerRequestFiles(context.Background(), files, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rel, marked := range server {
				if marked {
					got = append(got, rel)
				}
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("server files=%v; want %v", got, tc.want)
			}
		})
	}
}

func TestJSServerImportContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := buildJSServerRequestFiles(ctx, []sourceFile{{Rel: "client.ts", Ext: ".ts"}}, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got err=%v", err)
	}
}

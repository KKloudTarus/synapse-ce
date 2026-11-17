package jsresolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSourcePathsResolveRetainedModules(t *testing.T) {
	for _, tc := range []struct {
		name, config, from, spec, want string
		uncertain                      bool
	}{
		{"wildcard", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["lib/*"]}}}`, "server/proxy.ts", "@lib/http", "lib/http.ts", false},
		{"exact", `{"compilerOptions":{"paths":{"transport":["lib/http.ts"]}}}`, "server/proxy.ts", "transport", "lib/http.ts", false},
		{"jsonc", `{/* comment */"compilerOptions":{"moduleResolution":"node","baseUrl":".","paths":{"@lib/*":["lib/*",],},},}`, "server/proxy.ts", "@lib/http", "lib/http.ts", false},
		{"base URL", `{"compilerOptions":{"moduleResolution":"bundler","baseUrl":"lib","paths":{"@lib/*":["*"]}}}`, "server/proxy.ts", "@lib/http", "lib/http.ts", false},
		{"ordered fallback", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["missing/*","lib/*"]}}}`, "server/proxy.ts", "@lib/http", "lib/http.ts", false},
		{"first target wins", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["browser/*","lib/*"]}}}`, "server/proxy.ts", "@lib/http", "browser/http.ts", false},
		{"suffix", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*.js":["lib/*.ts"]}}}`, "server/proxy.ts", "@lib/http.js", "lib/http.ts", false},
		{"emitted extension", `{"compilerOptions":{"moduleResolution":"nodenext","paths":{"@lib/*":["lib/*.js"]}}}`, "server/proxy.ts", "@lib/http", "lib/http.ts", false},
		{"hash alias", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"#internal/*":["lib/*"]}}}`, "server/proxy.ts", "#internal/http", "lib/http.ts", false},
		{"tilde alias", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"~/*":["lib/*"]}}}`, "server/proxy.ts", "~/http", "lib/http.ts", false},
		{"unknown resolution mode", `{"compilerOptions":{"paths":{"@lib/*":["lib/*"]}}}`, "server/proxy.ts", "@lib/http", "", true},
		{"strict extensionless", `{"compilerOptions":{"moduleResolution":"nodenext","paths":{"@lib/*":["lib/*"]}}}`, "server/proxy.ts", "@lib/http", "", true},
		{"missing module", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["missing/*"]}}}`, "server/proxy.ts", "@lib/http", "", true},
		{"malformed", `{"compilerOptions":`, "server/proxy.ts", "@lib/http", "", true},
		{"inheritance", `{"extends":"./base.json"}`, "server/proxy.ts", "@lib/http", "", true},
		{"project membership", `{"include":["src"],"compilerOptions":{"paths":{"@lib/*":["lib/*.ts"]}}}`, "server/proxy.ts", "@lib/http", "", true},
		{"escaping capture", `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["lib/*"]}}}`, "server/proxy.ts", "@lib/../../outside", "", true},
		{"unrelated package", `{"compilerOptions":{"paths":{"@lib/*":["lib/*"]}}}`, "server/proxy.ts", "react", "", false},
		{"builtin", `{`, "server/proxy.ts", "node:http", "", false},
		{"relative", `{`, "server/proxy.ts", "../lib/http", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths SourcePaths
			if err := paths.Observe(context.Background(), "tsconfig.json", []byte(tc.config)); err != nil {
				t.Fatal(err)
			}
			got, err := paths.Resolve(context.Background(), tc.from, tc.spec, map[string]bool{"lib/http.ts": false, "browser/http.ts": false})
			if err != nil || got.Target != tc.want || got.Uncertain != tc.uncertain {
				t.Fatalf("result=%+v err=%v, want target %q uncertain %t", got, err, tc.want, tc.uncertain)
			}
		})
	}
}

func TestSourcePathsRetainAmbiguousAndBoundedContexts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		configs []string
	}{
		{"ambiguous", []string{"tsconfig.json", "jsconfig.json"}},
		{"budget", func() []string {
			var names []string
			for i := 0; i <= maxSourcePathEntries; i++ {
				names = append(names, fmt.Sprintf("tsconfig.%d.json", i))
			}
			return names
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths SourcePaths
			for _, name := range tc.configs {
				if err := paths.Observe(context.Background(), name, []byte(`{"compilerOptions":{"paths":{"@lib/*":["lib/*.ts"]}}}`)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := paths.Resolve(context.Background(), "server/proxy.ts", "@lib/http", map[string]bool{"lib/http.ts": false})
			if err != nil || !got.Applicable || !got.Uncertain {
				t.Fatalf("uncertain config accepted: %+v %v", got, err)
			}
		})
	}
}

func TestSourcePathsBoundedSourceAndCancellation(t *testing.T) {
	var paths SourcePaths
	if err := paths.Observe(context.Background(), "tsconfig.json", []byte(strings.Repeat(" ", int(defaultMaxAliasFileBytes)+1))); err != nil {
		t.Fatal(err)
	}
	got, err := paths.Resolve(context.Background(), "server/proxy.ts", "@lib/http", nil)
	if err != nil || !got.Uncertain {
		t.Fatalf("oversized config must remain uncertain: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := paths.Observe(ctx, "tsconfig.json", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("observe cancellation: %v", err)
	}
	if _, err := paths.Resolve(ctx, "server/proxy.ts", "@lib/http", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolve cancellation: %v", err)
	}
}

func TestSourcePathsPreferFilesBeforeDirectoryIndexes(t *testing.T) {
	var paths SourcePaths
	if err := paths.Observe(context.Background(), "tsconfig.json", []byte(`{"compilerOptions":{"moduleResolution":"bundler","paths":{"@lib/*":["lib/*"]}}}`)); err != nil {
		t.Fatal(err)
	}
	got, err := paths.Resolve(context.Background(), "server/proxy.ts", "@lib/http", map[string]bool{"lib/http.js": false, "lib/http/index.ts": false})
	if err != nil || got.Target != "lib/http.js" || got.Uncertain {
		t.Fatalf("file must precede directory index: %+v %v", got, err)
	}
}

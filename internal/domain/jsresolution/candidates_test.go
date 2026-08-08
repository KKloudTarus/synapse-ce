package jsresolution

import (
	"reflect"
	"testing"
)

func TestModuleSourceExtensionsIsACopy(t *testing.T) {
	t.Parallel()

	first := ModuleSourceExtensions()
	first[0] = "MUTATED"
	if ModuleSourceExtensions()[0] == "MUTATED" {
		t.Fatal("ModuleSourceExtensions must return a copy; a caller must not be able to reorder resolution")
	}
}

func TestModuleSourceExtensionsPrecedence(t *testing.T) {
	t.Parallel()

	got := ModuleSourceExtensions()
	// TypeScript sources must precede declarations, which must precede JavaScript: the first existing
	// candidate wins, so this order IS the resolution semantics.
	indexOf := func(ext string) int {
		for i, v := range got {
			if v == ext {
				return i
			}
		}
		t.Fatalf("extension %q missing from the candidate list", ext)
		return -1
	}
	if indexOf(".ts") >= indexOf(".d.ts") {
		t.Error(".ts must be preferred over .d.ts")
	}
	if indexOf(".d.ts") >= indexOf(".js") {
		t.Error(".d.ts must be preferred over .js")
	}
	if indexOf(".ts") >= indexOf(".tsx") {
		t.Error(".ts must be preferred over .tsx")
	}
}

func TestEmittedExtensionCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ext  string
		want []string
	}{
		{ext: ".js", want: []string{".ts", ".tsx", ".d.ts"}},
		{ext: ".jsx", want: []string{".tsx", ".d.ts"}},
		{ext: ".mjs", want: []string{".mts", ".d.mts"}},
		{ext: ".cjs", want: []string{".cts", ".d.cts"}},
		{ext: ".JS", want: []string{".ts", ".tsx", ".d.ts"}},
		{ext: ".ts", want: nil},
		{ext: ".css", want: nil},
		{ext: "", want: nil},
	}

	for _, test := range tests {
		test := test
		t.Run(test.ext, func(t *testing.T) {
			t.Parallel()
			got := EmittedExtensionCandidates(test.ext)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("EmittedExtensionCandidates(%q) = %v, want %v", test.ext, got, test.want)
			}
		})
	}
}

func TestModuleFileCandidates(t *testing.T) {
	t.Parallel()

	t.Run("extensionless base", func(t *testing.T) {
		t.Parallel()
		got := ModuleFileCandidates("src/util")
		if got[0] != "src/util.ts" {
			t.Fatalf("first candidate = %q, want src/util.ts", got[0])
		}
		if !contains(got, "src/util/index.ts") {
			t.Fatalf("directory index candidate missing: %v", got)
		}
		// The base itself is not a candidate when it carries no extension: a file with no extension is
		// not a module this scanner supports.
		if contains(got, "src/util") {
			t.Fatalf("an extensionless path must not be its own candidate: %v", got)
		}
	})

	t.Run("emitted extension", func(t *testing.T) {
		t.Parallel()
		got := ModuleFileCandidates("src/util.js")
		if got[0] != "src/util.js" {
			t.Fatalf("a written extension must be tried first, got %q", got[0])
		}
		// The rewrite must come before the generic extension candidates so "./util.js" prefers util.ts
		// over, say, util.js.ts.
		rewriteAt, genericAt := indexOf(got, "src/util.ts"), indexOf(got, "src/util.js.ts")
		if rewriteAt < 0 {
			t.Fatalf("emitted-extension rewrite missing: %v", got)
		}
		if genericAt >= 0 && rewriteAt > genericAt {
			t.Fatalf("the rewrite must precede the generic candidates: %v", got)
		}
	})

	t.Run("repository root", func(t *testing.T) {
		t.Parallel()
		got := ModuleFileCandidates("")
		if got[0] != "index.ts" {
			t.Fatalf("root candidates must start at index.ts, got %q", got[0])
		}
		for _, candidate := range got {
			if candidate == ".ts" || candidate == "" {
				t.Fatalf("root candidates must not include a bare extension: %v", got)
			}
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		if !reflect.DeepEqual(ModuleFileCandidates("a/b"), ModuleFileCandidates("a/b")) {
			t.Fatal("candidate generation must be deterministic")
		}
	})
}

func contains(values []string, want string) bool {
	return indexOf(values, want) >= 0
}

func indexOf(values []string, want string) int {
	for i, v := range values {
		if v == want {
			return i
		}
	}
	return -1
}

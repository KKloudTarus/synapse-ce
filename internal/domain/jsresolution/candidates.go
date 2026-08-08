package jsresolution

import (
	"path"
	"strings"
)

// Module file-resolution candidates are pure lexical rules shared by every phase of JavaScript and
// TypeScript resolution. They live in the domain because the source scanner (phase R1) and the package
// resolver (phase R2) must agree: if one orders candidates differently from the other, the same specifier
// can resolve to two different modules and the graph becomes internally inconsistent.

// moduleSourceExtensions is the ordered candidate extension list for a module specifier that carries no
// extension. The order mirrors TypeScript's documented precedence — TypeScript sources first, then
// declarations, then JavaScript — so exactly one candidate wins and resolution stays deterministic.
var moduleSourceExtensions = []string{
	".ts", ".tsx", ".mts", ".cts",
	".d.ts", ".d.mts", ".d.cts",
	".js", ".jsx", ".mjs", ".cjs",
}

// emittedExtensionRewrites maps the EMITTED extension a TypeScript project writes in a specifier to the
// source extensions that actually hold the code: an ESM TypeScript project imports "./util.js" for the
// file authored as util.ts.
var emittedExtensionRewrites = map[string][]string{
	".js":  {".ts", ".tsx", ".d.ts"},
	".jsx": {".tsx", ".d.ts"},
	".mjs": {".mts", ".d.mts"},
	".cjs": {".cts", ".d.cts"},
}

// ModuleSourceExtensions returns the ordered extension candidates for an extensionless specifier.
func ModuleSourceExtensions() []string {
	return append([]string(nil), moduleSourceExtensions...)
}

// EmittedExtensionCandidates returns the source extensions an emitted specifier extension may map to.
// It returns nil when ext is not an emitted JavaScript extension.
func EmittedExtensionCandidates(ext string) []string {
	rewrites, ok := emittedExtensionRewrites[strings.ToLower(ext)]
	if !ok {
		return nil
	}
	return append([]string(nil), rewrites...)
}

// ModuleFileCandidates returns the ordered module paths a resolved base path may refer to: the path as
// written, its emitted-extension rewrites, the extension candidates, and finally the directory index
// forms. base is a normalized repository-relative path; an empty base means the repository root.
//
// The returned order is the resolution order: the first candidate that exists wins.
func ModuleFileCandidates(base string) []string {
	base = strings.TrimSuffix(base, "/")
	out := make([]string, 0, 2*len(moduleSourceExtensions)+len(emittedExtensionRewrites)+1)

	if base != "" {
		if ext := path.Ext(base); ext != "" {
			// A specifier written with an extension resolves as written first, then through the
			// emitted-extension rewrite.
			out = append(out, base)
			stem := strings.TrimSuffix(base, ext)
			for _, rewrite := range EmittedExtensionCandidates(ext) {
				out = append(out, stem+rewrite)
			}
		}
		for _, ext := range moduleSourceExtensions {
			out = append(out, base+ext)
		}
	}

	indexBase := "index"
	if base != "" {
		indexBase = base + "/index"
	}
	for _, ext := range moduleSourceExtensions {
		out = append(out, indexBase+ext)
	}
	return out
}

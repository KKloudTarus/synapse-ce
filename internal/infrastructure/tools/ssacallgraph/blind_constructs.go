package ssacallgraph

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// goOpaqueConstructs are Go source/runtime escape hatches that can transfer control outside the static
// SSA call graph. They are deliberately named as stable evidence values because reachproof persists them in
// ReachabilityClaim.BlindConstructs and ProvedNotReachable treats any value here as a suppression blocker.
var goOpaqueConstructs = []string{"go:linkname", "unsafe", "cgo", "assembly"}

// These are the exported identifiers supplied by package unsafe. They matter only for a dot import, where
// the package qualifier is erased from source and an unsafe use would otherwise look like an ordinary bare
// identifier to the source pass. Keeping the closed stdlib surface here avoids treating every declaration in
// a file with `import . "unsafe"` as blind while still catching package initializers as well as function bodies.
var unsafeDotIdentifiers = map[string]bool{
	"Add":           true,
	"Alignof":       true,
	"ArbitraryType": true,
	"IntegerType":   true,
	"Offsetof":      true,
	"Pointer":       true,
	"Sizeof":        true,
	"Slice":         true,
	"SliceData":     true,
	"String":        true,
	"StringData":    true,
}

// sourceBlindFunctions returns construct -> first-party function symbols that contain an opaque Go construct.
// Detection is source-based because //go:linkname and cgo are rewritten before SSA, unsafe.Pointer is often a
// conversion rather than a call, and assembly-backed declarations have no Go body. Package-scope opaque
// expressions/directives map to the synthesized package init, which is a reachability root. Returned symbols
// use the same importPath.Symbol identity as nodeID, so the builder can intersect them with Graph.Reachable
// and only fail open when the opaque construct is actually on the reachable surface.
func sourceBlindFunctions(pkgs []*packages.Package) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for _, kind := range goOpaqueConstructs {
		out[kind] = map[string]bool{}
	}
	for _, pkg := range pkgs {
		if pkg == nil || pkg.PkgPath == "" {
			continue
		}
		ignored := ignoredFileSet(pkg)
		hasAssembly := packageHasAssembly(pkg, ignored)
		for _, filename := range pkg.GoFiles {
			// packages.GoFiles may contain a source file excluded by the active build tags/GOOS/GOARCH. Do
			// not let an inactive implementation poison the reachable symbol with a blind construct.
			if ignored[filepath.Clean(filename)] {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse Go blind-construct source %s: %w", filename, err)
			}
			// A //go:linkname directive is compiler-honored even when separated from its declaration
			// by a blank line. Such a floating comment lives only in file.Comments, not FuncDecl.Doc, so
			// scan the complete file comment set before walking declarations. Keep function directives
			// symbol-precise for reachable scoping; anything we cannot classify as a same-file top-level
			// function fails open through pkg.init rather than risking a false suppressing negative.
			linknameSymbols, linknameInit := fileLinknameBlindSymbols(file, pkg.PkgPath)
			for _, id := range linknameSymbols {
				out["go:linkname"][id] = true
			}
			if linknameInit {
				out["go:linkname"][pkg.PkgPath+".init"] = true
			}

			unsafeNames, unsafeDot, cgoNames, cgoDot := opaqueImportNames(file)
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					id := astFuncNodeID(pkg.PkgPath, d)
					if id == "" {
						continue
					}
					if hasDirective(d.Doc, "//go:linkname") {
						out["go:linkname"][id] = true
					}
					if d.Body == nil && hasAssembly {
						out["assembly"][id] = true
					}
					if d.Body == nil {
						continue
					}
					usesUnsafe, usesCgo := nodeUsesOpaqueImport(d.Body, unsafeNames, unsafeDot, cgoNames, cgoDot)
					if usesUnsafe {
						out["unsafe"][id] = true
					}
					if usesCgo {
						out["cgo"][id] = true
					}
				case *ast.GenDecl:
					// Package-level initializers execute from the synthesized pkg.init. A linknamed variable or
					// unsafe/cgo initializer can therefore hide control/data flow even when no source func body
					// contains the construct.
					initID := pkg.PkgPath + ".init"
					if hasDirective(d.Doc, "//go:linkname") || genDeclHasDirective(d, "//go:linkname") {
						out["go:linkname"][initID] = true
					}
					// unsafeDot is safe to inspect precisely using unsafeDotIdentifiers. cgo's pseudo-package
					// has no stable identifier catalog here, so package-scope selector uses are recognized by
					// cgoNames while an impossible/unsupported dot-import form is not guessed.
					usesUnsafe, usesCgo := nodeUsesOpaqueImport(d, unsafeNames, unsafeDot, cgoNames, false)
					if usesUnsafe {
						out["unsafe"][initID] = true
					}
					if usesCgo {
						out["cgo"][initID] = true
					}
				}
			}
		}
	}
	return out, nil
}

func ignoredFileSet(pkg *packages.Package) map[string]bool {
	out := map[string]bool{}
	if pkg == nil {
		return out
	}
	for _, name := range pkg.IgnoredFiles {
		out[filepath.Clean(name)] = true
	}
	return out
}

func packageHasAssembly(pkg *packages.Package, ignored map[string]bool) bool {
	for _, name := range pkg.OtherFiles {
		if ignored[filepath.Clean(name)] {
			continue
		}
		if strings.EqualFold(filepath.Ext(name), ".s") {
			return true
		}
	}
	return false
}

func opaqueImportNames(file *ast.File) (unsafeNames map[string]bool, unsafeDot bool, cgoNames map[string]bool, cgoDot bool) {
	unsafeNames = map[string]bool{}
	cgoNames = map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch path {
		case "unsafe":
			switch name {
			case ".":
				unsafeDot = true
			case "_":
				// Blank importing unsafe is commonly required solely to enable //go:linkname; it does not by
				// itself make a function an unsafe blind surface.
			default:
				if name == "" {
					name = "unsafe"
				}
				unsafeNames[name] = true
			}
		case "C":
			switch name {
			case ".":
				cgoDot = true
			case "_":
			default:
				if name == "" {
					name = "C"
				}
				cgoNames[name] = true
			}
		}
	}
	return unsafeNames, unsafeDot, cgoNames, cgoDot
}

func nodeUsesOpaqueImport(node ast.Node, unsafeNames map[string]bool, unsafeDot bool, cgoNames map[string]bool, cgoDot bool) (usesUnsafe, usesCgo bool) {
	// cgo is a compiler-generated pseudo-package, so a dot import cannot be attributed by a stable list of
	// identifiers; fail open for a function body in that unsupported form. For unsafe, the exported surface is
	// closed and known, so a dot import is matched by its bare identifier instead of tainting every function in
	// the file (which would needlessly disable suppressions for dead/unrelated functions).
	usesCgo = cgoDot
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && unsafeDot && unsafeDotIdentifiers[ident.Name] {
			usesUnsafe = true
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !(usesUnsafe && usesCgo)
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return !(usesUnsafe && usesCgo)
		}
		if unsafeNames[ident.Name] {
			usesUnsafe = true
		}
		if cgoNames[ident.Name] {
			usesCgo = true
		}
		return !(usesUnsafe && usesCgo)
	})
	return usesUnsafe, usesCgo
}

// fileLinknameBlindSymbols finds every compiler directive in file.Comments, including directives
// detached from their declarations by blank lines. A same-file top-level function is mapped to its exact
// call-graph symbol so dead linknamed helpers do not globally poison suppression. For package variables,
// methods, cross-file declarations, or any other shape we cannot prove to be that function, fail open via
// pkg.init: init is always a reachability root, so an opaque linkname can never be missed by a negative proof.
func fileLinknameBlindSymbols(file *ast.File, pkgPath string) (symbols []string, packageInit bool) {
	if file == nil || pkgPath == "" {
		return nil, false
	}
	topLevelFuncs := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name != nil {
			topLevelFuncs[fn.Name.Name] = true
		}
	}
	seen := map[string]bool{}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			fields := strings.Fields(strings.TrimSpace(comment.Text))
			if len(fields) < 2 || fields[0] != "//go:linkname" {
				continue
			}
			local := fields[1]
			if !topLevelFuncs[local] {
				packageInit = true
				continue
			}
			id := pkgPath + "." + local
			if !seen[id] {
				symbols = append(symbols, id)
				seen[id] = true
			}
		}
	}
	return symbols, packageInit
}

func genDeclHasDirective(decl *ast.GenDecl, prefix string) bool {
	if decl == nil {
		return false
	}
	for _, spec := range decl.Specs {
		if v, ok := spec.(*ast.ValueSpec); ok && (hasDirective(v.Doc, prefix) || hasDirective(v.Comment, prefix)) {
			return true
		}
	}
	return false
}

func hasDirective(group *ast.CommentGroup, prefix string) bool {
	if group == nil {
		return false
	}
	for _, comment := range group.List {
		text := strings.TrimSpace(comment.Text)
		if text == prefix || strings.HasPrefix(text, prefix+" ") || strings.HasPrefix(text, prefix+"\t") {
			return true
		}
	}
	return false
}

func astFuncNodeID(pkgPath string, fn *ast.FuncDecl) string {
	if fn == nil || fn.Name == nil || pkgPath == "" {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return pkgPath + "." + fn.Name.Name
	}
	recv := astReceiverName(fn.Recv.List[0].Type)
	if recv == "" {
		return ""
	}
	return pkgPath + "." + recv + "." + fn.Name.Name
}

func astReceiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return astReceiverName(t.X)
	case *ast.IndexExpr:
		return astReceiverName(t.X)
	case *ast.IndexListExpr:
		return astReceiverName(t.X)
	case *ast.ParenExpr:
		return astReceiverName(t.X)
	default:
		return ""
	}
}

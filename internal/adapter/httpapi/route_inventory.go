package httpapi

// Route inventory used by the tests that guard the authorization chokepoint. It lives in the
// non-test build so the parser and the router are compiled together: a change to how routes are
// registered is a compile-time concern here, not a silently-stale regex.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// RouteRegistration is one route as the router actually registers it.
type RouteRegistration struct {
	// Pattern is the ServeMux pattern, for example "GET /api/v1/engagements/{id}".
	Pattern string
	// Guard names the outermost wrapper applied to the handler, for example "rt.authz". Empty
	// when the handler is passed through unwrapped.
	Guard string
	// Permission names the permission constant the rt.authz guard requires, for example
	// "PermManageIntegrations". Empty when the guard is not rt.authz or its first argument is not a
	// selector such as userdom.PermView.
	Permission string
	// Recovery names the identity-recovery action an rt.recoverable guard declares, for example
	// "RecoveryLogout". Empty otherwise.
	Recovery string
	// PlatformOnly is true when rt.requirePlatformAdmin appears anywhere in the handler chain.
	PlatformOnly bool
	// Line is the line in the source file the registration sits on.
	Line int
	// Mux is the receiver the route is registered on as written, for example "mux" or "top", or
	// "http.DefaultServeMux" for the http package's own Handle and HandleFunc.
	Mux string
	// Func is the function the registration sits in, "Router.Handler" for a method.
	Func string
	// Handler is the handler argument as go/printer prints it, so a test can tie an exception to
	// the one handler that justifies it.
	Handler string
	// Table is the function a registration loop ranges over when the pattern is a row of that
	// table (see PatternSource). Empty for a pattern written in place.
	Table string
}

// PatternSource supplies the value of a route pattern the parser cannot read from the source text,
// read by the caller at run time from the same declaration the router uses. Two forms occur: a loop
// `for _, route := range fleetAgentPlaneRoutes()` that registers route.pattern for every row, where
// Range is "fleetAgentPlaneRoutes" and Expr is "route.pattern", and a constant expression such
// as "POST " + EgressGrantPath, where Range is empty. Expr is the pattern argument as go/printer
// prints it. A non-literal pattern with no matching source stays an error, and so does a source that
// matches no registration or supplies no patterns, so a supplied table cannot quietly go stale.
type PatternSource struct {
	Range    string
	Expr     string
	Patterns []string
}

// RouteClass is the one authentication and authorization classification of a human route.
type RouteClass string

const (
	// RoutePublic carries no human authentication.
	RoutePublic RouteClass = "public"
	// RouteAuthenticated needs an authenticated human principal but no role.
	RouteAuthenticated RouteClass = "authenticated"
	// RoutePermission needs a role permission (see Permission).
	RoutePermission RouteClass = "permission"
	// RoutePlatformOnly needs the permission and the bootstrap principal.
	RoutePlatformOnly RouteClass = "platform_only"
	// RouteUnclassified is a registration the inventory cannot place. It is always a failure.
	RouteUnclassified RouteClass = "unclassified"
)

// routeGuards are the human authorization guards and whether they carry a permission argument.
// Every one of them calls authz.Decide.
var routeGuards = map[string]bool{
	"rt.authz":               true,
	"rt.recoverable":         true,
	"rt.ownershipAuthorized": true,
	"rt.authenticated":       false,
}

// Class returns the route's single classification. A route with no guard is public only if it is
// listed in public; anything else unguarded, or guarded by an unknown wrapper, is unclassified.
func (r RouteRegistration) Class(public map[string]bool) RouteClass {
	takesPermission, guarded := routeGuards[r.Guard]
	switch {
	case r.Guard == "" && public[r.Pattern]:
		return RoutePublic
	case !guarded:
		return RouteUnclassified
	case r.PlatformOnly:
		if r.Permission == "" {
			return RouteUnclassified
		}
		return RoutePlatformOnly
	case takesPermission && r.Permission != "":
		return RoutePermission
	case r.Guard == "rt.authenticated" || r.Guard == "rt.recoverable":
		return RouteAuthenticated
	}
	return RouteUnclassified
}

// ParseRouteRegistrations reads a router source file and returns every route it registers.
//
// It walks the syntax tree rather than matching text, so a registration cannot hide from it by
// spanning several lines, by being written as mux.Handle, or by mentioning the guard's name inside
// a comment or an unrelated argument.
//
// Every Handle and HandleFunc call is a registration, whatever its receiver is called. The receiver
// must be declared in the file as an http.ServeMux (a parameter or variable of that type, or a
// variable made by http.NewServeMux, new, a composite literal or a copy of another such variable),
// or be the http package itself, which registers on the default mux. The parser has no type
// checker, so a receiver whose declaration it cannot see, such as a struct field, is an error. So is
// the registration method taken as a value, and a pattern that is not a plain string literal unless
// sources supplies its value. An inventory that quietly skips what it cannot read is worse than no
// inventory, because it reads as a pass.
func ParseRouteRegistrations(filename string, sources ...PatternSource) ([]RouteRegistration, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	p := &registrationParser{
		fset: fset, filename: filename, httpName: importName(file, "net/http"),
		fileDecls: map[string][]declaration{}, funcDecls: map[*ast.FuncDecl]map[string][]declaration{},
	}
	for _, decl := range file.Decls {
		if gen, ok := decl.(*ast.GenDecl); ok {
			collectSpecs(gen, p.fileDecls)
		}
	}
	used := make([]bool, len(sources))
	var routes []RouteRegistration
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		call, ok := stack[len(stack)-2].(*ast.CallExpr)
		if !ok || call.Fun != sel {
			p.problem(sel.Pos(), "%s is used as a value; the inventory reads only direct registration calls", p.render(sel))
			return true
		}
		fn := enclosingFunc(stack)
		mux, receiverProblem := p.receiver(sel.X, fn)
		if receiverProblem != "" {
			p.problem(call.Pos(), "%s", receiverProblem)
		}
		if len(call.Args) != 2 {
			p.problem(call.Pos(), "%s takes %d arguments; the inventory models exactly two", p.render(sel), len(call.Args))
			return true
		}
		patterns, table, ok := p.patterns(call.Args[0], stack, sources, used)
		if !ok || receiverProblem != "" {
			return true
		}
		handler := call.Args[1]
		for _, pattern := range patterns {
			routes = append(routes, RouteRegistration{
				Pattern: pattern, Guard: outermostCallee(handler), Permission: authzPermission(handler),
				Recovery: recoveryAction(handler), PlatformOnly: mentionsCallee(handler, "rt.requirePlatformAdmin"),
				Line: fset.Position(call.Pos()).Line, Mux: mux, Func: funcName(fn), Handler: p.render(handler), Table: table,
			})
		}
		return true
	})
	for i, source := range sources {
		if used[i] {
			continue
		}
		described := source.Expr
		if source.Range != "" {
			described += " ranging over " + source.Range + "()"
		}
		p.problems = append(p.problems, fmt.Sprintf("%s: the pattern source for %s matches no registration; a stale source would describe a loop that is gone", filename, described))
	}

	if len(p.problems) > 0 {
		sort.Strings(p.problems)
		return nil, fmt.Errorf("route registrations the inventory cannot read:\n  %s", strings.Join(p.problems, "\n  "))
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Line < routes[j].Line })
	return routes, nil
}

// registrationParser holds what one file declares, so a receiver can be checked against its
// declaration rather than trusted by name.
type registrationParser struct {
	fset      *token.FileSet
	filename  string
	httpName  string // the name net/http is imported under, "" when it is not imported
	fileDecls map[string][]declaration
	funcDecls map[*ast.FuncDecl]map[string][]declaration
	problems  []string
}

// declaration is what a name is declared with: a type, an initial value, or neither (a range
// variable or one side of a multi-value assignment), which the parser cannot type.
type declaration struct {
	typ   ast.Expr
	value ast.Expr
}

func (p *registrationParser) problem(pos token.Pos, format string, args ...any) {
	p.problems = append(p.problems, fmt.Sprintf("%s:%d: ", p.filename, p.fset.Position(pos).Line)+fmt.Sprintf(format, args...))
}

func (p *registrationParser) render(expr ast.Expr) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, p.fset, expr); err != nil {
		return fmt.Sprintf("%T", expr)
	}
	return b.String()
}

// receiver names the mux a registration is made on, or says why the parser cannot tell the
// receiver is an http.ServeMux.
func (p *registrationParser) receiver(expr ast.Expr, fn *ast.FuncDecl) (string, string) {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return "", fmt.Sprintf("cannot tell whether receiver %s is an http.ServeMux; register on a variable declared as one in this file", p.render(expr))
	}
	decls, declared := p.lookup(ident.Name, fn)
	if !declared {
		if p.httpName != "" && ident.Name == p.httpName {
			return "http.DefaultServeMux", ""
		}
		return "", fmt.Sprintf("receiver %s has no declaration in this file, so the inventory cannot tell it is an http.ServeMux", ident.Name)
	}
	if !p.allMux(decls, fn, 0) {
		return "", fmt.Sprintf("receiver %s is not declared as an http.ServeMux in this file", ident.Name)
	}
	return ident.Name, ""
}

// lookup returns every declaration of name in fn, or at file level when fn declares none. Scopes
// inside fn are not told apart: a name declared both as a mux and as something else is refused.
func (p *registrationParser) lookup(name string, fn *ast.FuncDecl) ([]declaration, bool) {
	if decls := p.localDecls(fn)[name]; len(decls) > 0 {
		return decls, true
	}
	decls := p.fileDecls[name]
	return decls, len(decls) > 0
}

func (p *registrationParser) localDecls(fn *ast.FuncDecl) map[string][]declaration {
	if fn == nil {
		return nil
	}
	if decls, ok := p.funcDecls[fn]; ok {
		return decls
	}
	decls := map[string][]declaration{}
	add := func(name *ast.Ident, d declaration) {
		if name.Name != "_" {
			decls[name.Name] = append(decls[name.Name], d)
		}
	}
	addFields := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			for _, name := range field.Names {
				add(name, declaration{typ: field.Type})
			}
		}
	}
	addFields(fn.Recv)
	ast.Inspect(fn, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncType:
			addFields(n.Params)
			addFields(n.Results)
		case *ast.GenDecl:
			collectSpecs(n, decls)
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				return true
			}
			for i, lhs := range n.Lhs {
				if name, ok := lhs.(*ast.Ident); ok {
					d := declaration{}
					if len(n.Lhs) == len(n.Rhs) {
						d.value = n.Rhs[i]
					}
					add(name, d)
				}
			}
		case *ast.RangeStmt:
			if n.Tok != token.DEFINE {
				return true
			}
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if name, ok := e.(*ast.Ident); ok {
					add(name, declaration{})
				}
			}
		}
		return true
	})
	p.funcDecls[fn] = decls
	return decls
}

// collectSpecs records the names a var or const declaration introduces.
func collectSpecs(gen *ast.GenDecl, decls map[string][]declaration) {
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range value.Names {
			if name.Name == "_" {
				continue
			}
			d := declaration{typ: value.Type}
			if value.Type == nil && len(value.Values) == len(value.Names) {
				d.value = value.Values[i]
			}
			decls[name.Name] = append(decls[name.Name], d)
		}
	}
}

func (p *registrationParser) allMux(decls []declaration, fn *ast.FuncDecl, depth int) bool {
	for _, d := range decls {
		switch {
		case d.typ != nil && p.isMuxType(d.typ):
		case d.typ == nil && d.value != nil && p.isMuxValue(d.value, fn, depth):
		default:
			return false
		}
	}
	return len(decls) > 0
}

// isMuxType reports whether expr is http.ServeMux or *http.ServeMux.
func (p *registrationParser) isMuxType(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = ast.Unparen(star.X)
	}
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "ServeMux" && p.isHTTP(sel.X)
}

// isMuxValue reports whether expr evaluates to a ServeMux: http.NewServeMux(), new(http.ServeMux),
// &http.ServeMux{}, http.ServeMux{} or another variable that is one.
func (p *registrationParser) isMuxValue(expr ast.Expr, fn *ast.FuncDecl, depth int) bool {
	switch v := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name == "NewServeMux" && p.isHTTP(sel.X) && len(v.Args) == 0
		}
		if ident, ok := v.Fun.(*ast.Ident); ok {
			return ident.Name == "new" && len(v.Args) == 1 && p.isMuxType(v.Args[0])
		}
	case *ast.UnaryExpr:
		if lit, ok := v.X.(*ast.CompositeLit); ok && v.Op == token.AND {
			return p.isMuxType(lit.Type)
		}
	case *ast.CompositeLit:
		return p.isMuxType(v.Type)
	case *ast.Ident:
		// A copy of another variable is a mux when that variable is. The depth bound stops a
		// self-referencing declaration from recursing forever.
		if depth < 8 {
			decls, declared := p.lookup(v.Name, fn)
			return declared && p.allMux(decls, fn, depth+1)
		}
	}
	return false
}

func (p *registrationParser) isHTTP(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && p.httpName != "" && ident.Name == p.httpName
}

// patterns returns the patterns a registration's first argument stands for: the literal itself, or
// the rows of the supplied source that matches it, and the table a loop ranges over.
func (p *registrationParser) patterns(expr ast.Expr, stack []ast.Node, sources []PatternSource, used []bool) ([]string, string, bool) {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			p.problem(expr.Pos(), "route pattern %s is not a valid string literal", lit.Value)
			return nil, "", false
		}
		return []string{pattern}, "", true
	}
	text := p.render(expr)
	table := rangedTable(expr, stack)
	for i, source := range sources {
		if source.Range != table || source.Expr != text {
			continue
		}
		used[i] = true
		if len(source.Patterns) == 0 {
			p.problem(expr.Pos(), "route pattern %s: its source supplies no patterns, which would read as a loop that registers nothing", text)
			return nil, "", false
		}
		return source.Patterns, table, true
	}
	if table != "" {
		p.problem(expr.Pos(), "route pattern %s is not a string literal; it ranges over %s(), and no rows were supplied for that table", text, table)
	} else {
		p.problem(expr.Pos(), "route pattern %s is not a string literal; the inventory cannot read it", text)
	}
	return nil, "", false
}

// rangedTable names the function a pattern's loop ranges over, for a pattern such as route.pattern
// or mount whose variable is declared by `for _, route := range table()`. Empty otherwise.
func rangedTable(expr ast.Expr, stack []ast.Node) string {
	root := expr
	for {
		sel, ok := root.(*ast.SelectorExpr)
		if !ok {
			break
		}
		root = sel.X
	}
	name, ok := root.(*ast.Ident)
	if !ok {
		return ""
	}
	for i := len(stack) - 1; i >= 0; i-- {
		loop, ok := stack[i].(*ast.RangeStmt)
		if !ok || loop.Tok != token.DEFINE {
			continue
		}
		value, ok := loop.Value.(*ast.Ident)
		if !ok || value.Name != name.Name {
			continue
		}
		call, ok := loop.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return ""
		}
		if fun, ok := call.Fun.(*ast.Ident); ok {
			return fun.Name
		}
		return ""
	}
	return ""
}

func enclosingFunc(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if fn, ok := stack[i].(*ast.FuncDecl); ok {
			return fn
		}
	}
	return nil
}

// funcName names a function as "Func" or, for a method, "Type.Method".
func funcName(fn *ast.FuncDecl) string {
	if fn == nil {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	switch generic := recv.(type) {
	case *ast.IndexExpr:
		recv = generic.X
	case *ast.IndexListExpr:
		recv = generic.X
	}
	if ident, ok := recv.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// importName returns the name a file imports path under, or "" when it does not import it by name.
func importName(file *ast.File, path string) string {
	for _, spec := range file.Imports {
		if imported, err := strconv.Unquote(spec.Path.Value); err != nil || imported != path {
			continue
		}
		if spec.Name == nil {
			return path[strings.LastIndex(path, "/")+1:]
		}
		if spec.Name.Name == "_" || spec.Name.Name == "." {
			return ""
		}
		return spec.Name.Name
	}
	return ""
}

// authzPermission returns the permission constant passed to an outermost permission guard
// (rt.authz, rt.recoverable or rt.ownershipAuthorized). An empty-string permission reports "".
func authzPermission(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !routeGuards[outermostCallee(expr)] || len(call.Args) == 0 {
		return ""
	}
	if sel, ok := call.Args[0].(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// recoveryAction returns the recovery action constant an outermost rt.recoverable guard names.
func recoveryAction(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || outermostCallee(expr) != "rt.recoverable" || len(call.Args) < 2 {
		return ""
	}
	if sel, ok := call.Args[1].(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// mentionsCallee reports whether callee is applied anywhere inside a handler expression.
func mentionsCallee(expr ast.Expr, callee string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && outermostCallee(e) == callee {
			found = true
		}
		return !found
	})
	return found
}

// outermostCallee names the function applied to a handler expression, so a route registered as
// rt.authz(perm, rt.withEngTenant(rt.handler)) reports "rt.authz". A bare handler reports "".
func outermostCallee(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

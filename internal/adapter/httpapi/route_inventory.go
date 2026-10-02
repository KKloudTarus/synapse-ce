package httpapi

// Route inventory used by the tests that guard the authorization chokepoint. It lives in the
// non-test build so the parser and the router are compiled together: a change to how routes are
// registered is a compile-time concern here, not a silently-stale regex.

import (
	"fmt"
	"go/ast"
	"go/parser"
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
// a comment or an unrelated argument. A registration whose pattern is not a plain string literal,
// or that uses a form this parser does not model, is returned as an error: an inventory that
// quietly skips what it cannot read is worse than no inventory, because it reads as a pass.
func ParseRouteRegistrations(filename string) ([]RouteRegistration, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	var routes []RouteRegistration
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := sel.X.(*ast.Ident)
		if !ok || receiver.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if len(call.Args) != 2 {
			problems = append(problems, fmt.Sprintf("%s:%d: mux.%s takes %d arguments; the inventory models exactly two", filename, line, sel.Sel.Name, len(call.Args)))
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			problems = append(problems, fmt.Sprintf("%s:%d: route pattern is not a string literal; the inventory cannot read it", filename, line))
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s:%d: route pattern %s is not a valid string literal", filename, line, lit.Value))
			return true
		}
		routes = append(routes, RouteRegistration{
			Pattern: pattern, Guard: outermostCallee(call.Args[1]), Permission: authzPermission(call.Args[1]),
			Recovery: recoveryAction(call.Args[1]), PlatformOnly: mentionsCallee(call.Args[1], "rt.requirePlatformAdmin"), Line: line,
		})
		return true
	})

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("route registrations the inventory cannot read:\n  %s", strings.Join(problems, "\n  "))
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Line < routes[j].Line })
	return routes, nil
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

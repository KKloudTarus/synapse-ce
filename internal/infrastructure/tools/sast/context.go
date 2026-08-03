package sast

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const contextWindow = 120

var routePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:app|router|route)\.(get|post|put|patch|delete|all)\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`\b[A-Za-z_$][\w$]*\.(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)@(?:app|router|blueprint)\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)@(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:["']([^"']*)["'])?`),
	regexp.MustCompile(`(?i)@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(\s*)?(?:path\s*=\s*)?["']([^"']+)["']`),
	regexp.MustCompile(`(?i)^\s*@(Query|Mutation|Subscription)\s*\(\s*(?:["']([^"']*)["'])?`),
	regexp.MustCompile(`(?i)\bhttp\.HandleFunc\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']`),
}

var controllerPrefixPattern = regexp.MustCompile(`(?i)@Controller\s*\(\s*["']([^"']*)["']\s*\)`)
var decoratedParamPattern = regexp.MustCompile(`(?i)@(Query|Param|Body|Args|Arg|Ctx|Context)\s*(?:\([^)]*\))?\s*([A-Za-z_$][\w$]*)`)
var pythonFunctionParamsPattern = regexp.MustCompile(`(?i)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(([^)]*)\)`)
var springParamPattern = regexp.MustCompile(`(?i)@(RequestParam|PathVariable|RequestBody|RequestPart)\b(?:\([^)]*\))?\s+(?:final\s+)?(?:[\w<>\[\].?,]+\s+)+([A-Za-z_$][\w$]*)`)

type routeContext struct {
	Route      string
	Evidence   string
	Line       int
	Middleware string
}

type projectContext struct {
	Files     []projectFile
	Summaries map[string]functionSummary
}

type projectFile struct {
	Rel   string
	Lines []string
}

type frameworkSourceParam struct {
	Name     string
	Label    string
	Evidence string
}

var sourceAssignmentPattern = regexp.MustCompile(`(?i)\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::=|=)\s*.*(req\.(body|query|params)|request\.(args|form|data|GET|POST)|r\.URL\.Query|FormValue|PostFormValue|c\.(Query|Param|PostForm)|\$_(GET|POST|REQUEST)|params\[|args\.|input\.|context\.(args|params)|ctx\.(args|params)|url\b|filename\b|originalname\b)`)

var assignmentPattern = regexp.MustCompile(`(?i)\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::=|=)\s*(.+)$`)
var destructuringAssignmentPattern = regexp.MustCompile(`(?i)\b(?:const|let|var)\s*\{(.+)}\s*=\s*(.+)$`)
var memberAssignmentPattern = regexp.MustCompile(`(?i)\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[['"][^'"]+['"]\]))\s*(?::=|=)\s*(.+)$`)

var functionHeaderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:export\s+)?async\s+function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)`),
	regexp.MustCompile(`(?i)\b(?:export\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)`),
	regexp.MustCompile(`(?i)\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(\s*([A-Za-z_$][\w$]*)`),
	regexp.MustCompile(`(?i)\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>`),
}

var simpleCallPattern = regexp.MustCompile(`(?i)\b([A-Za-z_$][\w$]*)\s*\(([^)]*)\)`)

var sourceCueTokens = []string{
	"req.body", "req.query", "req.params", "request.args", "request.form", "request.data",
	"request.get", "request.post", "$_get", "$_post", "$_request", "r.url.query", "formvalue", "postformvalue",
	"c.query", "c.param", "c.postform", "@query", "@param", "@body", "@args", "args.", "input.",
	"context.args", "context.params", "ctx.args", "ctx.params", "originalname", "filename", "params[", "localstorage", "url",
}

var sanitizerTokens = []string{
	"sanitize", "escape", "html.escape", "escapehtml", "dompurify", "validator.escape",
	"encodeuricomponent", "path.normalize", "filepath.clean", "safejoin", "realpath",
	"allowlist", "whitelist", "allowedhost", "isprivateip", "zod.", "joi.", "yup.",
	"parseint", "number(", "uuid.validate", "isuuid",
}

func buildProjectContext(ctx context.Context, files []sourceFile) (projectContext, error) {
	project := projectContext{
		Files:     make([]projectFile, 0, len(files)),
		Summaries: map[string]functionSummary{},
	}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return projectContext{}, err
		}
		lines := sourceContextLines(f.Lines)
		project.Files = append(project.Files, projectFile{Rel: f.Rel, Lines: lines})
		for name, summary := range summarizeLocalFunctions(lines, 1, len(lines)) {
			summary.File = f.Rel
			project.Summaries[name] = summary
		}
	}
	return project, nil
}

func sourceContextLines(lines []string) []string {
	for i, line := range lines {
		if len(line) > maxLineBytes {
			if lines == nil {
				return nil
			}
			out := append([]string(nil), lines...)
			for j := i; j < len(out); j++ {
				if len(out[j]) > maxLineBytes {
					out[j] = ""
				}
			}
			return out
		}
	}
	return lines
}

func enrichAppSecContext(h *ports.SASTRawFinding, lines []string, line int, rel string, project projectContext) {
	start := max(1, line-contextWindow)
	end := min(len(lines), line+contextWindow)
	before := lines[start-1 : line]
	around := lines[start-1 : end]

	routeCtx := nearestRoute(before, start)
	route := routeCtx.Route
	authScope, role, authEvidence, routeMiddleware := inferAuthScope(around, start, routeCtx)
	source, sourceEvidence := inferSource(h.RuleID, h.CWE, around, start)
	sink := inferSink(h.RuleID, h.CWE)
	counter := counterEvidenceSummary(h.RuleID, h.CWE, around)
	flowEvidence, flowConfidence := dataFlowEvidence(around, start, line, source, h.CWE, rel, project)
	if source == "unknown" && (flowConfidence == "cross-file" || flowConfidence == "interprocedural") && strings.Contains(flowEvidence, "request/source") {
		source = "HTTP request input via caller"
		sourceEvidence = "cross-file caller source cue"
	}
	if route == "unknown" && flowConfidence == "cross-file" {
		if callerRoute := routeFromEvidence(flowEvidence); callerRoute != "" {
			route = callerRoute
			routeCtx.Route = callerRoute
			routeCtx.Evidence = "cross-file caller route " + callerRoute
			authScope = "unauthenticated-or-public"
			authEvidence = "cross-file caller route; no auth middleware cue found in bounded caller context"
		}
	}

	h.OWASP2025 = owaspBucket(h.CWE)
	h.EntryPoint = entryPointSummary(route, before)
	h.Source = source
	h.SourceEvidence = sourceEvidence
	h.Sink = sink
	h.SinkEvidence = fmt.Sprintf("line %d: %s", line, sink)
	h.ControlEvidence = routeCtx.Evidence
	h.RouteMiddleware = routeMiddleware
	h.AuthEvidence = authEvidence
	h.Exposure = exposureSummary(authScope, route)
	h.TrustBoundary = trustBoundarySummary(authScope, route, source, sink)
	h.Impact = impactSummary(h.CWE, authScope)
	h.Route = route
	h.AuthScope = authScope
	h.RoleCheck = role
	h.DataFlow = dataflowSummary(source, sink, route)
	h.DataFlowEvidence = flowEvidence
	h.DataFlowConfidence = flowConfidence
	h.Preconditions = preconditionsSummary(authScope, route, source, h.CWE)
	ctx := ruleContext{
		RuleID:         h.RuleID,
		CWE:            h.CWE,
		Route:          route,
		Source:         source,
		Counter:        counter,
		FlowConfidence: flowConfidence,
		Rel:            rel,
		Lines:          around,
	}
	if reason := staticFalsePositiveReason(ctx); reason != "" {
		counter = "static false-positive counter-pattern: " + reason
		ctx.Counter = counter
	}
	h.CounterEvidence = counter
	h.ValidationRubric = validationRubric(route, source, sink, authScope, h.Exposure, counter, flowConfidence)
	h.ValidationMethod = "static-code-understanding"
	h.ValidationDisposition = validationDisposition(ctx)
	if h.ValidationDisposition == "false-positive-static" {
		h.Exploitability = "not exploitable in static triage: " + strings.TrimPrefix(counter, "static false-positive counter-pattern: ")
		h.AttackPath = "No attack path: deterministic framework/context counter-pattern closes this as a static false positive."
		h.Confidence = "low"
		h.SeverityRationale = "Closed as a static false positive by deterministic counter-pattern evidence; do not promote unless a human reopens it with new evidence."
	} else {
		h.Exploitability = exploitabilitySummary(authScope, route, source, sink, flowConfidence)
		h.AttackPath = attackPathSummary(h.CWE, authScope, route, source, sink)
		h.Confidence = confidenceSummary(route, source, sink, authScope, counter, flowConfidence)
		h.SeverityRationale = severityRationale(h.CWE, string(h.Severity), authScope, source, route, counter, flowConfidence)
	}
}

func nearestRoute(lines []string, firstLine int) routeContext {
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if commentOnlyLine(line) {
			continue
		}
		for _, re := range routePatterns {
			if m := re.FindStringSubmatch(line); len(m) > 0 {
				method, path := routeMethodPath(m)
				if method != "" {
					r := routeLabel(method, path, lines[:i+1])
					return routeContext{
						Route:      r,
						Evidence:   fmt.Sprintf("line %d: route %s", firstLine+i, r),
						Line:       firstLine + i,
						Middleware: routeLevelMiddlewareEvidence(line, firstLine+i),
					}
				}
				if path != "" {
					r := normalizeRoutePath(path)
					return routeContext{
						Route:      r,
						Evidence:   fmt.Sprintf("line %d: route %s", firstLine+i, r),
						Line:       firstLine + i,
						Middleware: routeLevelMiddlewareEvidence(line, firstLine+i),
					}
				}
			}
		}
	}
	return routeContext{Route: "unknown", Evidence: "not identified in bounded local context"}
}

func routeMethodPath(m []string) (method, path string) {
	if len(m) == 2 {
		return "", m[1]
	}
	if len(m) >= 3 {
		return m[1], m[2]
	}
	return "", ""
}

func routeLabel(method, path string, prior []string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = normalizeRoutePath(path)
	if method == "QUERY" || method == "MUTATION" || method == "SUBSCRIPTION" {
		if path == "/" {
			return "GRAPHQL " + method
		}
		return "GRAPHQL " + method + " " + strings.TrimPrefix(path, "/")
	}
	prefix := nearestControllerPrefix(prior)
	if prefix != "" {
		path = joinRoutePath(prefix, path)
	}
	return method + " " + path
}

func nearestControllerPrefix(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if m := controllerPrefixPattern.FindStringSubmatch(strings.TrimSpace(lines[i])); len(m) >= 2 {
			return normalizeRoutePath(m[1])
		}
	}
	return ""
}

func normalizeRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func joinRoutePath(prefix, path string) string {
	prefix = strings.TrimSuffix(normalizeRoutePath(prefix), "/")
	path = normalizeRoutePath(path)
	if path == "/" {
		return prefix
	}
	return prefix + path
}

func inferAuthScope(lines []string, firstLine int, route routeContext) (scope, role, authEvidence, middleware string) {
	if route.Middleware != "" {
		scope, role = authScopeForMiddleware(route.Middleware)
		return scope, role, route.Middleware, route.Middleware
	}
	if inherited := inheritedMiddlewareEvidence(lines, firstLine, route.Line); inherited != "" {
		scope, role = authScopeForMiddleware(inherited)
		return scope, role, inherited, inherited
	}
	text := strings.ToLower(strings.Join(lines, "\n"))
	switch {
	case strings.Contains(text, "requireadmin") || strings.Contains(text, "adminonly") ||
		strings.Contains(text, "role === 'admin'") || strings.Contains(text, `role == "admin"`) ||
		strings.Contains(text, "hasrole(\"admin") || strings.Contains(text, "has_role(\"admin"):
		return "role-scoped", "admin", "bounded context contains admin/role authorization cue", ""
	case strings.Contains(text, "authorize(") || strings.Contains(text, "requirepermission") ||
		strings.Contains(text, "permission") || strings.Contains(text, "can("):
		return "role-scoped", nearestCue(lines, []string{"authorize", "permission", "can("}), "bounded context contains permission/authorization cue", ""
	case strings.Contains(text, "requireauth") || strings.Contains(text, "authenticate") ||
		strings.Contains(text, "passport.authenticate") || strings.Contains(text, "jwtauth") ||
		strings.Contains(text, "login_required") || strings.Contains(text, "@preauthorize") ||
		strings.Contains(text, "is_authenticated") || strings.Contains(text, "authmiddleware"):
		return "authenticated", nearestCue(lines, []string{"requireAuth", "authenticate", "login_required", "PreAuthorize", "auth"}), "bounded context contains authentication middleware/check cue", ""
	case route.Route != "unknown":
		return "unauthenticated-or-public", "", "no auth middleware cue found in bounded route context", ""
	default:
		return "unknown", "", "authorization context not identified in bounded local context", ""
	}
}

func routeLevelMiddlewareEvidence(line string, lineNo int) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "requireadmin") || strings.Contains(lower, "adminonly") ||
		strings.Contains(lower, "requirepermission") || strings.Contains(lower, "authorize(") ||
		strings.Contains(lower, "permission") || strings.Contains(lower, "can("):
		return fmt.Sprintf("line %d: route-level role/permission middleware cue", lineNo)
	case strings.Contains(lower, "requireauth") || strings.Contains(lower, "authenticate") ||
		strings.Contains(lower, "passport.authenticate") || strings.Contains(lower, "jwtauth") ||
		strings.Contains(lower, "authmiddleware") || strings.Contains(lower, "login_required") ||
		strings.Contains(lower, "is_authenticated") || strings.Contains(lower, "@preauthorize"):
		return fmt.Sprintf("line %d: route-level authenticated middleware cue", lineNo)
	default:
		return ""
	}
}

func inheritedMiddlewareEvidence(lines []string, firstLine, routeLine int) string {
	for i := len(lines) - 1; i >= 0; i-- {
		lineNo := firstLine + i
		if routeLine > 0 && lineNo >= routeLine {
			continue
		}
		line := strings.TrimSpace(lines[i])
		if commentOnlyLine(line) {
			continue
		}
		lower := strings.ToLower(line)
		if !(strings.Contains(lower, ".use(") || strings.Contains(lower, "use ")) {
			continue
		}
		if strings.Contains(lower, "requireadmin") || strings.Contains(lower, "adminonly") ||
			strings.Contains(lower, "requirepermission") || strings.Contains(lower, "authorize(") ||
			strings.Contains(lower, "permission") || strings.Contains(lower, "can(") {
			return fmt.Sprintf("line %d: inherited role/permission middleware cue", lineNo)
		}
		if strings.Contains(lower, "requireauth") || strings.Contains(lower, "authenticate") ||
			strings.Contains(lower, "passport.authenticate") || strings.Contains(lower, "jwtauth") ||
			strings.Contains(lower, "authmiddleware") || strings.Contains(lower, "login_required") ||
			strings.Contains(lower, "is_authenticated") {
			return fmt.Sprintf("line %d: inherited authenticated middleware cue", lineNo)
		}
	}
	return ""
}

func authScopeForMiddleware(evidence string) (scope, role string) {
	lower := strings.ToLower(evidence)
	if strings.Contains(lower, "role/permission") {
		return "role-scoped", "middleware-protected"
	}
	return "authenticated", ""
}

func exposureSummary(authScope, route string) string {
	switch authScope {
	case "unauthenticated-or-public":
		return "public-or-unauthenticated application route"
	case "authenticated":
		return "authenticated application route"
	case "role-scoped":
		return "role-scoped application route"
	case "unknown":
		if route == "unknown" {
			return "unknown exposure; route not identified"
		}
	}
	return "unknown exposure; authorization context unresolved"
}

func nearestCue(lines []string, needles []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		lower := strings.ToLower(lines[i])
		for _, n := range needles {
			if strings.Contains(lower, strings.ToLower(n)) {
				return "bounded context authorization cue"
			}
		}
	}
	return ""
}

func inferSource(ruleID, cwe string, lines []string, firstLine int) (source, evidence string) {
	for i, raw := range lines {
		if label, ok := decoratedSourceLabel(raw); ok {
			return label, fmt.Sprintf("line %d: %s cue", firstLine+i, label)
		}
		if params := frameworkSourceParamsAt(lines, i, firstLine); len(params) > 0 {
			return params[0].Label, params[0].Evidence
		}
	}
	cues := []struct {
		token string
		label string
	}{
		{"req.body", "HTTP request body"},
		{"req.query", "HTTP query parameter"},
		{"req.params", "HTTP route parameter"},
		{"request.args", "HTTP query parameter"},
		{"request.form", "HTTP form body"},
		{"request.data", "HTTP request body"},
		{"request.get", "HTTP query parameter"},
		{"request.post", "HTTP form body"},
		{"$_get", "HTTP query parameter"},
		{"$_post", "HTTP form body"},
		{"$_request", "HTTP request parameter"},
		{"r.url.query", "HTTP query parameter"},
		{"formvalue", "HTTP form/query value"},
		{"postformvalue", "HTTP form body"},
		{"c.query", "HTTP form/query value"},
		{"c.param", "HTTP route parameter"},
		{"c.postform", "HTTP form body"},
		{"args.", "GraphQL/resolver argument"},
		{"input.", "GraphQL/API input object"},
		{"context.args", "GraphQL/resolver context argument"},
		{"ctx.args", "GraphQL/resolver context argument"},
		{"originalname", "multipart filename"},
		{"filename", "filename/path variable"},
		{"params[", "route/query parameter"},
		{"localstorage", "browser storage"},
		{"url", "URL variable"},
	}
	for i, raw := range lines {
		line := strings.ToLower(raw)
		for _, cue := range cues {
			if strings.Contains(line, cue.token) {
				return cue.label, fmt.Sprintf("line %d: %s cue", firstLine+i, cue.label)
			}
		}
	}
	switch cwe {
	case "CWE-798":
		return "source-code literal", "line-local credential/material literal"
	case "CWE-916", "CWE-327":
		return "password/crypto lifecycle", "line-local crypto/password lifecycle cue"
	case "CWE-79":
		return "stored or rendered user content", "bounded render/content cue"
	}
	if strings.Contains(ruleID, "idor") {
		return "object id parameter", "line-local object id selector cue"
	}
	return "unknown", "not identified in bounded local context"
}

func dataFlowEvidence(lines []string, firstLine, sinkLine int, source, cwe, rel string, project projectContext) (evidence, confidence string) {
	if staticLifecycleCWE(cwe) {
		return "not-applicable: finding is about source/lifecycle material rather than request source-to-sink flow", "not-applicable"
	}
	if len(lines) == 0 {
		return "missing: no bounded context lines available", "missing"
	}
	sinkIdx := sinkLine - firstLine
	if sinkIdx < 0 || sinkIdx >= len(lines) {
		return "context-only: sink line is outside the bounded context window", "context-only"
	}
	if source == "unknown" {
		if ev := callerToCurrentWrapperEvidence(lines, firstLine, sinkIdx); ev != "" {
			return ev, "interprocedural"
		}
		if ev := projectCallerToCurrentWrapperEvidence(lines, firstLine, sinkIdx, rel, project); ev != "" {
			return ev, "cross-file"
		}
		return "missing: attacker-controlled source was not identified", "missing"
	}
	sinkText := strings.ToLower(lines[sinkIdx])
	for _, token := range sourceCueTokens {
		if directSourceCueInSink(token, sinkText) {
			return fmt.Sprintf("direct: sink line %d contains %s", sinkLine, source), "direct"
		}
	}
	if sanitizes(sinkText) {
		return fmt.Sprintf("sanitized: sink line %d contains sanitizer/validator cue near %s", sinkLine, source), "sanitized"
	}
	if ev, conf := propagatedDataFlowEvidence(lines, firstLine, sinkIdx, project.Summaries); ev != "" {
		return ev, conf
	}
	if ev := callerToCurrentWrapperEvidence(lines, firstLine, sinkIdx); ev != "" {
		return ev, "interprocedural"
	}
	if ev := projectCallerToCurrentWrapperEvidence(lines, firstLine, sinkIdx, rel, project); ev != "" {
		return ev, "cross-file"
	}
	for i := 0; i <= sinkIdx; i++ {
		raw := lines[i]
		m := sourceAssignmentPattern.FindStringSubmatch(raw)
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" {
			continue
		}
		if variableUsedInLine(v, lines[sinkIdx]) {
			return fmt.Sprintf("variable-derived: %s assigned from request/source at line %d and used at sink line %d", v, firstLine+i, sinkLine), "variable-derived"
		}
	}
	return "context-only: source and sink are both present in bounded local context, but no same-line or variable-use proof was found", "context-only"
}

func callerToCurrentWrapperEvidence(lines []string, firstLine, sinkIdx int) string {
	wrapper, ok := enclosingFunction(lines, firstLine, sinkIdx)
	if !ok || !wrapper.Sinkish {
		return ""
	}
	tainted := map[string]taintState{}
	sanitized := map[string]taintState{}
	for i := sinkIdx + 1; i < len(lines); i++ {
		lineNo := firstLine + i
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if commentOnlyLine(line) {
			continue
		}
		lower := strings.ToLower(line)
		for _, param := range decoratedSourceParams(line) {
			if _, exists := tainted[param]; !exists {
				tainted[param] = taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-decorated-source@%d", param, lineNo)}}
			}
		}
		for _, param := range frameworkSourceParamsAt(lines, i, firstLine) {
			if _, exists := tainted[param.Name]; !exists {
				tainted[param.Name] = taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-framework-source@%d", param.Name, lineNo)}}
			}
		}
		if calledWithVariable(wrapper.Name, raw, sanitized) {
			return fmt.Sprintf("sanitized: source reaches sink wrapper %s defined at line %d through caller line %d after sanitizer/validator cue", wrapper.Name, wrapper.Line, lineNo)
		}
		if v, st, ok := calledWithTaintedVariable(wrapper.Name, raw, tainted); ok {
			return fmt.Sprintf("interprocedural: %s assigned from request/source at line %d reaches sink wrapper %s defined at line %d through caller line %d; path=%s", v, st.SourceLine, wrapper.Name, wrapper.Line, lineNo, strings.Join(st.Steps, " -> "))
		}
		if trackDestructuringTaint(line, lower, lineNo, tainted, sanitized) {
			continue
		}
		if trackMemberTaint(line, lower, lineNo, tainted, sanitized) {
			continue
		}
		m := assignmentPattern.FindStringSubmatch(line)
		if len(m) >= 3 {
			lhs := strings.TrimSpace(m[1])
			rhs := strings.TrimSpace(m[2])
			if trackObjectLiteralTaint(lhs, rhs, lines, i, firstLine, len(lines)-1, tainted, sanitized) {
				continue
			}
			if hasSourceCue(lower) {
				st := taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-source@%d", lhs, lineNo)}}
				if sanitizes(lower) {
					sanitized[lhs] = appendStep(st, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
					delete(tainted, lhs)
				} else {
					tainted[lhs] = st
					delete(sanitized, lhs)
				}
				continue
			}
			if v, st, ok := firstVariableUse(sanitized, rhs); ok {
				sanitized[lhs] = appendStep(st, fmt.Sprintf("%s<-sanitized(%s)@%d", lhs, v, lineNo))
				delete(tainted, lhs)
				continue
			}
			if v, st, ok := firstVariableUse(tainted, rhs); ok {
				next := appendStep(st, fmt.Sprintf("%s<-%s@%d", lhs, v, lineNo))
				if sanitizes(lower) {
					sanitized[lhs] = appendStep(next, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
					delete(tainted, lhs)
				} else {
					tainted[lhs] = next
					delete(sanitized, lhs)
				}
				continue
			}
		}
	}
	return ""
}

func projectCallerToCurrentWrapperEvidence(lines []string, firstLine, sinkIdx int, rel string, project projectContext) string {
	wrapper, ok := enclosingFunction(lines, firstLine, sinkIdx)
	if !ok || !wrapper.Sinkish || wrapper.Name == "" {
		return ""
	}
	wrapper.File = rel
	for _, file := range project.Files {
		if file.Rel == rel {
			continue
		}
		if ev := callerEvidenceInFile(wrapper, file); ev != "" {
			return ev
		}
	}
	return ""
}

func callerEvidenceInFile(wrapper functionSummary, file projectFile) string {
	tainted := map[string]taintState{}
	sanitized := map[string]taintState{}
	for i, raw := range file.Lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if commentOnlyLine(line) {
			continue
		}
		lower := strings.ToLower(line)
		if calledWithVariable(wrapper.Name, raw, sanitized) {
			route := nearestRoute(file.Lines[:i+1], 1).Route
			return fmt.Sprintf("sanitized: source reaches cross-file sink wrapper %s defined at %s:%d through caller %s:%d via route %s after sanitizer/validator cue", wrapper.Name, wrapper.File, wrapper.Line, file.Rel, lineNo, route)
		}
		if v, st, ok := calledWithTaintedVariable(wrapper.Name, raw, tainted); ok {
			route := nearestRoute(file.Lines[:i+1], 1).Route
			return fmt.Sprintf("cross-file: %s assigned from request/source at %s:%d reaches sink wrapper %s defined at %s:%d through caller %s:%d via route %s; path=%s", v, file.Rel, st.SourceLine, wrapper.Name, wrapper.File, wrapper.Line, file.Rel, lineNo, route, strings.Join(st.Steps, " -> "))
		}
		trackTaintAssignment(raw, lower, lineNo, tainted, sanitized)
	}
	return ""
}

func routeFromEvidence(evidence string) string {
	_, after, ok := strings.Cut(evidence, " via route ")
	if !ok {
		return ""
	}
	route, _, _ := strings.Cut(after, ";")
	route = strings.TrimSpace(route)
	if route == "unknown" {
		return ""
	}
	return route
}

func trackTaintAssignment(raw, lower string, lineNo int, tainted, sanitized map[string]taintState) {
	line := strings.TrimSpace(raw)
	if trackDestructuringTaint(line, lower, lineNo, tainted, sanitized) {
		return
	}
	if trackMemberTaint(line, lower, lineNo, tainted, sanitized) {
		return
	}
	m := assignmentPattern.FindStringSubmatch(line)
	if len(m) < 3 {
		return
	}
	lhs := strings.TrimSpace(m[1])
	rhs := strings.TrimSpace(m[2])
	if lhs == "" || rhs == "" {
		return
	}
	if trackObjectLiteralTaint(lhs, rhs, []string{line}, 0, lineNo, 0, tainted, sanitized) {
		return
	}
	if hasSourceCue(lower) {
		st := taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-source@%d", lhs, lineNo)}}
		if sanitizes(lower) {
			sanitized[lhs] = appendStep(st, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			delete(tainted, lhs)
		} else {
			tainted[lhs] = st
			delete(sanitized, lhs)
		}
		return
	}
	if v, st, ok := firstVariableUse(sanitized, rhs); ok {
		sanitized[lhs] = appendStep(st, fmt.Sprintf("%s<-sanitized(%s)@%d", lhs, v, lineNo))
		delete(tainted, lhs)
		return
	}
	if v, st, ok := firstVariableUse(tainted, rhs); ok {
		next := appendStep(st, fmt.Sprintf("%s<-%s@%d", lhs, v, lineNo))
		if sanitizes(lower) {
			sanitized[lhs] = appendStep(next, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			delete(tainted, lhs)
		} else {
			tainted[lhs] = next
			delete(sanitized, lhs)
		}
	}
}

func trackDestructuringTaint(line, lower string, lineNo int, tainted, sanitized map[string]taintState) bool {
	m := destructuringAssignmentPattern.FindStringSubmatch(line)
	if len(m) < 3 {
		return false
	}
	lhs := strings.TrimSpace(m[1])
	rhs := strings.TrimSpace(m[2])
	names := destructuredBindingNames(lhs)
	if len(names) == 0 {
		return false
	}
	if hasSourceCue(lower) {
		for _, name := range names {
			st := taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-destructured-source@%d", name, lineNo)}}
			if sanitizes(lower) {
				sanitized[name] = appendStep(st, fmt.Sprintf("%s sanitized@%d", name, lineNo))
				delete(tainted, name)
			} else {
				tainted[name] = st
				delete(sanitized, name)
			}
		}
		return true
	}
	if v, st, ok := firstVariableUse(sanitized, rhs); ok {
		for _, name := range names {
			sanitized[name] = appendStep(st, fmt.Sprintf("%s<-destructure(%s)@%d", name, v, lineNo))
			delete(tainted, name)
		}
		return true
	}
	if v, st, ok := firstVariableUse(tainted, rhs); ok {
		for _, name := range names {
			next := appendStep(st, fmt.Sprintf("%s<-destructure(%s)@%d", name, v, lineNo))
			if sanitizes(lower) {
				sanitized[name] = appendStep(next, fmt.Sprintf("%s sanitized@%d", name, lineNo))
				delete(tainted, name)
			} else {
				tainted[name] = next
				delete(sanitized, name)
			}
		}
		return true
	}
	return false
}

func trackMemberTaint(line, lower string, lineNo int, tainted, sanitized map[string]taintState) bool {
	m := memberAssignmentPattern.FindStringSubmatch(line)
	if len(m) < 3 {
		return false
	}
	lhs := strings.TrimSpace(m[1])
	rhs := strings.TrimSpace(m[2])
	if lhs == "" || rhs == "" {
		return false
	}
	base := accessPathBase(lhs)
	if hasSourceCue(lower) {
		st := taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-member-source@%d", lhs, lineNo)}}
		if sanitizes(lower) {
			sanitized[lhs] = appendStep(st, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			if base != "" {
				sanitized[base] = appendStep(st, fmt.Sprintf("%s<-container(%s)@%d", base, lhs, lineNo))
			}
			delete(tainted, lhs)
			delete(tainted, base)
		} else {
			tainted[lhs] = st
			if base != "" {
				tainted[base] = appendStep(st, fmt.Sprintf("%s<-container(%s)@%d", base, lhs, lineNo))
			}
			delete(sanitized, lhs)
			delete(sanitized, base)
		}
		return true
	}
	if v, st, ok := firstVariableUse(sanitized, rhs); ok {
		next := appendStep(st, fmt.Sprintf("%s<-member(%s)@%d", lhs, v, lineNo))
		sanitized[lhs] = next
		if base != "" {
			sanitized[base] = appendStep(next, fmt.Sprintf("%s<-container(%s)@%d", base, lhs, lineNo))
		}
		delete(tainted, lhs)
		delete(tainted, base)
		return true
	}
	if v, st, ok := firstVariableUse(tainted, rhs); ok {
		next := appendStep(st, fmt.Sprintf("%s<-member(%s)@%d", lhs, v, lineNo))
		if sanitizes(lower) {
			sanitized[lhs] = appendStep(next, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			if base != "" {
				sanitized[base] = appendStep(next, fmt.Sprintf("%s<-container(%s)@%d", base, lhs, lineNo))
			}
			delete(tainted, lhs)
			delete(tainted, base)
		} else {
			tainted[lhs] = next
			if base != "" {
				tainted[base] = appendStep(next, fmt.Sprintf("%s<-container(%s)@%d", base, lhs, lineNo))
			}
			delete(sanitized, lhs)
			delete(sanitized, base)
		}
		return true
	}
	return false
}

func trackObjectLiteralTaint(lhs, rhs string, lines []string, idx, firstLine, sinkIdx int, tainted, sanitized map[string]taintState) bool {
	if !strings.Contains(rhs, "{") {
		return false
	}
	lineNo := firstLine + idx
	block := objectLiteralBlockText(rhs, lines, idx, sinkIdx)
	if block == "" {
		return false
	}
	lowerBlock := strings.ToLower(block)
	if v, st, ok := firstVariableUse(sanitized, block); ok {
		sanitized[lhs] = appendStep(st, fmt.Sprintf("%s<-object-literal(%s)@%d", lhs, v, lineNo))
		delete(tainted, lhs)
		return true
	}
	if v, st, ok := firstVariableUse(tainted, block); ok {
		next := appendStep(st, fmt.Sprintf("%s<-object-literal(%s)@%d", lhs, v, lineNo))
		if sanitizes(lowerBlock) {
			sanitized[lhs] = appendStep(next, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			delete(tainted, lhs)
		} else {
			tainted[lhs] = next
			delete(sanitized, lhs)
		}
		return true
	}
	if hasSourceCue(lowerBlock) {
		st := taintState{SourceLine: lineNo, LastLine: lineNo, Steps: []string{fmt.Sprintf("%s<-object-literal-source@%d", lhs, lineNo)}}
		if sanitizes(lowerBlock) {
			sanitized[lhs] = appendStep(st, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
			delete(tainted, lhs)
		} else {
			tainted[lhs] = st
			delete(sanitized, lhs)
		}
		return true
	}
	return false
}

func objectLiteralBlockText(rhs string, lines []string, idx, sinkIdx int) string {
	var parts []string
	parts = append(parts, rhs)
	depth := braceDelta(rhs)
	if depth <= 0 {
		return rhs
	}
	limit := min(len(lines)-1, min(sinkIdx, idx+40))
	for j := idx + 1; j <= limit; j++ {
		line := strings.TrimSpace(lines[j])
		if commentOnlyLine(line) {
			continue
		}
		parts = append(parts, line)
		depth += braceDelta(line)
		if depth <= 0 {
			break
		}
	}
	return strings.Join(parts, "\n")
}

func braceDelta(s string) int {
	delta := 0
	inQuote := rune(0)
	escaped := false
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 {
			if r == '\\' {
				escaped = true
				continue
			}
			if r == inQuote {
				inQuote = 0
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			inQuote = r
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}

func destructuredBindingNames(raw string) []string {
	var out []string
	for _, part := range splitTopLevel(raw, ',') {
		name := destructuredBindingName(part)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func destructuredBindingName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "{") || strings.Contains(raw, "}") {
		return ""
	}
	if before, _, ok := strings.Cut(raw, "="); ok {
		raw = strings.TrimSpace(before)
	}
	if _, after, ok := strings.Cut(raw, ":"); ok {
		raw = strings.TrimSpace(after)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "[]().") {
		return ""
	}
	for _, r := range raw {
		if !(r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return raw
}

func splitTopLevel(raw string, sep rune) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if r == sep && depth == 0 {
				out = append(out, raw[start:i])
				start = i + len(string(r))
			}
		}
	}
	out = append(out, raw[start:])
	return out
}

func accessPathBase(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if before, _, ok := strings.Cut(path, "."); ok {
		return strings.TrimSpace(before)
	}
	if before, _, ok := strings.Cut(path, "["); ok {
		return strings.TrimSpace(before)
	}
	return path
}

func enclosingFunction(lines []string, firstLine, sinkIdx int) (functionSummary, bool) {
	for i := sinkIdx; i >= 0; i-- {
		name, param, ok := parseFunctionHeader(strings.TrimSpace(lines[i]))
		if !ok {
			continue
		}
		bodyStart := i
		bodyEnd := min(len(lines), sinkIdx+1)
		body := strings.ToLower(strings.Join(lines[bodyStart:bodyEnd], "\n"))
		return functionSummary{
			Name:      name,
			Param:     param,
			Line:      firstLine + i,
			Propagate: true,
			Sanitize:  sanitizes(body),
			Sinkish:   sinkishFunctionName(name) || sinkishBody(body),
		}, true
	}
	return functionSummary{}, false
}

func calledWithVariable(fn, line string, vars map[string]taintState) bool {
	_, _, ok := calledWithTaintedVariable(fn, line, vars)
	return ok
}

func calledWithTaintedVariable(fn, line string, vars map[string]taintState) (name string, state taintState, ok bool) {
	for _, m := range simpleCallPattern.FindAllStringSubmatch(line, -1) {
		if len(m) < 3 || !strings.EqualFold(strings.TrimSpace(m[1]), fn) {
			continue
		}
		if v, st, ok := firstVariableUse(vars, m[2]); ok {
			return v, st, true
		}
	}
	return "", taintState{}, false
}

type taintState struct {
	SourceLine int
	LastLine   int
	Steps      []string
}

func propagatedDataFlowEvidence(lines []string, firstLine, sinkIdx int, projectSummaries map[string]functionSummary) (evidence, confidence string) {
	tainted := map[string]taintState{}
	sanitized := map[string]taintState{}
	summaries := summarizeLocalFunctions(lines, firstLine, sinkIdx)
	for name, summary := range projectSummaries {
		if _, exists := summaries[name]; !exists {
			summaries[name] = summary
		}
	}
	for i := 0; i <= sinkIdx; i++ {
		lineNo := firstLine + i
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if commentOnlyLine(line) {
			continue
		}
		lower := strings.ToLower(line)
		for _, param := range decoratedSourceParams(line) {
			if _, exists := tainted[param]; !exists {
				tainted[param] = taintState{
					SourceLine: lineNo,
					LastLine:   lineNo,
					Steps:      []string{fmt.Sprintf("%s<-decorated-source@%d", param, lineNo)},
				}
			}
		}
		for _, param := range frameworkSourceParamsAt(lines, i, firstLine) {
			if _, exists := tainted[param.Name]; !exists {
				tainted[param.Name] = taintState{
					SourceLine: lineNo,
					LastLine:   lineNo,
					Steps:      []string{fmt.Sprintf("%s<-framework-source@%d", param.Name, lineNo)},
				}
			}
		}
		if trackDestructuringTaint(line, lower, lineNo, tainted, sanitized) {
			continue
		}
		if trackMemberTaint(line, lower, lineNo, tainted, sanitized) {
			continue
		}
		if i == sinkIdx {
			if v, st, ok := firstVariableUse(sanitized, raw); ok {
				return fmt.Sprintf("sanitized: %s reaches sink line %d after sanitizer/validator cue; path=%s", v, lineNo, strings.Join(st.Steps, " -> ")), "sanitized"
			}
			if v, st, ok := firstVariableUse(tainted, raw); ok {
				if ev := guardedTaintEvidence(lines[:i+1], firstLine, tainted); ev != "" {
					return fmt.Sprintf("guarded: %s assigned from request/source at line %d reaches sink line %d after guard cue; guard=%s; path=%s", v, st.SourceLine, lineNo, ev, strings.Join(st.Steps, " -> ")), "guarded"
				}
			}
			if ev, ok := wrapperSinkEvidence(raw, lineNo, tainted, sanitized); ok {
				return ev, "interprocedural"
			}
			if v, st, ok := firstVariableUse(tainted, raw); ok {
				return fmt.Sprintf("propagated: %s assigned from request/source at line %d reaches sink line %d; path=%s", v, st.SourceLine, lineNo, strings.Join(st.Steps, " -> ")), "propagated"
			}
			continue
		}
		m := assignmentPattern.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		lhs := strings.TrimSpace(m[1])
		rhs := strings.TrimSpace(m[2])
		if lhs == "" || rhs == "" {
			continue
		}
		if trackObjectLiteralTaint(lhs, rhs, lines, i, firstLine, sinkIdx, tainted, sanitized) {
			continue
		}
		if hasSourceCue(lower) {
			st := taintState{
				SourceLine: lineNo,
				LastLine:   lineNo,
				Steps:      []string{fmt.Sprintf("%s<-source@%d", lhs, lineNo)},
			}
			if sanitizes(lower) {
				sanitized[lhs] = appendStep(st, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
				delete(tainted, lhs)
			} else {
				tainted[lhs] = st
				delete(sanitized, lhs)
			}
			continue
		}
		if v, st, ok := firstVariableUse(sanitized, rhs); ok {
			next := appendStep(st, fmt.Sprintf("%s<-sanitized(%s)@%d", lhs, v, lineNo))
			sanitized[lhs] = next
			delete(tainted, lhs)
			continue
		}
		if next, sanitizedFlow, ok := helperCallTaint(lhs, rhs, lineNo, summaries, tainted, sanitized); ok {
			if sanitizedFlow {
				sanitized[lhs] = next
				delete(tainted, lhs)
			} else {
				tainted[lhs] = next
				delete(sanitized, lhs)
			}
			continue
		}
		if v, st, ok := firstVariableUse(tainted, rhs); ok {
			next := appendStep(st, fmt.Sprintf("%s<-%s@%d", lhs, v, lineNo))
			if sanitizes(lower) {
				sanitized[lhs] = appendStep(next, fmt.Sprintf("%s sanitized@%d", lhs, lineNo))
				delete(tainted, lhs)
			} else {
				tainted[lhs] = next
				delete(sanitized, lhs)
			}
		}
	}
	return "", ""
}

func guardedTaintEvidence(lines []string, firstLine int, tainted map[string]taintState) string {
	for v := range tainted {
		if ev := guardedVariableEvidence(lines, firstLine, v); ev != "" {
			return ev
		}
	}
	return ""
}

func guardedVariableEvidence(lines []string, firstLine int, variable string) string {
	if variable == "" {
		return ""
	}
	for i := len(lines) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(lines[i])
		if commentOnlyLine(raw) || !variableUsedInLine(variable, raw) {
			continue
		}
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "if ") || strings.Contains(lower, "if(") ||
			strings.Contains(lower, "unless ") || strings.Contains(lower, "return") ||
			strings.Contains(lower, "throw") || strings.Contains(lower, "abort") ||
			strings.Contains(lower, "reject") || strings.Contains(lower, "forbidden") {
			if hasGuardCue(lower) {
				return fmt.Sprintf("line %d: %s", firstLine+i, clampContext(raw, 140))
			}
		}
	}
	return ""
}

func hasGuardCue(line string) bool {
	for _, token := range []string{
		"allowlist", "whitelist", "allowedhost", "allowedhosts", ".includes(", ".has(",
		"isprivateip", "privateip", "metadata", "localhost", "127.0.0.1", "169.254.169.254",
		"validate", "validator", ".test(", "regexp", "regex", "matches(",
		"safejoin", "startswith(basedir", "startswith(basedir", "filepath.clean", "path.normalize",
		"ownerid", "tenantid", "organizationid", "userid", "permission", "authorize(",
	} {
		if strings.Contains(line, strings.ToLower(token)) {
			return true
		}
	}
	return false
}

type functionSummary struct {
	Name      string
	Param     string
	File      string
	Line      int
	Propagate bool
	Sanitize  bool
	Sinkish   bool
}

func summarizeLocalFunctions(lines []string, firstLine, sinkIdx int) map[string]functionSummary {
	out := map[string]functionSummary{}
	for i := 0; i < sinkIdx && i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if commentOnlyLine(line) {
			continue
		}
		name, param, ok := parseFunctionHeader(line)
		if !ok {
			continue
		}
		limit := min(len(lines), i+40)
		body := strings.ToLower(strings.Join(lines[i:min(limit, sinkIdx)], "\n"))
		paramLower := strings.ToLower(param)
		if !strings.Contains(body, paramLower) {
			continue
		}
		summary := functionSummary{
			Name:      name,
			Param:     param,
			Line:      firstLine + i,
			Propagate: strings.Contains(body, "return") || strings.Contains(body, "="),
			Sanitize:  sanitizes(body),
			Sinkish:   sinkishFunctionName(name) || sinkishBody(body),
		}
		out[strings.ToLower(name)] = summary
	}
	return out
}

func parseFunctionHeader(line string) (name, param string, ok bool) {
	for _, re := range functionHeaderPatterns {
		if m := re.FindStringSubmatch(line); len(m) >= 3 {
			return strings.TrimSpace(m[1]), strings.TrimSpace(m[2]), true
		}
	}
	return "", "", false
}

func helperCallTaint(lhs, rhs string, lineNo int, summaries map[string]functionSummary, tainted, sanitized map[string]taintState) (taintState, bool, bool) {
	m := simpleCallPattern.FindStringSubmatch(rhs)
	if len(m) < 3 {
		return taintState{}, false, false
	}
	fn := strings.ToLower(strings.TrimSpace(m[1]))
	summary, ok := summaries[fn]
	if !ok || !summary.Propagate {
		return taintState{}, false, false
	}
	args := strings.TrimSpace(m[2])
	if v, st, ok := firstVariableUse(sanitized, args); ok {
		next := appendStep(st, fmt.Sprintf("%s<-helper:%s(%s)@%d", lhs, summary.Name, v, lineNo))
		return appendStep(next, helperSummaryStep(summary)), true, true
	}
	if v, st, ok := firstVariableUse(tainted, args); ok {
		next := appendStep(st, fmt.Sprintf("%s<-helper:%s(%s)@%d", lhs, summary.Name, v, lineNo))
		next = appendStep(next, helperSummaryStep(summary))
		return next, summary.Sanitize, true
	}
	return taintState{}, false, false
}

func helperSummaryStep(summary functionSummary) string {
	if summary.File != "" {
		return fmt.Sprintf("helper:%s summarized@%s:%d", summary.Name, summary.File, summary.Line)
	}
	return fmt.Sprintf("helper:%s summarized@%d", summary.Name, summary.Line)
}

func wrapperSinkEvidence(line string, lineNo int, tainted, sanitized map[string]taintState) (string, bool) {
	for _, m := range simpleCallPattern.FindAllStringSubmatch(line, -1) {
		if len(m) < 3 || !sinkishWrapperName(m[1]) {
			continue
		}
		args := m[2]
		if v, st, ok := firstVariableUse(sanitized, args); ok {
			return fmt.Sprintf("sanitized: %s reaches sink-like wrapper %s at line %d after sanitizer/validator cue; path=%s", v, m[1], lineNo, strings.Join(st.Steps, " -> ")), true
		}
		if v, st, ok := firstVariableUse(tainted, args); ok {
			return fmt.Sprintf("interprocedural: %s assigned from request/source at line %d reaches sink-like wrapper %s at line %d; path=%s", v, st.SourceLine, m[1], lineNo, strings.Join(st.Steps, " -> ")), true
		}
	}
	return "", false
}

func sinkishFunctionName(name string) bool {
	lower := strings.ToLower(name)
	for _, token := range []string{"query", "exec", "execute", "sql", "fetch", "request", "render", "deserialize", "unserialize", "readfile", "writefile", "openfile", "runcommand"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func sinkishWrapperName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "queryrawunsafe", "$queryrawunsafe", "query", "querycontext", "queryrow", "queryrowcontext", "execute", "exec", "execcontext", "fetch", "get", "post", "open", "readfile", "writefile":
		return false
	}
	return sinkishFunctionName(name)
}

func sinkishBody(body string) bool {
	for _, token := range []string{"queryrawunsafe", "cursor.execute", "exec(", "fetch(", "axios.", "requests.", "dangerouslysetinnerhtml", "unserialize", "readfile", "writefile"} {
		if strings.Contains(body, token) {
			return true
		}
	}
	return false
}

func appendStep(st taintState, step string) taintState {
	steps := append([]string{}, st.Steps...)
	steps = append(steps, step)
	if len(steps) > 6 {
		steps = append([]string{steps[0]}, steps[len(steps)-5:]...)
	}
	st.Steps = steps
	return st
}

func firstVariableUse(vars map[string]taintState, line string) (name string, state taintState, ok bool) {
	for v, st := range vars {
		if variableUsedInLine(v, line) {
			return v, st, true
		}
	}
	return "", taintState{}, false
}

func hasSourceCue(line string) bool {
	lower := strings.ToLower(line)
	for _, token := range sourceCueTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func directSourceCueInSink(token, sinkText string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	switch token {
	case "", "url", "filename", "originalname", "localstorage":
		return false
	default:
		return strings.Contains(sinkText, token)
	}
}

func decoratedSourceParams(line string) []string {
	matches := decoratedParamPattern.FindAllStringSubmatch(line, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 3 {
			out = append(out, strings.TrimSpace(m[2]))
		}
	}
	return out
}

func frameworkSourceParamsAt(lines []string, idx, firstLine int) []frameworkSourceParam {
	if idx < 0 || idx >= len(lines) {
		return nil
	}
	line := strings.TrimSpace(lines[idx])
	if commentOnlyLine(line) {
		return nil
	}
	lineNo := firstLine + idx
	if m := springParamPattern.FindStringSubmatch(line); len(m) >= 3 {
		return []frameworkSourceParam{{
			Name:     strings.TrimSpace(m[2]),
			Label:    springParamLabel(m[1]),
			Evidence: fmt.Sprintf("line %d: %s cue", lineNo, springParamLabel(m[1])),
		}}
	}
	m := pythonFunctionParamsPattern.FindStringSubmatch(line)
	if len(m) < 2 || !hasNearbyRouteDecorator(lines, idx) {
		return nil
	}
	params := splitParams(m[1])
	out := make([]frameworkSourceParam, 0, len(params))
	for _, raw := range params {
		name := pythonParamName(raw)
		if name == "" || ignoredFrameworkParam(name) {
			continue
		}
		out = append(out, frameworkSourceParam{
			Name:     name,
			Label:    "framework route/query parameter",
			Evidence: fmt.Sprintf("line %d: framework route/query parameter cue", lineNo),
		})
	}
	return out
}

func springParamLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "requestparam":
		return "framework query parameter"
	case "pathvariable":
		return "framework route parameter"
	case "requestbody", "requestpart":
		return "framework request body"
	default:
		return "framework request parameter"
	}
}

func hasNearbyRouteDecorator(lines []string, idx int) bool {
	for i := idx - 1; i >= 0 && i >= idx-4; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || commentOnlyLine(line) {
			continue
		}
		for _, re := range routePatterns {
			if re.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func splitParams(raw string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, raw[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, raw[start:])
	return out
}

func pythonParamName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if before, _, ok := strings.Cut(raw, "="); ok {
		raw = strings.TrimSpace(before)
	}
	if before, _, ok := strings.Cut(raw, ":"); ok {
		raw = strings.TrimSpace(before)
	}
	raw = strings.TrimPrefix(raw, "*")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, r := range raw {
		if !(r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return raw
}

func ignoredFrameworkParam(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "self", "cls", "request", "response", "res", "db", "session", "ctx", "context", "current_user", "user":
		return true
	default:
		return false
	}
}

func decoratedSourceLabel(line string) (string, bool) {
	matches := decoratedParamPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return "", false
	}
	switch strings.ToLower(matches[0][1]) {
	case "query":
		return "framework query parameter", true
	case "param":
		return "framework route parameter", true
	case "body":
		return "framework request body", true
	case "args", "arg":
		return "GraphQL argument", true
	case "ctx", "context":
		return "GraphQL/resolver context", true
	default:
		return "framework decorated parameter", true
	}
}

func sanitizes(line string) bool {
	lower := strings.ToLower(line)
	for _, token := range sanitizerTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func staticLifecycleCWE(cwe string) bool {
	switch cwe {
	case "CWE-798", "CWE-916", "CWE-327", "CWE-614", "CWE-347", "CWE-489", "CWE-942", "CWE-295":
		return true
	default:
		return false
	}
}

func variableUsedInLine(name, line string) bool {
	if name == "" {
		return false
	}
	re := regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_$])` + regexp.QuoteMeta(name) + `([^A-Za-z0-9_$]|$)`)
	return re.MatchString(line)
}

func inferSink(ruleID, cwe string) string {
	switch cwe {
	case "CWE-89":
		return "SQL execution sink"
	case "CWE-78":
		return "OS command execution sink"
	case "CWE-502":
		return "unsafe deserialization sink"
	case "CWE-918":
		return "server-side outbound request sink"
	case "CWE-79":
		return "HTML/template rendering sink"
	case "CWE-640":
		return "password reset token response/log sink"
	case "CWE-639":
		return "object lookup/update/delete by id"
	case "CWE-22":
		return "filesystem path access sink"
	case "CWE-915":
		return "model create/update assignment sink"
	case "CWE-532":
		return "application log sink"
	case "CWE-347":
		return "JWT signing/verification sink"
	case "CWE-916":
		return "password hashing sink"
	case "CWE-798":
		return "credential material in source"
	default:
		if strings.Contains(ruleID, "sql") {
			return "SQL execution sink"
		}
		return "matched rule sink"
	}
}

func entryPointSummary(route string, lines []string) string {
	if route != "unknown" {
		return route
	}
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if commentOnlyLine(l) {
			continue
		}
		if strings.HasPrefix(l, "func ") || strings.Contains(l, " function ") ||
			strings.HasPrefix(l, "async function ") || strings.HasPrefix(l, "def ") ||
			strings.Contains(l, "=>") {
			return clampContext(l, 160)
		}
	}
	return "unknown"
}

func dataflowSummary(source, sink, route string) string {
	if source == "unknown" {
		return fmt.Sprintf("proof gap: %s is present, but an attacker-controlled source was not identified in the bounded local context", sink)
	}
	if route == "unknown" {
		return fmt.Sprintf("%s -> %s; route/entrypoint not proven in bounded context", source, sink)
	}
	return fmt.Sprintf("%s -> %s via %s", source, sink, route)
}

func validationRubric(route, source, sink, authScope, exposure, counter, flowConfidence string) string {
	items := []string{
		"source=" + presentToken(source != "unknown"),
		"control=" + presentToken(route != "unknown"),
		"sink=" + presentToken(sink != "" && sink != "matched rule sink"),
		"auth=" + authScope,
		"exposure=" + rubricToken(exposure),
		"dataflow=" + flowConfidence,
	}
	if counter != "" && counter != "none observed in bounded local context" {
		items = append(items, "counterevidence=present")
	} else {
		items = append(items, "counterevidence=none_observed")
	}
	return strings.Join(items, "; ")
}

func rubricToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ";", "")
	if s == "" {
		return "unknown"
	}
	return s
}

func presentToken(ok bool) string {
	if ok {
		return "present"
	}
	return "missing"
}

func trustBoundarySummary(authScope, route, source, sink string) string {
	if route == "unknown" || source == "unknown" {
		return "boundary unknown until entrypoint and attacker-controlled source are proven"
	}
	switch authScope {
	case "unauthenticated-or-public":
		return fmt.Sprintf("internet/client-controlled input crosses into server-side %s", sink)
	case "authenticated":
		return fmt.Sprintf("authenticated user input crosses account/tenant boundary into %s", sink)
	case "role-scoped":
		return fmt.Sprintf("role-scoped user input crosses privilege boundary into %s", sink)
	default:
		return fmt.Sprintf("request-controlled input crosses an unresolved auth boundary into %s", sink)
	}
}

func impactSummary(cwe, authScope string) string {
	switch cwe {
	case "CWE-89":
		return "possible database read/write semantics change; validate data exposure or mutation impact"
	case "CWE-78":
		return "possible server-side command execution; validate command argument control and execution context"
	case "CWE-918":
		return "possible server-side request to internal, metadata, or side-effecting services"
	case "CWE-79":
		return "possible script execution in a victim browser; validate victim role and session/token exposure"
	case "CWE-639":
		return "possible object-level authorization bypass; validate cross-user or cross-tenant object access"
	case "CWE-640":
		return "possible account recovery token exposure; validate token usability and recipient"
	case "CWE-502":
		return "possible object injection or code execution; validate gadget/runtime behavior"
	case "CWE-22":
		return "possible filesystem read/write outside intended base directory"
	case "CWE-915":
		return "possible overwrite of privileged, ownership, or workflow-control fields"
	case "CWE-532":
		return "possible credential or sensitive-data leakage through logs"
	case "CWE-798":
		return "possible reusable secret exposure; validate credential scope and rotation state"
	case "CWE-916", "CWE-327":
		return "possible weak cryptographic protection; validate whether it protects passwords, tokens, or signatures"
	}
	if authScope == "unauthenticated-or-public" {
		return "publicly reachable candidate; validate concrete security impact"
	}
	return "candidate impact requires verifier review"
}

func exploitabilitySummary(authScope, route, source, sink, flowConfidence string) string {
	if source == "unknown" {
		return "candidate only: needs source-to-sink validation before reportable exploitability can be claimed"
	}
	if flowConfidence == "sanitized" {
		return "candidate only: source appears to pass through sanitizer/validator cue before the sink; verifier should confirm whether the control fully neutralizes the CWE"
	}
	if flowConfidence == "guarded" {
		return "candidate only: source appears to pass through a guard/allowlist cue before the sink; verifier should confirm whether the control fully constrains attacker influence"
	}
	if flowConfidence == "context-only" {
		return "candidate only: source and sink are nearby, but direct value flow is not proven in bounded static context"
	}
	if route == "unknown" {
		return "plausible static issue: dangerous source/sink pair exists, but route reachability is unknown"
	}
	switch authScope {
	case "unauthenticated-or-public":
		return "higher likelihood: route appears public and attacker-controlled data reaches a dangerous sink"
	case "authenticated":
		return "requires authenticated user: validate tenant/ownership and role boundaries before severity promotion"
	case "role-scoped":
		return "requires role/permission context: severity depends on whether the allowed role is lower privilege than the impacted asset"
	default:
		return "route-reachable candidate with unknown authorization; validate middleware and deployment exposure"
	}
}

func counterEvidenceSummary(ruleID, cwe string, lines []string) string {
	text := strings.ToLower(strings.Join(lines, "\n"))
	var cues []string
	add := func(label string) {
		for _, existing := range cues {
			if existing == label {
				return
			}
		}
		cues = append(cues, label)
	}
	switch cwe {
	case "CWE-89":
		if strings.Contains(text, "$queryraw`") || strings.Contains(text, "parameterized") ||
			strings.Contains(text, "preparedstatement") || strings.Contains(text, "bindparam") ||
			strings.Contains(text, "where:") && !strings.Contains(ruleID, "raw") {
			add("nearby parameterized-query or ORM-builder cue")
		}
	case "CWE-78":
		if strings.Contains(text, "execfile(") || strings.Contains(text, "spawn(") ||
			strings.Contains(text, "allowlist") || strings.Contains(text, "whitelist") {
			add("nearby argv/allowlist command-execution cue")
		}
	case "CWE-79", "CWE-1336":
		if strings.Contains(text, "dompurify") || strings.Contains(text, "sanitize-html") ||
			strings.Contains(text, "sanitize(") || strings.Contains(text, "escapehtml") ||
			strings.Contains(text, "html.escape") {
			add("nearby HTML sanitization/escaping cue")
		}
	case "CWE-918":
		if strings.Contains(text, "allowlist") || strings.Contains(text, "allowedhost") ||
			strings.Contains(text, "isprivateip") || strings.Contains(text, "block private") ||
			strings.Contains(text, "metadata") && strings.Contains(text, "deny") {
			add("nearby URL allowlist/private-network blocking cue")
		}
	case "CWE-639":
		if strings.Contains(text, "ownerid") || strings.Contains(text, "userid") ||
			strings.Contains(text, "tenantid") || strings.Contains(text, "organizationid") ||
			strings.Contains(text, "where:") && strings.Contains(text, "user.") {
			add("nearby owner/tenant predicate cue")
		}
	case "CWE-22":
		if strings.Contains(text, "path.normalize") || strings.Contains(text, "filepath.clean") ||
			strings.Contains(text, "safejoin") || strings.Contains(text, "realpath") ||
			strings.Contains(text, "startswith(basedir") {
			add("nearby path normalization/base-directory cue")
		}
	case "CWE-915":
		if strings.Contains(text, "pick(") || strings.Contains(text, "omit(") ||
			strings.Contains(text, "whitelist") || strings.Contains(text, "allowlist") ||
			strings.Contains(text, "fillable") {
			add("nearby field allowlist cue")
		}
	case "CWE-640", "CWE-532", "CWE-798":
		if strings.Contains(text, "redact") || strings.Contains(text, "mask") ||
			strings.Contains(text, "secretmanager") || strings.Contains(text, "vault") {
			add("nearby redaction/secret-manager cue")
		}
	case "CWE-347":
		if strings.Contains(text, "rs256") || strings.Contains(text, "es256") ||
			strings.Contains(text, "algorithms") && !strings.Contains(text, "none") {
			add("nearby strong JWT algorithm cue")
		}
	}
	if len(cues) == 0 {
		return "none observed in bounded local context"
	}
	return strings.Join(cues, "; ")
}

type ruleContext struct {
	RuleID         string
	CWE            string
	Route          string
	Source         string
	Counter        string
	FlowConfidence string
	Rel            string
	Lines          []string
}

func validationDisposition(ctx ruleContext) string {
	hasCounter := ctx.Counter != "" && ctx.Counter != "none observed in bounded local context"
	switch {
	case staticFalsePositiveReason(ctx) != "":
		return "false-positive-static"
	case hasCounter:
		return "needs-review-counterevidence"
	case ctx.FlowConfidence == "sanitized":
		return "needs-review-counterevidence"
	case ctx.FlowConfidence == "guarded":
		return "needs-review-counterevidence"
	case ctx.FlowConfidence == "context-only" || ctx.FlowConfidence == "missing":
		return "deferred-proof-gap"
	case ctx.Source == "unknown" || ctx.Route == "unknown":
		return "deferred-proof-gap"
	case needsRuntimeProof(ctx):
		return "needs-runtime-proof"
	default:
		return "reportable-static-candidate"
	}
}

func staticFalsePositiveReason(ctx ruleContext) string {
	text := strings.ToLower(strings.Join(ctx.Lines, "\n"))
	rel := strings.ToLower(ctx.Rel)
	switch ctx.RuleID {
	case "hardcoded-credential":
		if strings.Contains(text, "password") &&
			(strings.Contains(rel, "locales") || strings.Contains(rel, "i18n") || strings.Contains(text, "confirm password") || strings.Contains(text, "forgot password")) {
			return "localized UI label, not credential material"
		}
	case "react-dangerous-html":
		if strings.Contains(text, "application/ld+json") && strings.Contains(text, "json.stringify") {
			return "JSON-LD structured data rendered through JSON.stringify"
		}
	case "reflected-response-write":
		if strings.Contains(text, "res.write") && strings.Contains(text, "data:") && strings.Contains(text, "json.stringify") {
			return "server-sent-event JSON framing, not HTML response rendering"
		}
	case "ssrf-fetch-user-url":
		if strings.Contains(text, "fetch(localuri)") || strings.Contains(text, "await fetch(localuri)") {
			return "client/mobile local URI blob read, not server-side outbound request"
		}
		if strings.Contains(text, `"use client"`) || strings.Contains(text, `'use client'`) {
			return "React/Next client component fetch, not server-side request"
		}
		if strings.Contains(rel, "src\\components") || strings.Contains(rel, "src/components") {
			return "client component fetch candidate, not server-side request"
		}
	}
	return ""
}

func needsRuntimeProof(ctx ruleContext) bool {
	switch ctx.CWE {
	case "CWE-89", "CWE-79", "CWE-918", "CWE-22", "CWE-78":
		switch ctx.FlowConfidence {
		case "direct", "propagated", "interprocedural", "cross-file", "variable-derived":
			return true
		}
	}
	return false
}

func preconditionsSummary(authScope, route, source, cwe string) string {
	var parts []string
	if route == "unknown" {
		parts = append(parts, "prove a reachable application entrypoint")
	}
	if source == "unknown" {
		parts = append(parts, "prove attacker-controlled input reaches this code")
	}
	switch authScope {
	case "authenticated":
		parts = append(parts, "valid authenticated account")
	case "role-scoped":
		parts = append(parts, "account with the observed role/permission")
	case "unknown":
		parts = append(parts, "resolve authorization middleware")
	}
	switch cwe {
	case "CWE-918":
		parts = append(parts, "prove reachable internal/metadata/side-effecting destination")
	case "CWE-79":
		parts = append(parts, "prove rendered content executes in a victim browser context")
	case "CWE-639":
		parts = append(parts, "prove missing owner/tenant predicate on target object")
	case "CWE-502":
		parts = append(parts, "prove untrusted serialized data and exploitable gadget/runtime behavior")
	}
	if len(parts) == 0 {
		return "no extra preconditions visible beyond the candidate source/sink path"
	}
	return strings.Join(parts, "; ")
}

func owaspBucket(cwe string) string {
	switch cwe {
	case "CWE-89", "CWE-78", "CWE-79", "CWE-918", "CWE-502", "CWE-1336":
		if cwe == "CWE-918" {
			return "A01:2025 Broken Access Control"
		}
		return "A05:2025 Injection"
	case "CWE-327", "CWE-916", "CWE-347":
		return "A04:2025 Cryptographic Failures"
	case "CWE-640", "CWE-639", "CWE-862":
		return "A01:2025 Broken Access Control"
	case "CWE-798", "CWE-489", "CWE-614", "CWE-942", "CWE-295":
		return "A02:2025 Security Misconfiguration"
	case "CWE-532":
		return "A09:2025 Security Logging and Alerting Failures"
	case "CWE-22":
		return "A01:2025 Broken Access Control"
	case "CWE-915":
		return "A06:2025 Insecure Design"
	default:
		return "OWASP Top 10:2025 mapping needs review"
	}
}

func severityRationale(cwe, severity, authScope, source, route, counter, flowConfidence string) string {
	base := fmt.Sprintf("Pattern severity is %s for %s.", severity, cwe)
	if counter != "" && counter != "none observed in bounded local context" {
		return base + " Nearby counterevidence was observed, so a verifier should confirm whether it defeats the path before promotion."
	}
	if flowConfidence == "sanitized" {
		return base + " A sanitizer/validator cue appears on the source-to-sink path, so severity should not be promoted until a verifier confirms whether it neutralizes the issue."
	}
	if flowConfidence == "guarded" {
		return base + " A guard/allowlist cue appears before the sink, so severity should not be promoted until a verifier confirms whether it fully constrains attacker control."
	}
	if flowConfidence == "context-only" || flowConfidence == "missing" {
		return base + " Severity should not be promoted until source-to-sink value flow is proven beyond bounded-context proximity."
	}
	if source == "unknown" || route == "unknown" {
		return base + " Severity should not be promoted until entrypoint and attacker-control proof gaps are closed."
	}
	switch authScope {
	case "unauthenticated-or-public":
		return base + " Public/unauthenticated reachability increases likelihood if the static path is correct."
	case "authenticated":
		return base + " Authenticated reachability keeps impact dependent on tenant, ownership, and role boundaries."
	case "role-scoped":
		return base + " Role-scoped reachability requires checking whether the allowed role is lower privilege than the impacted asset."
	default:
		return base + " Authorization is unknown, so severity depends on middleware and deployment exposure."
	}
}

func attackPathSummary(cwe, authScope, route, source, sink string) string {
	if source == "unknown" {
		return "No attack path yet: missing attacker-controlled source proof."
	}
	actor := "an attacker"
	if authScope == "authenticated" {
		actor = "an authenticated user"
	} else if authScope == "role-scoped" {
		actor = "a user with the allowed role"
	}
	surface := route
	if surface == "unknown" {
		surface = "the affected code path"
	}
	switch cwe {
	case "CWE-89":
		return fmt.Sprintf("%s controls input to %s and may alter database query semantics.", actor, surface)
	case "CWE-78":
		return fmt.Sprintf("%s controls input to %s and may influence shell command execution.", actor, surface)
	case "CWE-918":
		return fmt.Sprintf("%s controls a server-side destination through %s and may reach internal or metadata services.", actor, surface)
	case "CWE-79":
		return fmt.Sprintf("%s can influence HTML rendered through %s; impact depends on victim role/session material.", actor, surface)
	case "CWE-639":
		return fmt.Sprintf("%s may swap object identifiers through %s; validate owner/tenant predicates.", actor, surface)
	case "CWE-640":
		return fmt.Sprintf("%s may obtain or expose reset-token material through %s.", actor, surface)
	case "CWE-502":
		return fmt.Sprintf("%s may feed serialized data to %s; impact depends on gadget/runtime behavior.", actor, surface)
	default:
		return fmt.Sprintf("%s reaches %s where %s is present; validate impact and counterevidence.", actor, surface, sink)
	}
}

func confidenceSummary(route, source, sink, authScope, counter, flowConfidence string) string {
	score := 0
	if route != "unknown" {
		score++
	}
	if source != "unknown" {
		score++
	}
	if sink != "" && sink != "matched rule sink" {
		score++
	}
	if authScope != "unknown" {
		score++
	}
	if counter != "" && counter != "none observed in bounded local context" {
		score -= 2
	}
	switch flowConfidence {
	case "direct", "propagated", "interprocedural", "cross-file":
		score++
	case "variable-derived":
		// strongest signal for multi-line pattern SAST without AST/SSA.
	case "context-only", "missing", "sanitized", "guarded":
		score--
	}
	switch {
	case score >= 4:
		return "high"
	case score >= 2:
		return "medium"
	default:
		return "low"
	}
}

func clampContext(s string, maxLen int) string {
	s = strings.Join(strings.Fields(s), " ")
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

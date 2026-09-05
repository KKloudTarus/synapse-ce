package sast

import (
	"regexp"
	"strings"
)

// Bounded cross-line resolution for sinks whose danger lives on an EARLIER line.
//
// The engine is line-based, so `db.Exec(query)` looks harmless on its own: the concatenation that
// makes it SQL injection happened where `query` was assigned. Real code almost always builds the
// statement first and executes it after. This adds one focused capability rather than a dataflow
// engine: when a sink argument is a bare identifier, walk back at most crossLineLookback lines in
// the SAME file for the nearest assignment to that identifier and require that assignment (with
// its continuation lines) to carry construction or request-source evidence. The nearest assignment
// decides, so a constant literal closes the question instead of the scan reaching further back.
const crossLineLookback = 10

// crossLineBuildRe marks a value that was BUILT rather than written as a constant: Sprintf, printf
// %-formatting, .format(), an f-string, or string concatenation adjacent to a quote.
//
// `||` is deliberately absent. It concatenates in SQL and PL/SQL and nowhere else: in JavaScript,
// Ruby, Go and Python it is logical-or, so `const sql = opts.sql || DEFAULT_SQL` was read as string
// building and reported as SQL injection. sqlConcatBuildRe adds it back for the languages where it
// really is concatenation.
var crossLineBuildRe = regexp.MustCompile("(?i)(fmt\\.Sprintf|\\bsprintf\\s*\\(|\\.format\\s*\\(|\\bf[\"'`]|[\"'][^\"'\\n]*[\"']\\s*%|[\"'`]\\s*\\+|\\+\\s*[\"'`]|\\$\\{|#\\{|\\.\\s*\\$)")

// sqlConcatBuildRe is crossLineBuildRe plus the SQL string-concatenation operator, used only for
// files written in SQL dialects.
var sqlConcatBuildRe = regexp.MustCompile(crossLineBuildRe.String() + "|\\|\\|")

// sqlDialectExts are the extensions where `||` concatenates strings.
var sqlDialectExts = map[string]bool{".sql": true, ".pls": true, ".plsql": true, ".pks": true, ".pkb": true}

// crossLineRequestRe marks a value read from the request: the user-controlled subset only, so a
// redirect built from a server-derived host is not flagged.
var crossLineRequestRe = regexp.MustCompile(`(?i)(req\.(query|params|body|originalUrl|url|headers|cookies)|request\.(args|form|values|json|parameters|data|GET|POST)|params\[|r\.URL|c\.Query\(|c\.Param\(|getParameter\(|\$_(GET|POST|REQUEST)|\.FormValue\(|\.PostFormValue\(|cookies\[)`)

var crossLineBuildOrRequestRe = regexp.MustCompile(crossLineBuildRe.String() + "|" + crossLineRequestRe.String())

// crossLineSink locates a sink call on the current line and says what an earlier assignment to its
// bare-identifier argument must contain for the sink to be dangerous.
type crossLineSink struct {
	re       *regexp.Regexp // match ends ON the '(' of the call when paren is true, else at the sink name
	paren    bool
	evidence *regexp.Regexp
}

// crossLineSinks are the rules whose true positives are routinely split across two lines. Every
// entry keeps its rule's own language gate: appliesTo is checked by the caller before this runs.
var crossLineSinks = map[string]crossLineSink{
	"generic-sql-dynamic-execute": {
		re:       regexp.MustCompile(`(?i)(?:cursor\.execute|\.execute(?:query|update)?|mysqli_query|pg_query|sequelize\.query|ActiveRecord::Base\.connection\.execute)\s*\(`),
		paren:    true,
		evidence: crossLineBuildOrRequestRe,
	},
	"sqlalchemy-raw-sql-dynamic": {
		re:       regexp.MustCompile(`(?i)(?:session\.execute|connection\.execute|db\.session\.execute|\btext)\s*\(`),
		paren:    true,
		evidence: crossLineBuildOrRequestRe,
	},
	"go-sql-dynamic-query": {
		re:       regexp.MustCompile(`\.(?:Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)\s*\(`),
		paren:    true,
		evidence: crossLineBuildOrRequestRe,
	},
	"go-sql-string-format": {
		re:       regexp.MustCompile(`\.(?:Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)\s*\(`),
		paren:    true,
		evidence: crossLineBuildRe,
	},
	"open-redirect-user-url": {
		re:       regexp.MustCompile(`(?i)(?:res\.redirect|response\.redirect|sendRedirect|http\.Redirect|c\.Redirect)\s*\(`),
		paren:    true,
		evidence: crossLineRequestRe,
	},
	"rb:open-redirect": {
		re:       regexp.MustCompile(`\bredirect_to\b`),
		evidence: crossLineRequestRe,
	},
}

// crossLineIdentRe recognizes a bare identifier argument (`query`, `$sql`, `str_query`). Anything
// with a call, an index, an operator, or a literal in it is already visible to the line rule.
var crossLineIdentRe = regexp.MustCompile(`^\$?([A-Za-z_][A-Za-z0-9_]*)$`)

// crossLineAssignRe captures the target of a simple assignment (`q = …`, `query := …`, `sql += …`).
// The trailing class rejects `==`; `!=`, `<=` and `>=` never reach it because the operator must
// follow the identifier directly.
var crossLineAssignRe = regexp.MustCompile(`(?:^|[;{}(\s])\$?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|\+=|=)([^=]|$)`)

// crossLineMatch reports whether the sink for ruleID on lines[at] takes a bare identifier that an
// earlier line assigned from a built or request-derived value.
//
// The walk stops at the start of the enclosing definition, so an assignment in a DIFFERENT function
// cannot supply the evidence. Without that the ten-line window reaches over a function boundary and
// reports a safe `cursor.execute(query)` because some other function above built a `query`.
func crossLineMatch(ruleID, ext string, lines []string, at int) bool {
	sink, ok := crossLineSinks[ruleID]
	if !ok || at >= len(lines) || len(lines[at]) > maxLineBytes || commentOnlyLine(lines[at]) {
		return false
	}
	pending := crossLineSinkIdents(sink, lines[at])
	if len(pending) == 0 {
		return false
	}
	evidence := sink.evidence
	if sqlDialectExts[ext] && evidence == crossLineBuildRe {
		evidence = sqlConcatBuildRe
	} else if sqlDialectExts[ext] && evidence == crossLineBuildOrRequestRe {
		evidence = sqlConcatBuildOrRequestRe
	}
	sinkIndent := leadingIndent(lines[at])
	start := max(0, at-crossLineLookback)
	for j := at - 1; j >= start && len(pending) > 0; j-- {
		prev := lines[j]
		if len(prev) > maxLineBytes || commentOnlyLine(prev) {
			continue
		}
		if startsEnclosingDefinition(prev, sinkIndent) {
			return false // a different function's assignments are not this sink's data flow
		}
		m := crossLineAssignRe.FindStringSubmatch(prev)
		if m == nil || !pending[m[1]] {
			continue
		}
		delete(pending, m[1]) // nearest assignment wins: a constant literal closes this identifier
		statement := assignmentStatement(lines, j, at)
		if ruleID == "rb:open-redirect" && railsRecordLookup.MatchString(statement) {
			// `user = User.find(params[:id])` then `redirect_to user` routes through the model's
			// own path helper, which is the canonical safe Rails idiom. The request marker in the
			// finder's argument is a record id, not the redirect target.
			continue
		}
		if evidence.MatchString(statement) {
			return true
		}
	}
	return false
}

// sqlConcatBuildOrRequestRe is crossLineBuildOrRequestRe for SQL dialects, where `||` concatenates.
var sqlConcatBuildOrRequestRe = regexp.MustCompile(sqlConcatBuildRe.String() + "|" + crossLineRequestRe.String())

// railsRecordLookup matches an ActiveRecord lookup: the value it returns is a model instance, and
// redirecting to one produces a route from the model rather than from request text.
var railsRecordLookup = regexp.MustCompile(`(?i)\b[A-Z]\w*\.(?:find(?:_by\w*)?|where|first|last|find_or_\w+)\b|\.\s*(?:find|find_by\w*)\s*\(`)

// leadingIndent returns the width of a line's leading whitespace, counting a tab as one column.
func leadingIndent(line string) int {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return i
		}
	}
	return len(line)
}

// definitionStartRe matches the start of a function, method or class in the languages the
// cross-line sinks cover.
var definitionStartRe = regexp.MustCompile(`^\s*(?:(?:async\s+)?def|func|function|class|module|sub|public|private|protected|static)\b|^\s*[A-Za-z_$][\w$]*\s*(?:=|:)\s*(?:async\s+)?function\b|^\s*[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{\s*$`)

// startsEnclosingDefinition reports whether prev opens a definition that encloses or precedes the
// sink rather than sitting inside the sink's own body. An indentation no deeper than the sink's own
// means the sink cannot be inside it, so the walk has left the sink's function.
func startsEnclosingDefinition(prev string, sinkIndent int) bool {
	return leadingIndent(prev) < sinkIndent && definitionStartRe.MatchString(prev)
}

// crossLineSinkIdents returns the sink call's bare-identifier arguments.
func crossLineSinkIdents(sink crossLineSink, line string) map[string]bool {
	loc := sink.re.FindStringIndex(line)
	if loc == nil {
		return nil
	}
	at := loc[1]
	if sink.paren {
		at-- // the regex consumed the '(' that opens the argument list
	}
	out := map[string]bool{}
	for _, arg := range crossLineCallArgs(line, at) {
		if m := crossLineIdentRe.FindStringSubmatch(strings.TrimSpace(arg)); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// crossLineCallArgs splits the argument list starting at from. A paren-less call (Rails
// `redirect_to url`) is treated as a list that runs to the end of the line.
func crossLineCallArgs(line string, from int) []string {
	rest := strings.TrimLeft(line[min(from, len(line)):], " \t")
	if !strings.HasPrefix(rest, "(") {
		rest = "(" + rest
	}
	var args []string
	var cur strings.Builder
	depth, quote := 0, byte(0)
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if quote != 0 {
			cur.WriteByte(ch)
			switch ch {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			quote = ch
			cur.WriteByte(ch)
		case '(', '[', '{':
			depth++
			if depth > 1 {
				cur.WriteByte(ch)
			}
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return append(args, cur.String())
			}
			cur.WriteByte(ch)
		case ',':
			if depth == 1 {
				args = append(args, cur.String())
				cur.Reset()
				continue
			}
			cur.WriteByte(ch)
		default:
			cur.WriteByte(ch)
		}
	}
	return append(args, cur.String()) // unterminated on this line: keep what was parsed
}

// assignmentStatement joins the assignment on line j with the continuation lines that belong to the
// same statement, bounded by end. A multi-line SQL literal keeps its formatting operator.
func assignmentStatement(lines []string, j, end int) string {
	depth := 0
	var out []string
	for i := j; i < end && i < len(lines); i++ {
		out = append(out, lines[i])
		depth += bracketDelta(lines[i])
		if depth <= 0 && !continuedLine(lines[i]) {
			break
		}
	}
	return strings.Join(out, "\n")
}

func bracketDelta(line string) int {
	delta := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta
}

// continuedLine reports whether the statement obviously continues on the next line.
func continuedLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	switch t[len(t)-1] {
	case '\\', '+', ',', '%', '.', '(', '[', '{', '&', '|':
		return true
	}
	return false
}

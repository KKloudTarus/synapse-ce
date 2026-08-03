package sast

import (
	"context"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const vbContextLines = 200

var (
	vbDisposableAcquisitionRE = regexp.MustCompile(`(?i)^\s*Dim\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:As\s+[A-Za-z0-9_.]+\s*)?=\s*New\s+(?:(?:System\.IO\.)?(?:FileStream|StreamReader|StreamWriter|BinaryReader|BinaryWriter|StringReader|StringWriter)|(?:System\.Data\.(?:SqlClient|OleDb|Odbc)\.)?(?:SqlConnection|SqlCommand|SqlDataReader|OleDbConnection|OleDbCommand|OdbcConnection|OdbcCommand))\s*\(`)
	vbMemberStartRE           = regexp.MustCompile(`(?i)^(?:Public|Private|Friend|Protected|Shared|Overridable|Overrides|Partial|Default|ReadOnly|WriteOnly|Static|Async|Iterator|\s)*(?:Sub|Function|Property)\b`)
)

func (a *Analyzer) vbContextualFindings(ctx context.Context, rel, ext string, lines []string, project projectContext, out *[]ports.SASTRawFinding, limit int) error {
	if !vbExts[ext] {
		return nil
	}
	for i, raw := range lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(*out) == limit {
			return nil
		}
		if len(raw) > maxLineBytes {
			continue
		}
		code := vbCodeOnly(raw)
		if a.vbRuleLineMatches("vb:empty-catch", code) && !vbCatchContainsNestedTry(lines, i) && vbCatchBodyEmpty(lines, i) {
			if h, ok := a.findingFromRule(rel, ext, i+1, "vb:empty-catch", lines, project); ok {
				*out = append(*out, h)
			}
		}
		if len(*out) == limit {
			return nil
		}
		match := vbDisposableAcquisitionRE.FindStringSubmatch(code)
		if len(match) == 2 && !vbDisposedOnLine(code, match[1]) && !vbLocalDisposed(lines, i, match[1]) {
			if h, ok := a.findingFromRule(rel, ext, i+1, "vb:idisposable-not-disposed", lines, project); ok {
				*out = append(*out, h)
			}
		}
	}
	return nil
}

func (a *Analyzer) vbRuleLineMatches(id, code string) bool {
	for i := range a.rules {
		if a.rules[i].id == id {
			return a.rules[i].re.MatchString(code)
		}
	}
	return false
}

func vbCatchContainsNestedTry(lines []string, catchLine int) bool {
	end := min(len(lines), catchLine+vbContextLines)
	depth := 0
	for i := catchLine + 1; i < end; i++ {
		if len(lines[i]) > maxLineBytes {
			continue
		}
		code := strings.ToLower(strings.TrimSpace(vbCodeOnly(lines[i])))
		switch {
		case code == "try":
			depth++
		case code == "end try" && depth > 0:
			return true
		case code == "end try":
			return false
		case depth == 0 && (strings.HasPrefix(code, "catch") || code == "finally"):
			return false
		}
	}
	return false
}

func vbCatchBodyEmpty(lines []string, catchLine int) bool {
	end := min(len(lines), catchLine+vbContextLines)
	nestedTry := 0
	for i := catchLine + 1; i < end; i++ {
		if len(lines[i]) > maxLineBytes {
			continue
		}
		code := strings.TrimSpace(vbCodeOnly(lines[i]))
		if code == "" {
			continue
		}
		lower := strings.ToLower(code)
		switch {
		case lower == "try":
			nestedTry++
		case lower == "end try":
			if nestedTry > 0 {
				nestedTry--
				continue
			}
			return true
		case nestedTry == 0 && (strings.HasPrefix(lower, "catch") || lower == "finally"):
			return true
		case nestedTry > 0:
			continue
		default:
			return false
		}
	}
	return false
}

func vbLocalDisposed(lines []string, acquisitionLine int, name string) bool {
	end := min(len(lines), acquisitionLine+vbContextLines)
	name = strings.ToLower(name)
	for i := acquisitionLine + 1; i < end; i++ {
		if len(lines[i]) > maxLineBytes {
			continue
		}
		code := strings.TrimSpace(strings.ToLower(vbCodeOnly(lines[i])))
		if vbReceiverCleanup(code, name) {
			return true
		}
		if code == "" {
			continue
		}
		if vbMemberStartRE.MatchString(code) || vbMemberEnd(code) {
			return false
		}
		if vbReceiverCleanup(code, name) || code == "using "+name || strings.HasPrefix(code, "using "+name+" ") {
			return true
		}
	}
	return false
}

func vbDisposedOnLine(code, name string) bool {
	return strings.Contains(strings.ToLower(code), ": "+strings.ToLower(name)+".dispose()") ||
		strings.Contains(strings.ToLower(code), ": "+strings.ToLower(name)+".close()")
}

func vbMemberEnd(code string) bool {
	switch code {
	case "end sub", "end function", "end property", "end get", "end set":
		return true
	default:
		return false
	}
}

func vbReceiverCleanup(code, name string) bool {
	for _, statement := range strings.Split(code, ":") {
		statement = strings.TrimSpace(statement)
		statement = strings.TrimSpace(strings.TrimPrefix(statement, "call "))
		if strings.HasPrefix(statement, "if ") {
			if then := strings.Index(statement, " then "); then >= 0 {
				statement = strings.TrimSpace(statement[then+len(" then "):])
			}
		}
		for _, method := range []string{"dispose", "close"} {
			if strings.HasPrefix(statement, name+"."+method+"(") {
				return true
			}
		}
	}
	return false
}

//go:build cgo

package astwalk

import (
	"bytes"
	"crypto/sha256"
	"strings"
)

const (
	cssMaxMaintainabilityDepth = 256
	cssMaxSelectorDepth        = 32
	cssMaxPreludeBytes         = 64 * 1024
	cssMaxTrackedItems         = 4096
)

var cssVendorStandardPairs = map[string]string{
	"-webkit-transform":       "transform",
	"-webkit-user-select":     "user-select",
	"-moz-user-select":        "user-select",
	"-ms-user-select":         "user-select",
	"-webkit-appearance":      "appearance",
	"-moz-appearance":         "appearance",
	"-webkit-backdrop-filter": "backdrop-filter",
}

var cssShorthandMap = map[string]string{
	"margin-top":                 "margin",
	"margin-right":               "margin",
	"margin-bottom":              "margin",
	"margin-left":                "margin",
	"padding-top":                "padding",
	"padding-right":              "padding",
	"padding-bottom":             "padding",
	"padding-left":               "padding",
	"top":                        "inset",
	"right":                      "inset",
	"bottom":                     "inset",
	"left":                       "inset",
	"border-top-color":           "border-color",
	"border-right-color":         "border-color",
	"border-bottom-color":        "border-color",
	"border-left-color":          "border-color",
	"border-top-style":           "border-style",
	"border-right-style":         "border-style",
	"border-bottom-style":        "border-style",
	"border-left-style":          "border-style",
	"border-top-width":           "border-width",
	"border-right-width":         "border-width",
	"border-bottom-width":        "border-width",
	"border-left-width":          "border-width",
	"background-color":           "background",
	"background-image":           "background",
	"background-repeat":          "background",
	"background-position":        "background",
	"background-size":            "background",
	"font-family":                "font",
	"font-size":                  "font",
	"font-weight":                "font",
	"font-style":                 "font",
	"line-height":                "font",
	"animation-name":             "animation",
	"animation-duration":         "animation",
	"animation-timing-function":  "animation",
	"animation-delay":            "animation",
	"animation-iteration-count":  "animation",
	"animation-direction":        "animation",
	"animation-fill-mode":        "animation",
	"transition-property":        "transition",
	"transition-duration":        "transition",
	"transition-timing-function": "transition",
	"transition-delay":           "transition",
}

var cssLegacyProperties = map[string]string{
	"clip":              "clip-path",
	"page-break-before": "break-before",
	"page-break-after":  "break-after",
	"page-break-inside": "break-inside",
}

var cssZeroLengthUnits = map[string]bool{
	"em": true, "rem": true, "ex": true, "rex": true, "cap": true, "rcap": true,
	"ch": true, "rch": true, "ic": true, "ric": true, "lh": true, "rlh": true,
	"vw": true, "vh": true, "vi": true, "vb": true, "vmin": true, "vmax": true,
	"svw": true, "svh": true, "svi": true, "svb": true, "svmin": true, "svmax": true,
	"lvw": true, "lvh": true, "lvi": true, "lvb": true, "lvmin": true, "lvmax": true,
	"dvw": true, "dvh": true, "dvi": true, "dvb": true, "dvmin": true, "dvmax": true,
	"cqw": true, "cqh": true, "cqi": true, "cqb": true, "cqmin": true, "cqmax": true,
	"cm": true, "mm": true, "q": true, "in": true, "pt": true, "pc": true, "px": true,
}

var cssGenericFontFamilies = map[string]bool{
	"serif": true, "sans-serif": true, "monospace": true, "cursive": true,
	"fantasy": true, "system-ui": true, "ui-serif": true, "ui-sans-serif": true,
	"ui-monospace": true, "ui-rounded": true, "math": true, "emoji": true,
	"fangsong": true,
}

var cssWideKeywords = map[string]bool{
	"inherit": true, "initial": true, "unset": true, "revert": true, "revert-layer": true,
}

var cssLegacyPseudoElements = map[string]bool{
	"before": true, "after": true, "first-line": true, "first-letter": true,
}

type cssCanonicalResult struct {
	Text     string
	Complete bool
}

type cssScopedDigest [32]byte

type cssScopedName struct {
	ScopeHash [32]byte
	Keyword   string
	Name      string
}

type cssOccurrence struct {
	Line int
}

func canonicalizeCSSPrelude(src []byte) cssCanonicalResult {
	if len(src) > cssMaxPreludeBytes {
		return cssCanonicalResult{Complete: false}
	}

	var buf bytes.Buffer
	buf.Grow(len(src))

	inSingleQuote := false
	inDoubleQuote := false
	inComment := false
	escaped := false

	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0

	lastWasSpace := false

	for i := 0; i < len(src); i++ {
		b := src[i]

		if escaped {
			buf.WriteByte(b)
			escaped = false
			lastWasSpace = false
			continue
		}

		if (inSingleQuote || inDoubleQuote) && b == '\\' {
			buf.WriteByte(b)
			escaped = true
			continue
		}

		if inComment {
			if b == '*' && i+1 < len(src) && src[i+1] == '/' {
				inComment = false
				i++
			}
			continue
		}

		if !inSingleQuote && !inDoubleQuote {
			if b == '/' && i+1 < len(src) && src[i+1] == '*' {
				inComment = true
				i++
				continue
			}
			if b == '\'' {
				inSingleQuote = true
				buf.WriteByte(b)
				lastWasSpace = false
				continue
			}
			if b == '"' {
				inDoubleQuote = true
				buf.WriteByte(b)
				lastWasSpace = false
				continue
			}
		} else {
			if inSingleQuote && b == '\'' {
				inSingleQuote = false
			} else if inDoubleQuote && b == '"' {
				inDoubleQuote = false
			}
			buf.WriteByte(b)
			lastWasSpace = false
			continue
		}

		if b == '(' {
			parenDepth++
		} else if b == ')' {
			parenDepth--
			if parenDepth < 0 {
				return cssCanonicalResult{Complete: false}
			}
		} else if b == '[' {
			bracketDepth++
		} else if b == ']' {
			bracketDepth--
			if bracketDepth < 0 {
				return cssCanonicalResult{Complete: false}
			}
		} else if b == '{' {
			braceDepth++
		} else if b == '}' {
			braceDepth--
			if braceDepth < 0 {
				return cssCanonicalResult{Complete: false}
			}
		}

		if b == ',' && !inSingleQuote && !inDoubleQuote {
			for buf.Len() > 0 && buf.Bytes()[buf.Len()-1] == ' ' {
				buf.Truncate(buf.Len() - 1)
			}
			buf.WriteString(", ")
			lastWasSpace = true
			continue
		}

		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			if !lastWasSpace && buf.Len() > 0 {
				buf.WriteByte(' ')
				lastWasSpace = true
			}
			continue
		}

		buf.WriteByte(b)
		lastWasSpace = false
	}

	if inSingleQuote || inDoubleQuote || inComment || parenDepth != 0 || bracketDepth != 0 || braceDepth != 0 {
		return cssCanonicalResult{Complete: false}
	}

	resText := strings.TrimSpace(buf.String())
	return cssCanonicalResult{Text: resText, Complete: true}
}

func canonicalizeCSSSelectorPrelude(src []byte) cssCanonicalResult {
	canon := canonicalizeCSSPrelude(src)
	if !canon.Complete {
		return canon
	}
	canon.Text = normalizeCSSSelectorCombinators(canon.Text)
	return canon
}

func normalizeCSSSelectorCombinators(selector string) string {
	var result bytes.Buffer
	parenDepth := 0
	bracketDepth := 0
	inString := byte(0)
	escaped := false

	for i := 0; i < len(selector); i++ {
		b := selector[i]
		if escaped {
			result.WriteByte(b)
			escaped = false
			continue
		}
		if b == '\\' {
			result.WriteByte(b)
			escaped = true
			continue
		}
		if inString != 0 {
			result.WriteByte(b)
			if b == inString {
				inString = 0
			}
			continue
		}
		if b == '\'' || b == '"' {
			result.WriteByte(b)
			inString = b
			continue
		}
		switch b {
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		}

		if parenDepth == 0 && bracketDepth == 0 && (b == '>' || b == '+' || b == '~' || (b == '|' && i+1 < len(selector) && selector[i+1] == '|')) {
			for result.Len() > 0 && result.Bytes()[result.Len()-1] == ' ' {
				result.Truncate(result.Len() - 1)
			}
			result.WriteByte(b)
			if b == '|' {
				result.WriteByte('|')
				i++
			}
			for i+1 < len(selector) && selector[i+1] == ' ' {
				i++
			}
			continue
		}

		result.WriteByte(b)
	}
	return strings.TrimSpace(result.String())
}

func computeCSSScopeHash(scopeChain []string) [32]byte {
	h := sha256.New()
	for _, s := range scopeChain {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeCSSScopedDigest(scopeHash [32]byte, text string) cssScopedDigest {
	h := sha256.New()
	h.Write(scopeHash[:])
	h.Write([]byte(text))
	var digest cssScopedDigest
	copy(digest[:], h.Sum(nil))
	return digest
}

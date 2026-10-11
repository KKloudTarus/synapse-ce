package siem

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var urlPattern = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://\S+`)

// SafeDiagnostic keeps a short operator-facing reason. It strips URLs,
// authorization material, and non-printable bytes so a provider body cannot
// ride back out through an API error.
func SafeDiagnostic(text string) string {
	text = urlPattern.ReplaceAllString(text, "[url]")
	lower := strings.ToLower(text)
	for _, marker := range []string{"splunk ", "bearer ", "apikey ", "api_key ", "basic ", "token "} {
		for {
			i := strings.Index(lower, marker)
			if i < 0 {
				break
			}
			j := i + len(marker)
			for j < len(text) && text[j] != ' ' && text[j] != '\n' && text[j] != '"' {
				j++
			}
			text = text[:i] + "[secret]" + text[j:]
			lower = strings.ToLower(text)
		}
	}
	clean := strings.Builder{}
	clean.Grow(len(text))
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			clean.WriteByte(' ')
			continue
		}
		clean.WriteRune(r)
	}
	out := strings.Join(strings.Fields(clean.String()), " ")
	if utf8.RuneCountInString(out) <= MaxDiagnosticLen {
		return out
	}
	runes := []rune(out)
	return string(runes[:MaxDiagnosticLen])
}

// RecordID is the stable identity of one source row. Retries reuse it so a
// destination that deduplicates can collapse a crash duplicate.
func RecordID(tenant, source, identity string) string {
	return "siem:" + tenant + ":" + source + ":" + identity
}

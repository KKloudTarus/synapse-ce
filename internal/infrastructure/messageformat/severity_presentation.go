package messageformat

import (
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// severityTitle prefixes a channel title with a stable, non-textual severity marker. The marker
// is selected only from the typed event metadata; template text never controls presentation.
// limit is a provider's visible title limit. A non-positive limit means the provider has none.
func severityTitle(severity shared.Severity, title string, limit int) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return ""
	}
	if limit > 0 {
		title = truncateRunes(title, limit)
	}
	badge, ok := severityBadge(severity)
	if !ok {
		return title
	}
	prefix := badge + " "
	if limit <= 0 {
		return prefix + title
	}
	return prefix + truncateRunes(title, max(limit-utf8.RuneCountInString(prefix), 0))
}

// severityBadge carries the urgency palette consistently across chat clients: red, orange,
// yellow, blue, then neutral. Unknown and absent values deliberately make no risk claim.
func severityBadge(severity shared.Severity) (string, bool) {
	switch severity {
	case shared.SeverityCritical:
		return "🔴", true
	case shared.SeverityHigh:
		return "🟠", true
	case shared.SeverityMedium:
		return "🟡", true
	case shared.SeverityLow:
		return "🔵", true
	case shared.SeverityInfo:
		return "⚪", true
	default:
		return "", false
	}
}

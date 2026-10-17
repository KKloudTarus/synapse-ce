package jira

import (
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketExternalTextSanitizer = (*Adapter)(nil)

func (a *Adapter) RedactExternalTicketText(text string) (string, error) {
	if len(text) > 16<<10 || !utf8.ValidString(text) {
		return "", ticketError(0, "invalid_external_text", 0, false)
	}
	for _, c := range text {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			return "", ticketError(0, "invalid_external_text", 0, false)
		}
	}
	result := redact.AuditText(strings.TrimSpace(text), []string{a.email, a.token})
	if len(result) > 16<<10 {
		return "", ticketError(0, "invalid_external_text", 0, false)
	}
	return result, nil
}

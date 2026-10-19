package jira

import (
	"encoding/json"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketGroupFormatter = (*Adapter)(nil)

func (a *Adapter) FormatTicketGroupDescription(body string, links []ports.RenderedLink, headers []string, rows [][]string) (json.RawMessage, error) {
	if err := a.validateDescriptionLiterals(body, links, headers, rows); err != nil {
		return nil, err
	}
	var value any
	var err error
	if a.cloud {
		value, err = messageformat.JiraADFWithTable(body, links, headers, rows)
	} else {
		value, err = messageformat.JiraWikiWithTable(body, links, headers, rows)
	}
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ticketError(0, "invalid_payload", 0, false)
	}
	if err = a.ValidateTicketPayload(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Check literal values before a formatter can split or escape a credential. A
// wiki escape inside a token must not hide it from exact configured-value checks.
func (a *Adapter) validateDescriptionLiterals(body string, links []ports.RenderedLink, headers []string, rows [][]string) error {
	raw, err := json.Marshal(struct {
		Body    string
		Links   []ports.RenderedLink
		Headers []string
		Rows    [][]string
	}{body, links, headers, rows})
	if err != nil {
		return ticketError(0, "invalid_payload", 0, false)
	}
	return a.ValidateTicketPayload(raw)
}
